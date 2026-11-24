import { beforeAll, expect, test } from "bun:test"
import { eq, sql } from "@openwork-ee/den-db/drizzle"
import { AuthUserTable, InvitationTable, MemberTable, OrganizationTable, WorkerTable } from "@openwork-ee/den-db/schema"
import { createDenTypeId } from "@openwork-ee/utils/typeid"
import { hashPassword } from "better-auth/crypto"

const AUTH_ORIGIN = "http://127.0.0.1:8790"
const TEST_PASSWORD = "test-password-placeholder"
const RAISED_MEMBER_LIMIT = 5000
const RAISED_WORKER_LIMIT = 5000

function seedRequiredEnv() {
  process.env.DATABASE_URL = process.env.DATABASE_URL ?? "mysql://root:password@127.0.0.1:3306/openwork_test"
  process.env.DEN_DB_ENCRYPTION_KEY = process.env.DEN_DB_ENCRYPTION_KEY ?? "x".repeat(32)
  process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET ?? "y".repeat(32)
  process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL ?? AUTH_ORIGIN
  process.env.CORS_ORIGINS = process.env.CORS_ORIGINS ?? AUTH_ORIGIN
  process.env.OPENWORK_DEV_MODE = process.env.OPENWORK_DEV_MODE ?? "1"
  process.env.PROVISIONER_MODE = process.env.PROVISIONER_MODE ?? "stub"
}

seedRequiredEnv()

type App = typeof import("../src/app.js").default
type Db = typeof import("../src/db.js").db
type OrganizationId = typeof OrganizationTable.$inferSelect.id
type UserId = typeof AuthUserTable.$inferSelect.id

let app: App
let db: Db
let auth: typeof import("../src/auth.js").auth
let getOrganizationLimitStatus: typeof import("../src/organization-limits.js").getOrganizationLimitStatus
let seedDefaultOrganizationRoles: typeof import("../src/orgs.js").seedDefaultOrganizationRoles
let planLimits: { members: number; workers: number }

beforeAll(async () => {
  const { db: database } = await import("../src/db.js")
  const versionResult = await database.execute(sql`SELECT VERSION() AS version`)
  const versionRows = Array.isArray(versionResult) ? versionResult[0] : versionResult
  const version = Array.isArray(versionRows) ? String((versionRows[0] as { version?: string } | undefined)?.version ?? "") : ""
  if (!version.startsWith("8.") || /mariadb/i.test(version)) {
    throw new Error(`These tests must run on MySQL 8.x (the Den dev stack uses mysql:8.4). Connected server reported ${version || "an unknown version"}. MariaDB returns JSON columns as text, so this metadata write does not raise limits there.`)
  }

  const limits = await import("../src/organization-limits.js")
  planLimits = limits.DEFAULT_ORGANIZATION_LIMITS
  getOrganizationLimitStatus = limits.getOrganizationLimitStatus
  db = database
  const authModule = await import("../src/auth.js")
  auth = authModule.auth
  const orgs = await import("../src/orgs.js")
  seedDefaultOrganizationRoles = orgs.seedDefaultOrganizationRoles
  app = (await import("../src/app.js")).default
})

function uniqueEmail(label: string) {
  return `${label}-${createDenTypeId("user")}@example.com`
}

let forwardedForCounter = 0

function forwardedFor() {
  forwardedForCounter += 1
  return `203.0.113.${forwardedForCounter}`
}

async function responseBody(response: Response) {
  const text = await response.text()
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

function sessionCookie(response: Response) {
  const cookies = typeof response.headers.getSetCookie === "function" ? response.headers.getSetCookie() : []
  const pair = cookies.map((cookie) => cookie.split(";")[0] ?? "").find((cookie) => cookie.startsWith("better-auth.session_token="))
  if (!pair) {
    throw new Error("Better Auth sign-in did not set a session cookie")
  }
  return pair
}

async function signIn(email: string) {
  const response = await app.request(`${AUTH_ORIGIN}/api/auth/sign-in/email`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: AUTH_ORIGIN,
      "x-forwarded-for": forwardedFor(),
    },
    body: JSON.stringify({
      email,
      password: TEST_PASSWORD,
    }),
  })
  const body = await responseBody(response)
  expect(response.status, JSON.stringify(body)).toBe(200)
  return sessionCookie(response)
}

async function createCredentialUser(email: string) {
  const context = await auth.$context
  const user = await context.internalAdapter.createUser({
    name: email,
    email,
    emailVerified: true,
  })
  await context.internalAdapter.createAccount({
    userId: user.id,
    providerId: "credential",
    accountId: user.id,
    password: await hashPassword(TEST_PASSWORD),
  })
  return user.id as UserId
}

async function createOrganization(input: { name: string; metadata?: Record<string, unknown> | null }) {
  const organizationId = createDenTypeId("organization")
  await db.insert(OrganizationTable).values({
    id: organizationId,
    name: input.name,
    slug: organizationId,
    metadata: input.metadata ?? {
      limits: {
        members: planLimits.members,
        workers: planLimits.workers,
      },
    },
  })
  await seedDefaultOrganizationRoles(organizationId)
  return organizationId
}

async function addMember(organizationId: OrganizationId, userId: UserId, role: "owner" | "admin" | "member") {
  await db.insert(MemberTable).values({
    id: createDenTypeId("member"),
    organizationId,
    userId,
    role,
  })
}

async function signedInMember(role: "owner" | "admin" | "member") {
  const email = uniqueEmail(role)
  const userId = await createCredentialUser(email)
  const organizationId = await createOrganization({ name: `${role} workspace` })
  await addMember(organizationId, userId, role)
  const cookie = await signIn(email)
  return { cookie, organizationId, userId, email }
}

async function enforcedLimits(organizationId: OrganizationId) {
  const members = await getOrganizationLimitStatus(organizationId, "members")
  const workers = await getOrganizationLimitStatus(organizationId, "workers")
  return {
    members: members.limit,
    workers: workers.limit,
    memberCount: members.currentCount,
    workerCount: workers.currentCount,
  }
}

async function expectPlanLimits(organizationId: OrganizationId) {
  const limits = await enforcedLimits(organizationId)
  expect(limits.members).toBe(planLimits.members)
  expect(limits.workers).toBe(planLimits.workers)
}

async function postOrganizationUpdate(cookie: string, organizationId: OrganizationId, metadata: Record<string, unknown>) {
  const response = await app.request(`${AUTH_ORIGIN}/api/auth/organization/update`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie,
      origin: AUTH_ORIGIN,
      "x-forwarded-for": forwardedFor(),
    },
    body: JSON.stringify({
      organizationId,
      data: { metadata },
    }),
  })
  const body = await responseBody(response)
  return { response, body }
}

async function postOrganizationCreate(cookie: string, metadata: Record<string, unknown>) {
  const slug = `raised-${createDenTypeId("organization").slice(4)}`
  const response = await app.request(`${AUTH_ORIGIN}/api/auth/organization/create`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie,
      origin: AUTH_ORIGIN,
      "x-forwarded-for": forwardedFor(),
    },
    body: JSON.stringify({
      name: "Raised workspace",
      slug,
      metadata,
    }),
  })
  const body = await responseBody(response)
  const rows = await db.select({ id: OrganizationTable.id }).from(OrganizationTable).where(eq(OrganizationTable.slug, slug))
  return { response, body, organizationId: rows[0]?.id ?? null }
}

function numericLimitMetadata() {
  return {
    limits: {
      members: RAISED_MEMBER_LIMIT,
      workers: RAISED_WORKER_LIMIT,
    },
  }
}

function stringLimitMetadata() {
  return {
    limits: {
      members: String(RAISED_MEMBER_LIMIT),
      workers: String(RAISED_WORKER_LIMIT),
    },
  }
}

test("an organization owner cannot raise member or worker limits through Better Auth organization update", async () => {
  const actor = await signedInMember("owner")
  const { response, body } = await postOrganizationUpdate(actor.cookie, actor.organizationId, numericLimitMetadata())
  expect(response.status, JSON.stringify(body)).toBeLessThan(500)
  await expectPlanLimits(actor.organizationId)
})

test("an organization admin cannot raise member or worker limits through Better Auth organization update", async () => {
  const actor = await signedInMember("admin")
  const { response, body } = await postOrganizationUpdate(actor.cookie, actor.organizationId, numericLimitMetadata())
  expect(response.status, JSON.stringify(body)).toBeLessThan(500)
  await expectPlanLimits(actor.organizationId)
})

test("numeric strings in organization metadata cannot raise member or worker limits", async () => {
  const actor = await signedInMember("owner")
  const { response, body } = await postOrganizationUpdate(actor.cookie, actor.organizationId, stringLimitMetadata())
  expect(response.status, JSON.stringify(body)).toBeLessThan(500)
  await expectPlanLimits(actor.organizationId)
})

test("the Workers alias in organization metadata cannot raise the cloud worker limit", async () => {
  const actor = await signedInMember("owner")
  const { response, body } = await postOrganizationUpdate(actor.cookie, actor.organizationId, {
    limits: {
      members: planLimits.members,
      Workers: RAISED_WORKER_LIMIT,
    },
  })
  expect(response.status, JSON.stringify(body)).toBeLessThan(500)
  await expectPlanLimits(actor.organizationId)
})

test("a member without organization update permission cannot write limits", async () => {
  const actor = await signedInMember("member")
  const { response, body } = await postOrganizationUpdate(actor.cookie, actor.organizationId, numericLimitMetadata())
  expect(response.status, JSON.stringify(body)).toBe(403)
  await expectPlanLimits(actor.organizationId)
})

test("organization create cannot persist client-supplied member or worker limits", async () => {
  const email = uniqueEmail("creator")
  await createCredentialUser(email)
  const cookie = await signIn(email)

  for (const metadata of [numericLimitMetadata(), stringLimitMetadata()]) {
    const created = await postOrganizationCreate(cookie, metadata)
    expect(created.response.status, JSON.stringify(created.body)).toBeLessThan(500)
    if (created.organizationId) {
      await expectPlanLimits(created.organizationId)
    } else {
      expect(created.response.ok).toBe(false)
    }
  }
})

test("cloud worker creation stays capped at the plan limit after an owner writes metadata", async () => {
  const actor = await signedInMember("owner")
  await db.insert(WorkerTable).values({
    id: createDenTypeId("worker"),
    org_id: actor.organizationId,
    created_by_user_id: actor.userId,
    name: "existing-cloud-worker",
    destination: "cloud",
    status: "healthy",
  })

  const updated = await postOrganizationUpdate(actor.cookie, actor.organizationId, numericLimitMetadata())
  expect(updated.response.status, JSON.stringify(updated.body)).toBeLessThan(500)

  const response = await app.request(`${AUTH_ORIGIN}/v1/workers`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: actor.cookie,
      origin: AUTH_ORIGIN,
      "x-forwarded-for": forwardedFor(),
    },
    body: JSON.stringify({
      name: "extra-cloud-worker",
      destination: "cloud",
    }),
  })
  await responseBody(response)
  const rows = await db
    .select({ count: sql<number>`count(*)` })
    .from(WorkerTable)
    .where(eq(WorkerTable.org_id, actor.organizationId))
  expect({
    status: response.status,
    workers: Number(rows[0]?.count ?? 0),
  }).toEqual({
    status: 409,
    workers: 1,
  })
  const limits = await enforcedLimits(actor.organizationId)
  expect(limits.workers).toBe(planLimits.workers)
  expect(limits.workerCount).toBe(1)
})

test("member invitations stay capped at the plan limit after an owner writes metadata", async () => {
  const actor = await signedInMember("owner")
  for (let index = 0; index < planLimits.members - 1; index += 1) {
    const userId = await createCredentialUser(uniqueEmail(`seat-${index}`))
    await addMember(actor.organizationId, userId, "member")
  }

  const updated = await postOrganizationUpdate(actor.cookie, actor.organizationId, numericLimitMetadata())
  expect(updated.response.status, JSON.stringify(updated.body)).toBeLessThan(500)

  const before = await db
    .select({ count: sql<number>`count(*)` })
    .from(InvitationTable)
    .where(eq(InvitationTable.organizationId, actor.organizationId))

  const response = await app.request(`${AUTH_ORIGIN}/v1/invitations`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      cookie: actor.cookie,
      origin: AUTH_ORIGIN,
      "x-forwarded-for": forwardedFor(),
    },
    body: JSON.stringify({
      email: uniqueEmail("invitee"),
      role: "member",
    }),
  })
  await responseBody(response)
  const after = await db
    .select({ count: sql<number>`count(*)` })
    .from(InvitationTable)
    .where(eq(InvitationTable.organizationId, actor.organizationId))
  expect({
    status: response.status,
    invitations: Number(after[0]?.count ?? 0),
  }).toEqual({
    status: 409,
    invitations: Number(before[0]?.count ?? 0),
  })
  const limits = await enforcedLimits(actor.organizationId)
  expect(limits.members).toBe(planLimits.members)
  expect(limits.memberCount).toBe(planLimits.members)
})
