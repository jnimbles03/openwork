import { afterAll, beforeAll, describe, expect, test } from "bun:test"

/**
 * Cross-tenant plugin-system access.
 *
 * These tests exercise the live den-api routes, session lookup, and plugin
 * store. They fail while an owner of one organization can link config objects
 * to another organization's plugin, or can read and change that organization's
 * access grants, by supplying the other organization's resource id.
 */

function seedRequiredEnv() {
  process.env.DATABASE_URL = process.env.DATABASE_URL ?? "mysql://openwork:placeholder@127.0.0.1:3306/openwork_plugin_arch_test"
  process.env.DB_MODE = process.env.DB_MODE ?? "mysql"
  process.env.DEN_DB_ENCRYPTION_KEY = process.env.DEN_DB_ENCRYPTION_KEY ?? "placeholder-encryption-key-32chars"
  process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET ?? "placeholder-better-auth-secret-32"
  process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL ?? "http://127.0.0.1:8790"
}

seedRequiredEnv()

const VICTIM_OWNER_SESSION = "placeholder-victim-owner-session"
const VICTIM_MEMBER_SESSION = "placeholder-victim-member-session"
const ATTACKER_OWNER_SESSION = "placeholder-attacker-owner-session"
const ATTACKER_MEMBER_SESSION = "placeholder-attacker-member-session"

const ATTACK_SOURCE_PREFIX = "CROSS_TENANT_SOURCE"
const SEEDED_FOREIGN_SOURCE = "SEEDED_FOREIGN_PLUGIN_SOURCE"
const UPDATED_FOREIGN_SOURCE = "SEEDED_FOREIGN_PLUGIN_SOURCE_V2"

type AppModule = typeof import("../src/routes/org/plugin-system/routes.js")
type DbModule = typeof import("../src/db.js")
type SchemaModule = typeof import("@openwork-ee/den-db/schema")
type UtilsModule = typeof import("@openwork-ee/utils/typeid")
type DrizzleModule = typeof import("@openwork-ee/den-db/drizzle")

let app: { request: (input: string, init?: RequestInit) => Promise<Response> }
let db: DbModule["db"]
let schema: SchemaModule
let createDenTypeId: UtilsModule["createDenTypeId"]
let eq: DrizzleModule["eq"]

type Identity = {
  organizationId: string
  userId: string
  memberId: string
}

let victimOwner: Identity
let victimMember: Identity
let attackerOwner: Identity
let attackerMember: Identity
let victimPluginId = ""
let attackerPluginId = ""
let orgWidePluginId = ""
let victimMarketplaceId = ""
let victimConfigObjectId = ""
let victimConnectorInstanceId = ""
let victimPluginGrantId = ""

beforeAll(async () => {
  seedRequiredEnv()
  const hono = await import("hono")
  const routes = await import("../src/routes/org/plugin-system/routes.js") as AppModule
  const session = await import("../src/session.js")
  const dbModule = await import("../src/db.js")
  schema = await import("@openwork-ee/den-db/schema")
  const utils = await import("@openwork-ee/utils/typeid")
  const drizzle = await import("@openwork-ee/den-db/drizzle")
  db = dbModule.db
  createDenTypeId = utils.createDenTypeId
  eq = drizzle.eq

  const server = new hono.Hono()
  server.use("*", session.sessionMiddleware)
  routes.registerPluginArchRoutes(server as never)
  app = server

  const databaseUrl = process.env.DATABASE_URL ?? ""
  if (!databaseUrl.includes("/openwork_plugin_arch_test")) {
    throw new Error("Refusing to reset a database other than openwork_plugin_arch_test")
  }

  for (const statement of [
    "delete from plugin_config_object",
    "delete from plugin_access_grant",
    "delete from config_object_access_grant",
    "delete from config_object_version",
    "delete from config_object",
    "delete from marketplace_plugin",
    "delete from marketplace_access_grant",
    "delete from marketplace",
    "delete from plugin",
    "delete from connector_instance_access_grant",
    "delete from connector_instance",
    "delete from connector_account",
    "delete from organization_role",
    "delete from session",
    "delete from member",
    "delete from organization",
    "delete from user",
  ]) {
    await db.execute(drizzle.sql.raw(statement))
  }

  victimOwner = await insertIdentity({
    email: "victim-owner@example.test",
    name: "Victim Owner",
    role: "owner",
    sessionToken: VICTIM_OWNER_SESSION,
  })
  victimMember = await insertIdentity({
    email: "victim-member@example.test",
    name: "Victim Member",
    role: "member",
    sessionToken: VICTIM_MEMBER_SESSION,
    organizationId: victimOwner.organizationId,
  })
  attackerOwner = await insertIdentity({
    email: "attacker-owner@example.test",
    name: "Attacker Owner",
    role: "owner",
    sessionToken: ATTACKER_OWNER_SESSION,
  })
  attackerMember = await insertIdentity({
    email: "attacker-member@example.test",
    name: "Attacker Member",
    role: "member",
    sessionToken: ATTACKER_MEMBER_SESSION,
    organizationId: attackerOwner.organizationId,
  })
}, 120_000)

afterAll(async () => {
  const client = (db as { $client?: { end: () => Promise<void> } } | undefined)?.$client
  await client?.end()
})

async function insertIdentity(input: {
  email: string
  name: string
  role: "owner" | "member"
  sessionToken: string
  organizationId?: string
}): Promise<Identity> {
  const userId = createDenTypeId("user")
  const organizationId = input.organizationId ?? createDenTypeId("organization")
  const memberId = createDenTypeId("member")
  const now = new Date()

  await db.insert(schema.AuthUserTable).values({
    id: userId,
    name: input.name,
    email: input.email,
    emailVerified: true,
    image: null,
    createdAt: now,
    updatedAt: now,
  })

  if (!input.organizationId) {
    await db.insert(schema.OrganizationTable).values({
      id: organizationId,
      name: input.name,
      slug: organizationId,
      logo: null,
      metadata: null,
      createdAt: now,
      updatedAt: now,
    })
  }

  await db.insert(schema.MemberTable).values({
    id: memberId,
    organizationId,
    userId,
    role: input.role,
    createdAt: now,
  })

  await db.insert(schema.AuthSessionTable).values({
    id: createDenTypeId("session"),
    userId,
    activeOrganizationId: organizationId,
    activeTeamId: null,
    token: input.sessionToken,
    expiresAt: new Date("2038-01-01T00:00:00.000Z"),
    ipAddress: null,
    userAgent: null,
    createdAt: now,
    updatedAt: now,
  })

  return { organizationId, userId, memberId }
}

async function call(sessionToken: string, method: string, path: string, body?: unknown) {
  const response = await app.request(path, {
    method,
    headers: {
      authorization: `Bearer ${sessionToken}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  const text = await response.text()
  let parsed: unknown = null
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = text
    }
  }
  return { status: response.status, body: parsed, text }
}

function denialError(result: { status: number; text: string }, label: string) {
  if (result.status === 403 || result.status === 404) return null
  return `${label} returned ${result.status}: ${result.text}`
}

function expectDenied(result: { status: number; text: string }, label: string) {
  const error = denialError(result, label)
  if (error) throw new Error(error)
}

function expectNoDenials(errors: Array<string | null>) {
  const failures = errors.filter((error): error is string => Boolean(error))
  if (failures.length > 0) {
    throw new Error(failures.join("\n"))
  }
}

async function createPlugin(sessionToken: string, name: string) {
  const result = await call(sessionToken, "POST", "/v1/plugins", { name })
  if (result.status !== 201) {
    throw new Error(`create plugin failed ${result.status}: ${result.text}`)
  }
  return (result.body as { item: { id: string } }).item.id
}

async function createConfigObject(sessionToken: string, input: { type: string; rawSourceText: string; pluginIds?: string[] }) {
  return call(sessionToken, "POST", "/v1/config-objects", {
    type: input.type,
    sourceMode: "cloud",
    ...(input.pluginIds ? { pluginIds: input.pluginIds } : {}),
    input: { rawSourceText: input.rawSourceText },
  })
}

async function pluginLinks(pluginId: string) {
  return db.select().from(schema.PluginConfigObjectTable).where(eq(schema.PluginConfigObjectTable.pluginId, pluginId))
}

async function grantSnapshot(kind: "plugin" | "marketplace" | "config_object" | "connector_instance", resourceId: string) {
  const rows = kind === "plugin"
    ? await db.select().from(schema.PluginAccessGrantTable).where(eq(schema.PluginAccessGrantTable.pluginId, resourceId))
    : kind === "marketplace"
      ? await db.select().from(schema.MarketplaceAccessGrantTable).where(eq(schema.MarketplaceAccessGrantTable.marketplaceId, resourceId))
      : kind === "config_object"
        ? await db.select().from(schema.ConfigObjectAccessGrantTable).where(eq(schema.ConfigObjectAccessGrantTable.configObjectId, resourceId))
        : await db.select().from(schema.ConnectorInstanceAccessGrantTable).where(eq(schema.ConnectorInstanceAccessGrantTable.connectorInstanceId, resourceId))

  return rows
    .map((row) => ({
      id: row.id,
      organizationId: row.organizationId,
      orgMembershipId: row.orgMembershipId,
      orgWide: row.orgWide,
      removedAt: row.removedAt ? row.removedAt.toISOString() : null,
      role: row.role,
      teamId: row.teamId,
    }))
    .sort((left, right) => left.id.localeCompare(right.id))
}

describe.serial("cross-tenant plugin system access", () => {
beforeAll(async () => {
  victimPluginId = await createPlugin(VICTIM_OWNER_SESSION, "Victim Plugin")
  attackerPluginId = await createPlugin(ATTACKER_OWNER_SESSION, "Attacker Plugin")
  orgWidePluginId = await createPlugin(VICTIM_OWNER_SESSION, "Victim Org Wide Plugin")

  const marketplace = await call(VICTIM_OWNER_SESSION, "POST", "/v1/marketplaces", { name: "Victim Marketplace" })
  if (marketplace.status !== 201) throw new Error(`create marketplace failed ${marketplace.status}: ${marketplace.text}`)
  victimMarketplaceId = (marketplace.body as { item: { id: string } }).item.id
  const attached = await call(VICTIM_OWNER_SESSION, "POST", `/v1/marketplaces/${victimMarketplaceId}/plugins`, { pluginId: victimPluginId })
  if (attached.status !== 201) throw new Error(`attach plugin failed ${attached.status}: ${attached.text}`)

  const privateObject = await createConfigObject(VICTIM_OWNER_SESSION, {
    type: "skill",
    rawSourceText: "VICTIM_PRIVATE_SKILL",
  })
  if (privateObject.status !== 201) throw new Error(`create victim config object failed ${privateObject.status}: ${privateObject.text}`)
  victimConfigObjectId = (privateObject.body as { item: { id: string } }).item.id

  const account = await call(VICTIM_OWNER_SESSION, "POST", "/v1/connector-accounts", {
    connectorType: "github",
    remoteId: "victim-remote",
    displayName: "Victim GitHub",
  })
  if (account.status !== 201) throw new Error(`create connector account failed ${account.status}: ${account.text}`)
  const connectorAccountId = (account.body as { item: { id: string } }).item.id
  const instance = await call(VICTIM_OWNER_SESSION, "POST", "/v1/connector-instances", {
    connectorAccountId,
    connectorType: "github",
    name: "Victim Connector",
  })
  if (instance.status !== 201) throw new Error(`create connector instance failed ${instance.status}: ${instance.text}`)
  victimConnectorInstanceId = (instance.body as { item: { id: string } }).item.id

  const orgWide = await call(VICTIM_OWNER_SESSION, "POST", `/v1/plugins/${orgWidePluginId}/access`, {
    orgWide: true,
    role: "manager",
  })
  if (orgWide.status !== 201) throw new Error(`victim org-wide grant failed ${orgWide.status}: ${orgWide.text}`)
  victimPluginGrantId = (await grantSnapshot("plugin", victimPluginId))[0]!.id
}, 120_000)

test("an organization owner can still link a config object to their own plugin", async () => {
  const ownLink = await createConfigObject(ATTACKER_OWNER_SESSION, {
    type: "tool",
    rawSourceText: "ATTACKER_OWN_TOOL",
    pluginIds: [attackerPluginId],
  })
  expect(ownLink.status, ownLink.text).toBe(201)
  const ownLinks = await pluginLinks(attackerPluginId)
  expect(ownLinks.filter((row) => row.removedAt == null)).toHaveLength(1)
})

test("plugin detail stays inside the caller organization", async () => {
  const hiddenPlugin = await call(ATTACKER_OWNER_SESSION, "GET", `/v1/plugins/${victimPluginId}`)
  expectDenied(hiddenPlugin, "direct plugin read")
})

test("config object creation cannot link another organization's plugin", async () => {
  const failures: Array<string | null> = []
  for (const objectType of ["skill", "agent", "command", "tool", "mcp"] as const) {
    const created = await createConfigObject(ATTACKER_OWNER_SESSION, {
      type: objectType,
      rawSourceText: `${ATTACK_SOURCE_PREFIX}_${objectType}`,
      pluginIds: [victimPluginId],
    })
    failures.push(denialError(created, `link ${objectType} to victim plugin`))
  }

  const mixed = await createConfigObject(ATTACKER_OWNER_SESSION, {
    type: "command",
    rawSourceText: `${ATTACK_SOURCE_PREFIX}_mixed`,
    pluginIds: [attackerPluginId, victimPluginId],
  })
  failures.push(denialError(mixed, "link own plugin and victim plugin in one request"))
  expectNoDenials(failures)
  expect(await pluginLinks(victimPluginId)).toHaveLength(0)
  const attackerLinks = await pluginLinks(attackerPluginId)
  expect(attackerLinks.filter((row) => row.removedAt == null)).toHaveLength(1)

  const victimResolved = await call(VICTIM_OWNER_SESSION, "GET", `/v1/plugins/${victimPluginId}/resolved`)
  expect(victimResolved.status, victimResolved.text).toBe(200)
  expect(victimResolved.text).not.toContain(ATTACK_SOURCE_PREFIX)
})

test("access grants on another organization's resources cannot be listed, opened, or revoked", async () => {
  const resources = [
    {
      kind: "plugin" as const,
      resourceId: victimPluginId,
      listPath: `/v1/plugins/${victimPluginId}/access`,
      grantPath: (grantId: string) => `/v1/plugins/${victimPluginId}/access/${grantId}`,
    },
    {
      kind: "marketplace" as const,
      resourceId: victimMarketplaceId,
      listPath: `/v1/marketplaces/${victimMarketplaceId}/access`,
      grantPath: (grantId: string) => `/v1/marketplaces/${victimMarketplaceId}/access/${grantId}`,
    },
    {
      kind: "config_object" as const,
      resourceId: victimConfigObjectId,
      listPath: `/v1/config-objects/${victimConfigObjectId}/access`,
      grantPath: (grantId: string) => `/v1/config-objects/${victimConfigObjectId}/access/${grantId}`,
    },
    {
      kind: "connector_instance" as const,
      resourceId: victimConnectorInstanceId,
      listPath: `/v1/connector-instances/${victimConnectorInstanceId}/access`,
      grantPath: (grantId: string) => `/v1/connector-instances/${victimConnectorInstanceId}/access/${grantId}`,
    },
  ]

  const failures: Array<string | null> = []
  for (const resource of resources) {
    const before = await grantSnapshot(resource.kind, resource.resourceId)
    expect(before.length).toBeGreaterThan(0)
    const listed = await call(ATTACKER_OWNER_SESSION, "GET", resource.listPath)
    failures.push(denialError(listed, `list ${resource.kind} grants`))
    const opened = await call(ATTACKER_OWNER_SESSION, "POST", resource.listPath, { orgWide: true, role: "manager" })
    failures.push(denialError(opened, `open ${resource.kind} org-wide`))
    const revoked = await call(ATTACKER_OWNER_SESSION, "DELETE", resource.grantPath(before[0]!.id))
    failures.push(denialError(revoked, `revoke ${resource.kind} grant`))
    const after = await grantSnapshot(resource.kind, resource.resourceId)
    if (JSON.stringify(after) !== JSON.stringify(before)) {
      failures.push(`${resource.kind} grants changed\nbefore: ${JSON.stringify(before)}\nafter: ${JSON.stringify(after)}`)
    }
  }

  const downgraded = await call(ATTACKER_OWNER_SESSION, "POST", `/v1/plugins/${victimPluginId}/access`, {
    orgMembershipId: victimOwner.memberId,
    role: "viewer",
  })
  failures.push(denialError(downgraded, "overwrite victim plugin manager grant"))
  expectNoDenials(failures)
  const managerGrant = (await grantSnapshot("plugin", victimPluginId)).find((row) => row.id === victimPluginGrantId)
  expect(managerGrant?.role).toBe("manager")
  expect(managerGrant?.removedAt).toBeNull()
})

test("an org-wide grant does not authorize members of a different organization", async () => {
  const victimMemberList = await call(VICTIM_MEMBER_SESSION, "GET", `/v1/plugins/${orgWidePluginId}/access`)
  expect(victimMemberList.status, victimMemberList.text).toBe(200)
  const victimMemberPlugin = await call(VICTIM_MEMBER_SESSION, "GET", `/v1/plugins/${orgWidePluginId}`)
  expect(victimMemberPlugin.status, victimMemberPlugin.text).toBe(200)

  const beforeOrgWide = await grantSnapshot("plugin", orgWidePluginId)
  const directGrant = beforeOrgWide.find((row) => row.orgMembershipId === victimOwner.memberId)
  if (!directGrant) throw new Error("victim direct plugin grant missing")
  const foreignOrgWideList = await call(ATTACKER_MEMBER_SESSION, "GET", `/v1/plugins/${orgWidePluginId}/access`)
  const foreignOrgWideRevoke = await call(ATTACKER_MEMBER_SESSION, "DELETE", `/v1/plugins/${orgWidePluginId}/access/${directGrant.id}`)
  const foreignOrgWideOpen = await call(ATTACKER_MEMBER_SESSION, "POST", `/v1/plugins/${orgWidePluginId}/access`, {
    orgWide: true,
    role: "editor",
  })
  const afterOrgWide = await grantSnapshot("plugin", orgWidePluginId)
  expectNoDenials([
    denialError(foreignOrgWideList, "foreign member uses victim org-wide grant"),
    denialError(foreignOrgWideOpen, "foreign member adds a grant through the victim org-wide grant"),
    denialError(foreignOrgWideRevoke, "foreign member revokes a grant through the victim org-wide grant"),
    JSON.stringify(afterOrgWide) === JSON.stringify(beforeOrgWide)
      ? null
      : `org-wide plugin grants changed\nbefore: ${JSON.stringify(beforeOrgWide)}\nafter: ${JSON.stringify(afterOrgWide)}`,
  ])
  expect(await pluginLinks(orgWidePluginId)).toHaveLength(0)
})

test("resolved plugin and marketplace payloads omit config objects owned by another organization", async () => {
  const foreignObject = await createConfigObject(ATTACKER_OWNER_SESSION, {
    type: "hook",
    rawSourceText: SEEDED_FOREIGN_SOURCE,
  })
  if (foreignObject.status !== 201) throw new Error(`seed config object failed ${foreignObject.status}: ${foreignObject.text}`)
  const foreignObjectId = (foreignObject.body as { item: { id: string } }).item.id
  await db.insert(schema.PluginConfigObjectTable).values({
    id: createDenTypeId("pluginConfigObject"),
    organizationId: attackerOwner.organizationId,
    pluginId: victimPluginId,
    configObjectId: foreignObjectId,
    membershipSource: "manual",
    connectorMappingId: null,
    createdByOrgMembershipId: attackerOwner.memberId,
    createdAt: new Date(),
    removedAt: null,
  })
  const foreignGrantId = createDenTypeId("pluginAccessGrant")
  await db.insert(schema.PluginAccessGrantTable).values({
    id: foreignGrantId,
    organizationId: attackerOwner.organizationId,
    pluginId: victimPluginId,
    orgMembershipId: attackerOwner.memberId,
    teamId: null,
    orgWide: false,
    role: "manager",
    createdByOrgMembershipId: attackerOwner.memberId,
    createdAt: new Date(),
    removedAt: null,
  })

  const leaked = await call(VICTIM_OWNER_SESSION, "GET", `/v1/plugins/${victimPluginId}/resolved`)
  expect(leaked.status, leaked.text).toBe(200)
  expect(leaked.text).not.toContain(SEEDED_FOREIGN_SOURCE)
  expect(leaked.text).not.toContain(foreignObjectId)

  const version = await call(ATTACKER_OWNER_SESSION, "POST", `/v1/config-objects/${foreignObjectId}/versions`, {
    input: { rawSourceText: UPDATED_FOREIGN_SOURCE },
    reason: "replace",
  })
  expect(version.status, version.text).toBe(201)
  const afterVersion = await call(VICTIM_OWNER_SESSION, "GET", `/v1/plugins/${victimPluginId}/resolved`)
  expect(afterVersion.status, afterVersion.text).toBe(200)
  expect(afterVersion.text).not.toContain(UPDATED_FOREIGN_SOURCE)
  expect(afterVersion.text).not.toContain(SEEDED_FOREIGN_SOURCE)

  const marketplaceResolved = await call(VICTIM_OWNER_SESSION, "GET", `/v1/marketplaces/${victimMarketplaceId}/resolved`)
  expect(marketplaceResolved.status, marketplaceResolved.text).toBe(200)
  const marketplaceItem = (marketplaceResolved.body as { item: { plugins: Array<{ id: string; componentCounts?: Record<string, number> }> } }).item
  expect(marketplaceItem.plugins.map((plugin) => plugin.id)).toEqual([victimPluginId])
  expect(marketplaceItem.plugins[0]?.componentCounts?.hook ?? 0).toBe(0)

  const victimGrants = await call(VICTIM_OWNER_SESSION, "GET", `/v1/plugins/${victimPluginId}/access`)
  expect(victimGrants.status, victimGrants.text).toBe(200)
  const listedIds = ((victimGrants.body as { items: Array<{ id: string }> }).items).map((item) => item.id)
  expect(listedIds).not.toContain(foreignGrantId)
  expect(listedIds).toContain(victimPluginGrantId)
})
})
