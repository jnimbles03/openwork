import { createVerify, generateKeyPairSync, type KeyObject } from "node:crypto"
import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test"
import { Hono } from "hono"

/**
 * These tests are the spec for a missing authorization check.
 * They fail while a caller can save or use a GitHub App installation id
 * that was not proven to belong to that caller. They pass once every
 * operation below refuses that id before minting an installation token,
 * listing private repositories, or copying repository file contents.
 *
 * The GitHub stand-in follows the request and response fields read from
 * ee/apps/den-api/src/routes/org/plugin-system/github-app.ts. An app JWT
 * can mint a token for every installation of the app, which is the
 * documented behavior of POST /app/installations/{installation_id}/access_tokens.
 */

const APP_ID = "123456"
const VICTIM_INSTALLATION_ID = 900001
const OTHER_INSTALLATION_ID = 900002
const VICTIM_REPOSITORY_ID = 424242
const VICTIM_REPOSITORY = "victim-org/private-plugins"
const PRIVATE_SKILL_BODY = "victim-private-skill-body"
const PLACEHOLDER_WEBHOOK_SECRET = "placeholder-webhook-secret"
const HEAD_SHA = "head-sha-victim"
const TREE_SHA = "tree-sha-victim"

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
const privateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }).toString()

const pluginJson = JSON.stringify({ name: "victim-plugin", description: "Private plugin" })
const repositoryFiles: Record<string, string> = {
  ".claude-plugin/plugin.json": pluginJson,
  "skills/secret/SKILL.md": `${PRIVATE_SKILL_BODY}\n`,
}

type RecordedCall = {
  installationId: number | null
  method: string
  url: string
}

type Actor = {
  organizationId: string
  userId: string
}

type Fixture = {
  attackerMemberId: string
  attackerOrgId: string
  attackerUserId: string
  victimMemberId: string
  victimMemberUserId: string
  victimOrgId: string
  victimOwnerMemberId: string
  victimOwnerUserId: string
}

const actor: Actor = { organizationId: "", userId: "" }
const recorded: RecordedCall[] = []
const issuedTokens = new Map<string, number>()
let originalFetch: typeof fetch
let fixture: Fixture
let app: Hono
let db: any
let tables: Record<string, any>
let env: { betterAuthSecret: string; githubConnectorApp: { appId?: string; privateKey?: string; webhookSecret?: string } }
let createDenTypeId: (name: string) => string
let createGithubInstallStateToken: (input: { orgId: string; returnPath: string; secret: string; userId: string }) => string
let signGithubBody: (rawBody: string, secret: string) => string

function seedRequiredEnv() {
  process.env.DATABASE_URL = process.env.DATABASE_URL ?? "mysql://root:password@127.0.0.1:3306/openwork_test"
  process.env.DB_MODE = "mysql"
  process.env.DEN_DB_ENCRYPTION_KEY = process.env.DEN_DB_ENCRYPTION_KEY ?? "x".repeat(32)
  process.env.BETTER_AUTH_SECRET = process.env.BETTER_AUTH_SECRET ?? "y".repeat(32)
  process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL ?? "http://127.0.0.1:8790"
  process.env.GITHUB_CONNECTOR_APP_ID = APP_ID
  process.env.GITHUB_CONNECTOR_APP_PRIVATE_KEY = privateKeyPem
  process.env.GITHUB_CONNECTOR_APP_WEBHOOK_SECRET = PLACEHOLDER_WEBHOOK_SECRET
}

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

function verifyAppJwt(authorization: string | null) {
  if (!authorization?.startsWith("Bearer ")) return false
  const parts = authorization.slice("Bearer ".length).split(".")
  if (parts.length !== 3) return false
  const [header, payload, signature] = parts
  const verifier = createVerify("RSA-SHA256")
  verifier.update(`${header}.${payload}`)
  verifier.end()
  if (!verifier.verify(publicKey as KeyObject, Buffer.from(signature, "base64url"))) return false
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { iss?: unknown }
  return claims.iss === APP_ID
}

function bearerToken(authorization: string | null) {
  if (!authorization?.startsWith("Bearer ")) return null
  return authorization.slice("Bearer ".length)
}

function record(method: string, url: URL, installationId: number | null) {
  recorded.push({ installationId, method, url: url.toString() })
}

function victimCalls() {
  return recorded.filter((call) =>
    call.installationId === VICTIM_INSTALLATION_ID
    || call.url.includes(`/app/installations/${VICTIM_INSTALLATION_ID}`)
    || call.url.includes(`/repos/${VICTIM_REPOSITORY}`),
  )
}

function githubStandIn(input: RequestInfo | URL, init?: RequestInit) {
  const rawUrl = typeof input === "string"
    ? input
    : input instanceof URL
      ? input.toString()
      : input.url
  const url = new URL(rawUrl)
  const method = (init?.method ?? (typeof input === "object" && !(input instanceof URL) ? input.method : "GET")).toUpperCase()
  const headers = new Headers(init?.headers ?? (typeof input === "object" && !(input instanceof URL) ? input.headers : undefined))
  const authorization = headers.get("authorization")
  const installationFromPath = url.pathname.match(/^\/app\/installations\/(\d+)/)?.[1]
  const tokenInstallation = bearerToken(authorization)
  const installationId = installationFromPath
    ? Number(installationFromPath)
    : tokenInstallation
      ? issuedTokens.get(tokenInstallation) ?? null
      : null

  if (url.origin !== "https://api.github.com") {
    return jsonResponse({ message: "unexpected host" }, 404)
  }

  record(method, url, installationId)

  if (method === "POST" && /^\/app\/installations\/\d+\/access_tokens$/.test(url.pathname)) {
    if (!verifyAppJwt(authorization) || installationId === null) {
      return jsonResponse({ message: "Bad credentials" }, 401)
    }
    const token = `placeholder-installation-token-${installationId}`
    issuedTokens.set(token, installationId)
    return jsonResponse({ token }, 201)
  }

  if (method === "GET" && /^\/app\/installations\/\d+$/.test(url.pathname)) {
    if (!verifyAppJwt(authorization) || installationId === null) {
      return jsonResponse({ message: "Bad credentials" }, 401)
    }
    const login = installationId === VICTIM_INSTALLATION_ID ? "victim-org" : "other-account"
    return jsonResponse({
      account: { login, type: "Organization" },
      html_url: `https://github.com/organizations/${login}/settings/installations/${installationId}`,
      id: installationId,
      repository_selection: "all",
    })
  }

  if (url.pathname === "/installation/repositories") {
    if (installationId !== VICTIM_INSTALLATION_ID) {
      return jsonResponse({ message: "Bad credentials" }, 401)
    }
    return jsonResponse({
      repositories: [{
        default_branch: "main",
        full_name: VICTIM_REPOSITORY,
        id: VICTIM_REPOSITORY_ID,
        private: true,
      }],
    })
  }

  const repositoryMatch = url.pathname.match(/^\/repos\/([^/]+)\/([^/]+)(?:\/(.*))?$/)
  if (repositoryMatch) {
    const fullName = `${decodeURIComponent(repositoryMatch[1])}/${decodeURIComponent(repositoryMatch[2])}`
    const rest = repositoryMatch[3] ?? ""
    if (installationId !== VICTIM_INSTALLATION_ID || fullName !== VICTIM_REPOSITORY) {
      return jsonResponse({ message: "Not Found" }, 404)
    }
    if (rest === "") {
      return jsonResponse({
        default_branch: "main",
        full_name: VICTIM_REPOSITORY,
        id: VICTIM_REPOSITORY_ID,
        private: true,
      })
    }
    if (rest === "branches/main") {
      return jsonResponse({ name: "main" })
    }
    if (rest === `commits/${encodeURIComponent("main")}` || rest === "commits/main") {
      return jsonResponse({ commit: { tree: { sha: TREE_SHA } }, sha: HEAD_SHA })
    }
    if (rest.startsWith(`git/trees/${TREE_SHA}`)) {
      return jsonResponse({
        truncated: false,
        tree: [
          { path: ".claude-plugin", type: "tree" },
          { path: ".claude-plugin/plugin.json", sha: "plugin-json", size: pluginJson.length, type: "blob" },
          { path: "skills", type: "tree" },
          { path: "skills/secret", type: "tree" },
          { path: "skills/secret/SKILL.md", sha: "skill-md", size: PRIVATE_SKILL_BODY.length, type: "blob" },
        ],
      })
    }
    if (rest.startsWith("contents/")) {
      const filePath = rest.slice("contents/".length).split("?")[0].split("/").map(decodeURIComponent).join("/")
      const text = repositoryFiles[filePath]
      if (!text) return jsonResponse({ message: "Not Found" }, 404)
      return jsonResponse({ content: Buffer.from(text).toString("base64"), encoding: "base64" })
    }
  }

  return jsonResponse({ message: "Not Found" }, 404)
}

function useActor(userId: string, organizationId: string) {
  actor.userId = userId
  actor.organizationId = organizationId
}

async function request(path: string, init?: { body?: unknown; method?: string }) {
  return app.request(`http://den.local${path}`, {
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
    headers: init?.body === undefined ? undefined : { "content-type": "application/json" },
    method: init?.method ?? (init?.body === undefined ? "GET" : "POST"),
  })
}

async function attackerAccounts() {
  return db.select().from(tables.ConnectorAccountTable).where(eqOrg(tables.ConnectorAccountTable.organizationId, fixture.attackerOrgId))
}

async function attackerInstances() {
  return db.select().from(tables.ConnectorInstanceTable).where(eqOrg(tables.ConnectorInstanceTable.organizationId, fixture.attackerOrgId))
}

function eqOrg(column: unknown, organizationId: string) {
  return tables.eq(column, organizationId)
}

function bindsVictimInstallation(value: unknown) {
  return JSON.stringify(value ?? null).includes(String(VICTIM_INSTALLATION_ID))
}

async function importedPrivateSkill() {
  const versions = await db.select({ rawSourceText: tables.ConfigObjectVersionTable.rawSourceText }).from(tables.ConfigObjectVersionTable)
  return versions.filter((version: { rawSourceText: string | null }) => (version.rawSourceText ?? "").includes(PRIVATE_SKILL_BODY))
}

async function assertVictimInstallationWasNotUsed(response: Response) {
  const text = await response.text()
  expect(victimCalls()).toEqual([])
  expect(text).not.toContain(VICTIM_REPOSITORY)
  expect(text).not.toContain(PRIVATE_SKILL_BODY)
  expect(await importedPrivateSkill()).toEqual([])
  return text
}

async function seedPeople() {
  await db.insert(tables.AuthUserTable).values([
    { email: "victim-owner@example.com", emailVerified: true, id: fixture.victimOwnerUserId, name: "Victim Owner" },
    { email: "victim-member@example.com", emailVerified: true, id: fixture.victimMemberUserId, name: "Victim Member" },
    { email: "attacker-owner@example.com", emailVerified: true, id: fixture.attackerUserId, name: "Attacker Owner" },
  ])
  await db.insert(tables.OrganizationTable).values([
    { desktopAppRestrictions: {}, id: fixture.victimOrgId, name: "Victim Org", slug: "victim-org" },
    { desktopAppRestrictions: {}, id: fixture.attackerOrgId, name: "Attacker Org", slug: "attacker-org" },
  ])
  await db.insert(tables.MemberTable).values([
    { id: fixture.victimOwnerMemberId, organizationId: fixture.victimOrgId, role: "owner", userId: fixture.victimOwnerUserId },
    { id: fixture.victimMemberId, organizationId: fixture.victimOrgId, role: "member", userId: fixture.victimMemberUserId },
    { id: fixture.attackerMemberId, organizationId: fixture.attackerOrgId, role: "owner", userId: fixture.attackerUserId },
  ])
}

async function seedVictimConnectorAccount() {
  await db.insert(tables.ConnectorAccountTable).values({
    connectorType: "github",
    createdByOrgMembershipId: fixture.victimOwnerMemberId,
    displayName: "Victim GitHub",
    id: createDenTypeId("connectorAccount"),
    organizationId: fixture.victimOrgId,
    remoteId: String(VICTIM_INSTALLATION_ID),
    status: "active",
  })
}

async function seedAttackerAccount(remoteId: string) {
  const id = createDenTypeId("connectorAccount")
  await db.insert(tables.ConnectorAccountTable).values({
    connectorType: "github",
    createdByOrgMembershipId: fixture.attackerMemberId,
    displayName: "Attacker GitHub",
    id,
    organizationId: fixture.attackerOrgId,
    remoteId,
    status: "active",
  })
  return id
}

async function seedPoisonedConnector() {
  const accountId = await seedAttackerAccount(String(VICTIM_INSTALLATION_ID))
  const instanceId = createDenTypeId("connectorInstance")
  const targetId = createDenTypeId("connectorTarget")
  await db.insert(tables.ConnectorInstanceTable).values({
    connectorAccountId: accountId,
    connectorType: "github",
    createdByOrgMembershipId: fixture.attackerMemberId,
    id: instanceId,
    instanceConfigJson: {
      autoImportNewPlugins: true,
      installationId: VICTIM_INSTALLATION_ID,
    },
    name: `stolen-${instanceId}`,
    organizationId: fixture.attackerOrgId,
    remoteId: VICTIM_REPOSITORY,
    status: "active",
  })
  await db.insert(tables.ConnectorTargetTable).values({
    connectorInstanceId: instanceId,
    connectorType: "github",
    externalTargetRef: "main",
    id: targetId,
    organizationId: fixture.attackerOrgId,
    remoteId: VICTIM_REPOSITORY,
    targetConfigJson: {
      branch: "main",
      ref: "refs/heads/main",
      repositoryFullName: VICTIM_REPOSITORY,
      repositoryId: VICTIM_REPOSITORY_ID,
    },
    targetKind: "repository_branch",
  })
  return { accountId, instanceId, targetId }
}

async function clearConnectorData() {
  const ordered = [
    tables.ConfigObjectVersionTable,
    tables.ConfigObjectAccessGrantTable,
    tables.PluginConfigObjectTable,
    tables.ConnectorSourceBindingTable,
    tables.ConnectorSyncEventTable,
    tables.ConnectorMappingTable,
    tables.ConnectorTargetTable,
    tables.ConnectorInstanceAccessGrantTable,
    tables.ConnectorInstanceTable,
    tables.ConnectorAccountTable,
    tables.PluginAccessGrantTable,
    tables.MarketplacePluginTable,
    tables.MarketplaceAccessGrantTable,
    tables.PluginTable,
    tables.MarketplaceTable,
    tables.ConfigObjectTable,
  ]
  for (const table of ordered) {
    await db.delete(table)
  }
}

beforeAll(async () => {
  seedRequiredEnv()
  const schema = await import("@openwork-ee/den-db/schema")
  const drizzle = await import("@openwork-ee/den-db/drizzle")
  const dbModule = await import("../src/db.js")
  const envModule = await import("../src/env.js")
  const ids = await import("@openwork-ee/utils/typeid")
  const githubApp = await import("../src/routes/org/plugin-system/github-app.js")
  const routes = await import("../src/routes/org/plugin-system/routes.js")
  const webhooks = await import("../src/routes/webhooks/github.js")

  db = dbModule.db
  env = envModule.env
  env.githubConnectorApp.appId = APP_ID
  env.githubConnectorApp.privateKey = privateKeyPem
  env.githubConnectorApp.webhookSecret = PLACEHOLDER_WEBHOOK_SECRET
  createDenTypeId = ids.createDenTypeId
  createGithubInstallStateToken = githubApp.createGithubInstallStateToken
  signGithubBody = webhooks.signGithubBody
  tables = { ...schema, eq: drizzle.eq }
  fixture = {
    attackerMemberId: createDenTypeId("member"),
    attackerOrgId: createDenTypeId("organization"),
    attackerUserId: createDenTypeId("user"),
    victimMemberId: createDenTypeId("member"),
    victimMemberUserId: createDenTypeId("user"),
    victimOrgId: createDenTypeId("organization"),
    victimOwnerMemberId: createDenTypeId("member"),
    victimOwnerUserId: createDenTypeId("user"),
  }
  originalFetch = globalThis.fetch
  globalThis.fetch = githubStandIn as typeof fetch

  app = new Hono()
  app.use("*", async (c, next) => {
    if (actor.userId) {
      c.set("user", { id: actor.userId } as never)
      c.set("activeOrganizationId", actor.organizationId as never)
      c.set("session", { activeOrganizationId: actor.organizationId, userId: actor.userId } as never)
    }
    await next()
  })
  routes.registerPluginArchRoutes(app as never)
  webhooks.registerGithubWebhookRoutes(app as never)
  await seedPeople()
})

beforeEach(async () => {
  recorded.length = 0
  issuedTokens.clear()
  await clearConnectorData()
  useActor(fixture.attackerUserId, fixture.attackerOrgId)
})

afterAll(() => {
  globalThis.fetch = originalFetch
})

test("an ordinary member of the victim org can read the installation id from connector accounts", async () => {
  await seedVictimConnectorAccount()
  useActor(fixture.victimMemberUserId, fixture.victimOrgId)

  const accounts = await db.select().from(tables.ConnectorAccountTable)
  const list = await request("/v1/connector-accounts")
  const detail = await request(`/v1/connector-accounts/${accounts[0].id}`)

  expect(list.status).toBe(200)
  expect(detail.status).toBe(200)
  expect(await list.text()).not.toContain(String(VICTIM_INSTALLATION_ID))
  expect(await detail.text()).not.toContain(String(VICTIM_INSTALLATION_ID))
})

test("an owner of a different org cannot bind the victim installation through the github account route", async () => {
  const before = await attackerAccounts()
  const response = await request("/v1/connectors/github/accounts", {
    body: {
      accountLogin: "victim-org",
      accountType: "Organization",
      displayName: "Stolen",
      installationId: VICTIM_INSTALLATION_ID,
    },
  })

  await assertVictimInstallationWasNotUsed(response)
  expect(response.status).toBeGreaterThanOrEqual(400)
  const accounts = await attackerAccounts()
  expect(accounts).toHaveLength(before.length)
  expect(accounts.some((account: { remoteId: string }) => account.remoteId === String(VICTIM_INSTALLATION_ID))).toBe(false)
})

test("an owner of a different org cannot bind the victim installation through the generic connector account route", async () => {
  const response = await request("/v1/connector-accounts", {
    body: {
      connectorType: "github",
      displayName: "Stolen",
      remoteId: String(VICTIM_INSTALLATION_ID),
    },
  })

  await assertVictimInstallationWasNotUsed(response)
  expect(response.status).toBeGreaterThanOrEqual(400)
  const accounts = await attackerAccounts()
  expect(accounts.some((account: { remoteId: string }) => account.remoteId === String(VICTIM_INSTALLATION_ID))).toBe(false)
})

test("install completion accepts the attacker's own state and still rejects the victim installation id", async () => {
  const state = createGithubInstallStateToken({
    orgId: fixture.attackerOrgId,
    returnPath: "/o/attacker-org/dashboard",
    secret: env.betterAuthSecret,
    userId: fixture.attackerUserId,
  })
  const response = await request("/v1/connectors/github/install/complete", {
    body: { installationId: VICTIM_INSTALLATION_ID, state },
  })

  await assertVictimInstallationWasNotUsed(response)
  expect(response.status).toBeGreaterThanOrEqual(400)
  const accounts = await attackerAccounts()
  expect(accounts.some((account: { remoteId: string }) => account.remoteId === String(VICTIM_INSTALLATION_ID))).toBe(false)
})

test("github setup rejects a victim installation id even when the connector account id is the attacker's other account", async () => {
  const accountId = await seedAttackerAccount(String(OTHER_INSTALLATION_ID))
  const response = await request("/v1/connectors/github/setup", {
    body: {
      branch: "main",
      connectorAccountId: accountId,
      connectorInstanceName: "stolen-setup",
      installationId: VICTIM_INSTALLATION_ID,
      mappings: [],
      ref: "refs/heads/main",
      repositoryFullName: VICTIM_REPOSITORY,
      repositoryId: VICTIM_REPOSITORY_ID,
    },
  })

  await assertVictimInstallationWasNotUsed(response)
  expect(response.status).toBeGreaterThanOrEqual(400)
  const instances = await attackerInstances()
  expect(instances.some((instance: { instanceConfigJson: unknown }) => bindsVictimInstallation(instance.instanceConfigJson))).toBe(false)
})

test("github setup without an existing account does not save or use the victim installation id", async () => {
  const response = await request("/v1/connectors/github/setup", {
    body: {
      branch: "main",
      connectorInstanceName: "stolen-setup-new",
      installationId: VICTIM_INSTALLATION_ID,
      mappings: [],
      ref: "refs/heads/main",
      repositoryFullName: VICTIM_REPOSITORY,
      repositoryId: VICTIM_REPOSITORY_ID,
    },
  })

  await assertVictimInstallationWasNotUsed(response)
  expect(response.status).toBeGreaterThanOrEqual(400)
  expect(await attackerAccounts()).toEqual([])
  expect(await attackerInstances()).toEqual([])
})

test("target validation does not use an installation id supplied in the body", async () => {
  const response = await request("/v1/connectors/github/validate-target", {
    body: {
      branch: "main",
      installationId: VICTIM_INSTALLATION_ID,
      ref: "refs/heads/main",
      repositoryFullName: VICTIM_REPOSITORY,
      repositoryId: VICTIM_REPOSITORY_ID,
    },
  })
  const text = await assertVictimInstallationWasNotUsed(response)
  const body = text ? JSON.parse(text) as { item?: { repositoryAccessible?: boolean } } : {}
  expect(body.item?.repositoryAccessible).not.toBe(true)
})

test("listing repositories does not mint a token for a stored victim installation id", async () => {
  const accountId = await seedAttackerAccount(String(VICTIM_INSTALLATION_ID))
  const response = await request(`/v1/connectors/github/accounts/${accountId}/repositories`)
  await assertVictimInstallationWasNotUsed(response)
})

test("creating a connector instance does not persist a victim installation id in instance config", async () => {
  const accountId = await seedAttackerAccount(String(OTHER_INSTALLATION_ID))
  const response = await request("/v1/connector-instances", {
    body: {
      config: { installationId: VICTIM_INSTALLATION_ID },
      connectorAccountId: accountId,
      connectorType: "github",
      name: "config-injection",
    },
  })
  const text = await response.text()
  expect(text).not.toContain(String(VICTIM_INSTALLATION_ID))
  const instances = await attackerInstances()
  expect(instances.some((instance: { instanceConfigJson: unknown }) => bindsVictimInstallation(instance.instanceConfigJson))).toBe(false)
})

test("updating a connector instance does not replace config with a victim installation id", async () => {
  const accountId = await seedAttackerAccount(String(OTHER_INSTALLATION_ID))
  const instanceId = createDenTypeId("connectorInstance")
  await db.insert(tables.ConnectorInstanceTable).values({
    connectorAccountId: accountId,
    connectorType: "github",
    createdByOrgMembershipId: fixture.attackerMemberId,
    id: instanceId,
    instanceConfigJson: { installationId: OTHER_INSTALLATION_ID },
    name: "existing-instance",
    organizationId: fixture.attackerOrgId,
    status: "active",
  })

  const response = await request(`/v1/connector-instances/${instanceId}`, {
    body: { config: { installationId: VICTIM_INSTALLATION_ID } },
    method: "PATCH",
  })
  await response.text()
  const [instance] = await db.select().from(tables.ConnectorInstanceTable).where(tables.eq(tables.ConnectorInstanceTable.id, instanceId))
  expect(bindsVictimInstallation(instance.instanceConfigJson)).toBe(false)
})

test("github discovery does not read a repository through a stored victim installation id", async () => {
  const { instanceId } = await seedPoisonedConnector()
  const discovery = await request(`/v1/connector-instances/${instanceId}/discovery`)
  await assertVictimInstallationWasNotUsed(discovery)
})

test("github discovery tree does not read a repository through a stored victim installation id", async () => {
  const { instanceId } = await seedPoisonedConnector()
  const tree = await request(`/v1/connector-instances/${instanceId}/discovery/tree`)
  await assertVictimInstallationWasNotUsed(tree)
})

test("github discovery apply does not copy victim repository files into the attacker org", async () => {
  const { instanceId } = await seedPoisonedConnector()
  const applied = await request(`/v1/connector-instances/${instanceId}/discovery/apply`, {
    body: { autoImportNewPlugins: true, selectedKeys: ["manifest:root"] },
  })
  const imported = await importedPrivateSkill()
  expect(imported).toEqual([])
  await assertVictimInstallationWasNotUsed(applied)
})

test("a push webhook for the victim repository does not import its files into an attacker org that stored the installation id", async () => {
  await seedPoisonedConnector()
  const payload = JSON.stringify({
    after: HEAD_SHA,
    installation: { id: VICTIM_INSTALLATION_ID },
    ref: "refs/heads/main",
    repository: { full_name: VICTIM_REPOSITORY, id: VICTIM_REPOSITORY_ID },
  })
  const response = await app.request("http://den.local/v1/webhooks/connectors/github", {
    body: payload,
    headers: {
      "content-type": "application/json",
      "x-github-delivery": "delivery-victim-push",
      "x-github-event": "push",
      "x-hub-signature-256": signGithubBody(payload, PLACEHOLDER_WEBHOOK_SECRET),
    },
    method: "POST",
  })

  const text = await response.text()
  const events = await db.select().from(tables.ConnectorSyncEventTable)
  expect(events).toEqual([])
  expect(text).not.toContain(VICTIM_REPOSITORY)
  expect(text).not.toContain(PRIVATE_SKILL_BODY)
  expect(await importedPrivateSkill()).toEqual([])
  expect(victimCalls()).toEqual([])
})
