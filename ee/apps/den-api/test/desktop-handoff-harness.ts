import "./desktop-handoff-env.js"
import { sql } from "@openwork-ee/den-db/drizzle"
import { AuthSessionTable, AuthUserTable, DesktopHandoffGrantTable } from "@openwork-ee/den-db/schema"
import { createDenTypeId } from "@openwork-ee/utils/typeid"
import { Hono } from "hono"
import { db } from "../src/db.js"
import { registerDesktopAuthRoutes } from "../src/routes/auth/desktop-handoff.js"
import { registerMeRoutes } from "../src/routes/me/index.js"
import { getRequestSession, sessionMiddleware } from "../src/session.js"

export const PLACEHOLDER_SESSION_TOKEN = "placeholder-session-token"
export const VICTIM_EMAIL = "victim@example.com"

export const ALLOWED_DESKTOP_SCHEMES = new Set(["openwork", "openwork-dev"])

let chain: Promise<unknown> = Promise.resolve()

export function exclusive<T>(fn: () => Promise<T>): Promise<T> {
  const run = chain.then(fn, fn)
  chain = run.then(
    () => undefined,
    () => undefined,
  )
  return run
}

export function desktopSchemeOf(value: string): string | null {
  try {
    return new URL(value).protocol.replace(/:$/, "").toLowerCase()
  } catch {
    return null
  }
}

export function isAllowedDesktopScheme(scheme: string | null | undefined): boolean {
  return Boolean(scheme && ALLOWED_DESKTOP_SCHEMES.has(scheme.toLowerCase()))
}

let tablesReady: Promise<void> | null = null

async function ensureTables() {
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS \`user\` (
      id varchar(64) NOT NULL PRIMARY KEY,
      name varchar(255) NOT NULL,
      email varchar(255) NOT NULL,
      email_verified boolean NOT NULL DEFAULT false,
      image text NULL,
      created_at timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      updated_at timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    )
  `)
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS \`session\` (
      id varchar(64) NOT NULL PRIMARY KEY,
      user_id varchar(64) NOT NULL,
      active_organization_id varchar(64) NULL,
      active_team_id varchar(64) NULL,
      token varchar(255) NOT NULL,
      expires_at timestamp(3) NOT NULL,
      ip_address text NULL,
      user_agent text NULL,
      created_at timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      updated_at timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
      UNIQUE KEY session_token (token)
    )
  `)
  await db.execute(sql`
    CREATE TABLE IF NOT EXISTS desktop_handoff_grant (
      id varchar(64) NOT NULL PRIMARY KEY,
      user_id varchar(64) NOT NULL,
      session_token text NOT NULL,
      expires_at timestamp(3) NOT NULL,
      consumed_at timestamp(3) NULL,
      created_at timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    )
  `)
}

export async function resetHandoffTables() {
  if (!tablesReady) {
    tablesReady = ensureTables()
  }
  await tablesReady
  await db.execute(sql`DELETE FROM desktop_handoff_grant`)
  await db.execute(sql`DELETE FROM \`session\``)
  await db.execute(sql`DELETE FROM \`user\``)
}

export async function countHandoffGrants(): Promise<number> {
  const result = await db.execute(sql`SELECT COUNT(*) AS total FROM desktop_handoff_grant`)
  const rows = Array.isArray(result) ? result[0] : (result as { rows?: unknown }).rows
  const list = Array.isArray(rows) ? rows : []
  const first = list[0] as { total?: number | string } | undefined
  return Number(first?.total ?? 0)
}

export type VictimSession = {
  userId: string
  email: string
  token: string
}

export async function seedVictimSession(token = PLACEHOLDER_SESSION_TOKEN): Promise<VictimSession> {
  await resetHandoffTables()
  const userId = createDenTypeId("user")
  const sessionId = createDenTypeId("session")
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000)
  await db.insert(AuthUserTable).values({
    id: userId,
    name: "Victim",
    email: VICTIM_EMAIL,
    emailVerified: true,
  })
  await db.insert(AuthSessionTable).values({
    id: sessionId,
    userId,
    token,
    expiresAt,
  })
  return { userId, email: VICTIM_EMAIL, token }
}

export function createHandoffApp() {
  const app = new Hono()
  app.use("*", sessionMiddleware)
  registerMeRoutes(app)
  registerDesktopAuthRoutes(app)
  return app
}

export function bearerHeaders(token: string, extra?: HeadersInit): Headers {
  const headers = new Headers(extra)
  headers.set("authorization", `Bearer ${token}`)
  headers.set("content-type", "application/json")
  headers.set("origin", "https://app.openworklabs.com")
  return headers
}

export async function createDesktopHandoff(app: Hono, token: string, desktopScheme?: string) {
  return app.request("http://den.local/v1/auth/desktop-handoff", {
    method: "POST",
    headers: bearerHeaders(token),
    body: JSON.stringify(desktopScheme === undefined ? {} : { desktopScheme }),
  })
}

export async function exchangeDesktopHandoff(app: Hono, grant: string) {
  return app.request("http://den.local/v1/auth/desktop-handoff/exchange", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ grant }),
  })
}

export async function sessionFromBearer(token: string) {
  return getRequestSession(new Headers({ authorization: `Bearer ${token}` }))
}

export async function closeHandoffDb() {
  const client = (db as unknown as { $client?: { end?: () => Promise<void> } }).$client
  await client?.end?.()
}
