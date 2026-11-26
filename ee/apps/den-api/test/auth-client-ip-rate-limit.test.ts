import { beforeAll, expect, test } from "bun:test"
import { execFileSync } from "node:child_process"
import { Hono } from "hono"
import type { Hono as HonoApp } from "hono"

/**
 * Spec for the client IP used by Better Auth rate limits.
 *
 * A caller can set X-Forwarded-For and X-Real-IP. The edge client address is the
 * right-most X-Forwarded-For hop and CF-Connecting-IP. Those stay fixed below.
 * Requests 1..max must be allowed. Request max+1 must be 429 for that same edge
 * client, including when the left-most X-Forwarded-For and X-Real-IP change every time.
 */

const DATABASE_URL = process.env.RATE_LIMIT_TEST_DATABASE_URL
  ?? "mysql://openwork:password@127.0.0.1:3306/openwork_rate_limit_test"
const ORIGIN = "http://127.0.0.1:8790"
const CONTROL_IP = "198.51.100.10"
const EDGE_IP = "198.51.100.20"

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS \`user\` (
  id varchar(64) NOT NULL PRIMARY KEY,
  name varchar(255) NOT NULL,
  email varchar(255) NOT NULL,
  email_verified tinyint(1) NOT NULL DEFAULT 0,
  image text NULL,
  created_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY user_email (email)
);
CREATE TABLE IF NOT EXISTS session (
  id varchar(64) NOT NULL PRIMARY KEY,
  user_id varchar(64) NOT NULL,
  active_organization_id varchar(64) NULL,
  active_team_id varchar(64) NULL,
  token varchar(255) NOT NULL,
  expires_at datetime(3) NOT NULL,
  ip_address text NULL,
  user_agent text NULL,
  created_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  UNIQUE KEY session_token (token)
);
CREATE TABLE IF NOT EXISTS account (
  id varchar(64) NOT NULL PRIMARY KEY,
  user_id varchar(64) NOT NULL,
  account_id text NOT NULL,
  provider_id text NOT NULL,
  access_token text NULL,
  refresh_token text NULL,
  access_token_expires_at datetime(3) NULL,
  refresh_token_expires_at datetime(3) NULL,
  scope text NULL,
  id_token text NULL,
  password text NULL,
  created_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
);
CREATE TABLE IF NOT EXISTS verification (
  id varchar(64) NOT NULL PRIMARY KEY,
  identifier varchar(255) NOT NULL,
  value text NOT NULL,
  expires_at datetime(3) NOT NULL,
  created_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3)
);
CREATE TABLE IF NOT EXISTS rate_limit (
  id varchar(255) NOT NULL PRIMARY KEY,
  \`key\` varchar(512) NOT NULL,
  count int NOT NULL DEFAULT 0,
  last_request bigint NOT NULL,
  UNIQUE KEY rate_limit_key (\`key\`)
);
DELETE FROM rate_limit;
`

type EndpointCase = {
  name: string
  path: string
  max: number
  body: Record<string, unknown>
}

const ENDPOINTS: EndpointCase[] = [
  {
    name: "email sign-in",
    path: "/api/auth/sign-in/email",
    max: 5,
    body: { email: "victim@example.com", password: "placeholder-password" },
  },
  {
    name: "email sign-up",
    path: "/api/auth/sign-up/email",
    max: 3,
    body: { name: "Victim", email: "new-user@example.com", password: "placeholder-password" },
  },
  {
    name: "email OTP sign-in",
    path: "/api/auth/sign-in/email-otp",
    max: 3,
    body: { email: "victim@example.com", otp: "000000" },
  },
  {
    name: "verification OTP send",
    path: "/api/auth/email-otp/send-verification-otp",
    max: 5,
    body: { email: "victim@example.com", type: "email-verification" },
  },
  {
    name: "verification OTP check",
    path: "/api/auth/email-otp/verify-email",
    max: 10,
    body: { email: "victim@example.com", otp: "000000" },
  },
  {
    name: "password reset request",
    path: "/api/auth/request-password-reset",
    max: 5,
    body: { email: "victim@example.com" },
  },
  {
    name: "organization invitation",
    path: "/api/auth/organization/invite-member",
    max: 20,
    body: { email: "invitee@example.com", role: "member", organizationId: "org_01h455vb4pex5vsknk084sn02q" },
  },
]

let app: HonoApp

function mysql(sql: string) {
  const url = new URL(DATABASE_URL)
  execFileSync("mysql", [
    "-h",
    url.hostname,
    "-P",
    url.port || "3306",
    "-u",
    decodeURIComponent(url.username),
    `-p${decodeURIComponent(url.password)}`,
    url.pathname.replace(/^\//, ""),
    "-e",
    sql,
  ], { stdio: "pipe" })
}

beforeAll(async () => {
  process.env.DATABASE_URL = DATABASE_URL
  process.env.DB_MODE = "mysql"
  process.env.DEN_DB_ENCRYPTION_KEY = "x".repeat(32)
  process.env.BETTER_AUTH_SECRET = "y".repeat(32)
  process.env.BETTER_AUTH_URL = ORIGIN
  process.env.CORS_ORIGINS = ORIGIN
  process.env.OPENWORK_DEV_MODE = "0"
  process.env.NODE_ENV = "production"
  delete process.env.TEST
  mysql(SCHEMA_SQL)

  const session = await import("../src/session.ts")
  const authRoutes = await import("../src/routes/auth/index.ts")
  const hono = new Hono()
  hono.use("*", session.sessionMiddleware)
  authRoutes.registerAuthRoutes(hono)
  app = hono
})

function controlHeaders(ip: string) {
  return {
    "x-forwarded-for": ip,
    "x-real-ip": ip,
    "cf-connecting-ip": ip,
  }
}

function spoofedHeaders(attempt: number, edgeIp: string) {
  return {
    "x-forwarded-for": `203.0.113.${attempt}, ${edgeIp}`,
    "x-real-ip": `192.0.2.${attempt}`,
    "cf-connecting-ip": edgeIp,
  }
}

async function post(path: string, headers: Record<string, string>, body: Record<string, unknown>) {
  const response = await app.request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...headers,
    },
    body: JSON.stringify(body),
  })
  await response.arrayBuffer()
  return response.status
}

async function attemptStatuses(endpoint: EndpointCase, mode: "control" | "spoof", ip: string) {
  const statuses: number[] = []
  for (let attempt = 1; attempt <= endpoint.max + 1; attempt += 1) {
    const headers = mode === "control" ? controlHeaders(ip) : spoofedHeaders(attempt, ip)
    statuses.push(await post(endpoint.path, headers, endpoint.body))
  }
  return statuses
}

for (const endpoint of ENDPOINTS) {
  test(`${endpoint.name} stays limited when X-Forwarded-For is spoofed`, async () => {
    const stable = await attemptStatuses(endpoint, "control", CONTROL_IP)
    const spoofed = await attemptStatuses(endpoint, "spoof", EDGE_IP)

    expect(stable.slice(0, endpoint.max).every((status) => status !== 429)).toBe(true)
    expect(stable[endpoint.max]).toBe(429)
    expect(spoofed.slice(0, endpoint.max).every((status) => status !== 429)).toBe(true)
    expect(spoofed[endpoint.max]).toBe(429)
  })
}
