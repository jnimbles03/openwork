/**
 * Runs in its own process so module mocks cannot leak into the rest of the suite.
 * The parent test expects this process to exit 0 once registration no longer
 * grants mcp:write by itself.
 */
import { mock } from "bun:test"
import { Hono } from "hono"

process.env.DATABASE_URL ??= "mysql://user:placeholder@127.0.0.1:9/openwork_test"
process.env.DEN_DB_ENCRYPTION_KEY ??= "x".repeat(32)
process.env.BETTER_AUTH_SECRET ??= "y".repeat(32)
process.env.BETTER_AUTH_URL ??= "http://127.0.0.1:8790"
process.env.CORS_ORIGINS ??= "http://127.0.0.1:8790"
process.env.OPENWORK_DEV_MODE ??= "1"

type Captured = {
  url: string
  body: Record<string, unknown> | null
}

const captured: Captured[] = []
const scopeWrites: string[] = []

mock.module("../src/auth.ts", () => ({
  auth: {
    handler: async (request: Request) => {
      const contentType = request.headers.get("content-type") ?? ""
      const body = contentType.includes("application/json")
        ? await request.clone().json() as Record<string, unknown>
        : null
      captured.push({ url: request.url, body })
      return new Response(JSON.stringify({ ok: true }), {
        status: 201,
        headers: { "content-type": "application/json" },
      })
    },
  },
}))

mock.module("../src/db.ts", () => ({
  db: {
    select() {
      return {
        from() {
          return {
            where() {
              return {
                limit: async () => [{
                  scopes: JSON.stringify(["openid", "profile", "email", "offline_access", "mcp:read"]),
                }],
              }
            },
          }
        },
      }
    },
    update() {
      return {
        set(values: { scopes: string }) {
          scopeWrites.push(values.scopes)
          return { where: async () => undefined }
        },
      }
    },
  },
}))

function scopeSet(scope: unknown) {
  return new Set(String(scope ?? "").split(/\s+/).filter(Boolean))
}

function fail(message: string): never {
  console.error(message)
  process.exit(1)
}

const { registerAuthRoutes } = await import("../src/routes/auth/index.ts")
const app = new Hono()
registerAuthRoutes(app)

const registrationBody = {
  client_name: "Hostile Connector",
  redirect_uris: ["https://attacker.example/cb"],
  token_endpoint_auth_method: "none",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  scope: "openid profile email offline_access mcp:read",
}

for (const path of ["/api/auth/oauth2/register", "/register"]) {
  captured.length = 0
  const response = await app.request(`http://127.0.0.1:8790${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "http://127.0.0.1:8790" },
    body: JSON.stringify(registrationBody),
  })
  if (response.status !== 201) fail(`${path} status ${response.status}`)
  if (captured.length !== 1) fail(`${path} did not reach the auth handler`)
  if (new URL(captured[0].url).pathname !== "/api/auth/oauth2/register") {
    fail(`${path} was not rewritten to /api/auth/oauth2/register`)
  }
  const forwarded = scopeSet(captured[0].body?.scope)
  if (!forwarded.has("mcp:read") || !forwarded.has("offline_access")) {
    fail(`${path} dropped requested scopes: ${[...forwarded].join(" ")}`)
  }
  if (forwarded.has("mcp:write")) {
    fail(`${path} added mcp:write even though the client asked only for mcp:read`)
  }
}

const authorize = new URL("http://127.0.0.1:8790/api/auth/oauth2/authorize")
authorize.searchParams.set("response_type", "code")
authorize.searchParams.set("client_id", "client-attacker")
authorize.searchParams.set("redirect_uri", "https://attacker.example/cb")
authorize.searchParams.set("scope", "openid profile email offline_access mcp:read mcp:write")
authorize.searchParams.set("code_challenge", "placeholder-challenge")
authorize.searchParams.set("code_challenge_method", "S256")
await app.request(authorize)

for (const scopes of scopeWrites) {
  const parsed = JSON.parse(scopes) as string[]
  if (parsed.includes("mcp:write")) {
    fail("authorize persisted mcp:write onto a client that was only registered for mcp:read")
  }
}

console.log("registration and authorize scope checks passed")
