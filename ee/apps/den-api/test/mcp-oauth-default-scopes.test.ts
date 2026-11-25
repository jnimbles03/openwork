import { expect, test } from "bun:test"

process.env.DATABASE_URL ??= "mysql://user:placeholder@127.0.0.1:9/openwork_test"
process.env.DEN_DB_ENCRYPTION_KEY ??= "x".repeat(32)
process.env.BETTER_AUTH_SECRET ??= "y".repeat(32)
process.env.BETTER_AUTH_URL ??= "http://127.0.0.1:8790"
process.env.CORS_ORIGINS ??= "http://127.0.0.1:8790"
process.env.OPENWORK_DEV_MODE ??= "1"

test("dynamic client registration defaults do not include mcp:write", async () => {
  const { auth } = await import("../src/auth.ts")
  const plugins = auth.options.plugins ?? []
  const oauth = plugins.find((plugin) => plugin.id === "oauth-provider")
  const defaults = oauth?.options?.clientRegistrationDefaultScopes as string[] | undefined

  expect(defaults).toBeDefined()
  expect(defaults).not.toContain("mcp:write")
  expect(defaults).toContain("mcp:read")
})
