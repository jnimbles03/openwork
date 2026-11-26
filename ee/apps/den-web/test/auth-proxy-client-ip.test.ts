import { afterAll, beforeAll, expect, test } from "bun:test"
import { createServer, type Server } from "node:http"
import type { AddressInfo } from "node:net"
import { NextRequest } from "next/server"

/**
 * Spec for the den-web auth proxy.
 *
 * The browser-supplied X-Forwarded-For value must not be copied onto the Den API
 * request. Each auth route below sends a different client-supplied address.
 */

const AUTH_PATHS = [
  "/api/auth/sign-in/email",
  "/api/auth/sign-up/email",
  "/api/auth/sign-in/email-otp",
  "/api/auth/email-otp/send-verification-otp",
  "/api/auth/email-otp/verify-email",
  "/api/auth/request-password-reset",
  "/api/auth/organization/invite-member",
]

let server: Server
let port = 0
const forwardedByPath = new Map<string, string | null>()

beforeAll(async () => {
  server = createServer((request, response) => {
    const path = request.url?.split("?")[0] ?? ""
    const forwarded = request.headers["x-forwarded-for"]
    forwardedByPath.set(path, Array.isArray(forwarded) ? forwarded.join(",") : forwarded ?? null)
    response.writeHead(200, { "content-type": "application/json" })
    response.end(JSON.stringify({ ok: true }))
  })
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve())
  })
  port = (server.address() as AddressInfo).port
  process.env.DEN_API_BASE = `http://127.0.0.1:${port}`
  process.env.DEN_AUTH_FALLBACK_BASE = `http://127.0.0.1:${port}`
  process.env.DEN_AUTH_ORIGIN = "http://127.0.0.1:3005"
})

afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve())
  })
})

test("auth proxy does not forward a caller-supplied X-Forwarded-For", async () => {
  const { POST } = await import("../app/api/auth/[...path]/route.ts")

  for (const [index, path] of AUTH_PATHS.entries()) {
    const spoofed = `203.0.113.${index + 1}`
    const request = new NextRequest(`http://127.0.0.1:3005${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-forwarded-for": `${spoofed}, 198.51.100.20`,
      },
      body: JSON.stringify({ email: "victim@example.com" }),
    })
    const response = await POST(request)
    expect(response.status).toBe(200)
    await response.arrayBuffer()
  }

  expect(forwardedByPath.size).toBe(AUTH_PATHS.length)
  for (const path of AUTH_PATHS) {
    const forwarded = forwardedByPath.get(path) ?? ""
    expect(forwarded).not.toContain("203.0.113.")
  }
})
