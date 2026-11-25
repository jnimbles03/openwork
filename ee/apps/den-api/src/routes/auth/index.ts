import { eq } from "@openwork-ee/den-db/drizzle"
import { OAuthClientTable } from "@openwork-ee/den-db/schema"
import type { Hono } from "hono"
import { oauthProviderAuthServerMetadata, oauthProviderOpenIdConfigMetadata } from "@better-auth/oauth-provider"
import { describeRoute } from "hono-openapi"
import { auth } from "../../auth.js"
import { db } from "../../db.js"
import { env } from "../../env.js"
import { emptyResponse } from "../../openapi.js"
import type { AuthContextVariables } from "../../session.js"
import { registerDesktopAuthRoutes } from "./desktop-handoff.js"

function rewriteAuthRequest(request: Request, path: string) {
  const url = new URL(request.url)
  url.pathname = path
  return new Request(url, request)
}

async function rewriteMetadataOrigin(response: Response, origin: string) {
  const metadata = await response.json() as Record<string, unknown>
  const headers = new Headers(response.headers)
  headers.delete("content-length")
  headers.set("content-type", "application/json")

  for (const [key, value] of Object.entries(metadata)) {
    if (typeof value === "string") {
      metadata[key] = value.replace(env.betterAuthUrl, origin)
    }
  }

  return new Response(JSON.stringify(metadata), {
    status: response.status,
    headers,
  })
}

function requestOrigin(request: Request) {
  return new URL(request.url).origin
}

async function readOAuthClientOwnerId(clientId: string) {
  const [client] = await db
    .select({ userId: OAuthClientTable.userId })
    .from(OAuthClientTable)
    .where(eq(OAuthClientTable.clientId, clientId))
    .limit(1)
  return client?.userId ?? null
}

// Consent screens label a client "verified" only when the signed-in viewer
// registered it. Anyone can register a client (dynamically or with their own
// account), so ownership by some other account must not read as trust.
async function withViewerOwnership(response: Response, viewerId: string | null) {
  if (!response.ok) {
    return response
  }

  const client = await response.json() as Record<string, unknown>
  const clientId = typeof client.client_id === "string" ? client.client_id : null
  const ownerId = clientId ? await readOAuthClientOwnerId(clientId) : null
  const headers = new Headers(response.headers)
  headers.delete("content-length")
  headers.set("content-type", "application/json")
  headers.set("cache-control", "no-store")

  return new Response(JSON.stringify({
    ...client,
    user_id: ownerId && viewerId && ownerId === viewerId ? ownerId : undefined,
  }), {
    status: response.status,
    headers,
  })
}

export function registerAuthRoutes<T extends { Variables: AuthContextVariables }>(app: Hono<T>) {
  app.get("/api/auth/.well-known/oauth-authorization-server", async (c) => rewriteMetadataOrigin(await oauthProviderAuthServerMetadata(auth)(c.req.raw), requestOrigin(c.req.raw)))
  app.get("/api/auth/.well-known/openid-configuration", async (c) => rewriteMetadataOrigin(await oauthProviderOpenIdConfigMetadata(auth)(c.req.raw), requestOrigin(c.req.raw)))
  app.get("/.well-known/oauth-authorization-server/api/auth", async (c) => rewriteMetadataOrigin(await oauthProviderAuthServerMetadata(auth)(c.req.raw), requestOrigin(c.req.raw)))
  app.get("/.well-known/openid-configuration/api/auth", async (c) => rewriteMetadataOrigin(await oauthProviderOpenIdConfigMetadata(auth)(c.req.raw), requestOrigin(c.req.raw)))
  app.get("/.well-known/oauth-authorization-server", async (c) => rewriteMetadataOrigin(await oauthProviderAuthServerMetadata(auth)(rewriteAuthRequest(c.req.raw, "/api/auth/.well-known/oauth-authorization-server")), requestOrigin(c.req.raw)))
  app.get("/.well-known/openid-configuration", async (c) => rewriteMetadataOrigin(await oauthProviderOpenIdConfigMetadata(auth)(rewriteAuthRequest(c.req.raw, "/api/auth/.well-known/openid-configuration")), requestOrigin(c.req.raw)))
  app.post("/register", async (c) => auth.handler(rewriteAuthRequest(c.req.raw, "/api/auth/oauth2/register")))
  app.get("/api/auth/oauth2/public-client", async (c) => withViewerOwnership(await auth.handler(c.req.raw), c.get("user")?.id ?? null))

  app.on(
    ["GET", "POST"],
    "/api/auth/*",
    describeRoute({
      hide: true,
      tags: ["Authentication"],
      summary: "Handle Better Auth flow",
      description: "Proxies Better Auth sign-in, sign-out, session, and verification flows under the Den API auth namespace.",
      responses: {
        200: emptyResponse("Better Auth handled the request successfully."),
        302: emptyResponse("Better Auth redirected the user to continue the auth flow."),
        400: emptyResponse("Better Auth rejected the request as invalid."),
        401: emptyResponse("Better Auth rejected the request because authentication failed."),
      },
    }),
    (c) => auth.handler(c.req.raw),
  )
  registerDesktopAuthRoutes(app)
}
