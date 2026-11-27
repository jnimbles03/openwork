import type { MiddlewareHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import { getRequestContext, type AppBindings } from "../context/request-context.js";
import { routePaths } from "../routes/route-paths.js";

const PUBLIC_READ_PATHS = new Set<string>([
  routePaths.root,
  routePaths.system.health,
  routePaths.openapiDocument,
]);

function isPublicRead(method: string, pathname: string) {
  return (method === "GET" || method === "HEAD") && PUBLIC_READ_PATHS.has(pathname);
}

/**
 * Every route except the public read surfaces needs a client or host token.
 * This runs before routing so a route that forgets its own guard still
 * refuses anonymous callers.
 */
export const authenticationGateMiddleware: MiddlewareHandler<AppBindings> = async (c, next) => {
  const requestContext = getRequestContext(c);
  if (requestContext.actor.kind === "anonymous" && !isPublicRead(c.req.method, c.req.path)) {
    throw new HTTPException(401, {
      message: "A client or host token is required for this route.",
    });
  }
  await next();
};

/** Refuses requests addressed to an unexpected Host or sent by a foreign browser Origin (DNS rebinding, cross-site calls). */
export const hostOriginGuardMiddleware: MiddlewareHandler<AppBindings> = async (c, next) => {
  const policy = getRequestContext(c).services.hostPolicy;
  const headers = c.req.raw.headers;
  const host = headers.get("host");

  if (!policy.isAllowedHost(host)) {
    throw new HTTPException(403, {
      message: "Request Host is not allowed. Set OPENWORK_SERVER_V2_ALLOWED_HOSTS to accept additional host names.",
    });
  }

  if (!policy.isAllowedOrigin(headers.get("origin"), host)) {
    throw new HTTPException(403, {
      message: "Request Origin is not allowed. Set OPENWORK_SERVER_V2_ALLOWED_ORIGINS to accept additional origins.",
    });
  }

  await next();
};
