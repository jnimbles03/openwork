import { createHash, timingSafeEqual } from "node:crypto"
import { isIP } from "node:net"
import { env } from "./env.js"

/**
 * Better Auth keys its rate limits on the first IP header it finds, so it must
 * only ever see a header that den-api itself sets. Incoming copies of both
 * headers are always discarded.
 */
export const DEN_CLIENT_IP_HEADER = "x-openwork-client-ip"
export const DEN_WEB_PROXY_SECRET_HEADER = "x-openwork-proxy-secret"

function normalizeIp(value: string | null | undefined) {
  const candidate = value?.trim() ?? ""
  return isIP(candidate) ? candidate : null
}

function digest(value: string) {
  return new Uint8Array(createHash("sha256").update(value).digest())
}

function isDenWebProxy(headers: Headers) {
  const expected = env.denWebProxySecret
  const provided = headers.get(DEN_WEB_PROXY_SECRET_HEADER)
  if (!expected || !provided) {
    return false
  }
  return timingSafeEqual(digest(provided), digest(expected))
}

// Proxies append the address they received the connection from, so only the
// last `trustedProxyHops` entries were written by infrastructure we trust.
function readTrustedForwardedFor(headers: Headers) {
  const hops = env.trustedProxyHops
  if (hops < 1) {
    return null
  }
  const entries = (headers.get("x-forwarded-for") ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
  return normalizeIp(entries[entries.length - hops])
}

export function resolveClientIp(headers: Headers, remoteAddress?: string | null) {
  if (isDenWebProxy(headers)) {
    const forwardedByDenWeb = normalizeIp(headers.get(DEN_CLIENT_IP_HEADER))
    if (forwardedByDenWeb) {
      return forwardedByDenWeb
    }
  }
  return readTrustedForwardedFor(headers) ?? normalizeIp(remoteAddress)
}

export function withTrustedClientIp(request: Request, remoteAddress?: string | null) {
  const clientIp = resolveClientIp(request.headers, remoteAddress)
  const headers = new Headers(request.headers)
  headers.delete(DEN_CLIENT_IP_HEADER)
  headers.delete(DEN_WEB_PROXY_SECRET_HEADER)
  if (clientIp) {
    headers.set(DEN_CLIENT_IP_HEADER, clientIp)
  }
  return new Request(request, { headers })
}
