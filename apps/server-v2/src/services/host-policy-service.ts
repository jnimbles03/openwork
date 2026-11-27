const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "[::1]"]);
const WILDCARD_HOSTNAMES = new Set(["", "0.0.0.0", "[::]"]);

type ParsedHost = {
  host: string;
  hostname: string;
  port: number;
};

function parseList(value: string | undefined) {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function parseHost(value: string, defaultPort: number): ParsedHost | null {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || /[\s/?#@\\]/.test(trimmed)) {
    return null;
  }

  try {
    const url = new URL(`http://${trimmed}`);
    // Reject spellings the URL parser would normalize (trailing dots, short IPv4 forms).
    if (url.hostname !== trimmed.replace(/:\d*$/, "")) {
      return null;
    }
    return {
      host: url.host,
      hostname: url.hostname,
      port: url.port ? Number(url.port) : defaultPort,
    };
  } catch {
    return null;
  }
}

function normalizeBindHostname(hostname: string) {
  const trimmed = hostname.trim().toLowerCase();
  if (trimmed.includes(":") && !trimmed.startsWith("[")) {
    return `[${trimmed}]`;
  }
  return trimmed;
}

export type HostPolicyService = ReturnType<typeof createHostPolicyService>;

/**
 * Decides which Host and Origin headers the server answers. Browsers always
 * send Host, so a DNS-rebound page shows up here with its own domain name even
 * though the TCP connection lands on loopback.
 */
export function createHostPolicyService() {
  const extraHosts = parseList(process.env.OPENWORK_SERVER_V2_ALLOWED_HOSTS);
  const extraOrigins = new Set(parseList(process.env.OPENWORK_SERVER_V2_ALLOWED_ORIGINS));
  let bound: { hostname: string; port: number } | null = null;

  function isExtraHost(parsed: ParsedHost) {
    return extraHosts.some((entry) => entry === parsed.host || entry === parsed.hostname);
  }

  function isAllowedParsedHost(parsed: ParsedHost) {
    if (isExtraHost(parsed)) {
      return true;
    }

    if (!bound) {
      return LOOPBACK_HOSTNAMES.has(parsed.hostname);
    }

    // A wildcard bind is an explicit opt-in to network exposure; the names
    // clients use cannot be known, so only the token gate applies.
    if (WILDCARD_HOSTNAMES.has(bound.hostname) && extraHosts.length === 0) {
      return true;
    }

    const nameAllowed = LOOPBACK_HOSTNAMES.has(parsed.hostname) || parsed.hostname === bound.hostname;
    return nameAllowed && (bound.port === 0 || parsed.port === bound.port);
  }

  return {
    attachBoundAddress(input: { hostname: string; port: number }) {
      bound = { hostname: normalizeBindHostname(input.hostname), port: input.port };
    },

    isAllowedHost(hostHeader: string | null) {
      if (hostHeader === null) {
        return true;
      }

      const parsed = parseHost(hostHeader, 80);
      return parsed !== null && isAllowedParsedHost(parsed);
    },

    isAllowedOrigin(originHeader: string | null, hostHeader: string | null) {
      if (originHeader === null) {
        return true;
      }

      const origin = originHeader.trim().toLowerCase();
      if (extraOrigins.has(origin)) {
        return true;
      }

      let url: URL;
      try {
        url = new URL(origin);
      } catch {
        return false;
      }
      if ((url.protocol !== "http:" && url.protocol !== "https:") || url.origin !== origin) {
        return false;
      }

      const parsed = parseHost(url.host, url.protocol === "https:" ? 443 : 80);
      if (!parsed || !isAllowedParsedHost(parsed)) {
        return false;
      }

      if (hostHeader === null) {
        return true;
      }
      const requestHost = parseHost(hostHeader, 80);
      return requestHost !== null && requestHost.host === parsed.host;
    },
  };
}
