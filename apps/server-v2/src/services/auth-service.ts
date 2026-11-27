import { randomBytes, timingSafeEqual } from "node:crypto";
import { HTTPException } from "hono/http-exception";

export type RequestActor = {
  kind: "anonymous" | "client" | "host";
};

export type AuthSummary = {
  actorKind: RequestActor["kind"];
  configured: {
    clientToken: boolean;
    hostToken: boolean;
  };
  headers: {
    authorization: "Authorization";
    hostToken: "X-OpenWork-Host-Token";
  };
  required: boolean;
  scopes: {
    hiddenWorkspaceReads: "host";
    serverInventory: "host";
    visibleRead: "client_or_host";
  };
};

function readBearer(headers: Headers) {
  const raw = headers.get("authorization")?.trim() ?? "";
  const match = raw.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() ?? "";
}

function trimToken(value: string | null | undefined) {
  const trimmed = value?.trim() ?? "";
  return trimmed || null;
}

function tokensMatch(presented: string, expected: string | null) {
  if (!expected || !presented) {
    return false;
  }

  const left = Buffer.from(presented);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

export type AuthService = ReturnType<typeof createAuthService>;

export type CreateAuthServiceOptions = {
  clientToken?: string | null;
  hostToken?: string | null;
};

export function createAuthService(options: CreateAuthServiceOptions = {}) {
  const clientToken = trimToken(
    options.clientToken
      ?? process.env.OPENWORK_SERVER_V2_CLIENT_TOKEN
      ?? process.env.OPENWORK_CLIENT_TOKEN
      ?? process.env.OPENWORK_TOKEN,
  );
  const configuredHostToken = trimToken(
    options.hostToken
      ?? process.env.OPENWORK_SERVER_V2_HOST_TOKEN
      ?? process.env.OPENWORK_HOST_TOKEN,
  );
  // Authentication is never optional: without configured tokens, a random host
  // token is minted so anonymous callers (including DNS-rebound browser pages)
  // cannot reach any protected route.
  const generatedHostToken = !clientToken && !configuredHostToken
    ? randomBytes(32).toString("base64url")
    : null;
  const hostToken = configuredHostToken ?? generatedHostToken;

  function resolveActor(headers: Headers): RequestActor {
    const hostHeader = headers.get("x-openwork-host-token")?.trim() ?? "";
    if (tokensMatch(hostHeader, hostToken)) {
      return { kind: "host" };
    }

    const bearer = readBearer(headers);
    if (tokensMatch(bearer, hostToken)) {
      return { kind: "host" };
    }

    if (tokensMatch(bearer, clientToken)) {
      return { kind: "client" };
    }

    return { kind: "anonymous" };
  }

  function getSummary(actor: RequestActor): AuthSummary {
    return {
      actorKind: actor.kind,
      configured: {
        clientToken: Boolean(clientToken),
        hostToken: Boolean(hostToken),
      },
      headers: {
        authorization: "Authorization",
        hostToken: "X-OpenWork-Host-Token",
      },
      required: true,
      scopes: {
        hiddenWorkspaceReads: "host",
        serverInventory: "host",
        visibleRead: "client_or_host",
      },
    };
  }

  function requireVisibleRead(actor: RequestActor) {
    if (actor.kind === "anonymous") {
      throw new HTTPException(401, {
        message: "A client or host token is required for this route.",
      });
    }
  }

  function requireHost(actor: RequestActor) {
    if (actor.kind === "anonymous") {
      throw new HTTPException(401, {
        message: "A host token is required for this route.",
      });
    }

    if (actor.kind !== "host") {
      throw new HTTPException(403, {
        message: "Host scope is required for this route.",
      });
    }
  }

  return {
    /** The host token minted at startup when none was configured, so the server can hand it to the local operator. */
    getGeneratedHostToken() {
      return generatedHostToken;
    },
    getSummary,
    requireHost,
    requireVisibleRead,
    resolveActor,
  };
}
