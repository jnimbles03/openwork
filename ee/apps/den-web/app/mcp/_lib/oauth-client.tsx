"use client";

import { useEffect, useState } from "react";

export type OAuthAuthorizationRequest = {
  clientId: string | null;
  redirectHost: string | null;
  scope: string;
  scopes: string[];
};

export type OAuthClientInfo = {
  clientId: string;
  name: string | null;
  logoUri: string | null;
  ownedByViewer: boolean;
};

export type OAuthClientState =
  | { status: "loading"; client: null; error: null }
  | { status: "ready"; client: OAuthClientInfo; error: null }
  | { status: "error"; client: null; error: string };

const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: "Confirm your OpenWork identity",
  profile: "See your name and profile picture",
  email: "See your email address",
  offline_access: "Stay connected without asking you again",
  "mcp:read": "Read workspace data through MCP",
  "mcp:write": "Make changes in the workspace through MCP",
};

function readRedirectHost(redirectUri: string | null) {
  if (!redirectUri) return null;
  try {
    return new URL(redirectUri).host || null;
  } catch {
    return null;
  }
}

function readSafeImageUrl(value: unknown) {
  if (typeof value !== "string" || !value) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
  } catch {
    return null;
  }
}

/**
 * Everything shown on the consent screen about the request must come from the
 * same signed `oauth_query` that is posted back to `/oauth2/consent`.
 */
export function readOAuthAuthorizationRequest(
  oauthQuery: string,
  fallbackScope: string,
): OAuthAuthorizationRequest {
  const params = new URLSearchParams(oauthQuery);
  const scope = params.get("scope") ?? fallbackScope;
  return {
    clientId: params.get("client_id"),
    redirectHost: readRedirectHost(params.get("redirect_uri")),
    scope,
    scopes: scope.split(/\s+/).filter(Boolean),
  };
}

export function useOAuthClient(clientId: string | null): OAuthClientState {
  const [state, setState] = useState<OAuthClientState>({
    status: "loading",
    client: null,
    error: null,
  });

  useEffect(() => {
    if (!clientId) {
      setState({
        status: "error",
        client: null,
        error: "This authorization request does not name a client.",
      });
      return;
    }

    let cancelled = false;
    setState({ status: "loading", client: null, error: null });
    void (async () => {
      const response = await fetch(
        `/api/auth/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`,
        { method: "GET", credentials: "include" },
      ).catch(() => null);
      const payload = response
        ? ((await response.json().catch(() => null)) as unknown)
        : null;
      if (cancelled) return;

      const record =
        typeof payload === "object" && payload !== null
          ? (payload as Record<string, unknown>)
          : null;
      if (!response?.ok || !record || record.client_id !== clientId) {
        setState({
          status: "error",
          client: null,
          error: "We couldn't confirm which application is asking for access.",
        });
        return;
      }

      setState({
        status: "ready",
        error: null,
        client: {
          clientId,
          name:
            typeof record.client_name === "string" && record.client_name.trim()
              ? record.client_name.trim()
              : null,
          logoUri: readSafeImageUrl(record.logo_uri),
          ownedByViewer:
            typeof record.user_id === "string" && record.user_id.length > 0,
        },
      });
    })();

    return () => {
      cancelled = true;
    };
  }, [clientId]);

  return state;
}

type DisclosureTone = "light" | "dark";

const TONE_CLASSES: Record<
  DisclosureTone,
  {
    card: string;
    label: string;
    value: string;
    muted: string;
    code: string;
    verified: string;
    unverified: string;
    warning: string;
  }
> = {
  light: {
    card: "rounded-2xl border border-[var(--dls-border)] bg-white p-4",
    label: "text-[11px] font-medium uppercase tracking-[0.14em] text-[var(--dls-text-secondary)]",
    value: "text-[14px] text-[var(--dls-text-primary)]",
    muted: "text-[12px] text-[var(--dls-text-secondary)]",
    code: "font-mono text-[12px] text-[var(--dls-text-primary)] break-all",
    verified: "border-emerald-200 bg-emerald-50 text-emerald-800",
    unverified: "border-amber-200 bg-amber-50 text-amber-800",
    warning: "rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] leading-5 text-amber-900",
  },
  dark: {
    card: "rounded-2xl border border-white/10 bg-slate-900/70 p-4",
    label: "text-[11px] font-medium uppercase tracking-[0.14em] text-slate-400",
    value: "text-sm text-white",
    muted: "text-xs text-slate-400",
    code: "font-mono text-xs text-cyan-100 break-all",
    verified: "border-emerald-300/40 bg-emerald-300/10 text-emerald-200",
    unverified: "border-amber-300/40 bg-amber-300/10 text-amber-200",
    warning: "rounded-xl border border-amber-300/30 bg-amber-300/10 px-3 py-2 text-xs leading-5 text-amber-100",
  },
};

export function OAuthClientDisclosure({
  request,
  clientState,
  tone = "light",
}: {
  request: OAuthAuthorizationRequest;
  clientState: OAuthClientState;
  tone?: DisclosureTone;
}) {
  const classes = TONE_CLASSES[tone];

  if (clientState.status === "loading") {
    return (
      <div className={classes.card} aria-busy="true">
        <p className={classes.muted}>Checking which application is asking for access...</p>
      </div>
    );
  }

  if (clientState.status === "error") {
    return (
      <div className={classes.card} role="alert">
        <p className={classes.value}>{clientState.error}</p>
        <p className={`mt-1 ${classes.muted}`}>
          Don't authorize this request. Start the connection again from the
          application you trust.
        </p>
      </div>
    );
  }

  const { client } = clientState;
  const verified = client.ownedByViewer;

  return (
    <section className={`${classes.card} grid gap-4`} aria-label="Application requesting access">
      <div className="flex items-start gap-3">
        {client.logoUri ? (
          <img
            src={client.logoUri}
            alt=""
            referrerPolicy="no-referrer"
            className="h-10 w-10 shrink-0 rounded-xl object-cover"
          />
        ) : null}
        <div className="grid min-w-0 flex-1 gap-1">
          <p className={classes.label}>Application</p>
          <p className={`${classes.value} font-semibold`} data-oauth-client-name>
            {client.name ?? "Unnamed application"}
          </p>
          <p className={classes.muted}>
            Client ID <span className={classes.code} data-oauth-client-id>{client.clientId}</span>
          </p>
        </div>
        <span
          className={`inline-flex shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-semibold ${
            verified ? classes.verified : classes.unverified
          }`}
          data-oauth-client-trust
        >
          {verified ? "Verified" : "Unverified"}
        </span>
      </div>

      {verified ? (
        <p className={classes.muted}>You registered this application with your OpenWork account.</p>
      ) : (
        <p className={classes.warning}>
          This application registered itself and has not been verified by
          OpenWork or by you. Its name and logo are chosen by whoever created
          it. Only continue if you started this connection and recognize where
          access will be sent.
        </p>
      )}

      <div className="grid gap-1">
        <p className={classes.label}>Access will be sent to</p>
        <p className={classes.code} data-oauth-redirect-host>
          {request.redirectHost ?? "Unknown destination"}
        </p>
      </div>

      <div className="grid gap-1">
        <p className={classes.label}>Requested access</p>
        <ul className="grid gap-1" data-oauth-scopes>
          {request.scopes.map((scope) => (
            <li key={scope} className="flex flex-wrap items-baseline gap-x-2">
              <span className={classes.code}>{scope}</span>
              {SCOPE_DESCRIPTIONS[scope] ? (
                <span className={classes.muted}>{SCOPE_DESCRIPTIONS[scope]}</span>
              ) : null}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}

export function canAuthorizeOAuthRequest(
  request: OAuthAuthorizationRequest,
  clientState: OAuthClientState,
) {
  return (
    clientState.status === "ready" &&
    clientState.client.clientId === request.clientId &&
    request.redirectHost !== null
  );
}
