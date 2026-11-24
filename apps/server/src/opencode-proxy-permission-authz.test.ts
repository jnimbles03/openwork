import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { startServer } from "./server.js";
import type { ServerConfig } from "./types.js";
import { hashToken } from "./utils.js";

/**
 * Upstream stand-in for OpenCode v1.4.9 (constants.json opencodeVersion).
 *
 * Path matching copies Hono 4.10.7 getPath (hono/dist/utils/url.js): percent-decoding
 * uses decodeURI, which leaves %2F encoded and decodes segments such as %70 and %72.
 * Route patterns are the two handlers that call Permission.Service.reply:
 * - POST /session/:sessionID/permissions/:permissionID with { response } (session.ts)
 * - POST /permission/:requestID/reply with { reply } (permission.ts)
 * Reply behavior copies Permission.reply: once and always unblock the waiting tool;
 * reject fails it; an unknown id is a no-op. Basic auth copies AuthMiddleware.
 */

const COLLABORATOR_TOKEN = "collaborator-token";
const OWNER_TOKEN = "owner-token";
const VIEWER_TOKEN = "viewer-token";
const HOST_TOKEN = "host-token";
const UPSTREAM_USER = "upstream-user";
const UPSTREAM_PASSWORD = "upstream-password";
const SESSION_ID = "ses_pending";
const PERMISSION_ID = "per_pending";
const HOST_COMMAND = "hostname";

const REPLIES = new Set(["once", "always", "reject"]);

type Served = {
  port: number;
  stop: (closeActiveConnections?: boolean) => void | Promise<void>;
};

type PendingPermission = {
  id: string;
  sessionID: string;
  permission: string;
  command: string;
};

type ReplyHit = {
  pathname: string;
  usedUpstreamBasicAuth: boolean;
  forwardedClientBearer: boolean;
  body: unknown;
  outcome: "ran" | "rejected" | "ignored";
};

const stops: Array<() => void | Promise<void>> = [];
const roots: string[] = [];

afterEach(async () => {
  while (stops.length) {
    await stops.pop()?.();
  }
  while (roots.length) {
    await rm(roots.pop()!, { recursive: true, force: true });
  }
});

function tryDecode(value: string, decoder: (input: string) => string): string {
  try {
    return decoder(value);
  } catch {
    return value.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match) => {
      try {
        return decoder(match);
      } catch {
        return match;
      }
    });
  }
}

function honoPath(url: string): string {
  const start = url.indexOf("/", url.indexOf(":") + 4);
  let index = start;
  for (; index < url.length; index += 1) {
    const charCode = url.charCodeAt(index);
    if (charCode === 37) {
      const queryIndex = url.indexOf("?", index);
      const path = url.slice(start, queryIndex === -1 ? undefined : queryIndex);
      const prepared = path.includes("%25") ? path.replace(/%25/g, "%2525") : path;
      return tryDecode(prepared, decodeURI);
    }
    if (charCode === 63) break;
  }
  return url.slice(start, index);
}

function parseBasicAuth(header: string | null): { username: string; password: string } | null {
  const match = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/.exec(header ?? "");
  if (!match) return null;
  const decoded = Buffer.from(match[1], "base64").toString("utf8");
  const separator = decoded.indexOf(":");
  if (separator < 0) return null;
  return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1) };
}

function startUpstream() {
  const pending = new Map<string, PendingPermission>();
  const hits: ReplyHit[] = [];
  const requests: string[] = [];

  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const path = honoPath(request.url);
      requests.push(`${request.method} ${path}`);

      const authorization = request.headers.get("authorization");
      const user = parseBasicAuth(authorization);
      const usedUpstreamBasicAuth = user?.username === UPSTREAM_USER && user.password === UPSTREAM_PASSWORD;
      const forwardedClientBearer = authorization?.toLowerCase().startsWith("bearer ") === true;
      if (!usedUpstreamBasicAuth || forwardedClientBearer) {
        return new Response("Unauthorized", { status: 401 });
      }

      if (request.method === "POST" && /^\/session\/([^/]+)\/message$/.test(path)) {
        const sessionID = decodeURIComponent(path.split("/")[2] ?? "");
        if (!sessionID.startsWith("ses")) {
          return Response.json({ code: "validation", message: "invalid session" }, { status: 400 });
        }
        const body = (await request.json().catch(() => null)) as { parts?: Array<{ type?: string; text?: string }> } | null;
        const text = body?.parts?.find((part) => part.type === "text")?.text ?? "";
        if (!text.trim()) {
          return Response.json({ code: "validation", message: "parts required" }, { status: 400 });
        }
        pending.set(PERMISSION_ID, {
          id: PERMISSION_ID,
          sessionID,
          permission: "bash",
          command: HOST_COMMAND,
        });
        return Response.json({ info: { id: "msg_pending", sessionID, role: "assistant" }, parts: [] });
      }

      if (request.method === "GET" && path === "/permission") {
        return Response.json([...pending.values()]);
      }

      if (request.method === "GET" && path === `/session/${SESSION_ID}`) {
        return Response.json({ id: SESSION_ID });
      }

      const sessionReply = /^\/session\/([^/]+)\/permissions\/([^/]+)$/.exec(path);
      const directReply = /^\/permission\/([^/]+)\/reply$/.exec(path);
      if (request.method === "POST" && (sessionReply || directReply)) {
        const body = (await request.json().catch(() => null)) as { response?: unknown; reply?: unknown } | null;
        const sessionID = sessionReply?.[1] ?? "";
        const permissionID = sessionReply?.[2] ?? directReply?.[1] ?? "";
        const reply = sessionReply ? body?.response : body?.reply;
        if (sessionReply && !sessionID.startsWith("ses")) {
          return Response.json({ code: "validation", message: "invalid session" }, { status: 400 });
        }
        if (!permissionID.startsWith("per") || typeof reply !== "string" || !REPLIES.has(reply)) {
          return Response.json({ code: "validation", message: "invalid permission reply" }, { status: 400 });
        }

        const existing = pending.get(permissionID);
        const authRecord = { pathname: path, usedUpstreamBasicAuth, forwardedClientBearer, body };
        if (!existing || (sessionReply && existing.sessionID !== sessionID)) {
          hits.push({ ...authRecord, outcome: "ignored" });
          return Response.json(true);
        }
        pending.delete(permissionID);
        const outcome = reply === "reject" ? "rejected" : "ran";
        hits.push({ ...authRecord, outcome });
        return Response.json(true);
      }

      return Response.json({ code: "not_found", message: "Not found" }, { status: 404 });
    },
  }) as Served;
  stops.push(() => server.stop(true));

  return {
    url: `http://127.0.0.1:${server.port}`,
    requests,
    hits,
    pending,
    ran(): string[] {
      return hits.filter((hit) => hit.outcome === "ran").map(() => HOST_COMMAND);
    },
  };
}

async function startOpenwork(upstreamUrl: string) {
  const root = join(tmpdir(), `openwork-permission-proxy-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  await mkdir(root, { recursive: true });
  roots.push(root);
  const configPath = join(root, "server.json");
  await writeFile(
    join(root, "tokens.json"),
    JSON.stringify(
      {
        schemaVersion: 1,
        updatedAt: 1,
        tokens: [
          { id: "owner", hash: hashToken(OWNER_TOKEN), scope: "owner", createdAt: 1 },
          { id: "viewer", hash: hashToken(VIEWER_TOKEN), scope: "viewer", createdAt: 1 },
        ],
      },
      null,
      2,
    ),
  );

  const config: ServerConfig = {
    host: "127.0.0.1",
    port: 0,
    token: COLLABORATOR_TOKEN,
    hostToken: HOST_TOKEN,
    configPath,
    approval: { mode: "manual", timeoutMs: 1000 },
    corsOrigins: ["*"],
    workspaces: [
      {
        id: "ws_test",
        name: "Workspace",
        path: root,
        preset: "starter",
        workspaceType: "local",
        baseUrl: upstreamUrl,
        opencodeUsername: UPSTREAM_USER,
        opencodePassword: UPSTREAM_PASSWORD,
      },
    ],
    authorizedRoots: [root],
    readOnly: true,
    startedAt: Date.now(),
    tokenSource: "cli",
    hostTokenSource: "cli",
    logFormat: "pretty",
    logRequests: false,
  };
  const server = startServer(config) as Served;
  stops.push(() => server.stop(true));
  return { baseUrl: `http://127.0.0.1:${server.port}` };
}

function bearer(token: string) {
  return { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };
}

async function raisePermission(baseUrl: string, token: string) {
  const response = await fetch(`${baseUrl}/opencode/session/${SESSION_ID}/message`, {
    method: "POST",
    headers: bearer(token),
    body: JSON.stringify({ parts: [{ type: "text", text: "Run hostname on the host." }] }),
  });
  expect(response.status).toBe(200);
  const listed = await fetch(`${baseUrl}/opencode/permission`, { headers: bearer(token) });
  expect(listed.status).toBe(200);
  const permissions = (await listed.json()) as Array<{ id?: string }>;
  expect(permissions.map((permission) => permission.id)).toContain(PERMISSION_ID);
}

describe("opencode proxy permission authorization", () => {
  test("collaborator prompts are forwarded, but both permission replies stay unanswered", async () => {
    const upstream = startUpstream();
    const openwork = await startOpenwork(upstream.url);
    await raisePermission(openwork.baseUrl, COLLABORATOR_TOKEN);

    const cases = [
      {
        path: `/opencode/session/${SESSION_ID}/permissions/${PERMISSION_ID}`,
        body: { response: "always" },
      },
      {
        path: `/w/ws_test/opencode/session/${SESSION_ID}/permissions/${PERMISSION_ID}`,
        body: { response: "always" },
      },
      {
        path: `/opencode/session/${SESSION_ID}/permissions/${PERMISSION_ID}?directory=/tmp`,
        body: { response: "always" },
      },
      {
        path: `/opencode/session/${SESSION_ID}/%70ermissions/${PERMISSION_ID}`,
        body: { response: "always" },
      },
      {
        path: `/opencode/session/%73es_pending/permissions/${PERMISSION_ID}`,
        body: { response: "once" },
      },
      {
        path: `/opencode/session/${SESSION_ID}/permissions/per%5Fpending`,
        body: { response: "always" },
      },
      {
        path: `/opencode/session/${SESSION_ID}/permissions/${PERMISSION_ID}/`,
        body: { response: "always" },
      },
      {
        path: `/opencode/session//${SESSION_ID}/permissions/${PERMISSION_ID}`,
        body: { response: "always" },
      },
      {
        path: `/opencode/session/${SESSION_ID}//permissions/${PERMISSION_ID}`,
        body: { response: "always" },
      },
      {
        path: `/opencode/permission/${PERMISSION_ID}/reply`,
        body: { reply: "always" },
      },
      {
        path: `/opencode/permission/${PERMISSION_ID}/%72%65%70%6c%79`,
        body: { reply: "always" },
      },
      {
        path: `/w/ws_test/opencode/permission/${PERMISSION_ID}/%72%65%70%6c%79`,
        body: { reply: "always" },
      },
      {
        path: `/opencode/permission/${PERMISSION_ID}/reply/`,
        body: { reply: "reject" },
      },
    ];

    const failures: Array<{ path: string; status: number; outcomes: string[] }> = [];
    for (const entry of cases) {
      if (!upstream.pending.has(PERMISSION_ID)) {
        await raisePermission(openwork.baseUrl, COLLABORATOR_TOKEN);
      }
      const before = upstream.hits.length;
      const response = await fetch(`${openwork.baseUrl}${entry.path}`, {
        method: "POST",
        headers: bearer(COLLABORATOR_TOKEN),
        body: JSON.stringify(entry.body),
      });
      await response.json().catch(() => null);
      const outcomes = upstream.hits.slice(before).map((hit) => hit.outcome);
      if (response.status !== 403 || outcomes.length > 0) {
        failures.push({ path: entry.path, status: response.status, outcomes });
      }
    }

    expect(failures).toEqual([]);
    expect(upstream.ran()).toEqual([]);
  });

  test("viewer tokens cannot answer a pending permission", async () => {
    const upstream = startUpstream();
    const openwork = await startOpenwork(upstream.url);
    await raisePermission(openwork.baseUrl, COLLABORATOR_TOKEN);

    const response = await fetch(
      `${openwork.baseUrl}/opencode/session/${SESSION_ID}/permissions/${PERMISSION_ID}`,
      {
        method: "POST",
        headers: bearer(VIEWER_TOKEN),
        body: JSON.stringify({ response: "always" }),
      },
    );
    expect(response.status).toBe(403);
    expect(upstream.ran()).toEqual([]);
    expect(upstream.pending.has(PERMISSION_ID)).toBe(true);
  });

  test("owner session permission response is proxied with upstream credentials and runs the command", async () => {
    const upstream = startUpstream();
    const openwork = await startOpenwork(upstream.url);
    await raisePermission(openwork.baseUrl, COLLABORATOR_TOKEN);

    const response = await fetch(
      `${openwork.baseUrl}/opencode/session/${SESSION_ID}/permissions/${PERMISSION_ID}`,
      {
        method: "POST",
        headers: bearer(OWNER_TOKEN),
        body: JSON.stringify({ response: "always" }),
      },
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toBe(true);
    expect(upstream.ran()).toEqual([HOST_COMMAND]);
    expect(upstream.hits).toEqual([
      {
        pathname: `/session/${SESSION_ID}/permissions/${PERMISSION_ID}`,
        usedUpstreamBasicAuth: true,
        forwardedClientBearer: false,
        body: { response: "always" },
        outcome: "ran",
      },
    ]);
    expect(upstream.pending.size).toBe(0);
  });

  test("owner permission reply path runs the command and a mismatched body does not", async () => {
    const upstream = startUpstream();
    const openwork = await startOpenwork(upstream.url);
    await raisePermission(openwork.baseUrl, OWNER_TOKEN);

    const mismatched = await fetch(
      `${openwork.baseUrl}/opencode/session/${SESSION_ID}/permissions/${PERMISSION_ID}`,
      {
        method: "POST",
        headers: bearer(OWNER_TOKEN),
        body: JSON.stringify({ reply: "always" }),
      },
    );
    expect(mismatched.status).toBe(400);
    expect(upstream.ran()).toEqual([]);
    expect(upstream.pending.has(PERMISSION_ID)).toBe(true);

    const response = await fetch(`${openwork.baseUrl}/w/ws_test/opencode/permission/${PERMISSION_ID}/reply`, {
      method: "POST",
      headers: bearer(OWNER_TOKEN),
      body: JSON.stringify({ reply: "once" }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toBe(true);
    expect(upstream.ran()).toEqual([HOST_COMMAND]);
    expect(upstream.hits.at(-1)).toMatchObject({
      pathname: `/permission/${PERMISSION_ID}/reply`,
      usedUpstreamBasicAuth: true,
      forwardedClientBearer: false,
      body: { reply: "once" },
      outcome: "ran",
    });
  });
});
