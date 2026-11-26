import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { listMcp } from "./mcp.js";
import { startServer } from "./server.js";
import type { ServerConfig } from "./types.js";

/**
 * Spec for the minimatch globstar stall in MCP tool-deny matching.
 *
 * These tests fail while apps/server is locked to minimatch 10.1.1.
 * `isMcpDisabledByTools` compiles `tools.deny` strings with the default
 * `minimatch()` API and tests them against candidates built from MCP entry
 * names. A collaborator can supply both the pattern and a multi-segment name
 * through workspace config. Listing must stay responsive. The bound below is
 * far above a fixed minimatch (10.2.3 completes the same input in a few
 * milliseconds) and far below the vulnerable runtime.
 */
const LIST_BUDGET_MS = 1000;
const GLOBSTARS = 11;
const PATH_SEGMENTS = 30;

const HOST_TOKEN = "owt_test_host";
const CLIENT_TOKEN = "owt_test_client";

type Served = {
  port: number;
  stop: (closeActiveConnections?: boolean) => void | Promise<void>;
};

type McpList = { items: Array<{ name: string; source: string; disabledByTools?: boolean }> };

const stops: Array<() => void | Promise<void>> = [];
const dirs: string[] = [];
const priorHome = process.env.HOME;
const priorTokenStore = process.env.OPENWORK_TOKEN_STORE;

function hostilePattern(): string {
  return Array.from({ length: GLOBSTARS }, () => "**/a").join("/") + "/b/**";
}

function hostileMcpName(): string {
  return Array.from({ length: PATH_SEGMENTS }, () => "a").join("/");
}

function remoteMcp(url = "https://example.com/mcp"): Record<string, unknown> {
  return { type: "remote", url };
}

function workspaceConfig(workspaceRoot: string, approval: "auto" | "manual"): ServerConfig {
  return {
    host: "127.0.0.1",
    port: 0,
    token: CLIENT_TOKEN,
    hostToken: HOST_TOKEN,
    approval: { mode: approval, timeoutMs: 10000 },
    corsOrigins: ["*"],
    workspaces: [
      {
        id: "ws_mcp_glob",
        name: "MCP glob",
        path: workspaceRoot,
        preset: "starter",
        workspaceType: "local",
      },
    ],
    authorizedRoots: [workspaceRoot],
    readOnly: false,
    startedAt: Date.now(),
    tokenSource: "cli",
    hostTokenSource: "cli",
    logFormat: "pretty",
    logRequests: false,
  };
}

function boot(workspaceRoot: string, approval: "auto" | "manual" = "auto") {
  const server = startServer(workspaceConfig(workspaceRoot, approval)) as Served;
  stops.push(() => server.stop(true));
  return { base: `http://127.0.0.1:${server.port}` };
}

function hostAuth(): Record<string, string> {
  return { "x-openwork-host-token": HOST_TOKEN, "content-type": "application/json" };
}

function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}`, "content-type": "application/json" };
}

async function issueToken(base: string, scope: "collaborator" | "viewer"): Promise<string> {
  const issued = await fetch(`${base}/tokens`, {
    method: "POST",
    headers: hostAuth(),
    body: JSON.stringify({ scope, label: `mcp-glob-${scope}` }),
  });
  expect(issued.status).toBe(201);
  const body = (await issued.json()) as { token?: string };
  expect(typeof body.token).toBe("string");
  return body.token as string;
}

async function patchOpencode(
  base: string,
  token: string,
  opencode: Record<string, unknown>,
): Promise<Response> {
  return fetch(`${base}/workspace/ws_mcp_glob/config`, {
    method: "PATCH",
    headers: bearer(token),
    body: JSON.stringify({ opencode }),
  });
}

async function allowPending(base: string): Promise<void> {
  const deadline = Date.now() + 2000;
  let id = "";
  while (Date.now() < deadline) {
    const listed = await fetch(`${base}/approvals`, { headers: hostAuth() });
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as { items: Array<{ id: string }> };
    if (body.items.length > 0) {
      id = body.items[0].id;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 15));
  }
  expect(id).not.toBe("");
  const decision = await fetch(`${base}/approvals/${encodeURIComponent(id)}`, {
    method: "POST",
    headers: hostAuth(),
    body: JSON.stringify({ reply: "allow" }),
  });
  expect(decision.status).toBe(200);
}

async function timedMcpList(base: string, token: string): Promise<{ elapsedMs: number; body: McpList; status: number }> {
  const started = performance.now();
  const response = await fetch(`${base}/workspace/ws_mcp_glob/mcp`, { headers: bearer(token) });
  const elapsedMs = performance.now() - started;
  const body = (await response.json()) as McpList;
  return { elapsedMs, body, status: response.status };
}

function expectListedQuickly(
  result: { elapsedMs: number; body: McpList; status: number },
  name: string,
): void {
  expect(result.status).toBe(200);
  expect(result.body.items.some((item) => item.name === name)).toBe(true);
  expect(result.elapsedMs).toBeLessThan(LIST_BUDGET_MS);
}

function writeProjectConfig(workspaceRoot: string, opencode: Record<string, unknown>): void {
  writeFileSync(join(workspaceRoot, "opencode.json"), JSON.stringify(opencode, null, 2) + "\n", "utf8");
}

beforeEach(() => {
  const dir = mkdtempSync(join(tmpdir(), "openwork-mcp-glob-"));
  dirs.push(dir);
  process.env.HOME = dir;
  process.env.OPENWORK_TOKEN_STORE = join(dir, "tokens.json");
  mkdirSync(join(dir, "workspace"), { recursive: true });
});

afterEach(async () => {
  while (stops.length) {
    await stops.pop()?.();
  }
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
  if (priorHome === undefined) delete process.env.HOME;
  else process.env.HOME = priorHome;
  if (priorTokenStore === undefined) delete process.env.OPENWORK_TOKEN_STORE;
  else process.env.OPENWORK_TOKEN_STORE = priorTokenStore;
});

describe.serial("mcp tools.deny minimatch", () => {
  test("keeps a multi-segment mcp name when tools.deny is an ordinary string", async () => {
    const workspaceRoot = join(process.env.HOME!, "workspace");
    const name = hostileMcpName();
    const { base } = boot(workspaceRoot);
    const collaborator = await issueToken(base, "collaborator");
    const viewer = await issueToken(base, "viewer");

    const patched = await patchOpencode(base, collaborator, {
      tools: { deny: ["other-tool"] },
      mcp: { [name]: remoteMcp() },
    });
    expect(patched.status).toBe(200);

    const listed = await timedMcpList(base, viewer);
    expectListedQuickly(listed, name);
    expect(listed.body.items.find((item) => item.name === name)?.disabledByTools).toBeUndefined();
  });

  test("lists workspace mcp entries without stalling on a non-matching multi-globstar deny pattern", async () => {
    const workspaceRoot = join(process.env.HOME!, "workspace");
    const name = hostileMcpName();
    writeProjectConfig(workspaceRoot, {
      tools: { deny: [hostilePattern()] },
      mcp: { [name]: remoteMcp() },
    });

    const started = performance.now();
    const items = await listMcp(workspaceRoot);
    const elapsedMs = performance.now() - started;

    expect(items.some((item) => item.name === name && item.source === "config.project")).toBe(true);
    expect(items.find((item) => item.name === name)?.disabledByTools).toBeUndefined();
    expect(elapsedMs).toBeLessThan(LIST_BUDGET_MS);
  }, 30000);

  test("does not stall GET /workspace/:id/mcp after a collaborator patches tools.deny and the mcp key", async () => {
    const workspaceRoot = join(process.env.HOME!, "workspace");
    const name = hostileMcpName();
    const { base } = boot(workspaceRoot, "auto");
    const collaborator = await issueToken(base, "collaborator");
    const viewer = await issueToken(base, "viewer");

    const patched = await patchOpencode(base, collaborator, {
      tools: { deny: [hostilePattern()] },
      mcp: { [name]: remoteMcp() },
    });
    expect(patched.status).toBe(200);

    const listed = await timedMcpList(base, viewer);
    expectListedQuickly(listed, name);
  }, 30000);

  test("does not stall mcp add, enable, or remove while a hostile entry remains configured", async () => {
    const workspaceRoot = join(process.env.HOME!, "workspace");
    const name = hostileMcpName();
    const { base } = boot(workspaceRoot, "auto");
    const collaborator = await issueToken(base, "collaborator");

    const patched = await patchOpencode(base, collaborator, {
      tools: { deny: [hostilePattern()] },
      mcp: { [name]: remoteMcp() },
    });
    expect(patched.status).toBe(200);

    const safe = remoteMcp("https://example.com/safe");
    const addedStarted = performance.now();
    const added = await fetch(`${base}/workspace/ws_mcp_glob/mcp`, {
      method: "POST",
      headers: bearer(collaborator),
      body: JSON.stringify({ name: "safe-server", config: safe }),
    });
    const addedMs = performance.now() - addedStarted;
    expect(added.status).toBe(200);
    const addedBody = (await added.json()) as McpList;
    expect(addedBody.items.some((item) => item.name === name)).toBe(true);
    expect(addedBody.items.some((item) => item.name === "safe-server")).toBe(true);
    expect(addedMs).toBeLessThan(LIST_BUDGET_MS);

    const enabledStarted = performance.now();
    const enabled = await fetch(`${base}/workspace/ws_mcp_glob/mcp/safe-server/enabled`, {
      method: "POST",
      headers: bearer(collaborator),
      body: JSON.stringify({ enabled: false }),
    });
    const enabledMs = performance.now() - enabledStarted;
    expect(enabled.status).toBe(200);
    const enabledBody = (await enabled.json()) as McpList;
    expect(enabledBody.items.some((item) => item.name === name)).toBe(true);
    expect(enabledMs).toBeLessThan(LIST_BUDGET_MS);

    const removedStarted = performance.now();
    const removed = await fetch(`${base}/workspace/ws_mcp_glob/mcp/safe-server`, {
      method: "DELETE",
      headers: bearer(collaborator),
    });
    const removedMs = performance.now() - removedStarted;
    expect(removed.status).toBe(200);
    const removedBody = (await removed.json()) as McpList;
    expect(removedBody.items.some((item) => item.name === name)).toBe(true);
    expect(removedBody.items.some((item) => item.name === "safe-server")).toBe(false);
    expect(removedMs).toBeLessThan(LIST_BUDGET_MS);
  }, 90000);

  test("does not stall listing when the hostile pattern and name come from global opencode config", async () => {
    const workspaceRoot = join(process.env.HOME!, "workspace");
    const name = hostileMcpName();
    const { base } = boot(workspaceRoot, "auto");
    const collaborator = await issueToken(base, "collaborator");
    const viewer = await issueToken(base, "viewer");

    const written = await fetch(`${base}/workspace/ws_mcp_glob/opencode-config`, {
      method: "POST",
      headers: bearer(collaborator),
      body: JSON.stringify({
        scope: "global",
        content: JSON.stringify({
          tools: { deny: [hostilePattern()] },
          mcp: { [name]: remoteMcp() },
        }),
      }),
    });
    expect(written.status).toBe(200);

    const listed = await timedMcpList(base, viewer);
    expect(listed.status).toBe(200);
    expect(listed.body.items.some((item) => item.name === name && item.source === "config.global")).toBe(true);
    expect(listed.elapsedMs).toBeLessThan(LIST_BUDGET_MS);
  }, 30000);

  test("does not stall listing after the host allows a manual config patch", async () => {
    const workspaceRoot = join(process.env.HOME!, "workspace");
    const name = hostileMcpName();
    const { base } = boot(workspaceRoot, "manual");
    const collaborator = await issueToken(base, "collaborator");
    const viewer = await issueToken(base, "viewer");

    const patching = patchOpencode(base, collaborator, {
      tools: { deny: [hostilePattern()] },
      mcp: { [name]: remoteMcp() },
    });
    await allowPending(base);
    const patched = await patching;
    expect(patched.status).toBe(200);

    const listed = await timedMcpList(base, viewer);
    expectListedQuickly(listed, name);
  }, 30000);
});
