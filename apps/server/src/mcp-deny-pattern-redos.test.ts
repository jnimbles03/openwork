import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

import { startServer } from "./server.js";
import type { ApprovalRequest, ServerConfig } from "./types.js";

type Served = {
  port: number;
  stop: (closeActiveConnections?: boolean) => void | Promise<void>;
};

const RESPONSIVE_MS = 500;
const STAR_COUNT = 30;
const MCP_NAME = "files";
const SECOND_MCP_NAME = "notes";
const WORKSPACE_ID = "ws_1";

// Consecutive "*" wildcards followed by a literal "+" miss minimatch's
// star/extension fast path and compile to one lazy "[^/]*?" group per star.
const stallPattern = `${"*".repeat(STAR_COUNT)}+`;

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

function auth(token: string) {
  return { authorization: `Bearer ${token}` };
}

function hostHeaders(hostToken: string) {
  return { "x-openwork-host-token": hostToken };
}

function jsonHeaders(token: string) {
  return { ...auth(token), "content-type": "application/json" };
}

function opencodeDocument(deny: string[]) {
  return {
    mcp: {
      [MCP_NAME]: { type: "remote", url: "https://example.com/mcp" },
    },
    tools: { deny },
  };
}

async function createWorkspaceRoot() {
  const root = await mkdtemp(join(tmpdir(), "openwork-mcp-deny-"));
  roots.push(root);
  return root;
}

function startOpenworkServer(workspaceRoot: string, approvalMode: "manual" | "auto") {
  const config: ServerConfig = {
    host: "127.0.0.1",
    port: 0,
    token: "test-client-token",
    hostToken: "test-host-token",
    configPath: join(workspaceRoot, "server-config.json"),
    approval: { mode: approvalMode, timeoutMs: 15_000 },
    corsOrigins: ["*"],
    workspaces: [
      {
        id: WORKSPACE_ID,
        name: "Workspace",
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
  const server = startServer(config) as Served;
  stops.push(() => server.stop(true));
  return {
    server,
    base: `http://127.0.0.1:${server.port}`,
    hostToken: config.hostToken,
  };
}

async function issueToken(base: string, hostToken: string, scope: "collaborator" | "viewer" | "owner") {
  const response = await fetch(`${base}/tokens`, {
    method: "POST",
    headers: { ...hostHeaders(hostToken), "content-type": "application/json" },
    body: JSON.stringify({ scope, label: `${scope}-redos-test` }),
  });
  expect(response.status).toBe(201);
  const body = (await response.json()) as { token: string; scope: string };
  expect(body.scope).toBe(scope);
  return body.token;
}

async function waitForApproval(base: string, hostToken: string): Promise<ApprovalRequest> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    const response = await fetch(`${base}/approvals`, { headers: hostHeaders(hostToken) });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { items: ApprovalRequest[] };
    const pending = body.items[0];
    if (pending) return pending;
    await Bun.sleep(15);
  }
  throw new Error("timed out waiting for a host approval");
}

async function allowPendingWrite(base: string, hostToken: string, pending: Promise<Response>) {
  const approval = await waitForApproval(base, hostToken);
  const serialized = JSON.stringify(approval);
  expect(serialized.includes(stallPattern)).toBe(false);
  expect(approval.actor.scope).toBe("collaborator");
  const reply = await fetch(`${base}/approvals/${approval.id}`, {
    method: "POST",
    headers: { ...hostHeaders(hostToken), "content-type": "application/json" },
    body: JSON.stringify({ reply: "allow" }),
  });
  expect(reply.status).toBe(200);
  const response = await pending;
  expect(response.status).toBe(200);
  return { approval, response };
}

async function plantConfig(workspaceRoot: string, deny: string[]) {
  await writeFile(join(workspaceRoot, "opencode.jsonc"), `${JSON.stringify(opencodeDocument(deny), null, 2)}\n`, "utf8");
}

async function timeRequest(request: Promise<Response>) {
  const started = performance.now();
  const response = await request;
  return { response, ms: performance.now() - started };
}

function mcpUrl(base: string, suffix = "") {
  return `${base}/workspace/${WORKSPACE_ID}/mcp${suffix}`;
}

async function expectListStaysResponsive(base: string, viewerToken: string) {
  const probe = Bun.spawn({
    cmd: [
      process.execPath,
      "-e",
      `const base = process.argv[1];
       const delay = Number(process.argv[2]);
       await Bun.sleep(delay);
       const started = performance.now();
       const response = await fetch(base + "/health");
       console.log(JSON.stringify({ status: response.status, ms: performance.now() - started }));`,
      base,
      "300",
    ],
    stdout: "pipe",
    stderr: "pipe",
  });

  const started = performance.now();
  const response = await fetch(mcpUrl(base), { headers: auth(viewerToken) });
  const mcpMs = performance.now() - started;
  const probeText = await new Response(probe.stdout).text();
  const probeError = await new Response(probe.stderr).text();
  const probeExit = await probe.exited;
  expect(probeExit, probeError).toBe(0);
  const health = JSON.parse(probeText) as { status: number; ms: number };

  expect(response.status).toBe(200);
  const body = (await response.json()) as { items: Array<{ name: string; disabledByTools?: boolean }> };
  expect(body.items.some((item) => item.name === MCP_NAME)).toBe(true);
  expect(health.status).toBe(200);
  const slow: string[] = [];
  if (mcpMs >= RESPONSIVE_MS) slow.push(`GET /mcp took ${mcpMs.toFixed(0)}ms`);
  if (health.ms >= RESPONSIVE_MS) slow.push(`concurrent GET /health took ${health.ms.toFixed(0)}ms`);
  expect(slow).toEqual([]);
  return body;
}

describe("tools.deny patterns passed to minimatch", () => {
  test("a normal deny glob still marks the matching MCP disabled", async () => {
    const workspaceRoot = await createWorkspaceRoot();
    await plantConfig(workspaceRoot, ["mcp.*"]);
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "manual");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    const { response, ms } = await timeRequest(fetch(mcpUrl(base), { headers: auth(viewerToken) }));
    expect(response.status).toBe(200);
    const body = (await response.json()) as { items: Array<{ name: string; disabledByTools?: boolean }> };
    expect(body.items).toEqual([
      expect.objectContaining({ name: MCP_NAME, disabledByTools: true }),
    ]);
    expect(ms).toBeLessThan(RESPONSIVE_MS);
  });

  test("a collaborator deny pattern approved without its text does not stall MCP listing", async () => {
    const workspaceRoot = await createWorkspaceRoot();
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "manual");
    const collaboratorToken = await issueToken(base, hostToken, "collaborator");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    const pending = fetch(`${base}/workspace/${WORKSPACE_ID}/config`, {
      method: "PATCH",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({ opencode: opencodeDocument([stallPattern]) }),
    });
    const { approval } = await allowPendingWrite(base, hostToken, pending);
    expect(approval.action).toBe("config.patch");
    expect(approval.summary).toBe("Patch workspace config");

    await expectListStaysResponsive(base, viewerToken);
  }, 20_000);

  test("automatic approval still lets a collaborator plant a deny pattern that must not stall listing", async () => {
    const workspaceRoot = await createWorkspaceRoot();
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "auto");
    const collaboratorToken = await issueToken(base, hostToken, "collaborator");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    const patched = await fetch(`${base}/workspace/${WORKSPACE_ID}/config`, {
      method: "PATCH",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({ opencode: opencodeDocument([stallPattern]) }),
    });
    expect(patched.status).toBe(200);

    await expectListStaysResponsive(base, viewerToken);
  }, 20_000);

  test("a raw OpenCode config write must not stall the following MCP list", async () => {
    const workspaceRoot = await createWorkspaceRoot();
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "manual");
    const collaboratorToken = await issueToken(base, hostToken, "collaborator");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    const pending = fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config`, {
      method: "POST",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({
        scope: "project",
        content: `${JSON.stringify(opencodeDocument([stallPattern]), null, 2)}\n`,
      }),
    });
    const { approval } = await allowPendingWrite(base, hostToken, pending);
    expect(approval.action).toBe("config.write");

    await expectListStaysResponsive(base, viewerToken);
  }, 20_000);

  test("an imported workspace config must not stall the following MCP list", async () => {
    const workspaceRoot = await createWorkspaceRoot();
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "manual");
    const collaboratorToken = await issueToken(base, hostToken, "collaborator");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    const pending = fetch(`${base}/workspace/${WORKSPACE_ID}/import`, {
      method: "POST",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({ opencode: opencodeDocument([stallPattern]) }),
    });
    const { approval } = await allowPendingWrite(base, hostToken, pending);
    expect(approval.action).toBe("config.import");

    await expectListStaysResponsive(base, viewerToken);
  }, 20_000);

  test("a file-session write of opencode.jsonc must not stall the following MCP list", async () => {
    const workspaceRoot = await createWorkspaceRoot();
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "manual");
    const collaboratorToken = await issueToken(base, hostToken, "collaborator");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    const opened = await fetch(`${base}/workspace/${WORKSPACE_ID}/files/sessions`, {
      method: "POST",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({ write: true }),
    });
    expect(opened.status).toBe(200);
    const openedBody = (await opened.json()) as { session: { id: string } };

    const content = `${JSON.stringify(opencodeDocument([stallPattern]), null, 2)}\n`;
    const pending = fetch(`${base}/files/sessions/${openedBody.session.id}/write-batch`, {
      method: "POST",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({
        writes: [
          {
            path: "opencode.jsonc",
            contentBase64: Buffer.from(content, "utf8").toString("base64"),
            force: true,
          },
        ],
      }),
    });
    const { approval } = await allowPendingWrite(base, hostToken, pending);
    expect(approval.action).toBe("workspace.files.session.write");

    await expectListStaysResponsive(base, viewerToken);
  }, 20_000);

  test("a global OpenCode config write must not stall MCP listing for a workspace", async () => {
    const globalDir = join(homedir(), ".config", "opencode");
    const globalPath = join(globalDir, "opencode.jsonc");
    const workspaceRoot = await createWorkspaceRoot();
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "manual");
    const collaboratorToken = await issueToken(base, hostToken, "collaborator");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    try {
      const pending = fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config`, {
        method: "POST",
        headers: jsonHeaders(collaboratorToken),
        body: JSON.stringify({
          scope: "global",
          content: `${JSON.stringify(opencodeDocument([stallPattern]), null, 2)}\n`,
        }),
      });
      const { approval } = await allowPendingWrite(base, hostToken, pending);
      expect(approval.action).toBe("config.global.write");

      await expectListStaysResponsive(base, viewerToken);
    } finally {
      await rm(globalPath, { force: true });
      await rm(globalDir, { recursive: true, force: true });
    }
  }, 20_000);

  test("a workspace config file already on disk must not stall any route that lists MCP", async () => {
    const workspaceRoot = await createWorkspaceRoot();
    await plantConfig(workspaceRoot, [stallPattern]);
    const { base, hostToken } = startOpenworkServer(workspaceRoot, "manual");
    const collaboratorToken = await issueToken(base, hostToken, "collaborator");
    const viewerToken = await issueToken(base, hostToken, "viewer");

    const failures: string[] = [];
    const note = (label: string, ms: number, status: number) => {
      if (status !== 200 || ms >= RESPONSIVE_MS) {
        failures.push(`${label} status=${status} ms=${ms.toFixed(0)}`);
      }
    };

    const listedStarted = performance.now();
    const listed = await fetch(mcpUrl(base), { headers: auth(viewerToken) });
    note("GET /mcp", performance.now() - listedStarted, listed.status);

    const enabledStarted = performance.now();
    const enabled = fetch(mcpUrl(base, `/${MCP_NAME}/enabled`), {
      method: "POST",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({ enabled: false }),
    });
    const enabledResult = await allowPendingWrite(base, hostToken, enabled);
    note("POST /mcp/:name/enabled", performance.now() - enabledStarted, enabledResult.response.status);

    const addedStarted = performance.now();
    const added = fetch(mcpUrl(base), {
      method: "POST",
      headers: jsonHeaders(collaboratorToken),
      body: JSON.stringify({
        name: SECOND_MCP_NAME,
        config: { type: "remote", url: "https://example.com/notes" },
      }),
    });
    const addedResult = await allowPendingWrite(base, hostToken, added);
    note("POST /mcp", performance.now() - addedStarted, addedResult.response.status);

    const removedStarted = performance.now();
    const removed = fetch(mcpUrl(base, `/${SECOND_MCP_NAME}`), {
      method: "DELETE",
      headers: auth(collaboratorToken),
    });
    const removedResult = await allowPendingWrite(base, hostToken, removed);
    note("DELETE /mcp/:name", performance.now() - removedStarted, removedResult.response.status);

    expect(failures).toEqual([]);
  }, 60_000);
});
