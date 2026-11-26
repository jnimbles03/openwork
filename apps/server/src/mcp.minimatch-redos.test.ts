import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir, homedir } from "node:os";
import { join } from "node:path";

import { listMcp } from "./mcp.js";
import { startServer } from "./server.js";
import type { ServerConfig } from "./types.js";

// Bun caches os.homedir() on its first call and ignores later HOME changes,
// and that first call happens while this file is imported. Launch it as:
//   home=$(mktemp -d)
//   HOME="$home" OPENWORK_MINIMATCH_TEST_HOME="$home" \
//     OPENWORK_TOKEN_STORE="$home/tokens.json" \
//     bun test src/mcp.minimatch-redos.test.ts
// Global OpenCode config is read from that directory.

// Nested *() / +() extglobs in minimatch 10.1.1 compile to regexes with nested
// unbounded quantifiers. listMcp feeds tools.deny patterns to minimatch() with
// default options (extglob on) and tests them against candidates such as
// `mcp.<name>` and `mcp.<name>.*`. The body has to be able to consume that
// prefix; a trailing character outside the body is what forces the backtrack.
// A following "*" matches only after that check returns, so disabledByTools
// is set only once the nested pattern has been evaluated.
const NESTED_STAR = "*(*(*(a|b|c|m|p|.)))";
const NESTED_PLUS = "+(+(+(a|b|c|m|p|.)))";
// Matches every mcp.* candidate in linear time, and only after the nested
// pattern has already returned false. disabledByTools stays true once listing finishes.
const CONFIRMING_PATTERN = "*";
const BUDGET_MS = 500;
const COLLABORATOR_TOKEN = "owt_collaborator_placeholder";
const HOST_TOKEN = "owt_host_placeholder";

type Served = {
  port: number;
  stop: (closeActiveConnections?: boolean) => void | Promise<void>;
};

type McpList = { items: Array<{ name: string; disabledByTools?: boolean }> };

const stops: Array<() => void | Promise<void>> = [];
const dirs: string[] = [];

// Seed must be drawn from the extglob body (a, b, c, m, p). Any other
// character fails the candidate at `mcp.<seed>` and returns immediately.
function slowName(seed: string): string {
  return `${seed}${"a".repeat(16)}x`;
}

function opencodeConfig(pattern: string, names: string[]): Record<string, unknown> {
  const mcp: Record<string, unknown> = {};
  for (const name of names) {
    mcp[name] = { type: "remote", url: "http://127.0.0.1/mcp" };
  }
  return {
    tools: { deny: [pattern, CONFIRMING_PATTERN] },
    mcp,
  };
}

async function writeWorkspaceConfig(workspaceRoot: string, pattern: string, names: string[]): Promise<void> {
  await writeFile(join(workspaceRoot, "opencode.jsonc"), `${JSON.stringify(opencodeConfig(pattern, names), null, 2)}\n`, "utf8");
}

async function makeWorkspace(): Promise<string> {
  const workspaceRoot = await mkdtemp(join(tmpdir(), "openwork-minimatch-ws-"));
  dirs.push(workspaceRoot);
  return workspaceRoot;
}

function boot(workspaceRoot: string): { base: string; token: string } {
  const config: ServerConfig = {
    host: "127.0.0.1",
    port: 0,
    token: COLLABORATOR_TOKEN,
    hostToken: HOST_TOKEN,
    approval: { mode: "auto", timeoutMs: 1000 },
    corsOrigins: ["*"],
    workspaces: [
      {
        id: "ws_minimatch",
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
  return { base: `http://127.0.0.1:${server.port}`, token: config.token };
}

function auth(token: string): HeadersInit {
  return { authorization: `Bearer ${token}`, "content-type": "application/json" };
}

async function issueViewer(base: string): Promise<string> {
  const issued = await fetch(`${base}/tokens`, {
    method: "POST",
    headers: { "x-openwork-host-token": HOST_TOKEN, "content-type": "application/json" },
    body: JSON.stringify({ scope: "viewer", label: "viewer placeholder" }),
  });
  expect(issued.status).toBe(201);
  const body = (await issued.json()) as { token: string };
  return body.token;
}

async function expectListedWithinBudget(run: () => Promise<Response>, names: string[]): Promise<void> {
  const started = Date.now();
  const response = await run();
  const elapsed = Date.now() - started;
  expect(response.status).toBe(200);
  const body = (await response.json()) as McpList;
  for (const name of names) {
    const item = body.items.find((entry) => entry.name === name);
    expect(item).toBeDefined();
    expect(item?.disabledByTools).toBe(true);
  }
  expect(elapsed).toBeLessThan(BUDGET_MS);
}

function homeDir(): string {
  const home = homedir();
  if (!home || process.env.OPENWORK_MINIMATCH_TEST_HOME !== home) {
    throw new Error(
      "Refusing to run: set HOME and OPENWORK_MINIMATCH_TEST_HOME to the same disposable directory before starting bun",
    );
  }
  return home;
}

beforeEach(() => {
  homeDir();
});

afterEach(async () => {
  while (stops.length) {
    await stops.pop()?.();
  }
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
  rmSync(join(homeDir(), ".config"), { recursive: true, force: true });
});

describe.serial("minimatch nested extglob deny patterns", () => {
  test("workspace config file: nested *() deny does not stall listMcp", async () => {
    const workspaceRoot = await makeWorkspace();
    const names = [slowName("a"), slowName("b")];
    await writeWorkspaceConfig(workspaceRoot, NESTED_STAR, names);

    const started = Date.now();
    const items = await listMcp(workspaceRoot);
    const elapsed = Date.now() - started;

    for (const name of names) {
      const item = items.find((entry) => entry.name === name);
      expect(item?.source).toBe("config.project");
      expect(item?.disabledByTools).toBe(true);
    }
    expect(elapsed).toBeLessThan(BUDGET_MS);
  }, 20_000);

  test("workspace config file: nested +() deny does not stall listMcp", async () => {
    const workspaceRoot = await makeWorkspace();
    const names = [slowName("c"), slowName("m")];
    await writeWorkspaceConfig(workspaceRoot, NESTED_PLUS, names);

    const started = Date.now();
    const items = await listMcp(workspaceRoot);
    const elapsed = Date.now() - started;

    for (const name of names) {
      expect(items.find((entry) => entry.name === name)?.disabledByTools).toBe(true);
    }
    expect(elapsed).toBeLessThan(BUDGET_MS);
  }, 20_000);

  test("global config file: nested *() deny does not stall listMcp", async () => {
    const workspaceRoot = await makeWorkspace();
    const names = [slowName("p"), slowName("aa")];
    const globalDir = join(homeDir(), ".config", "opencode");
    mkdirSync(globalDir, { recursive: true });
    await writeFile(join(globalDir, "opencode.jsonc"), `${JSON.stringify(opencodeConfig(NESTED_STAR, names), null, 2)}\n`, "utf8");

    const started = Date.now();
    const items = await listMcp(workspaceRoot);
    const elapsed = Date.now() - started;

    for (const name of names) {
      const item = items.find((entry) => entry.name === name);
      expect(item?.source).toBe("config.global");
      expect(item?.disabledByTools).toBe(true);
    }
    expect(elapsed).toBeLessThan(BUDGET_MS);
  }, 20_000);

  test("collaborator config PATCH then viewer MCP list does not stall", async () => {
    const workspaceRoot = await makeWorkspace();
    const { base, token } = boot(workspaceRoot);
    const viewer = await issueViewer(base);
    const names = [slowName("ab"), slowName("ac")];

    const patched = await fetch(`${base}/workspace/ws_minimatch/config`, {
      method: "PATCH",
      headers: auth(token),
      body: JSON.stringify({ opencode: opencodeConfig(NESTED_STAR, names) }),
    });
    expect(patched.status).toBe(200);

    await expectListedWithinBudget(
      () => fetch(`${base}/workspace/ws_minimatch/mcp`, { headers: auth(viewer) }),
      names,
    );
  }, 20_000);

  test("collaborator global opencode-config write then viewer MCP list does not stall", async () => {
    const workspaceRoot = await makeWorkspace();
    const { base, token } = boot(workspaceRoot);
    const viewer = await issueViewer(base);
    const names = [slowName("am"), slowName("ap")];

    const written = await fetch(`${base}/workspace/ws_minimatch/opencode-config`, {
      method: "POST",
      headers: auth(token),
      body: JSON.stringify({
        scope: "global",
        content: JSON.stringify(opencodeConfig(NESTED_STAR, names)),
      }),
    });
    expect(written.status).toBe(200);

    await expectListedWithinBudget(
      () => fetch(`${base}/workspace/ws_minimatch/mcp`, { headers: auth(viewer) }),
      names,
    );
  }, 20_000);

  test("POST /mcp still lists through the nested deny pattern without stalling", async () => {
    const workspaceRoot = await makeWorkspace();
    const names = [slowName("ba"), slowName("bb")];
    await writeWorkspaceConfig(workspaceRoot, NESTED_STAR, names);
    const { base, token } = boot(workspaceRoot);

    await expectListedWithinBudget(
      () =>
        fetch(`${base}/workspace/ws_minimatch/mcp`, {
          method: "POST",
          headers: auth(token),
          body: JSON.stringify({
            name: "added-remote",
            config: { type: "remote", url: "http://127.0.0.1/mcp" },
          }),
        }),
      names,
    );
  }, 20_000);

  test("DELETE /mcp still lists through the nested deny pattern without stalling", async () => {
    const workspaceRoot = await makeWorkspace();
    const kept = slowName("bc");
    const removed = slowName("bm");
    await writeWorkspaceConfig(workspaceRoot, NESTED_STAR, [kept, removed]);
    const { base, token } = boot(workspaceRoot);

    await expectListedWithinBudget(
      () =>
        fetch(`${base}/workspace/ws_minimatch/mcp/${removed}`, {
          method: "DELETE",
          headers: auth(token),
        }),
      [kept],
    );
  }, 20_000);

  test("POST /mcp/:name/enabled still lists through the nested deny pattern without stalling", async () => {
    const workspaceRoot = await makeWorkspace();
    const names = [slowName("bp"), slowName("ca")];
    await writeWorkspaceConfig(workspaceRoot, NESTED_PLUS, names);
    const { base, token } = boot(workspaceRoot);

    await expectListedWithinBudget(
      () =>
        fetch(`${base}/workspace/ws_minimatch/mcp/${names[0]}/enabled`, {
          method: "POST",
          headers: auth(token),
          body: JSON.stringify({ enabled: false }),
        }),
      names,
    );
  }, 20_000);
});
