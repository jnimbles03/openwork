import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

import { startServer } from "./server.js";
import type { ServerConfig, WorkspaceInfo } from "./types.js";

type Served = {
  port: number;
  stop: (closeActiveConnections?: boolean) => void | Promise<void>;
};

const WORKSPACE_MARKER = "workspace-only-marker";
const OUTSIDE_MARKER = "outside-only-marker";
const NEUTRAL_MARKER = "neutral-cwd-marker";
const WORKSPACE_SEARCH = "workspace-search-marker";
const OUTSIDE_SEARCH = "outside-search-marker";
const WORKSPACE_CONFIG = "workspace-config-marker";
const OUTSIDE_CONFIG = "outside-config-marker";
const WORKSPACE_FILE = "only-workspace.txt";
const OUTSIDE_FILE = "only-outside.txt";
const STATUS_FILE = "outside-status.txt";
const OPENCODE_PASSWORD = "placeholder-opencode-password";

const previousTokenStore = process.env.OPENWORK_TOKEN_STORE;

let root = "";
let workspaceRoot = "";
let outsideRoot = "";
let neutralRoot = "";
let openworkBase = "";
let viewerToken = "";
const stops: Array<() => Promise<void>> = [];

function resolveOpencodeBin(): string {
  const fromEnv = process.env.OPENCODE_BIN?.trim();
  const found = fromEnv || Bun.which("opencode");
  if (!found) {
    throw new Error(
      "OPENCODE_BIN is not set and opencode is not on PATH. Install opencode-ai@1.4.9 and point OPENCODE_BIN at its bin/opencode.",
    );
  }
  // The npm launcher is a Node wrapper that spawnSyncs the real binary. Signal the binary itself
  // so the test can stop the server it started.
  const real = join(dirname(found), ".opencode");
  return existsSync(real) ? real : found;
}

async function writeMarkers(dir: string, marker: string, search: string, configName: string, uniqueFile: string) {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "marker.txt"), `${marker}\n`, "utf8");
  await writeFile(join(dir, "search.txt"), `${search}\n`, "utf8");
  await writeFile(join(dir, uniqueFile), `${uniqueFile}\n`, "utf8");
  await writeFile(
    join(dir, "opencode.json"),
    JSON.stringify({ $schema: "https://opencode.ai/config.json", username: configName }, null, 2) + "\n",
    "utf8",
  );
}

function initOutsideGit(dir: string) {
  const gitEnv = {
    ...process.env,
    GIT_AUTHOR_NAME: "OpenWork Test",
    GIT_AUTHOR_EMAIL: "openwork-test@example.com",
    GIT_COMMITTER_NAME: "OpenWork Test",
    GIT_COMMITTER_EMAIL: "openwork-test@example.com",
  };
  const run = (args: string[]) => {
    const result = spawnSync("git", args, { cwd: dir, env: gitEnv, encoding: "utf8" });
    if (result.status !== 0) {
      throw new Error(`git ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
    }
  };
  run(["init"]);
  run(["add", STATUS_FILE]);
  run(["commit", "-m", "status fixture"]);
}

async function startOpencode(input: { home: string; port: number; password?: string }) {
  const home = input.home;
  await mkdir(join(home, ".config"), { recursive: true });
  await mkdir(join(home, ".local", "share"), { recursive: true });
  await mkdir(join(home, ".local", "state"), { recursive: true });
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (typeof value === "string") env[key] = value;
  }
  env.HOME = home;
  env.XDG_CONFIG_HOME = join(home, ".config");
  env.XDG_DATA_HOME = join(home, ".local", "share");
  env.XDG_STATE_HOME = join(home, ".local", "state");
  if (input.password) {
    env.OPENCODE_SERVER_USERNAME = "opencode";
    env.OPENCODE_SERVER_PASSWORD = input.password;
  } else {
    delete env.OPENCODE_SERVER_PASSWORD;
    delete env.OPENCODE_SERVER_USERNAME;
  }

  const proc = Bun.spawn([resolveOpencodeBin(), "serve", "--hostname", "127.0.0.1", "--port", String(input.port)], {
    cwd: neutralRoot,
    env,
    stdout: "pipe",
    stderr: "pipe",
  });
  stops.push(async () => {
    proc.kill();
    await Promise.race([proc.exited, new Promise((resolve) => setTimeout(resolve, 2000))]);
  });

  void drain(proc.stdout.getReader());
  void drain(proc.stderr.getReader());

  const base = `http://127.0.0.1:${input.port}`;
  const deadline = Date.now() + 60_000;
  let exitCode: number | null = null;
  const exited = proc.exited.then((code) => {
    exitCode = code;
  });
  while (Date.now() < deadline && exitCode === null) {
    try {
      const response = await fetch(base, { signal: AbortSignal.timeout(500) });
      await response.arrayBuffer();
      return base;
    } catch {
      await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 100))]);
    }
  }
  throw new Error(`OpenCode did not listen on ${input.port} (exit ${exitCode ?? "running"})`);
}

async function drain(reader: ReadableStreamDefaultReader<Uint8Array>) {
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) return;
    }
  } catch {
    // The process is shutting down.
  }
}

function workspace(input: {
  id: string;
  path: string;
  baseUrl: string;
  workspaceType: WorkspaceInfo["workspaceType"];
  password?: string;
}): WorkspaceInfo {
  return {
    id: input.id,
    name: input.id,
    path: input.path,
    preset: "starter",
    workspaceType: input.workspaceType,
    baseUrl: input.baseUrl,
    ...(input.password
      ? { opencodeUsername: "opencode", opencodePassword: input.password }
      : {}),
  };
}

function viewer(extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set("authorization", `Bearer ${viewerToken}`);
  return headers;
}

function contentUrl(mount: string, directory?: string | string[]) {
  const url = new URL(`${openworkBase}${mount}/file/content`);
  url.searchParams.set("path", "marker.txt");
  if (Array.isArray(directory)) {
    for (const value of directory) url.searchParams.append("directory", value);
  } else if (directory !== undefined) {
    url.searchParams.set("directory", directory);
  }
  return url;
}

async function readProxy(url: URL, headers: Headers) {
  const response = await fetch(url, { headers });
  const text = await response.text();
  return { status: response.status, text };
}

function expectWorkspaceMarker(result: { status: number; text: string }) {
  expect(result.status).toBe(200);
  expect(result.text).toContain(WORKSPACE_MARKER);
  expect(result.text).not.toContain(OUTSIDE_MARKER);
  expect(result.text).not.toContain(outsideRoot);
}

beforeAll(async () => {
  root = await mkdtemp(join(tmpdir(), "openwork-directory-boundary-"));
  workspaceRoot = join(root, "workspace");
  outsideRoot = join(root, "outside");
  neutralRoot = join(root, "neutral");
  await writeMarkers(workspaceRoot, WORKSPACE_MARKER, WORKSPACE_SEARCH, WORKSPACE_CONFIG, WORKSPACE_FILE);
  await writeMarkers(outsideRoot, OUTSIDE_MARKER, OUTSIDE_SEARCH, OUTSIDE_CONFIG, OUTSIDE_FILE);
  await writeFile(join(outsideRoot, STATUS_FILE), "status-line\n", "utf8");
  initOutsideGit(outsideRoot);
  await writeFile(join(outsideRoot, STATUS_FILE), "status-line-changed\n", "utf8");
  await mkdir(join(workspaceRoot, ".opencode"), { recursive: true });
  await symlink(outsideRoot, join(workspaceRoot, "linked-outside"), "dir");
  await writeMarkers(neutralRoot, NEUTRAL_MARKER, "neutral-search", "neutral-config", "only-neutral.txt");

  const tokenStore = join(root, "tokens.json");
  process.env.OPENWORK_TOKEN_STORE = tokenStore;

  const openBase = await startOpencode({ home: join(root, "opencode-home"), port: 43111 });
  const authBase = await startOpencode({
    home: join(root, "opencode-auth-home"),
    port: 43112,
    password: OPENCODE_PASSWORD,
  });

  const config: ServerConfig = {
    host: "127.0.0.1",
    port: 0,
    token: "owt_test_client",
    hostToken: "owt_test_host",
    configPath: join(root, "server.json"),
    approval: { mode: "auto", timeoutMs: 1000 },
    corsOrigins: ["*"],
    workspaces: [
      workspace({ id: "ws_local", path: workspaceRoot, baseUrl: openBase, workspaceType: "local" }),
      workspace({ id: "ws_remote", path: workspaceRoot, baseUrl: openBase, workspaceType: "remote" }),
      workspace({
        id: "ws_auth",
        path: workspaceRoot,
        baseUrl: authBase,
        workspaceType: "local",
        password: OPENCODE_PASSWORD,
      }),
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
  stops.push(async () => {
    await server.stop(true);
  });
  openworkBase = `http://127.0.0.1:${server.port}`;

  const issued = await fetch(`${openworkBase}/tokens`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-openwork-host-token": config.hostToken,
    },
    body: JSON.stringify({ scope: "viewer", label: "boundary" }),
  });
  expect(issued.status).toBe(201);
  const body = (await issued.json()) as { token?: string; scope?: string };
  expect(body.scope).toBe("viewer");
  if (!body.token) throw new Error("viewer token was not issued");
  viewerToken = body.token;
}, 90_000);

afterAll(async () => {
  if (previousTokenStore === undefined) delete process.env.OPENWORK_TOKEN_STORE;
  else process.env.OPENWORK_TOKEN_STORE = previousTokenStore;
  while (stops.length) {
    await stops.pop()?.();
  }
  if (root) await rm(root, { recursive: true, force: true });
});

describe("opencode proxy directory boundary", () => {
  test("reads the workspace when the viewer does not choose a directory", async () => {
    const result = await readProxy(contentUrl("/opencode"), viewer());
    expectWorkspaceMarker(result);
  });

  test("rejects a viewer with no bearer token", async () => {
    const result = await readProxy(contentUrl("/opencode"), new Headers());
    expect(result.status).toBe(401);
    expect(result.text).not.toContain(OUTSIDE_MARKER);
    expect(result.text).not.toContain(WORKSPACE_MARKER);
  });

  test("rejects a viewer write through the proxy", async () => {
    const response = await fetch(`${openworkBase}/opencode/file/content`, {
      method: "POST",
      headers: viewer({ "content-type": "application/json" }),
      body: JSON.stringify({ path: "marker.txt" }),
    });
    expect(response.status).toBe(403);
    expect(await response.text()).not.toContain(OUTSIDE_MARKER);
  });

  test("ignores a viewer x-opencode-directory on the unmounted proxy", async () => {
    const result = await readProxy(contentUrl("/opencode"), viewer({ "x-opencode-directory": outsideRoot }));
    expectWorkspaceMarker(result);
  });

  test("ignores a viewer directory query on the unmounted proxy", async () => {
    const result = await readProxy(contentUrl("/opencode", outsideRoot), viewer());
    expectWorkspaceMarker(result);
  });

  test("ignores a viewer x-opencode-directory on the mounted proxy", async () => {
    const result = await readProxy(
      contentUrl("/w/ws_local/opencode"),
      viewer({ "x-opencode-directory": outsideRoot }),
    );
    expectWorkspaceMarker(result);
  });

  test("ignores a viewer directory query on the mounted proxy", async () => {
    const result = await readProxy(contentUrl("/w/ws_local/opencode", outsideRoot), viewer());
    expectWorkspaceMarker(result);
  });

  test("ignores a percent-encoded directory header", async () => {
    const result = await readProxy(
      contentUrl("/opencode"),
      viewer({ "x-opencode-directory": encodeURIComponent(outsideRoot) }),
    );
    expectWorkspaceMarker(result);
  });

  test("ignores a directory query that is still encoded after one decode", async () => {
    const result = await readProxy(contentUrl("/w/ws_local/opencode", encodeURIComponent(outsideRoot)), viewer());
    expectWorkspaceMarker(result);
  });

  test("ignores an outside directory query even when the header names a different outside path", async () => {
    const other = join(root, "missing-outside");
    const result = await readProxy(
      contentUrl("/opencode", outsideRoot),
      viewer({ "x-opencode-directory": other }),
    );
    expectWorkspaceMarker(result);
  });

  test("ignores a directory that escapes the workspace with ..", async () => {
    const traversal = `${workspaceRoot}/../${basename(outsideRoot)}`;
    const result = await readProxy(contentUrl("/opencode"), viewer({ "x-opencode-directory": traversal }));
    expectWorkspaceMarker(result);
  });

  test("ignores a workspace symlink whose real path is outside the workspace", async () => {
    const link = join(workspaceRoot, "linked-outside");
    const result = await readProxy(contentUrl("/w/ws_local/opencode"), viewer({ "x-opencode-directory": link }));
    expectWorkspaceMarker(result);
  });

  test("ignores repeated directory query parameters", async () => {
    const result = await readProxy(contentUrl("/opencode", [outsideRoot, workspaceRoot]), viewer());
    expectWorkspaceMarker(result);
  });

  test("lists the workspace when the viewer sets directory", async () => {
    const url = new URL(`${openworkBase}/opencode/file`);
    url.searchParams.set("path", ".");
    url.searchParams.set("directory", outsideRoot);
    const result = await readProxy(url, viewer({ "x-opencode-directory": outsideRoot }));
    expect(result.status).toBe(200);
    expect(result.text).toContain(WORKSPACE_FILE);
    expect(result.text).not.toContain(OUTSIDE_FILE);
    expect(result.text).not.toContain(outsideRoot);
    expect(result.text).toContain(workspaceRoot);
  });

  test("searches the workspace when the viewer does not choose a directory", async () => {
    const text = new URL(`${openworkBase}/opencode/find`);
    text.searchParams.set("pattern", WORKSPACE_SEARCH);
    const textResult = await readProxy(text, viewer());
    expect(textResult.status).toBe(200);
    expect(textResult.text).toContain(WORKSPACE_SEARCH);

    const files = new URL(`${openworkBase}/opencode/find/file`);
    files.searchParams.set("query", WORKSPACE_FILE);
    const fileResult = await readProxy(files, viewer());
    expect(fileResult.status).toBe(200);
    expect(fileResult.text).toContain(WORKSPACE_FILE);
  });

  test("searches text in the workspace when the viewer sets directory", async () => {
    const outsideUrl = new URL(`${openworkBase}/opencode/find`);
    outsideUrl.searchParams.set("pattern", OUTSIDE_SEARCH);
    outsideUrl.searchParams.set("directory", outsideRoot);
    const outside = await readProxy(outsideUrl, viewer({ "x-opencode-directory": outsideRoot }));
    expect(outside.status).toBe(200);
    expect(outside.text).not.toContain(OUTSIDE_SEARCH);

    const url = new URL(`${openworkBase}/w/ws_local/opencode/find`);
    url.searchParams.set("pattern", WORKSPACE_SEARCH);
    url.searchParams.set("directory", outsideRoot);
    const result = await readProxy(url, viewer({ "x-opencode-directory": outsideRoot }));
    expect(result.status).toBe(200);
    expect(result.text).toContain(WORKSPACE_SEARCH);
  });

  test("searches file names in the workspace when the viewer sets directory", async () => {
    const outsideUrl = new URL(`${openworkBase}/w/ws_local/opencode/find/file`);
    outsideUrl.searchParams.set("query", OUTSIDE_FILE);
    outsideUrl.searchParams.set("directory", outsideRoot);
    const outside = await readProxy(outsideUrl, viewer({ "x-opencode-directory": outsideRoot }));
    expect(outside.status).toBe(200);
    expect(outside.text).not.toContain(OUTSIDE_FILE);

    const url = new URL(`${openworkBase}/opencode/find/file`);
    url.searchParams.set("query", WORKSPACE_FILE);
    url.searchParams.set("directory", outsideRoot);
    const result = await readProxy(url, viewer({ "x-opencode-directory": outsideRoot }));
    expect(result.status).toBe(200);
    expect(result.text).toContain(WORKSPACE_FILE);
  });

  test("reads workspace config when the viewer sets directory", async () => {
    const url = new URL(`${openworkBase}/w/ws_local/opencode/config`);
    url.searchParams.set("directory", outsideRoot);
    const result = await readProxy(url, viewer({ "x-opencode-directory": outsideRoot }));
    expect(result.status).toBe(200);
    expect(result.text).toContain(WORKSPACE_CONFIG);
    expect(result.text).not.toContain(OUTSIDE_CONFIG);
  });

  test("reads workspace git status when the viewer sets directory", async () => {
    const url = new URL(`${openworkBase}/opencode/file/status`);
    url.searchParams.set("directory", outsideRoot);
    const result = await readProxy(url, viewer({ "x-opencode-directory": outsideRoot }));
    expect(result.status).toBe(200);
    expect(result.text).not.toContain(STATUS_FILE);
    expect(result.text).not.toContain(outsideRoot);
  });

  test("ignores a client directory for a remote workspace that has no server directory", async () => {
    const result = await readProxy(
      contentUrl("/w/ws_remote/opencode"),
      viewer({ "x-opencode-directory": outsideRoot }),
    );
    expect(result.status).toBe(200);
    expect(result.text).not.toContain(OUTSIDE_MARKER);
    expect(result.text).not.toContain(outsideRoot);
    expect(result.text.includes(WORKSPACE_MARKER) || result.text.includes(NEUTRAL_MARKER)).toBe(true);
  });

  test("ignores a client directory when the proxy authenticates to OpenCode", async () => {
    const result = await readProxy(
      contentUrl("/w/ws_auth/opencode", outsideRoot),
      viewer({ "x-opencode-directory": outsideRoot }),
    );
    expectWorkspaceMarker(result);
  });
});
