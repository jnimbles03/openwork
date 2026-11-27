import { afterEach, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { startServer } from "./bootstrap/server.js";
import { createAppDependencies, type AppDependencies } from "./context/app-dependencies.js";
import { routePaths } from "./routes/route-paths.js";

/**
 * Spec for the default-auth and Host/Origin gaps.
 *
 * These tests describe the secure behavior. They fail while anonymous callers
 * can use host routes, and while a foreign Host or Origin is accepted.
 *
 * The session shell stand-in follows OpenCode v1.4.9
 * (packages/opencode/src/server/routes/instance/session.ts shell route,
 * packages/opencode/src/session/prompt.ts SessionPrompt.shellImpl, and
 * packages/opencode/src/agent/agent.ts native agent names). It spawns only
 * after the same agent/command/model checks that precede ChildProcess.spawn.
 *
 * Routes left to the shared guards, not called individually here:
 * session abort, share, unshare, summarize, prompt_async, init, fork, revert,
 * unrevert, messages, todos, status, snapshot, and events (all use
 * requireReadableWorkspace); file-session batch and operations, inbox,
 * artifacts, config, display name, and engine reload (all use readActorKey);
 * managed plugins, skills, router, cloud sign-in, and shared bundles (all use
 * requireVisible and the managed JSON parser). POST /system/runtime/upgrade,
 * POST /system/servers/connect, and dispose are not called because they
 * download, dial remote servers, or restart the runtime. GET /, GET
 * /system/health, and GET /openapi.json do not call the auth guards.
 */

const TOKEN_ENV_KEYS = [
  "OPENWORK_SERVER_V2_CLIENT_TOKEN",
  "OPENWORK_CLIENT_TOKEN",
  "OPENWORK_TOKEN",
  "OPENWORK_SERVER_V2_HOST_TOKEN",
  "OPENWORK_HOST_TOKEN",
] as const;

const PLACEHOLDER_HOST_TOKEN = "placeholder-host-token";
const NATIVE_AGENTS = new Set(["build", "plan", "general", "explore", "compaction", "title", "summary"]);
const MARKER = "workspace-secret-marker";

const savedEnv = new Map(TOKEN_ENV_KEYS.map((key) => [key, process.env[key]]));
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) {
      await cleanup();
    }
  }
  for (const key of TOKEN_ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
});

type HttpResult = { body: string; status: number };

function clearTokenEnv() {
  for (const key of TOKEN_ENV_KEYS) {
    delete process.env[key];
  }
}

function sendHttp(input: {
  body?: string;
  headers?: Record<string, string>;
  host: string;
  method?: string;
  origin?: string;
  path: string;
  port: number;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const payload = input.body ?? "";
    const req = httpRequest(
      {
        headers: {
          Host: input.host,
          ...(input.origin ? { Origin: input.origin } : {}),
          ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}),
          ...(input.headers ?? {}),
        },
        hostname: "127.0.0.1",
        method: input.method ?? "GET",
        path: input.path,
        port: input.port,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        response.on("end", () => {
          resolve({ body: Buffer.concat(chunks).toString("utf8"), status: response.statusCode ?? 0 });
        });
      },
    );
    req.on("error", reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

function readIncomingBody(request: IncomingMessage) {
  return new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    request.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    request.on("error", reject);
  });
}

function preferredShell() {
  const file = process.env.SHELL?.trim() ?? "";
  const base = path.basename(file).toLowerCase();
  if (file && base !== "fish" && base !== "nu") {
    return file;
  }
  return process.platform === "darwin" ? "/bin/zsh" : "/bin/bash";
}

function shellInvocation(shellPath: string, command: string) {
  const shellName = path.basename(shellPath).toLowerCase();
  const invocations: Record<string, string[]> = {
    bash: [
      "-l",
      "-c",
      `
              __oc_cwd=$PWD
              shopt -s expand_aliases
              [[ -f ~/.bashrc ]] && source ~/.bashrc >/dev/null 2>&1 || true
              cd "$__oc_cwd"
              eval ${JSON.stringify(command)}
            `,
    ],
    nu: ["-c", command],
    fish: ["-c", command],
    zsh: [
      "-l",
      "-c",
      `
              __oc_cwd=$PWD
              [[ -f ~/.zshenv ]] && source ~/.zshenv >/dev/null 2>&1 || true
              [[ -f "\${ZDOTDIR:-$HOME}/.zshrc" ]] && source "\${ZDOTDIR:-$HOME}/.zshrc" >/dev/null 2>&1 || true
              cd "$__oc_cwd"
              eval ${JSON.stringify(command)}
            `,
    ],
    "": ["-c", command],
  };
  return invocations[shellName] ?? invocations[""] ?? ["-c", command];
}

/**
 * Local stand-in for the OpenCode session API the product forwards to.
 * Shell execution matches prompt.ts shellImpl: require a native agent, a
 * command, and an explicit model (the build agent has no model), then spawn
 * the preferred shell. Requests that fail those checks do not spawn.
 */
async function startOpencodeStandIn() {
  const executed: string[] = [];
  const received: string[] = [];
  const server = createServer(async (request: IncomingMessage, response: ServerResponse) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    received.push(`${request.method} ${url.pathname}`);
    if (request.method === "POST" && url.pathname === "/session") {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ id: "ses_rebind" }));
      return;
    }

    const shellMatch = url.pathname.match(/^\/session\/([^/]+)\/shell$/);
    if (request.method === "POST" && shellMatch) {
      const raw = await readIncomingBody(request);
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(raw) as Record<string, unknown>;
      } catch {
        response.writeHead(400, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ message: "invalid json" }));
        return;
      }

      const agent = typeof body.agent === "string" ? body.agent : "";
      const command = typeof body.command === "string" ? body.command : "";
      const model = body.model && typeof body.model === "object" ? body.model as Record<string, unknown> : null;
      const directory = request.headers["x-opencode-directory"];
      const cwd = typeof directory === "string" ? decodeURIComponent(directory) : "";
      if (!NATIVE_AGENTS.has(agent) || !command || !model || typeof model.providerID !== "string" || typeof model.modelID !== "string" || !cwd) {
        response.writeHead(400, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ message: "shell input rejected before spawn" }));
        return;
      }

      const shellPath = preferredShell();
      executed.push(command);
      const exitCode = await new Promise<number>((resolve) => {
        const child = spawn(shellPath, shellInvocation(shellPath, command), {
          cwd,
          env: { ...process.env, TERM: "dumb" },
          stdio: "ignore",
        });
        const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
        child.once("exit", (code) => {
          clearTimeout(timer);
          resolve(code ?? 1);
        });
        child.once("error", () => {
          clearTimeout(timer);
          resolve(1);
        });
      });
      response.writeHead(exitCode === 0 ? 200 : 500, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ exitCode }));
      return;
    }

    response.writeHead(404, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ message: "not found" }));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("OpenCode stand-in did not bind a TCP port.");
  }

  return {
    executed,
    received,
    stop: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
    url: `http://127.0.0.1:${address.port}`,
  };
}

async function startHarness(options?: { hostToken?: string }) {
  clearTokenEnv();
  if (options?.hostToken) {
    process.env.OPENWORK_SERVER_V2_HOST_TOKEN = options.hostToken;
  }

  const root = mkdtempSync(path.join(tmpdir(), "openwork-server-v2-auth-"));
  const opencode = await startOpencodeStandIn();
  const dependencies = createAppDependencies({
    environment: "test",
    inMemory: true,
    legacy: {
      desktopDataDir: path.join(root, "desktop"),
      orchestratorDataDir: path.join(root, "orchestrator"),
    },
    runtime: { bootstrapPolicy: "disabled" },
    startedAt: new Date("2026-04-14T00:00:00.000Z"),
    version: "0.0.0-test",
    workingDirectory: root,
  });
  const runtime = dependencies.services.runtime;
  const originalHealth = runtime.getOpencodeHealth.bind(runtime);
  runtime.getOpencodeHealth = () => ({
    ...originalHealth(),
    baseUrl: opencode.url,
    running: true,
    status: "running",
  });

  const started = startServer({
    dependencies,
    host: "127.0.0.1",
    port: 0,
    silent: true,
  });
  const dataDir = path.join(root, "workspace");
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(path.join(dataDir, "NOTES.md"), `${MARKER}\n`, "utf8");
  const workspace = dependencies.persistence.registry.importLocalWorkspace({
    dataDir,
    displayName: "Local Project",
    status: "ready",
  });

  const harness = {
    dataDir,
    dependencies,
    opencode,
    port: started.port,
    root,
    server: started,
    workspaceId: workspace.id,
  };
  cleanups.push(async () => {
    await started.stop();
    await opencode.stop();
    rmSync(root, { force: true, recursive: true });
  });
  return harness;
}

function reboundHost(port: number) {
  return `rebinding.example:${port}`;
}

function loopbackHost(port: number) {
  return `127.0.0.1:${port}`;
}

function activeWorkspaceId(dependencies: AppDependencies) {
  const state = dependencies.persistence.repositories.serverRuntimeState.getByServerId(
    dependencies.persistence.registry.localServerId,
  );
  const health = state?.health;
  if (!health || typeof health !== "object") {
    return undefined;
  }
  const runtime = (health as { runtime?: { phase7?: { activeWorkspaceId?: string } } }).runtime;
  return runtime?.phase7?.activeWorkspaceId;
}

test("the bound server forwards the request Host header unchanged", async () => {
  const server = Bun.serve({
    fetch(request) {
      return new Response(request.headers.get("host") ?? "");
    },
    hostname: "127.0.0.1",
    port: 0,
  });
  try {
    const host = `rebinding.example:${server.port}`;
    const response = await sendHttp({ host, path: "/workspaces", port: server.port });
    expect(response.status).toBe(200);
    expect(response.body).toBe(host);
  } finally {
    server.stop(true);
  }
});

test("rejects anonymous workspace reads from a rebound host before returning data", async () => {
  const harness = await startHarness();
  const host = reboundHost(harness.port);
  const listed = await sendHttp({
    host,
    origin: `http://${host}`,
    path: "/workspaces",
    port: harness.port,
  });
  const hidden = await sendHttp({
    host,
    origin: `http://${host}`,
    path: "/workspaces?includeHidden=true",
    port: harness.port,
  });
  const servers = await sendHttp({
    host,
    origin: `http://${host}`,
    path: "/system/servers",
    port: harness.port,
  });
  const notes = await sendHttp({
    host,
    origin: `http://${host}`,
    path: `${routePaths.workspaces.simpleContent(harness.workspaceId)}?path=NOTES.md`,
    port: harness.port,
  });

  expect(listed.status).toBe(401);
  expect(hidden.status).toBe(401);
  expect(servers.status).toBe(401);
  expect(notes.status).toBe(401);
  expect(listed.body.includes("Local Project")).toBe(false);
  expect(notes.body.includes(MARKER)).toBe(false);
  expect(servers.body.includes("srv_")).toBe(false);
});

test("rejects anonymous workspace creation, activation, and deletion before those side effects", async () => {
  const harness = await startHarness();
  const host = reboundHost(harness.port);
  const folderPath = path.join(harness.root, "should-not-be-created");
  const created = await sendHttp({
    body: JSON.stringify({ folderPath, name: "Created by caller" }),
    headers: { "Content-Type": "application/json" },
    host,
    method: "POST",
    origin: `http://${host}`,
    path: routePaths.workspaces.createLocal,
    port: harness.port,
  });
  const activated = await sendHttp({
    headers: { "Content-Type": "application/json" },
    host,
    method: "POST",
    origin: `http://${host}`,
    path: routePaths.workspaces.activate(harness.workspaceId),
    port: harness.port,
  });
  const deleted = await sendHttp({
    host,
    method: "DELETE",
    origin: `http://${host}`,
    path: routePaths.workspaces.byId(harness.workspaceId),
    port: harness.port,
  });

  expect(created.status).toBe(401);
  expect(activated.status).toBe(401);
  expect(deleted.status).toBe(401);
  expect(existsSync(folderPath)).toBe(false);
  expect(existsSync(path.join(folderPath, ".opencode"))).toBe(false);
  expect(activeWorkspaceId(harness.dependencies)).toBeUndefined();
  expect(harness.dependencies.persistence.repositories.workspaces.getById(harness.workspaceId)?.id).toBe(harness.workspaceId);
});

test("rejects an anonymous rebound session shell before the runtime spawns a command", async () => {
  const harness = await startHarness();
  const host = reboundHost(harness.port);
  const markerPath = path.join(harness.dataDir, "shell-marker.txt");
  const created = await sendHttp({
    body: JSON.stringify({ title: "rebound" }),
    headers: { "Content-Type": "application/json" },
    host,
    method: "POST",
    origin: `http://${host}`,
    path: routePaths.workspaces.sessions.base(harness.workspaceId),
    port: harness.port,
  });
  const sessionId = created.status === 200 ? JSON.parse(created.body).data.id as string : "ses_unused";
  const shell = await sendHttp({
    body: JSON.stringify({
      agent: "build",
      command: `printf exposed > ${markerPath}`,
      model: { modelID: "placeholder-model", providerID: "placeholder-provider" },
    }),
    headers: { "Content-Type": "application/json" },
    host,
    method: "POST",
    origin: `http://${host}`,
    path: routePaths.workspaces.sessions.shell(sessionId, harness.workspaceId),
    port: harness.port,
  });

  expect(created.status).toBe(401);
  expect(shell.status).toBe(401);
  expect(harness.opencode.executed).toEqual([]);
  expect(harness.opencode.received.filter((entry) => entry.startsWith("POST /session"))).toEqual([]);
  expect(existsSync(markerPath)).toBe(false);
});

test("rejects the same anonymous shell call when it targets the loopback Host directly", async () => {
  const harness = await startHarness();
  const host = loopbackHost(harness.port);
  const markerPath = path.join(harness.dataDir, "shell-marker.txt");
  const shell = await sendHttp({
    body: JSON.stringify({
      agent: "build",
      command: `printf exposed > ${markerPath}`,
      model: { modelID: "placeholder-model", providerID: "placeholder-provider" },
    }),
    headers: { "Content-Type": "application/json" },
    host,
    method: "POST",
    path: routePaths.workspaces.sessions.shell("ses_unused", harness.workspaceId),
    port: harness.port,
  });

  expect(shell.status).toBe(401);
  expect(harness.opencode.executed).toEqual([]);
  expect(existsSync(markerPath)).toBe(false);
});

test("rejects anonymous MCP registration from a rebound host before saving the command", async () => {
  const harness = await startHarness();
  const host = reboundHost(harness.port);
  const response = await sendHttp({
    body: JSON.stringify({
      config: { command: ["placeholder-mcp-bin"], type: "local" },
      name: "rebindmcp",
    }),
    headers: { "Content-Type": "application/json" },
    host,
    method: "POST",
    origin: `http://${host}`,
    path: routePaths.workspaces.mcp(harness.workspaceId),
    port: harness.port,
  });

  expect(response.status).toBe(401);
  expect(harness.dependencies.services.managed.listWorkspaceMcp(harness.workspaceId)).toEqual([]);
  expect(JSON.stringify(walkFiles(harness.dataDir)).includes("placeholder-mcp-bin")).toBe(false);
});

test("rejects a valid host token when the Host header is not the bound loopback name", async () => {
  const harness = await startHarness({ hostToken: PLACEHOLDER_HOST_TOKEN });
  const host = reboundHost(harness.port);
  const folderPath = path.join(harness.root, "token-foreign-host");
  const response = await sendHttp({
    body: JSON.stringify({ folderPath, name: "Foreign host" }),
    headers: {
      "Content-Type": "application/json",
      "X-OpenWork-Host-Token": PLACEHOLDER_HOST_TOKEN,
    },
    host,
    method: "POST",
    path: routePaths.workspaces.createLocal,
    port: harness.port,
  });

  expect(response.status).toBe(403);
  expect(existsSync(folderPath)).toBe(false);
});

test("rejects a valid host token when the browser Origin is not allowed", async () => {
  const harness = await startHarness({ hostToken: PLACEHOLDER_HOST_TOKEN });
  const host = loopbackHost(harness.port);
  const folderPath = path.join(harness.root, "token-foreign-origin");
  const response = await sendHttp({
    body: JSON.stringify({ folderPath, name: "Foreign origin" }),
    headers: {
      "Content-Type": "application/json",
      Origin: "http://rebinding.example",
      "X-OpenWork-Host-Token": PLACEHOLDER_HOST_TOKEN,
    },
    host,
    method: "POST",
    path: routePaths.workspaces.createLocal,
    port: harness.port,
  });

  expect(response.status).toBe(403);
  expect(existsSync(folderPath)).toBe(false);
});

test("rejects a managed write whose body is not application/json before saving it", async () => {
  const harness = await startHarness({ hostToken: PLACEHOLDER_HOST_TOKEN });
  const host = loopbackHost(harness.port);
  const response = await sendHttp({
    body: JSON.stringify({
      config: { command: ["placeholder-mcp-bin"], type: "local" },
      name: "plaintextmcp",
    }),
    headers: {
      "Content-Type": "text/plain",
      "X-OpenWork-Host-Token": PLACEHOLDER_HOST_TOKEN,
    },
    host,
    method: "POST",
    path: routePaths.workspaces.mcp(harness.workspaceId),
    port: harness.port,
  });

  expect(response.status).toBe(415);
  expect(harness.dependencies.services.managed.listWorkspaceMcp(harness.workspaceId)).toEqual([]);
});

test("still serves a loopback request that presents the host token and no browser Origin", async () => {
  const harness = await startHarness({ hostToken: PLACEHOLDER_HOST_TOKEN });
  const response = await sendHttp({
    headers: { "X-OpenWork-Host-Token": PLACEHOLDER_HOST_TOKEN },
    host: loopbackHost(harness.port),
    path: "/workspaces",
    port: harness.port,
  });

  expect(response.status).toBe(200);
  expect(response.body.includes("Local Project")).toBe(true);
});

function walkFiles(directory: string): string[] {
  if (!existsSync(directory)) {
    return [];
  }
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...walkFiles(absolute));
      continue;
    }
    if (entry.isFile() && statSync(absolute).size < 1_000_000) {
      files.push(readFileSync(absolute, "utf8"));
    }
  }
  return files;
}
