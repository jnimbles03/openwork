import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterAll, expect, test } from "bun:test";

const repoRoot = dirname(dirname(dirname(fileURLToPath(import.meta.url))));
const entrypoint = join(repoRoot, "packaging/docker/microsandbox-entrypoint.sh");
const packagingReadme = join(repoRoot, "packaging/docker/README.md");
const rustMain = join(repoRoot, "examples/microsandbox-openwork-rust/src/main.rs");
const rustReadme = join(repoRoot, "examples/microsandbox-openwork-rust/README.md");
const attackerOrigin = "https://attacker.example";
const children: ChildProcess[] = [];

type RunningSandbox = {
  baseUrl: string;
  workspaceDir: string;
  logPath: string;
  stop: () => Promise<void>;
};

function sanitizeLog(text: string): string {
  return text
    .replace(/(--openwork-token\s+)\S+/g, "$1[redacted]")
    .replace(/(--openwork-host-token\s+)\S+/g, "$1[redacted]")
    .replace(/(Authorization:\s*Bearer\s+)\S+/gi, "$1[redacted]")
    .replace(/(Bearer\s+)\S+/gi, "$1[redacted]")
    .replace(/(client token:\s*)\S+/gi, "$1[redacted]")
    .replace(/(host token:\s*)\S+/gi, "$1[redacted]")
    .replace(/(Remote connect token:\s*)\S+/gi, "$1[redacted]")
    .replace(/(Host\/admin token:\s*)\S+/gi, "$1[redacted]")
    .replace(/(OPENWORK_TOKEN=)\S+/g, "$1[redacted]")
    .replace(/(OPENWORK_HOST_TOKEN=)\S+/g, "$1[redacted]")
    .replace(/("(?:token|hostToken|ownerToken|password|authorization)"\s*:\s*")[^"]*(")/gi, "$1[redacted]$2");
}

function addLiteral(found: Set<string>, value: string | undefined) {
  const trimmed = (value ?? "").trim().replace(/^['"]|['"]$/g, "");
  if (!trimmed) return;
  if (trimmed.includes("$") || trimmed.includes("{") || trimmed.includes("}")) return;
  if (trimmed === "true" || trimmed === "false" || trimmed === "auto" || trimmed === "manual") return;
  found.add(trimmed);
}

function publishedCredentialLiterals(): string[] {
  const found = new Set<string>();
  const entrypointSource = readFileSync(entrypoint, "utf8");
  const rustSource = readFileSync(rustMain, "utf8");
  const docs = [readFileSync(packagingReadme, "utf8"), readFileSync(rustReadme, "utf8")];

  for (const match of entrypointSource.matchAll(
    /OPENWORK_(?:HOST_)?TOKEN="?\$\{OPENWORK_(?:HOST_)?TOKEN:-([^}"\n]+)\}"?/g,
  )) {
    addLiteral(found, match[1]);
  }
  for (const match of rustSource.matchAll(
    /env::var\("OPENWORK_(?:HOST_)?TOKEN"\)[\s\S]{0,180}?"([^"]+)"/g,
  )) {
    addLiteral(found, match[1]);
  }
  for (const text of docs) {
    for (const match of text.matchAll(/OPENWORK_(?:HOST_)?TOKEN\s*=\s*([^\s`]+)/g)) {
      addLiteral(found, match[1]);
    }
    for (const match of text.matchAll(/OPENWORK_(?:HOST_)?TOKEN[^\n]{0,160}?Defaults to `([^`]+)`/g)) {
      addLiteral(found, match[1]);
    }
  }
  return [...found];
}

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("failed to allocate a port"));
        return;
      }
      const { port } = address;
      server.close(() => resolve(port));
    });
  });
}

function writeExecutable(path: string, contents: string) {
  writeFileSync(path, contents, { mode: 0o755 });
  chmodSync(path, 0o755);
}

async function stopChild(child: ChildProcess) {
  if (child.exitCode !== null || child.signalCode !== null || !child.pid) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    child.kill("SIGTERM");
  }
  const exited = await Promise.race([
    new Promise<boolean>((resolve) => child.once("exit", () => resolve(true))),
    new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 2000)),
  ]);
  if (!exited && child.pid) {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  }
}

async function startMicrosandbox(options: {
  clientToken?: string;
  hostToken?: string;
}): Promise<RunningSandbox | { refused: true; log: string }> {
  const root = mkdtempSync(join(tmpdir(), "openwork-microsandbox-"));
  const binDir = join(root, "bin");
  const workspaceDir = join(root, "workspace");
  const dataDir = join(root, "data");
  const sidecarDir = join(root, "sidecars");
  const homeDir = join(root, "home");
  const logPath = join(root, "entrypoint.log");
  mkdirSync(binDir);
  mkdirSync(workspaceDir);
  mkdirSync(dataDir);
  mkdirSync(sidecarDir);
  mkdirSync(homeDir, { recursive: true });

  const openworkPort = await freePort();
  const opencodePort = await freePort();
  const bun = process.execPath;
  const hostPath = process.env.PATH ?? "";

  writeExecutable(
    join(binDir, "opencode"),
    `#!${bun}
const args = process.argv.slice(2);
if (args.includes("--version")) {
  console.log("0.0.0");
  process.exit(0);
}
let host = "127.0.0.1";
let port = ${opencodePort};
for (let i = 0; i < args.length; i += 1) {
  if (args[i] === "--hostname" && args[i + 1]) host = args[++i];
  if (args[i] === "--port" && args[i + 1]) port = Number(args[++i]);
}
Bun.serve({
  hostname: host,
  port,
  fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/global/health" || url.pathname === "/health") {
      return Response.json({ healthy: true });
    }
    if (url.pathname === "/path") {
      return Response.json({ directory: ${JSON.stringify(workspaceDir)} });
    }
    return new Response("not found", { status: 404 });
  },
});
`,
  );
  writeExecutable(
    join(binDir, "openwork-server"),
    `#!/bin/sh
export PATH=${JSON.stringify(hostPath)}
exec ${JSON.stringify(bun)} ${JSON.stringify(join(repoRoot, "apps/server/src/cli.ts"))} "$@"
`,
  );
  writeExecutable(
    join(binDir, "openwork"),
    `#!/bin/sh
export PATH=${JSON.stringify(hostPath)}
exec ${JSON.stringify(bun)} ${JSON.stringify(join(repoRoot, "apps/orchestrator/src/cli.ts"))} "$@"
`,
  );
  const launch = join(root, "launch.sh");
  writeExecutable(
    launch,
    `#!/bin/sh
set -eu
mount --bind ${JSON.stringify(binDir)} /usr/local/bin
export PATH=${JSON.stringify(`${binDir}:${hostPath}`)}
export HOME=${JSON.stringify(homeDir)}
export OPENWORK_WORKSPACE=${JSON.stringify(workspaceDir)}
export OPENWORK_DATA_DIR=${JSON.stringify(dataDir)}
export OPENWORK_SIDECAR_DIR=${JSON.stringify(sidecarDir)}
export OPENWORK_PORT=${String(openworkPort)}
export OPENWORK_OPENCODE_PORT=${String(opencodePort)}
export OPENWORK_TOKEN_STORE=${JSON.stringify(join(root, "tokens.json"))}
export OPENWORK_ENV_STORE=${JSON.stringify(join(root, "env.json"))}
export OPENWORK_LOG_FORMAT=json
unset OPENWORK_APPROVAL_MODE OPENWORK_CORS_ORIGINS OPENWORK_REMOTE_ACCESS
if [ -n ${JSON.stringify(options.clientToken ?? "")} ]; then
  export OPENWORK_TOKEN=${JSON.stringify(options.clientToken ?? "")}
else
  unset OPENWORK_TOKEN
fi
if [ -n ${JSON.stringify(options.hostToken ?? "")} ]; then
  export OPENWORK_HOST_TOKEN=${JSON.stringify(options.hostToken ?? "")}
else
  unset OPENWORK_HOST_TOKEN
fi
exec ${JSON.stringify(entrypoint)}
`,
  );

  const logFd = Bun.file(logPath);
  const log = Bun.file(logPath).writer();
  const child = spawn("unshare", ["--user", "--map-root-user", "--mount", "--propagation", "private", launch], {
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.push(child);
  child.stdout?.on("data", (chunk) => log.write(chunk));
  child.stderr?.on("data", (chunk) => log.write(chunk));
  const baseUrl = `http://127.0.0.1:${openworkPort}`;
  const deadline = Date.now() + 40_000;
  let healthy = false;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) break;
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) {
        healthy = true;
        break;
      }
    } catch {
      // entrypoint has not bound the port yet
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  await log.end();
  const logText = sanitizeLog(await logFd.text());
  const stop = () => stopChild(child);

  if (!healthy) {
    const refused = child.exitCode !== null && child.exitCode !== 0 && /token/i.test(logText);
    if (refused && !/Cannot find module|EADDRINUSE|unshare:|mount:|not found/i.test(logText)) {
      return { refused: true, log: logText };
    }
    await stop();
    throw new Error(
      `microsandbox entrypoint did not become healthy (exit=${child.exitCode ?? "running"}).\n${logText.slice(-4000)}`,
    );
  }

  return { baseUrl, workspaceDir, logPath, stop };
}

function allowsAnyOriginAuthorization(response: Response): boolean {
  const allowOrigin = response.headers.get("access-control-allow-origin");
  const allowHeaders = response.headers.get("access-control-allow-headers") ?? "";
  return allowOrigin === "*" && /authorization/i.test(allowHeaders);
}

async function preflight(baseUrl: string): Promise<Response> {
  return fetch(`${baseUrl}/workspaces`, {
    method: "OPTIONS",
    headers: {
      Origin: attackerOrigin,
      "Access-Control-Request-Method": "POST",
      "Access-Control-Request-Headers": "authorization, content-type, x-openwork-host-token",
    },
  });
}

let unsetSandbox: RunningSandbox | { refused: true; log: string } | undefined;

afterAll(async () => {
  if (unsetSandbox && "stop" in unsetSandbox) await unsetSandbox.stop();
  while (children.length) {
    const child = children.pop();
    if (child) await stopChild(child);
  }
});

test(
  "published microsandbox credentials cannot authenticate or write the workspace",
  async () => {
    unsetSandbox = await startMicrosandbox({});
    if ("refused" in unsetSandbox) return;

    const literals = publishedCredentialLiterals();
    const entrypointSource = readFileSync(entrypoint, "utf8");
    const entrypointHasTokenFallback =
      /OPENWORK_(?:HOST_)?TOKEN="?\$\{OPENWORK_(?:HOST_)?TOKEN:-[^}"\n]+\}/.test(entrypointSource);
    if (literals.length === 0 && entrypointHasTokenFallback) {
      throw new Error("entrypoint still has a token fallback, but no published literal was extracted");
    }

    const bearerStatuses: number[] = [];
    const hostStatuses: number[] = [];
    let wroteFile = false;
    for (const literal of literals) {
      const workspaces = await fetch(`${unsetSandbox.baseUrl}/workspaces`, {
        headers: { Authorization: `Bearer ${literal}` },
      });
      bearerStatuses.push(workspaces.status);
      const minted = await fetch(`${unsetSandbox.baseUrl}/tokens`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-openwork-host-token": literal,
        },
        body: JSON.stringify({ scope: "owner", label: "intruder" }),
      });
      hostStatuses.push(minted.status);
      await minted.arrayBuffer().catch(() => undefined);

      if (workspaces.status === 401 || wroteFile) continue;
      const listed = (await workspaces.json()) as { items?: Array<{ id?: string }> };
      const workspaceId = listed.items?.[0]?.id;
      if (!workspaceId) continue;
      const created = await fetch(`${unsetSandbox.baseUrl}/workspace/${workspaceId}/files/sessions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${literal}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      });
      if (!created.ok) continue;
      const payload = (await created.json()) as { session?: { id?: string } };
      const sessionId = payload.session?.id;
      if (!sessionId) continue;
      const marker = "intruder-write";
      await fetch(`${unsetSandbox.baseUrl}/files/sessions/${sessionId}/write-batch`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${literal}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          writes: [
            {
              path: "intruder-owned.txt",
              contentBase64: Buffer.from(marker).toString("base64"),
              force: true,
            },
          ],
        }),
      });
      const target = join(unsetSandbox.workspaceDir, "intruder-owned.txt");
      wroteFile = existsSync(target) && readFileSync(target, "utf8") === marker;
    }

    expect(wroteFile).toBe(false);
    expect(bearerStatuses).toEqual(literals.map(() => 401));
    expect(hostStatuses).toEqual(literals.map(() => 401));
  },
  { timeout: 60_000 },
);

test(
  "default microsandbox CORS does not let an arbitrary website send authorization",
  async () => {
    unsetSandbox ??= await startMicrosandbox({});
    if ("refused" in unsetSandbox) return;
    const response = await preflight(unsetSandbox.baseUrl);
    expect(allowsAnyOriginAuthorization(response)).toBe(false);
  },
  { timeout: 60_000 },
);

test(
  "unset approval and CORS defaults do not auto-approve a workspace write",
  async () => {
    const clientToken = "test-client-token";
    const hostToken = "test-host-token";
    const running = await startMicrosandbox({ clientToken, hostToken });
    if ("refused" in running) {
      throw new Error("entrypoint refused to start even though both tokens were set");
    }
    try {
      const status = await fetch(`${running.baseUrl}/status`, {
        headers: { Authorization: `Bearer ${clientToken}` },
      });
      expect(status.status).toBe(200);
      const body = (await status.json()) as {
        approval?: { mode?: string };
        corsOrigins?: string[];
        server?: { host?: string };
      };
      expect(body.approval?.mode).toBe("manual");
      expect(body.corsOrigins ?? []).not.toContain("*");

      const preflightResponse = await preflight(running.baseUrl);
      expect(allowsAnyOriginAuthorization(preflightResponse)).toBe(false);

      const listed = await fetch(`${running.baseUrl}/workspaces`, {
        headers: { Authorization: `Bearer ${clientToken}` },
      });
      expect(listed.status).toBe(200);
      const workspaces = (await listed.json()) as { items?: Array<{ id?: string }> };
      const workspaceId = workspaces.items?.[0]?.id;
      expect(workspaceId).toBeTruthy();
      const created = await fetch(`${running.baseUrl}/workspace/${workspaceId}/files/sessions`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${clientToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({}),
      });
      expect(created.status).toBe(200);
      const session = (await created.json()) as { session?: { id?: string; canWrite?: boolean } };
      expect(session.session?.canWrite).toBe(true);
      const target = join(running.workspaceDir, "pending-write.txt");
      const write = fetch(`${running.baseUrl}/files/sessions/${session.session?.id}/write-batch`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${clientToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          writes: [
            {
              path: "pending-write.txt",
              contentBase64: Buffer.from("pending").toString("base64"),
              force: true,
            },
          ],
        }),
        signal: AbortSignal.timeout(800),
      }).then(
        async (response) => ({ status: response.status, aborted: false }),
        () => ({ status: 0, aborted: true }),
      );
      const result = await write;
      expect(existsSync(target)).toBe(false);
      expect(result.status === 200).toBe(false);
    } finally {
      await running.stop();
    }
  },
  { timeout: 60_000 },
);

test("microsandbox run instructions publish the server on loopback and do not assign token literals", () => {
  const readme = readFileSync(packagingReadme, "utf8");
  const start = readme.indexOf("## Pre-baked Micro-Sandbox Image");
  const end = readme.indexOf("\n## ", start + 1);
  expect(start).toBeGreaterThanOrEqual(0);
  const section = readme.slice(start, end === -1 ? undefined : end);
  const publishes = section.match(/--publish(?:=|\s+)\S+|(^|\s)-p\s+\S+/gm) ?? [];
  expect(publishes.length).toBeGreaterThan(0);
  for (const publish of publishes) {
    expect(publish.includes("127.0.0.1:")).toBe(true);
  }
  expect(/OPENWORK_(?:HOST_)?TOKEN\s*=\s*\S+/.test(section)).toBe(false);

  const rustDocs = readFileSync(rustReadme, "utf8");
  expect(/OPENWORK_(?:HOST_)?TOKEN[^\n]*Defaults to `[^`]+`/.test(rustDocs)).toBe(false);
});

test("rust microsandbox launcher does not fall back to a literal token or force auto approval", () => {
  const source = readFileSync(rustMain, "utf8");
  const testAt = source.indexOf("#[cfg(test)]");
  const production = testAt === -1 ? source : source.slice(0, testAt);
  expect(
    /env::var\("OPENWORK_TOKEN"\)[\s\S]{0,200}?unwrap_or(?:_else)?\([\s\S]{0,80}?"[^"]+"/.test(production),
  ).toBe(false);
  expect(
    /env::var\("OPENWORK_HOST_TOKEN"\)[\s\S]{0,200}?unwrap_or(?:_else)?\([\s\S]{0,80}?"[^"]+"/.test(production),
  ).toBe(false);
  expect(production.includes('.env("OPENWORK_APPROVAL_MODE", "auto")')).toBe(false);
});
