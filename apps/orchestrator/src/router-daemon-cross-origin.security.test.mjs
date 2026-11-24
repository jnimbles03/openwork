/**
 * Spec for the orchestrator router daemon cross-origin control bug.
 *
 * These tests fail while the daemon accepts unauthenticated browser requests.
 * They pass once that daemon requires a per-launch secret and stops attaching
 * managed OpenCode credentials to remote workspace base URLs.
 *
 * Contract the product must meet:
 * - Read the per-launch secret from OPENWORK_ROUTER_DAEMON_TOKEN.
 * - Require Authorization: Bearer <that secret> on every route except a
 *   minimal GET /health. Compare the full secret; a prefix or suffix is not
 *   enough. Missing and wrong secrets are refused before any state, file, or
 *   outbound request changes.
 * - Minimal GET /health may answer without the secret, but its body must not
 *   include OpenCode addressing, sidecar metadata, binaries, or workspace paths.
 * - Do not send Access-Control-Allow-Origin: * or reflect an arbitrary Origin.
 * - Ignore request bodies whose Content-Type is not application/json, before
 *   any side effect, even when the secret is present.
 * - Refuse a Host header other than 127.0.0.1 or localhost, before any side
 *   effect, even when the secret is present.
 * - A caller that presents the secret may register a remote workspace, but the
 *   managed OpenCode username and password must not be attached to requests
 *   the daemon makes to that workspace's base URL.
 *
 * Run:
 *   node --test --test-concurrency=1 apps/orchestrator/src/router-daemon-cross-origin.security.test.mjs
 */
import assert from "node:assert/strict";
import { execFile, spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { createServer as createNetServer } from "node:net";
import { createServer as createHttpServer } from "node:http";
import { request as httpRequest } from "node:http";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  watch,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));
const cliPath = resolve(here, "cli.ts");
const routerToken = "placeholder-router-daemon-token";
const opencodeUsername = "placeholder-opencode-username";
const opencodePassword = "placeholder-opencode-password";
const privateOriginIp = "192.168.50.10";

function managedAuthorizationValue() {
  return `Basic ${Buffer.from(`${opencodeUsername}:${opencodePassword}`, "utf8").toString("base64")}`;
}

function workspaceIdForRemote(baseUrl, directory) {
  const key = directory ? `${baseUrl}::${directory}` : baseUrl;
  return `ws-${createHash("sha1").update(key).digest("hex").slice(0, 12)}`;
}

function findFreePort() {
  return new Promise((resolvePort, reject) => {
    const server = createNetServer();
    server.unref();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Failed to allocate a free port"));
        return;
      }
      const port = address.port;
      server.close(() => resolvePort(port));
    });
  });
}

function exec(command, args) {
  return new Promise((resolveExec) => {
    execFile(command, args, () => resolveExec());
  });
}

async function ensurePrivateOriginAddress() {
  await exec("ip", ["addr", "add", `${privateOriginIp}/32`, "dev", "lo"]);
  await exec("sudo", ["ip", "addr", "add", `${privateOriginIp}/32`, "dev", "lo"]);
  await new Promise((resolveBind, reject) => {
    const probe = createNetServer();
    probe.once("error", () => {
      probe.close();
      reject(
        new Error(
          `Cannot bind ${privateOriginIp}. The private-network page origin is required to exercise the browser path.`,
        ),
      );
    });
    probe.listen(0, privateOriginIp, () => probe.close(() => resolveBind()));
  });
}

function writeFakeOpencode(directory) {
  const bin = join(directory, "opencode-fake");
  writeFileSync(
    bin,
    `#!/usr/bin/env node
const { appendFileSync } = require("node:fs");
const { createServer } = require("node:http");
const args = process.argv.slice(2);
const logPath = process.env.OPENWORK_FAKE_OPENCODE_LOG;
const note = (entry) => {
  if (!logPath) return;
  appendFileSync(logPath, JSON.stringify(entry) + "\\n");
};
if (args.includes("--version")) {
  console.log("0.0.0-test");
  process.exit(0);
}
const port = Number(args[args.indexOf("--port") + 1]);
createServer((req, res) => {
  note({ method: req.method, url: req.url || "/" });
  const url = req.url || "/";
  res.setHeader("Content-Type", "application/json");
  if (url.startsWith("/global/health")) {
    res.end(JSON.stringify({ healthy: true }));
    return;
  }
  if (url.startsWith("/path")) {
    res.end(JSON.stringify({ directory: "/tmp/local-opencode" }));
    return;
  }
  if (url.startsWith("/instance/dispose")) {
    res.end(JSON.stringify({ ok: true }));
    return;
  }
  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not found" }));
}).listen(port, "127.0.0.1");
`,
    "utf8",
  );
  chmodSync(bin, 0o755);
  return bin;
}

function rawRequest({ port, method, path, headers = {}, body, hostHeader }) {
  return new Promise((resolveResponse, reject) => {
    const req = httpRequest(
      {
        host: "127.0.0.1",
        port,
        method,
        path,
        setHost: false,
        headers: {
          ...headers,
          Host: hostHeader || `127.0.0.1:${port}`,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolveResponse({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function bearer(token = routerToken) {
  return { Authorization: `Bearer ${token}` };
}

function jsonHeaders(extra = {}) {
  return {
    "Content-Type": "application/json",
    ...extra,
  };
}

async function startDaemon(root, options = {}) {
  const dataDir = join(root, "data");
  const workdir = join(root, "workdir");
  const createRoot = join(root, "creates");
  mkdirSync(dataDir, { recursive: true });
  mkdirSync(workdir, { recursive: true });
  mkdirSync(createRoot, { recursive: true });
  const statePath = join(dataDir, "openwork-orchestrator-state.json");
  writeFileSync(
    statePath,
    `${JSON.stringify(
      {
        version: 1,
        activeId: options.activeId || "",
        workspaces: options.workspaces || [],
      },
      null,
      2,
    )}\n`,
  );
  const fakeLog = join(root, "opencode-requests.log");
  writeFileSync(fakeLog, "");
  const bin = writeFakeOpencode(root);
  const daemonPort = await findFreePort();
  const opencodePort = await findFreePort();
  const child = spawn(
    process.execPath,
    [
      "--experimental-strip-types",
      cliPath,
      "daemon",
      "run",
      "--data-dir",
      dataDir,
      "--daemon-host",
      "127.0.0.1",
      "--daemon-port",
      String(daemonPort),
      "--opencode-bin",
      bin,
      "--allow-external",
      "--opencode-source",
      "external",
      "--opencode-host",
      "127.0.0.1",
      "--opencode-port",
      String(opencodePort),
      "--opencode-workdir",
      workdir,
      "--cors",
      "*",
      "--log-format",
      "json",
    ],
    {
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        OPENWORK_INTERNAL_ALLOW_OPENCODE_CREDENTIALS: "1",
        OPENWORK_OPENCODE_USERNAME: opencodeUsername,
        OPENWORK_OPENCODE_PASSWORD: opencodePassword,
        OPENWORK_ROUTER_DAEMON_TOKEN: routerToken,
        OPENWORK_FAKE_OPENCODE_LOG: fakeLog,
      },
    },
  );
  let logs = "";
  child.stdout?.on("data", (chunk) => {
    logs += chunk.toString();
  });
  child.stderr?.on("data", (chunk) => {
    logs += chunk.toString();
  });
  const deadline = Date.now() + 20_000;
  let ready = false;
  let lastError = "daemon did not become ready";
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      lastError = `daemon exited ${child.exitCode}`;
      break;
    }
    try {
      const response = await rawRequest({
        port: daemonPort,
        method: "GET",
        path: "/health",
      });
      if (response.status > 0) {
        ready = true;
        break;
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 100));
  }
  if (!ready) {
    await stopDaemon(child);
    const redacted = logs
      .split(opencodePassword)
      .join("[redacted]")
      .split(routerToken)
      .join("[redacted]");
    throw new Error(`${lastError}\n${redacted.slice(-2000)}`);
  }
  return {
    port: daemonPort,
    dataDir,
    createRoot,
    fakeLog,
    child,
    statePath,
  };
}

async function stopDaemon(child) {
  if (!child?.pid || child.exitCode !== null) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    try {
      child.kill("SIGTERM");
    } catch {
      // already gone
    }
  }
  const exited = await Promise.race([
    once(child, "exit").then(() => true),
    new Promise((resolveWait) => setTimeout(resolveWait, 2000, false)),
  ]);
  if (!exited) {
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
    }
    await Promise.race([
      once(child, "exit").then(() => true),
      new Promise((resolveWait) => setTimeout(resolveWait, 1000, false)),
    ]);
  }
}

function readState(daemon) {
  return JSON.parse(readFileSync(daemon.statePath, "utf8"));
}

function opencodeRequests(daemon) {
  const raw = readFileSync(daemon.fakeLog, "utf8").trim();
  if (!raw) return [];
  return raw.split("\n").map((line) => JSON.parse(line));
}

function assertNoWildcardCors(response, label) {
  const allow = response.headers["access-control-allow-origin"];
  assert.notEqual(
    allow,
    "*",
    `${label} advertised every origin as allowed to read the response`,
  );
  if (typeof allow === "string") {
    assert.equal(
      allow.includes(privateOriginIp),
      false,
      `${label} reflected the attacker page origin`,
    );
  }
}

function assertRefused(response, label) {
  assert.ok(
    response.status >= 400 && response.status < 500,
    `${label} was applied (HTTP ${response.status})`,
  );
  assertNoWildcardCors(response, label);
}

function startAttacker() {
  const hits = [];
  const managed = managedAuthorizationValue();
  const server = createHttpServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const authorization = req.headers.authorization;
      hits.push({
        method: req.method,
        path: (req.url || "/").split("?")[0],
        managedAuthorization: authorization === managed,
        hasAuthorization: Boolean(authorization),
      });
      const body = JSON.stringify({ healthy: true, directory: "/tmp/remote" });
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.end(body);
    });
  });
  return new Promise((resolveServer) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolveServer({
        server,
        hits,
        baseUrl: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((resolveClose) => server.close(() => resolveClose())),
      });
    });
  });
}

function watchCreates(directory) {
  const events = [];
  const watcher = watch(directory, { persistent: false }, (_event, name) => {
    events.push(String(name));
  });
  return { events, watcher };
}

async function withDaemon(fn, configure = () => ({})) {
  const root = mkdtempSync(join(tmpdir(), "openwork-router-auth-"));
  const daemon = await startDaemon(root, configure(root) || {});
  try {
    await fn(daemon, root);
  } finally {
    await stopDaemon(daemon.child);
    rmSync(root, { recursive: true, force: true });
  }
}

let serial = Promise.resolve();
function testSerial(name, fn) {
  test(name, async () => {
    const previous = serial;
    let release = () => {};
    serial = new Promise((resolveDone) => {
      release = resolveDone;
    });
    await previous;
    try {
      await fn();
    } finally {
      release();
    }
  });
}

testSerial(
  "anonymous health does not reveal OpenCode and does not allow every origin",
  async () => {
    await withDaemon(async (daemon) => {
      const response = await rawRequest({
        port: daemon.port,
        method: "GET",
        path: "/health",
        headers: { Origin: `http://${privateOriginIp}:9` },
      });
      assertNoWildcardCors(response, "GET /health");
      if (response.status === 200) {
        const body = JSON.parse(response.body);
        assert.equal(body.opencode, undefined);
        assert.equal(body.binaries, undefined);
        assert.equal(body.sidecar, undefined);
      } else {
        assertRefused(response, "GET /health");
      }
      const preflight = await rawRequest({
        port: daemon.port,
        method: "OPTIONS",
        path: "/workspaces",
        headers: {
          Origin: `http://${privateOriginIp}:9`,
          "Access-Control-Request-Method": "POST",
          "Access-Control-Request-Headers": "authorization,content-type",
        },
      });
      assertNoWildcardCors(preflight, "OPTIONS /workspaces");
      const allowHeaders = String(
        preflight.headers["access-control-allow-headers"] || "",
      ).toLowerCase();
      assert.equal(
        allowHeaders.includes("authorization"),
        false,
        "preflight invited a cross-origin Authorization header",
      );
    });
  },
);

testSerial(
  "anonymous router routes are refused before they read or change anything",
  async () => {
    const seededPath = join(tmpdir(), `openwork-seeded-${randomBytes(4).toString("hex")}`);
    const seeded = {
      id: "ws-seeded-local",
      name: "Seeded",
      path: seededPath,
      workspaceType: "local",
      createdAt: 1,
      lastUsedAt: 1,
    };
    await withDaemon(
      async (daemon) => {
      const attacker = await startAttacker();
      const watched = watchCreates(daemon.createRoot);
      const localPath = join(daemon.createRoot, "anonymous-local");
      const remoteId = workspaceIdForRemote(attacker.baseUrl);
      const calls = [
        ["GET", "/workspaces", undefined],
        ["GET", `/workspaces/${seeded.id}`, undefined],
        ["POST", `/workspaces/${seeded.id}/activate`, ""],
        ["GET", `/workspaces/${seeded.id}/path`, undefined],
        ["POST", `/instances/${seeded.id}/dispose`, "{}"],
        [
          "POST",
          "/workspaces/remote",
          JSON.stringify({ baseUrl: attacker.baseUrl, name: "attacker" }),
        ],
        [
          "POST",
          `/instances/${remoteId}/dispose`,
          "{}",
        ],
        [
          "GET",
          `/workspaces/${remoteId}/path`,
          undefined,
        ],
        [
          "POST",
          "/workspaces",
          JSON.stringify({ path: localPath, name: "planted" }),
        ],
      ];
      try {
        for (const [method, path, body] of calls) {
          const headers = {
            Origin: `http://${privateOriginIp}:9`,
          };
          if (body !== undefined) headers["Content-Type"] = "text/plain";
          const response = await rawRequest({
            port: daemon.port,
            method,
            path,
            headers,
            body,
          });
          assertRefused(response, `${method} ${path}`);
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 150));
        assert.equal(
          existsSync(join(localPath, "opencode.jsonc")),
          false,
          "anonymous POST /workspaces created opencode.jsonc",
        );
        assert.equal(
          existsSync(localPath),
          false,
          "anonymous POST /workspaces created a directory",
        );
        assert.deepEqual(watched.events, []);
        const after = readState(daemon);
        assert.equal(after.activeId || "", "");
        assert.equal(
          JSON.stringify(after.workspaces).includes(attacker.baseUrl),
          false,
          "anonymous POST /workspaces/remote registered the attacker base URL",
        );
        assert.equal(
          attacker.hits.some((hit) => hit.managedAuthorization),
          false,
          "anonymous dispose or path lookup forwarded managed OpenCode authorization",
        );
        assert.equal(attacker.hits.length, 0);
        const outbound = opencodeRequests(daemon).map((entry) => entry.url);
        assert.equal(
          outbound.some((url) => url.startsWith("/path") || url.startsWith("/instance/dispose")),
          false,
          "anonymous workspace path or dispose called the local OpenCode server",
        );
      } finally {
        watched.watcher.close();
        await attacker.close();
      }
    },
      () => ({ workspaces: [seeded] }),
    );
  },
);

testSerial(
  "a non-JSON body is ignored before side effects even with the daemon token",
  async () => {
    await withDaemon(async (daemon) => {
      const attacker = await startAttacker();
      const localPath = join(daemon.createRoot, "plain-with-token");
      const watched = watchCreates(daemon.createRoot);
      try {
        const created = await rawRequest({
          port: daemon.port,
          method: "POST",
          path: "/workspaces",
          headers: {
            ...bearer(),
            "Content-Type": "text/plain",
            Origin: `http://${privateOriginIp}:9`,
          },
          body: JSON.stringify({ path: localPath, name: "plain" }),
        });
        assertRefused(created, "text/plain POST /workspaces");
        const remote = await rawRequest({
          port: daemon.port,
          method: "POST",
          path: "/workspaces/remote",
          headers: {
            ...bearer(),
            "Content-Type": "text/plain",
          },
          body: JSON.stringify({ baseUrl: attacker.baseUrl }),
        });
        assertRefused(remote, "text/plain POST /workspaces/remote");
        await new Promise((resolveWait) => setTimeout(resolveWait, 150));
        assert.equal(existsSync(localPath), false);
        assert.deepEqual(watched.events, []);
        assert.equal(
          JSON.stringify(readState(daemon).workspaces).includes(attacker.baseUrl),
          false,
        );
        assert.equal(attacker.hits.length, 0);
      } finally {
        watched.watcher.close();
        await attacker.close();
      }
    });
  },
);

testSerial(
  "a non-loopback Host is refused before side effects even with the daemon token",
  async () => {
    await withDaemon(async (daemon) => {
      const attacker = await startAttacker();
      const localPath = join(daemon.createRoot, "rebinding");
      try {
        const response = await rawRequest({
          port: daemon.port,
          method: "POST",
          path: "/workspaces",
          headers: {
            ...bearer(),
            "Content-Type": "application/json",
          },
          hostHeader: `rebinding.example:${daemon.port}`,
          body: JSON.stringify({ path: localPath }),
        });
        assertRefused(response, "POST /workspaces with a rebound Host");
        const remote = await rawRequest({
          port: daemon.port,
          method: "POST",
          path: "/workspaces/remote",
          headers: {
            ...bearer(),
            "Content-Type": "application/json",
          },
          hostHeader: `rebinding.example:${daemon.port}`,
          body: JSON.stringify({ baseUrl: attacker.baseUrl }),
        });
        assertRefused(remote, "POST /workspaces/remote with a rebound Host");
        await new Promise((resolveWait) => setTimeout(resolveWait, 100));
        assert.equal(existsSync(localPath), false);
        assert.equal(
          JSON.stringify(readState(daemon).workspaces).includes(attacker.baseUrl),
          false,
        );
      } finally {
        await attacker.close();
      }
    });
  },
);

testSerial("a wrong daemon token is refused before side effects", async () => {
  await withDaemon(async (daemon) => {
    const localPath = join(daemon.createRoot, "wrong-token");
    const tokens = [
      "",
      "placeholder",
      routerToken.slice(0, -1),
      `${routerToken}-extra`,
      randomBytes(8).toString("hex"),
    ];
    for (const token of tokens) {
      const response = await rawRequest({
        port: daemon.port,
        method: "POST",
        path: "/workspaces",
        headers: {
          ...bearer(token),
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ path: localPath }),
      });
      assertRefused(response, "POST /workspaces with a wrong daemon token");
    }
    assert.equal(existsSync(localPath), false);
  });
});

testSerial(
  "the daemon token can create a local workspace with an application/json body",
  async () => {
    await withDaemon(async (daemon) => {
      const localPath = join(daemon.createRoot, "authorized-local");
      const response = await rawRequest({
        port: daemon.port,
        method: "POST",
        path: "/workspaces",
        headers: jsonHeaders(bearer()),
        body: JSON.stringify({ path: localPath, name: "Authorized" }),
      });
      assert.equal(response.status, 200);
      assertNoWildcardCors(response, "authorized POST /workspaces");
      assert.equal(existsSync(join(localPath, "opencode.jsonc")), true);
      const listed = await rawRequest({
        port: daemon.port,
        method: "GET",
        path: "/workspaces",
        headers: bearer(),
      });
      assert.equal(listed.status, 200);
      assert.equal(listed.body.includes(localPath), true);
    });
  },
);

testSerial(
  "managed OpenCode authorization is not sent to a remote workspace base URL",
  async () => {
    await withDaemon(async (daemon) => {
      const attacker = await startAttacker();
      try {
        const registered = await rawRequest({
          port: daemon.port,
          method: "POST",
          path: "/workspaces/remote",
          headers: jsonHeaders(bearer()),
          body: JSON.stringify({
            baseUrl: attacker.baseUrl,
            name: "remote",
          }),
        });
        assert.equal(registered.status, 200);
        const body = JSON.parse(registered.body);
        const id = body.workspace?.id;
        assert.equal(typeof id, "string");
        attacker.hits.length = 0;
        const disposed = await rawRequest({
          port: daemon.port,
          method: "POST",
          path: `/instances/${encodeURIComponent(id)}/dispose`,
          headers: jsonHeaders(bearer()),
          body: "{}",
        });
        assert.notEqual(disposed.status, 401);
        assert.notEqual(disposed.status, 403);
        const lookedUp = await rawRequest({
          port: daemon.port,
          method: "GET",
          path: `/workspaces/${encodeURIComponent(id)}/path`,
          headers: bearer(),
        });
        assert.notEqual(lookedUp.status, 401);
        assert.notEqual(lookedUp.status, 403);
        const disposeHit = attacker.hits.find(
          (hit) => hit.path === "/instance/dispose",
        );
        const pathHit = attacker.hits.find((hit) => hit.path === "/path");
        assert.ok(disposeHit, "POST /instances/:id/dispose did not call the remote base URL");
        assert.ok(pathHit, "GET /workspaces/:id/path did not call the remote base URL");
        assert.equal(
          disposeHit.managedAuthorization,
          false,
          "POST /instances/:id/dispose forwarded managed OpenCode authorization",
        );
        assert.equal(
          pathHit.managedAuthorization,
          false,
          "GET /workspaces/:id/path forwarded managed OpenCode authorization",
        );
      } finally {
        await attacker.close();
      }
    });
  },
);

function chromePath() {
  const fromEnv = process.env.CHROME_PATH?.trim();
  if (fromEnv) return fromEnv;
  for (const candidate of ["google-chrome", "google-chrome-stable", "chromium"]) {
    const found = spawnSync("which", [candidate], { encoding: "utf8" });
    if (found.status === 0 && found.stdout.trim()) return found.stdout.trim();
  }
  return "";
}

testSerial(
  "a private-network web page cannot read or drive the loopback router daemon",
  async () => {
    await ensurePrivateOriginAddress();
    const chrome = chromePath();
    assert.ok(chrome, "google-chrome is required to exercise the browser path");
    const visiblePath = join(
      tmpdir(),
      `openwork-visible-${randomBytes(4).toString("hex")}`,
    );
    await withDaemon(async (daemon) => {
      const attacker = await startAttacker();
      const localPath = join(daemon.createRoot, "from-page");
      const remoteId = workspaceIdForRemote(attacker.baseUrl);
      const watched = watchCreates(daemon.createRoot);
      const reportPath = join(daemon.dataDir, "page-report.json");
      const page = `<!doctype html><pre id="out">pending</pre><script>
        const daemonBase = ${JSON.stringify(`http://127.0.0.1:${daemon.port}`)};
        const remoteId = ${JSON.stringify(remoteId)};
        const localPath = ${JSON.stringify(localPath)};
        const remoteBase = ${JSON.stringify(attacker.baseUrl)};
        const out = { steps: [] };
        async function step(name, fn) {
          try { out.steps.push({ name, ok: true, value: await fn() }); }
          catch (error) { out.steps.push({ name, ok: false, error: String(error) }); }
        }
        (async () => {
          await step("health", async () => {
            const response = await fetch(daemonBase + "/health");
            const body = await response.json();
            return {
              status: response.status,
              opencodePort: body.opencode && body.opencode.port || null,
              opencodeBaseUrl: body.opencode && body.opencode.baseUrl || null
            };
          });
          await step("workspaces", async () => {
            const response = await fetch(daemonBase + "/workspaces");
            const body = await response.json();
            return { status: response.status, paths: (body.workspaces || []).map((item) => item.path) };
          });
          await step("create", async () => {
            const response = await fetch(daemonBase + "/workspaces", {
              method: "POST",
              headers: { "Content-Type": "text/plain" },
              body: JSON.stringify({ path: localPath, name: "from-page" })
            });
            return { status: response.status, body: await response.text() };
          });
          await step("remote", async () => {
            const response = await fetch(daemonBase + "/workspaces/remote", {
              method: "POST",
              headers: { "Content-Type": "text/plain" },
              body: JSON.stringify({ baseUrl: remoteBase, name: "from-page" })
            });
            const body = await response.json();
            return { status: response.status, id: body.workspace && body.workspace.id };
          });
          await step("dispose", async () => {
            const response = await fetch(daemonBase + "/instances/" + encodeURIComponent(remoteId) + "/dispose", {
              method: "POST",
              headers: { "Content-Type": "text/plain" },
              body: "{}"
            });
            return { status: response.status };
          });
          await step("path", async () => {
            const response = await fetch(daemonBase + "/workspaces/" + encodeURIComponent(remoteId) + "/path");
            return { status: response.status };
          });
          document.getElementById("out").textContent = JSON.stringify(out);
          await fetch("/result", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: JSON.stringify(out)
          });
        })();
      </script>`;
      const pageServer = createHttpServer((req, res) => {
        if (req.method === "POST") {
          const chunks = [];
          req.on("data", (chunk) => chunks.push(chunk));
          req.on("end", () => {
            writeFileSync(reportPath, Buffer.concat(chunks));
            res.statusCode = 204;
            res.end();
          });
          return;
        }
        const body = Buffer.from(page);
        res.statusCode = 200;
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.setHeader("Content-Length", String(body.length));
        res.end(body);
      });
      const profile = mkdtempSync(join(tmpdir(), "openwork-chrome-"));
      try {
        const pagePort = await new Promise((resolvePort) => {
          pageServer.listen(0, privateOriginIp, () => {
            const address = pageServer.address();
            resolvePort(typeof address === "object" && address ? address.port : 0);
          });
        });
        const child = spawn(
          "timeout",
          [
            "25",
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            `--user-data-dir=${profile}`,
            "--virtual-time-budget=12000",
            "--timeout=20000",
            "--dump-dom",
            `http://${privateOriginIp}:${pagePort}/`,
          ],
          { stdio: "ignore" },
        );
        await Promise.race([
          once(child, "exit"),
          new Promise((resolveWait) => setTimeout(resolveWait, 30_000, "hung")),
        ]);
        if (child.exitCode === null) child.kill("SIGKILL");
        assert.equal(
          existsSync(reportPath),
          true,
          "the private-network page did not finish its requests",
        );
        const report = JSON.parse(readFileSync(reportPath, "utf8"));
        const breaches = [];
        const health = report.steps.find((step) => step.name === "health");
        if (!health) breaches.push("health step missing");
        if (health?.ok && (health.value.opencodePort || health.value.opencodeBaseUrl)) {
          breaches.push("page read OpenCode addressing from GET /health");
        }
        const revealedPaths = report.steps.find((step) => step.name === "workspaces");
        if (
          revealedPaths?.ok &&
          revealedPaths.value.status === 200 &&
          revealedPaths.value.paths.includes(visiblePath)
        ) {
          breaches.push("page read a local workspace path from GET /workspaces");
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 200));
        if (existsSync(localPath) || watched.events.length > 0) {
          breaches.push("page POST /workspaces created files");
        }
        if (JSON.stringify(readState(daemon).workspaces || []).includes(attacker.baseUrl)) {
          breaches.push("page POST /workspaces/remote registered the attacker base URL");
        }
        const forwarded = attacker.hits.filter((hit) => hit.managedAuthorization);
        if (forwarded.length > 0) {
          breaches.push(
            `page caused managed OpenCode authorization to be sent (${forwarded.map((hit) => hit.method + " " + hit.path).join(", ")})`,
          );
        }
        assert.deepEqual(breaches, []);
      } finally {
        watched.watcher.close();
        await new Promise((resolveClose) => pageServer.close(() => resolveClose()));
        await attacker.close();
        rmSync(profile, { recursive: true, force: true });
      }
    }, () => ({
      workspaces: [
        {
          id: "ws-visible",
          name: "Visible",
          path: visiblePath,
          workspaceType: "local",
          createdAt: 1,
          lastUsedAt: 1,
        },
      ],
    }));
  },
);

testSerial(
  "anonymous shutdown leaves the daemon running and the daemon token can stop it",
  async () => {
    await withDaemon(async (daemon) => {
      const anonymous = await rawRequest({
        port: daemon.port,
        method: "POST",
        path: "/shutdown",
        headers: {
          "Content-Type": "text/plain",
          Origin: `http://${privateOriginIp}:9`,
        },
        body: "{}",
      });
      assertRefused(anonymous, "POST /shutdown");
      await new Promise((resolveWait) => setTimeout(resolveWait, 300));
      let stillUp;
      try {
        stillUp = await rawRequest({
          port: daemon.port,
          method: "GET",
          path: "/health",
          headers: bearer(),
        });
      } catch {
        assert.fail("anonymous POST /shutdown stopped the daemon");
      }
      assert.ok(stillUp.status > 0, "anonymous POST /shutdown stopped the daemon");
      const authorized = await rawRequest({
        port: daemon.port,
        method: "POST",
        path: "/shutdown",
        headers: jsonHeaders(bearer()),
        body: "{}",
      });
      assert.equal(authorized.status, 200);
      const deadline = Date.now() + 5_000;
      let down = false;
      while (Date.now() < deadline) {
        if (daemon.child.exitCode !== null) {
          down = true;
          break;
        }
        try {
          await rawRequest({
            port: daemon.port,
            method: "GET",
            path: "/health",
          });
        } catch {
          down = true;
          break;
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 100));
      }
      assert.equal(down, true, "authorized POST /shutdown left the daemon running");
    });
  },
);
