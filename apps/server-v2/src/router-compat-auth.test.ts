import { afterEach, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createApp } from "./app.js";
import { createAppDependencies, type AppDependencies } from "./context/app-dependencies.js";
import { resolveRuntimeTarget, type RuntimeManifest } from "./runtime/manifest.js";

const CLIENT_TOKEN = "placeholder-client-token";
const HOST_TOKEN = "placeholder-host-token";
const UNCONFIGURED_TOKEN = "placeholder-unconfigured-token";
const TELEGRAM_TOKEN = "placeholder-telegram-bot-token";
const SLACK_BOT_TOKEN = "placeholder-slack-bot-token";
const SLACK_APP_TOKEN = "placeholder-slack-app-token";

const tempRoots: string[] = [];
const openApps: AppDependencies[] = [];
const envKeys = [
  "OPENWORK_SERVER_V2_CLIENT_TOKEN",
  "OPENWORK_CLIENT_TOKEN",
  "OPENWORK_TOKEN",
  "OPENWORK_SERVER_V2_HOST_TOKEN",
  "OPENWORK_HOST_TOKEN",
  "PERMISSION_MODE",
  "ROUTER_AUDIT_PATH",
] as const;
const envBackup = new Map(envKeys.map((key) => [key, process.env[key]]));
const originalFetch = globalThis.fetch;

afterEach(async () => {
  while (openApps.length) {
    const dependencies = openApps.pop();
    if (dependencies) {
      await dependencies.close();
    }
  }
  while (tempRoots.length) {
    const next = tempRoots.pop();
    if (next) {
      fs.rmSync(next, { force: true, recursive: true });
    }
  }
  for (const [key, value] of envBackup) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  globalThis.fetch = originalFetch;
});

function createTempRoot(label: string) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `${label}-`));
  tempRoots.push(root);
  return root;
}

function hostHeaders(contentType = "application/json") {
  return {
    "content-type": contentType,
    "x-openwork-host-token": HOST_TOKEN,
  };
}

function clientHeaders(contentType = "application/json") {
  return {
    authorization: `Bearer ${CLIENT_TOKEN}`,
    "content-type": contentType,
  };
}

function installFetchStub() {
  globalThis.fetch = Object.assign(
    async (input: URL | RequestInfo, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith("https://api.telegram.org/")) {
        return new Response(JSON.stringify({ ok: false }), {
          headers: { "content-type": "application/json" },
          status: 401,
        });
      }
      return originalFetch(input, init);
    },
    { preconnect: originalFetch.preconnect },
  ) as typeof fetch;
}

async function sha256(filePath: string) {
  const contents = await Bun.file(filePath).arrayBuffer();
  return createHash("sha256").update(Buffer.from(contents)).digest("hex");
}

async function createFakeAssetService(opencodePath: string, routerPath: string) {
  const target = resolveRuntimeTarget();
  if (!target) {
    throw new Error("Unsupported test target.");
  }
  const opencodeStats = fs.statSync(opencodePath);
  const routerStats = fs.statSync(routerPath);
  const manifest: RuntimeManifest = {
    files: {
      opencode: {
        path: path.basename(opencodePath),
        sha256: await sha256(opencodePath),
        size: opencodeStats.size,
      },
      "opencode-router": {
        path: path.basename(routerPath),
        sha256: await sha256(routerPath),
        size: routerStats.size,
      },
    },
    generatedAt: new Date().toISOString(),
    manifestVersion: 1,
    opencodeVersion: "1.4.9",
    rootDir: path.dirname(opencodePath),
    routerVersion: "0.11.206",
    serverVersion: "0.0.0-test",
    source: "development",
    target,
  };
  const opencodeBinary = {
    absolutePath: opencodePath,
    name: "opencode" as const,
    sha256: manifest.files.opencode.sha256,
    size: manifest.files.opencode.size,
    source: "development" as const,
    stagedRoot: path.dirname(opencodePath),
    target,
    version: "1.4.9",
  };
  const routerBinary = {
    absolutePath: routerPath,
    name: "opencode-router" as const,
    sha256: manifest.files["opencode-router"].sha256,
    size: manifest.files["opencode-router"].size,
    source: "development" as const,
    stagedRoot: path.dirname(routerPath),
    target,
    version: "0.11.206",
  };
  return {
    ensureOpencodeBinary: async () => opencodeBinary,
    ensureRouterBinary: async () => routerBinary,
    getDevelopmentRoot: () => path.dirname(opencodePath),
    getPinnedOpencodeVersion: async () => "1.4.9",
    getReleaseRoot: () => path.dirname(opencodePath),
    getRouterVersion: async () => "0.11.206",
    getSource: () => "development" as const,
    getTarget: () => target,
    resolveRuntimeBundle: async () => ({
      manifest,
      opencode: opencodeBinary,
      router: routerBinary,
    }),
  };
}

function writeExecutable(filePath: string, contents: string) {
  fs.writeFileSync(filePath, contents, "utf8");
  fs.chmodSync(filePath, 0o755);
}

async function createRuntimeBinaries(auditPath: string) {
  const root = createTempRoot("openwork-router-compat-bin");
  const fixturePath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "test-fixtures", "fake-runtime.ts");
  const opencodePath = path.join(root, "opencode");
  writeExecutable(
    opencodePath,
    [
      "#!/bin/sh",
      "export FAKE_RUNTIME_KIND=opencode",
      "export FAKE_RUNTIME_MODE=success",
      `exec ${JSON.stringify(process.execPath)} ${JSON.stringify(fixturePath)} "$@"`,
      "",
    ].join("\n"),
  );
  const routerScript = path.join(root, "router-audit.ts");
  fs.writeFileSync(
    routerScript,
    `
import fs from "node:fs";
import http from "node:http";

const auditPath = process.env.ROUTER_AUDIT_PATH;
const serveIndex = process.argv.indexOf("serve");
const audit = {
  permissionModeSet: Boolean(process.env.PERMISSION_MODE),
  sendCount: 0,
  serveDirectory: serveIndex >= 0 ? process.argv[serveIndex + 1] ?? null : null,
};
function flush() {
  if (auditPath) fs.writeFileSync(auditPath, JSON.stringify(audit));
}
const port = Number.parseInt(process.env.OPENCODE_ROUTER_HEALTH_PORT ?? "0", 10);
if (!port) throw new Error("OPENCODE_ROUTER_HEALTH_PORT is required");
const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const pathname = req.url ? new URL(req.url, "http://127.0.0.1").pathname : "";
    if (pathname === "/send") audit.sendCount += 1;
    flush();
    if (pathname === "/health" || pathname === "/" || pathname === "/send") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });
});
server.listen(port, "127.0.0.1", () => flush());
process.on("SIGTERM", () => server.close());
process.on("SIGINT", () => server.close());
`,
    "utf8",
  );
  const routerPath = path.join(root, "opencode-router");
  writeExecutable(
    routerPath,
    [
      "#!/bin/sh",
      `export ROUTER_AUDIT_PATH=${JSON.stringify(auditPath)}`,
      `exec ${JSON.stringify(process.execPath)} ${JSON.stringify(routerScript)} "$@"`,
      "",
    ].join("\n"),
  );
  return { assetService: await createFakeAssetService(opencodePath, routerPath), auditPath };
}

function createHarness(input: { auditPath?: string; bootstrapPolicy: "disabled" | "manual"; root: string }) {
  const previous = new Map(envKeys.map((key) => [key, process.env[key]]));
  process.env.OPENWORK_SERVER_V2_CLIENT_TOKEN = CLIENT_TOKEN;
  process.env.OPENWORK_SERVER_V2_HOST_TOKEN = HOST_TOKEN;
  delete process.env.OPENWORK_CLIENT_TOKEN;
  delete process.env.OPENWORK_TOKEN;
  delete process.env.OPENWORK_HOST_TOKEN;
  delete process.env.PERMISSION_MODE;
  if (input.auditPath) {
    process.env.ROUTER_AUDIT_PATH = input.auditPath;
  } else {
    delete process.env.ROUTER_AUDIT_PATH;
  }
  try {
    const dependencies = createAppDependencies({
      environment: "test",
      inMemory: true,
      runtime: { bootstrapPolicy: "disabled" },
      startedAt: new Date("2026-04-15T00:00:00.000Z"),
      version: "0.0.0-test",
      workingDirectory: input.root,
    });
    openApps.push(dependencies);
    return { app: createApp({ dependencies }), dependencies, root: input.root };
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

async function createManualHarness() {
  const root = createTempRoot("openwork-router-compat-manual");
  const auditPath = path.join(root, "router-audit.json");
  const { assetService } = await createRuntimeBinaries(auditPath);
  const previous = new Map(envKeys.map((key) => [key, process.env[key]]));
  process.env.OPENWORK_SERVER_V2_CLIENT_TOKEN = CLIENT_TOKEN;
  process.env.OPENWORK_SERVER_V2_HOST_TOKEN = HOST_TOKEN;
  delete process.env.OPENWORK_CLIENT_TOKEN;
  delete process.env.OPENWORK_TOKEN;
  delete process.env.OPENWORK_HOST_TOKEN;
  delete process.env.PERMISSION_MODE;
  process.env.ROUTER_AUDIT_PATH = auditPath;
  try {
    const dependencies = createAppDependencies({
      environment: "test",
      inMemory: true,
      runtime: {
        assetService,
        bootstrapPolicy: "manual",
        restartPolicy: { backoffMs: 25, maxAttempts: 0, windowMs: 1000 },
      },
      startedAt: new Date("2026-04-15T00:00:00.000Z"),
      version: "0.0.0-test",
      workingDirectory: root,
    });
    openApps.push(dependencies);
    return { app: createApp({ dependencies }), auditPath, dependencies, root };
  } finally {
    for (const [key, value] of previous) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

function routerBases(workspaceId: string) {
  return [
    `/workspace/${workspaceId}/opencode-router`,
    `/workspaces/${workspaceId}/opencode-router`,
  ];
}

function seedOwnerIdentities(dependencies: AppDependencies) {
  const serverId = dependencies.persistence.registry.localServerId;
  const repositories = dependencies.persistence.repositories;
  for (const identity of repositories.routerIdentities.listByServer(serverId)) {
    repositories.routerIdentities.deleteById(identity.id);
  }
  for (const binding of repositories.routerBindings.listByServer(serverId)) {
    repositories.routerBindings.deleteById(binding.id);
  }
  repositories.routerIdentities.upsert({
    auth: { token: TELEGRAM_TOKEN },
    config: { access: "private" },
    displayName: "owner-telegram",
    id: "owner-telegram",
    isEnabled: true,
    kind: "telegram",
    serverId,
  });
  repositories.routerIdentities.upsert({
    auth: { appToken: SLACK_APP_TOKEN, botToken: SLACK_BOT_TOKEN },
    config: {},
    displayName: "owner-slack",
    id: "owner-slack",
    isEnabled: true,
    kind: "slack",
    serverId,
  });
}

function routerStateFingerprint(dependencies: AppDependencies) {
  const serverId = dependencies.persistence.registry.localServerId;
  const identities = dependencies.persistence.repositories.routerIdentities.listByServer(serverId).map((identity) => ({
    access: typeof identity.config.access === "string" ? identity.config.access : null,
    enabled: identity.isEnabled,
    hasAppToken: typeof identity.auth?.appToken === "string" && identity.auth.appToken.length > 0,
    hasBotToken: typeof identity.auth?.botToken === "string" && identity.auth.botToken.length > 0,
    hasToken: typeof identity.auth?.token === "string" && identity.auth.token.length > 0,
    id: identity.id,
    kind: identity.kind,
  }));
  const bindings = dependencies.persistence.repositories.routerBindings.listByServer(serverId).map((binding) => ({
    directory: typeof binding.config.directory === "string" ? binding.config.directory : null,
    enabled: binding.isEnabled,
    identityId: binding.routerIdentityId,
    peerId: binding.bindingKey,
  }));
  return { bindings, identities };
}

function readMaterializedRouter(root: string) {
  const configPath = path.join(root, "runtime", "router", "opencode-router.json");
  if (!fs.existsSync(configPath)) {
    return null;
  }
  const config = JSON.parse(fs.readFileSync(configPath, "utf8")) as {
    channels?: { slack?: { apps?: Array<Record<string, unknown>> }; telegram?: { bots?: Array<Record<string, unknown>> } };
    opencodeDirectory?: string;
  };
  const bots = config.channels?.telegram?.bots ?? [];
  const apps = config.channels?.slack?.apps ?? [];
  return {
    opencodeDirectory: config.opencodeDirectory ?? null,
    slackApps: apps.map((app) => ({
      hasAppToken: typeof app.appToken === "string" && app.appToken.length > 0,
      hasBotToken: typeof app.botToken === "string" && app.botToken.length > 0,
      id: typeof app.id === "string" ? app.id : null,
    })),
    telegramBots: bots.map((bot) => ({
      access: typeof bot.access === "string" ? bot.access : null,
      enabled: bot.enabled === true,
      hasToken: typeof bot.token === "string" && bot.token.length > 0,
      id: typeof bot.id === "string" ? bot.id : null,
    })),
  };
}

function readAudit(auditPath: string) {
  if (!fs.existsSync(auditPath)) {
    return null;
  }
  const parsed = JSON.parse(fs.readFileSync(auditPath, "utf8")) as {
    permissionModeSet?: boolean;
    sendCount?: number;
    serveDirectory?: string | null;
  };
  return {
    permissionModeSet: Boolean(parsed.permissionModeSet),
    sendCount: parsed.sendCount ?? 0,
    serveDirectory: parsed.serveDirectory ?? null,
  };
}

test("configured tokens already protect the canonical router routes", async () => {
  installFetchStub();
  const root = createTempRoot("openwork-router-compat-control");
  const { app } = createHarness({ bootstrapPolicy: "disabled", root });
  const response = await app.request("http://openwork.local/system/router/bindings", {
    body: JSON.stringify({ channel: "telegram", directory: root, peerId: "4242" }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  expect(response.status).toBe(401);
});

test("a host token can still install a router identity with an application/json body", async () => {
  installFetchStub();
  const root = createTempRoot("openwork-router-compat-host");
  const { app, dependencies } = createHarness({ bootstrapPolicy: "disabled", root });
  const response = await app.request("http://openwork.local/workspaces/anything/opencode-router/telegram-token", {
    body: JSON.stringify({ token: TELEGRAM_TOKEN }),
    headers: hostHeaders("application/json; charset=utf-8"),
    method: "POST",
  });
  expect(response.status).toBe(200);
  const identities = routerStateFingerprint(dependencies).identities;
  expect(identities.some((identity) => identity.kind === "telegram" && identity.hasToken && identity.enabled)).toBe(true);
});

test("anonymous and non-json requests cannot install a telegram identity or start the router", async () => {
  installFetchStub();
  const { app, auditPath, dependencies, root } = await createManualHarness();
  const body = JSON.stringify({ token: TELEGRAM_TOKEN });
  const headers = { "content-type": "text/plain;charset=UTF-8" };
  const requests = [
    ["unconfigured-bearer", { authorization: `Bearer ${UNCONFIGURED_TOKEN}`, ...headers }],
    ["no-authorization", headers],
    ["singular-prefix", headers],
  ] as const;
  const statuses: Record<string, number> = {};
  const plural = await app.request("http://openwork.local/workspaces/anything/opencode-router/telegram-token", {
    body,
    headers: requests[0][1],
    method: "POST",
  });
  statuses[requests[0][0]] = plural.status;
  const plain = await app.request("http://openwork.local/workspaces/anything/opencode-router/telegram-token", {
    body,
    headers: requests[1][1],
    method: "POST",
  });
  statuses[requests[1][0]] = plain.status;
  const singular = await app.request("http://openwork.local/workspace/anything/opencode-router/telegram-token", {
    body,
    headers: requests[2][1],
    method: "POST",
  });
  statuses[requests[2][0]] = singular.status;

  const health = dependencies.services.runtime.getRouterHealth();
  expect({
    audit: readAudit(auditPath),
    config: readMaterializedRouter(root),
    identities: routerStateFingerprint(dependencies).identities,
    routerRunning: health.running,
    routerStatus: health.status,
    statuses,
  }).toEqual({
    audit: null,
    config: null,
    identities: [],
    routerRunning: false,
    routerStatus: "disabled",
    statuses: {
      "no-authorization": 401,
      "singular-prefix": 401,
      "unconfigured-bearer": 401,
    },
  });
}, 60_000);

test("anonymous callers cannot read or mutate router identities, bindings, enablement, or outbound send", async () => {
  installFetchStub();
  const root = createTempRoot("openwork-router-compat-matrix");
  const { app, dependencies } = createHarness({ bootstrapPolicy: "disabled", root });
  const outsideDirectory = path.join(root, "outside-workspace");
  fs.mkdirSync(outsideDirectory, { recursive: true });
  const textPlain = "text/plain;charset=UTF-8";
  const cases = [
    { method: "GET", path: "/telegram", headers: {} },
    { method: "POST", path: "/telegram-enabled", headers: { "content-type": textPlain }, body: JSON.stringify({ clearToken: true, enabled: false }) },
    { method: "GET", path: "/identities/telegram", headers: {} },
    { method: "POST", path: "/identities/telegram", headers: { "content-type": "application/json" }, body: JSON.stringify({ access: "public", enabled: true, id: "attacker-telegram", token: TELEGRAM_TOKEN }) },
    { method: "DELETE", path: "/identities/telegram/owner-telegram", headers: {} },
    { method: "GET", path: "/identities/slack", headers: {} },
    { method: "POST", path: "/identities/slack", headers: { "content-type": textPlain }, body: JSON.stringify({ appToken: SLACK_APP_TOKEN, botToken: SLACK_BOT_TOKEN, id: "attacker-slack" }) },
    { method: "DELETE", path: "/identities/slack/owner-slack", headers: {} },
    { method: "POST", path: "/slack-tokens", headers: { "content-type": "application/json" }, body: JSON.stringify({ appToken: SLACK_APP_TOKEN, botToken: SLACK_BOT_TOKEN }) },
    { method: "GET", path: "/bindings", headers: {} },
    { method: "POST", path: "/bindings", headers: { "content-type": textPlain }, body: JSON.stringify({ channel: "telegram", directory: outsideDirectory, peerId: "4242" }) },
    { method: "POST", path: "/send", headers: { "content-type": "application/json" }, body: JSON.stringify({ channel: "telegram", peerId: "4242", text: "hello" }) },
  ];

  const results = [];
  for (const base of routerBases("anything")) {
    for (const entry of cases) {
      seedOwnerIdentities(dependencies);
      const before = routerStateFingerprint(dependencies);
      const response = await app.request(`http://openwork.local${base}${entry.path}`, {
        body: "body" in entry ? entry.body : undefined,
        headers: entry.headers,
        method: entry.method,
      });
      results.push({
        after: routerStateFingerprint(dependencies),
        before,
        method: entry.method,
        path: `${base}${entry.path}`,
        status: response.status,
      });
    }
  }

  expect(results.map((result) => ({
    mutated: JSON.stringify(result.after) !== JSON.stringify(result.before),
    path: result.path,
    status: result.status,
  }))).toEqual(results.map((result) => ({
    mutated: false,
    path: result.path,
    status: 401,
  })));
});

test("a text/plain body does not change router state even when the host token is present", async () => {
  installFetchStub();
  const root = createTempRoot("openwork-router-compat-content-type");
  const { app, dependencies } = createHarness({ bootstrapPolicy: "disabled", root });
  seedOwnerIdentities(dependencies);
  const before = routerStateFingerprint(dependencies);
  const tokenResponse = await app.request("http://openwork.local/workspaces/anything/opencode-router/telegram-token", {
    body: JSON.stringify({ token: TELEGRAM_TOKEN }),
    headers: hostHeaders("text/plain;charset=UTF-8"),
    method: "POST",
  });
  const enabledResponse = await app.request("http://openwork.local/workspace/anything/opencode-router/telegram-enabled", {
    body: JSON.stringify({ clearToken: true, enabled: false }),
    headers: hostHeaders("text/plain"),
    method: "POST",
  });
  const bindingResponse = await app.request("http://openwork.local/workspaces/anything/opencode-router/bindings", {
    body: JSON.stringify({ channel: "slack", directory: root, identityId: "owner-slack", peerId: "U123" }),
    headers: hostHeaders("text/plain"),
    method: "POST",
  });
  const after = routerStateFingerprint(dependencies);
  const rejected = (status: number) => status === 400 || status === 415;
  expect({
    bindingRejected: rejected(bindingResponse.status),
    bindingStatus: bindingResponse.status,
    enabledRejected: rejected(enabledResponse.status),
    enabledStatus: enabledResponse.status,
    state: after,
    tokenRejected: rejected(tokenResponse.status),
    tokenStatus: tokenResponse.status,
  }).toEqual({
    bindingRejected: true,
    bindingStatus: bindingResponse.status === 415 ? 415 : 400,
    enabledRejected: true,
    enabledStatus: enabledResponse.status === 415 ? 415 : 400,
    state: before,
    tokenRejected: true,
    tokenStatus: tokenResponse.status === 415 ? 415 : 400,
  });
});

test("a client token cannot bind a hidden workspace directory the client is not allowed to read", async () => {
  installFetchStub();
  const root = createTempRoot("openwork-router-compat-hidden");
  const folder = path.join(root, "hidden-workspace");
  fs.mkdirSync(folder, { recursive: true });
  const { app, dependencies } = createHarness({ bootstrapPolicy: "disabled", root });
  const created = await app.request("http://openwork.local/workspaces/local", {
    body: JSON.stringify({ folderPath: folder, name: "Hidden", preset: "starter" }),
    headers: hostHeaders(),
    method: "POST",
  });
  expect(created.status).toBe(200);
  const workspaceId = (await created.json()).data.id as string;
  const record = dependencies.persistence.repositories.workspaces.getById(workspaceId);
  if (!record?.dataDir) {
    throw new Error("workspace data dir missing");
  }
  dependencies.persistence.repositories.workspaces.upsert({ ...record, isHidden: true });
  seedOwnerIdentities(dependencies);
  const hiddenRead = await app.request(`http://openwork.local/workspaces/${workspaceId}`, {
    headers: { authorization: `Bearer ${CLIENT_TOKEN}` },
  });
  expect(hiddenRead.status).toBe(404);
  const before = routerStateFingerprint(dependencies);
  const binding = await app.request(`http://openwork.local/workspaces/${workspaceId}/opencode-router/bindings`, {
    body: JSON.stringify({ channel: "telegram", peerId: "4242" }),
    headers: clientHeaders(),
    method: "POST",
  });
  const after = routerStateFingerprint(dependencies);
  expect({
    bindingRejected: binding.status === 403 || binding.status === 404,
    bindingStatus: binding.status,
    bindings: after.bindings,
    clientCanReadHiddenWorkspace: hiddenRead.status === 200,
  }).toEqual({
    bindingRejected: true,
    bindingStatus: binding.status === 404 ? 404 : 403,
    bindings: before.bindings,
    clientCanReadHiddenWorkspace: false,
  });
});

test("anonymous send is rejected before the supervised router receives it", async () => {
  installFetchStub();
  const { app, auditPath, dependencies } = await createManualHarness();
  seedOwnerIdentities(dependencies);
  await dependencies.services.runtime.bootstrap();
  expect(dependencies.services.runtime.getRouterHealth().running).toBe(true);
  const beforeSends = readAudit(auditPath)?.sendCount ?? 0;
  const response = await app.request("http://openwork.local/workspaces/anything/opencode-router/send", {
    body: JSON.stringify({ channel: "telegram", peerId: "4242", text: "run a shell command" }),
    headers: { "content-type": "text/plain;charset=UTF-8" },
    method: "POST",
  });
  const singular = await app.request("http://openwork.local/workspace/anything/opencode-router/send", {
    body: JSON.stringify({ channel: "slack", identityId: "owner-slack", peerId: "U123", text: "hello" }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  expect({
    sendCount: readAudit(auditPath)?.sendCount ?? 0,
    singularStatus: singular.status,
    status: response.status,
  }).toEqual({
    sendCount: beforeSends,
    singularStatus: 401,
    status: 401,
  });
}, 60_000);
