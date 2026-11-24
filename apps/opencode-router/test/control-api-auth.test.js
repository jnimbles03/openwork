import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { Readable, Writable } from "node:stream";
import test from "node:test";
import assert from "node:assert/strict";

import { startBridge } from "../dist/bridge.js";
import { loadConfig, readConfigFile } from "../dist/config.js";
import { BridgeStore } from "../dist/db.js";

const ATTACK_ORIGIN = "https://evil.example";
const CONTROL_TOKEN_ENV = "OPENCODE_ROUTER_CONTROL_TOKEN";
const CONTROL_TOKEN = "placeholder-control-token";
const TELEGRAM_TOKEN = "placeholder-telegram-bot-token";
const EXISTING_TELEGRAM_TOKEN = "placeholder-existing-telegram-token";
const SLACK_BOT_TOKEN = "placeholder-slack-bot-token";
const SLACK_APP_TOKEN = "placeholder-slack-app-token";
const EXISTING_SLACK_BOT_TOKEN = "placeholder-existing-slack-bot-token";
const EXISTING_SLACK_APP_TOKEN = "placeholder-existing-slack-app-token";
const ATTACKER_TEXT = "workspace-probe";
const PAIRING_HASH = "a".repeat(64);

const originalHttpsRequest = https.request;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function headerValue(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === "function") {
    const value = headers.get(name);
    return value === null ? undefined : value;
  }
  const raw = headers[name.toLowerCase()];
  if (Array.isArray(raw)) return raw.join(", ");
  return raw;
}

function assertNoAttackCors(headers) {
  const origin = headerValue(headers, "access-control-allow-origin");
  assert.notEqual(origin, ATTACK_ORIGIN);
  assert.notEqual(origin, "*");
  assert.notEqual(headerValue(headers, "access-control-allow-private-network"), "true");
  const allowHeaders = headerValue(headers, "access-control-allow-headers") ?? "";
  assert.equal(allowHeaders.toLowerCase().includes("x-attacker-probe"), false);
}

function assertRejected(status) {
  assert.ok(status === 401 || status === 403, `expected 401 or 403, received ${status}`);
}

class FakeIncomingMessage extends Readable {
  constructor(statusCode, body) {
    super();
    this.statusCode = statusCode;
    this.statusMessage = statusCode === 200 ? "OK" : "ERROR";
    const payload = Buffer.from(body);
    this.headers = {
      "content-type": "application/json",
      "content-length": String(payload.length),
    };
    this._payload = payload;
  }

  _read() {
    if (this._payload) {
      this.push(this._payload);
      this._payload = null;
      return;
    }
    this.push(null);
  }
}

class FakeClientRequest extends Writable {
  constructor(target, onResponse) {
    super();
    this.target = target;
    this.chunks = [];
    this.aborted = false;
    this.finished = false;
    if (typeof onResponse === "function") this.on("response", onResponse);
    this.on("finish", () => {
      this.finished = true;
      this.dispatch();
    });
  }

  setTimeout() {
    return this;
  }

  setHeader() {}

  getHeader() {
    return undefined;
  }

  abort() {
    this.aborted = true;
    this.emit("abort");
    if (!this.responseSent) {
      this.responseSent = true;
      this.emit("error", new Error("aborted"));
    }
  }

  dispatch() {
    if (this.aborted || this.responseSent) return;
    const body = Buffer.concat(this.chunks).toString("utf8");
    const outcome = this.target.hostname === "api.telegram.org" ? telegramResult(this.target.path, body) : slackResult();
    if (outcome.hang) {
      this.hanging = true;
      return;
    }
    this.respond(outcome.statusCode, outcome.body);
  }

  respond(statusCode, body) {
    if (this.responseSent) return;
    this.responseSent = true;
    const incoming = new FakeIncomingMessage(statusCode, body);
    this.emit("response", incoming);
  }
}

const telegramUpdates = new Map();

function telegramResult(requestPath, rawBody) {
  const match = String(requestPath ?? "").match(/^\/bot([^/]+)\/([^/?]+)/);
  const token = match?.[1] ?? "";
  const method = match?.[2] ?? "";
  if (method === "getMe") {
    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: true,
        result: { id: 999, is_bot: true, first_name: "Placeholder", username: "placeholder_bot" },
      }),
    };
  }
  if (method === "deleteWebhook") {
    return { statusCode: 200, body: JSON.stringify({ ok: true, result: true }) };
  }
  if (method === "getUpdates") {
    const seen = telegramUpdates.get(token) ?? 0;
    if (seen === 0) {
      telegramUpdates.set(token, 1);
      return {
        statusCode: 200,
        body: JSON.stringify({
          ok: true,
          result: [
            {
              update_id: 1,
              message: {
                message_id: 10,
                date: 1_700_000_000,
                chat: { id: 4242, type: "private" },
                from: { id: 111, is_bot: false, first_name: "Visitor" },
                text: ATTACKER_TEXT,
              },
            },
          ],
        }),
      };
    }
    return { hang: true };
  }
  if (method === "sendMessage") {
    let chatId = 4242;
    try {
      const parsed = JSON.parse(rawBody || "{}");
      if (typeof parsed.chat_id === "number") chatId = parsed.chat_id;
    } catch {
      // grammy always sends JSON; a parse failure still has to answer the call.
    }
    return {
      statusCode: 200,
      body: JSON.stringify({
        ok: true,
        result: {
          message_id: 11,
          date: 1_700_000_001,
          chat: { id: chatId, type: "private" },
          text: "ack",
        },
      }),
    };
  }
  return { statusCode: 200, body: JSON.stringify({ ok: true, result: true }) };
}

function slackResult() {
  return { statusCode: 200, body: JSON.stringify({ ok: false, error: "invalid_auth" }) };
}

function resolveHttpsTarget(args) {
  const [first, second] = args;
  if (typeof first === "string" || first instanceof URL) {
    const url = new URL(first);
    return {
      hostname: url.hostname,
      path: `${url.pathname}${url.search}`,
      callback: typeof second === "function" ? second : args.find((entry) => typeof entry === "function"),
    };
  }
  const options = first ?? {};
  const host = String(options.hostname || options.host || "").split(":")[0];
  return {
    hostname: host,
    path: options.path || options.pathname || "/",
    callback: args.find((entry) => typeof entry === "function"),
  };
}

https.request = function patchedHttpsRequest(...args) {
  const target = resolveHttpsTarget(args);
  if (target.hostname !== "api.telegram.org" && target.hostname !== "slack.com") {
    return originalHttpsRequest.apply(https, args);
  }
  return new FakeClientRequest(target, target.callback);
};

function createLoggerStub() {
  const base = {
    child() {
      return base;
    },
    debug() {},
    info() {},
    warn() {},
    error() {},
  };
  return base;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

function startOpencodeMock() {
  const sessions = [];
  const prompts = [];
  const permissionReplies = [];
  const streams = [];
  let connected;

  const connectedPromise = new Promise((resolve) => {
    connected = resolve;
  });

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = raw ? JSON.parse(raw) : {};
      if (req.method === "GET" && url.pathname === "/global/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ healthy: true, version: "1.4.9" }));
        return;
      }
      if (req.method === "GET" && url.pathname === "/event") {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });
        streams.push(res);
        connected();
        req.on("close", () => {
          res.end();
        });
        return;
      }
      if (req.method === "POST" && url.pathname === "/session") {
        sessions.push(body);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ id: "session-1" }));
        return;
      }
      if (req.method === "POST" && url.pathname === "/session/session-1/message") {
        prompts.push(body);
        const frame = `data: ${JSON.stringify({
          type: "permission.asked",
          properties: { id: "perm-1", sessionID: "session-1" },
        })}\n\n`;
        for (const stream of streams) stream.write(frame);
        const started = Date.now();
        const finish = () => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ parts: [{ type: "text", text: "ack" }] }));
        };
        const wait = () => {
          if (permissionReplies.length > 0 || Date.now() - started > 1000) {
            finish();
            return;
          }
          setTimeout(wait, 20);
        };
        wait();
        return;
      }
      const permissionMatch = url.pathname.match(/^\/session\/([^/]+)\/permissions\/([^/]+)$/);
      if (req.method === "POST" && permissionMatch) {
        permissionReplies.push({
          sessionID: permissionMatch[1],
          permissionID: permissionMatch[2],
          body,
        });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(true));
        return;
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "not found", path: url.pathname }));
    });
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}`,
        sessions,
        prompts,
        permissionReplies,
        whenConnected: () => connectedPromise,
        async close() {
          for (const stream of streams) stream.end();
          await new Promise((done) => server.close(done));
        },
      });
    });
  });
}

function writeSeedConfig(configPath) {
  const config = {
    version: 1,
    channels: {
      telegram: {
        enabled: true,
        bots: [
          {
            id: "existing",
            token: EXISTING_TELEGRAM_TOKEN,
            enabled: false,
            access: "private",
            pairingCodeHash: PAIRING_HASH,
          },
        ],
      },
      slack: {
        enabled: true,
        apps: [
          {
            id: "existing",
            botToken: EXISTING_SLACK_BOT_TOKEN,
            appToken: EXISTING_SLACK_APP_TOKEN,
            enabled: false,
          },
        ],
      },
    },
  };
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`);
}

async function startRouter(options = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opencode-router-control-"));
  const configPath = path.join(dir, "opencode-router.json");
  writeSeedConfig(configPath);
  const healthPort = await freePort();
  const opencode = options.opencode ?? (await startOpencodeMock());
  const env = {
    OPENCODE_ROUTER_DATA_DIR: dir,
    OPENCODE_ROUTER_DB_PATH: path.join(dir, "opencode-router.db"),
    OPENCODE_ROUTER_CONFIG_PATH: configPath,
    OPENCODE_ROUTER_LOG_FILE: path.join(dir, "logs", "opencode-router.log"),
    OPENCODE_DIRECTORY: dir,
    OPENCODE_URL: opencode.url,
    OPENCODE_ROUTER_HEALTH_PORT: String(healthPort),
  };
  const config = loadConfig(env, { requireOpencode: false });
  assert.equal(config.permissionMode, "allow");
  const store = new BridgeStore(config.dbPath);
  store.upsertBinding("slack", "default", "D123", dir);
  const sent = [];
  const slackAdapter = {
    key: "slack:default",
    name: "slack",
    identityId: "default",
    maxTextLength: 39_000,
    async start() {},
    async stop() {},
    async sendText(peerId, text) {
      sent.push({ peerId, text });
    },
  };
  const bridge = await startBridge(config, createLoggerStub(), undefined, {
    store,
    adapters: options.injectAdapters === false ? undefined : new Map([["slack:default", slackAdapter]]),
    disableEventStream: options.disableEventStream === true,
  });
  if (options.disableEventStream !== true) {
    await Promise.race([
      opencode.whenConnected(),
      delay(2000).then(() => {
        throw new Error("OpenCode event stream did not connect");
      }),
    ]);
  }
  return {
    dir,
    configPath,
    healthPort,
    opencode,
    store,
    sent,
    bridge,
    async stop() {
      await bridge.stop();
      if (!options.opencode) await opencode.close();
    },
  };
}

async function browserFetch(port, method, requestPath, body, extraHeaders = {}) {
  return fetch(`http://127.0.0.1:${port}${requestPath}`, {
    method,
    headers: {
      Origin: ATTACK_ORIGIN,
      "Access-Control-Request-Private-Network": "true",
      "Access-Control-Request-Headers": "content-type, x-attacker-probe",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...extraHeaders,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

function rawRequest(port, { method, requestPath, host, headers, body }) {
  return new Promise((resolve, reject) => {
    const payload = body ?? "";
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: requestPath,
        headers: {
          ...headers,
          Host: host,
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("error", reject);
    req.end(payload);
  });
}

function configText(configPath) {
  return fs.readFileSync(configPath, "utf8");
}

test("health and preflight responses do not open the control server to a public origin", async () => {
  const router = await startRouter({ disableEventStream: true });
  try {
    const health = await browserFetch(router.healthPort, "GET", "/health");
    assert.equal(health.status, 200);
    assertNoAttackCors(health.headers);

    const preflight = await browserFetch(router.healthPort, "OPTIONS", "/identities/telegram");
    assertNoAttackCors(preflight.headers);
  } finally {
    await router.stop();
  }
});

test("unauthenticated browser calls cannot read or mutate control routes", async () => {
  delete process.env[CONTROL_TOKEN_ENV];
  const router = await startRouter({ disableEventStream: true });
  const before = configText(router.configPath);
  try {
    const calls = [
      ["GET", "/identities/telegram"],
      ["GET", "/identities/slack"],
      ["GET", "/bindings"],
      ["GET", "/config/groups"],
      ["POST", "/identities/telegram", { token: TELEGRAM_TOKEN, access: "public", directory: ".", enabled: false }],
      ["POST", "/config/telegram-token", { token: TELEGRAM_TOKEN }],
      ["POST", "/identities/slack", { botToken: SLACK_BOT_TOKEN, appToken: SLACK_APP_TOKEN, enabled: false }],
      ["POST", "/config/slack-tokens", { botToken: SLACK_BOT_TOKEN, appToken: SLACK_APP_TOKEN }],
      ["DELETE", "/identities/telegram/existing"],
      ["DELETE", "/identities/slack/existing"],
      ["POST", "/config/groups", { enabled: true }],
      ["POST", "/bindings", { channel: "slack", identityId: "default", peerId: "D999", directory: router.dir }],
      ["POST", "/bindings", { channel: "slack", identityId: "default", peerId: "D123", directory: "" }],
      ["POST", "/send", { channel: "slack", directory: router.dir, text: ATTACKER_TEXT }],
    ];

    for (const [method, requestPath, body] of calls) {
      const response = await browserFetch(router.healthPort, method, requestPath, body);
      assertRejected(response.status);
      assertNoAttackCors(response.headers);
    }

    await delay(300);
    assert.equal(configText(router.configPath), before);
    assert.equal(router.store.getBinding("slack", "default", "D123")?.directory, router.dir);
    assert.equal(router.store.getBinding("slack", "default", "D999"), null);
    assert.equal(router.sent.length, 0);
    assert.equal(router.opencode.sessions.length, 0);
    assert.equal(router.opencode.prompts.length, 0);
    assert.equal(router.opencode.permissionReplies.length, 0);
  } finally {
    await router.stop();
  }
});

test("a rebinding Host is rejected before the control server changes identity state", async () => {
  delete process.env[CONTROL_TOKEN_ENV];
  const router = await startRouter({ disableEventStream: true });
  const before = configText(router.configPath);
  try {
    const response = await rawRequest(router.healthPort, {
      method: "POST",
      requestPath: "/identities/telegram",
      host: "rebinding.example",
      headers: {
        Origin: "http://rebinding.example",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ token: TELEGRAM_TOKEN, access: "public", directory: ".", enabled: false }),
    });
    assert.ok(response.status === 400 || response.status === 403, `expected 400 or 403, received ${response.status}`);
    await delay(200);
    assert.equal(configText(router.configPath), before);
    assert.equal(router.opencode.sessions.length, 0);
  } finally {
    await router.stop();
  }
});

test("a wrong control token cannot create a telegram identity", async () => {
  process.env[CONTROL_TOKEN_ENV] = CONTROL_TOKEN;
  const router = await startRouter({ disableEventStream: true });
  const before = configText(router.configPath);
  try {
    const response = await browserFetch(
      router.healthPort,
      "POST",
      "/identities/telegram",
      { token: TELEGRAM_TOKEN, access: "public", directory: ".", enabled: false },
      { Authorization: "Bearer placeholder-wrong-control-token" },
    );
    assertRejected(response.status);
    assertNoAttackCors(response.headers);
    await delay(200);
    assert.equal(configText(router.configPath), before);
  } finally {
    delete process.env[CONTROL_TOKEN_ENV];
    await router.stop();
  }
});

test("the process control token can disable a new identity without reflecting CORS", async () => {
  process.env[CONTROL_TOKEN_ENV] = CONTROL_TOKEN;
  const router = await startRouter({ disableEventStream: true });
  try {
    const response = await fetch(`http://127.0.0.1:${router.healthPort}/identities/telegram`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${CONTROL_TOKEN}`,
      },
      body: JSON.stringify({
        id: "operator",
        token: TELEGRAM_TOKEN,
        enabled: false,
        access: "private",
        pairingCodeHash: PAIRING_HASH,
      }),
    });
    assert.equal(response.status, 200);
    assert.equal(headerValue(response.headers, "access-control-allow-origin"), undefined);
    assert.notEqual(headerValue(response.headers, "access-control-allow-private-network"), "true");
    const saved = readConfigFile(router.configPath);
    const bots = saved.config.channels?.telegram?.bots ?? [];
    assert.equal(
      bots.some((bot) => bot.id === "operator" && bot.enabled === false && bot.access === "private"),
      true,
    );
  } finally {
    delete process.env[CONTROL_TOKEN_ENV];
    await router.stop();
  }
});

test("a public page cannot register a telegram bot that prompts OpenCode with every tool allowed", async () => {
  delete process.env[CONTROL_TOKEN_ENV];
  const router = await startRouter({ injectAdapters: false });
  const before = configText(router.configPath);
  try {
    const preflight = await browserFetch(router.healthPort, "OPTIONS", "/identities/telegram");
    assertNoAttackCors(preflight.headers);

    const response = await browserFetch(router.healthPort, "POST", "/identities/telegram", {
      token: TELEGRAM_TOKEN,
      access: "public",
      directory: ".",
    });
    assertRejected(response.status);
    assertNoAttackCors(response.headers);

    const deadline = Date.now() + 1000;
    while (Date.now() < deadline) {
      if (router.opencode.sessions.length > 0 || configText(router.configPath) !== before) break;
      await delay(50);
    }

    assert.equal(configText(router.configPath), before);
    assert.equal(router.opencode.sessions.length, 0);
    assert.equal(router.opencode.prompts.length, 0);
    assert.equal(
      router.opencode.permissionReplies.some((reply) => reply.body?.response === "always"),
      false,
    );
  } finally {
    await router.stop();
  }
});
