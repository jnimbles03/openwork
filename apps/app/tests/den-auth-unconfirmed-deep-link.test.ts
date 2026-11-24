import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Window } from "happy-dom";
import { act, createElement, useEffect } from "react";
import { createRoot, type Root } from "react-dom/client";

import {
  initializeDenBootstrapConfig,
  readDenSettings,
  writeDenSettings,
} from "../src/app/lib/den";
import { pushPendingDeepLinks } from "../src/app/lib/deep-link-bridge";
import type { OpenworkServerClient } from "../src/app/lib/openwork-server";
import type { Client, WorkspaceDisplay } from "../src/app/types";
import { DenAuthProvider, useDenAuth } from "../src/react-app/domains/cloud/den-auth-provider";
import { createProviderAuthStore } from "../src/react-app/domains/connections/provider-auth/store";
import { startDeepLinkBridge } from "../src/react-app/shell/startup-deep-links";

const OFFICIAL_ORIGIN = "https://app.openworklabs.com";
const HANDOFF_GRANT = "placeholder-handoff-grant";
const EXISTING_TOKEN = "placeholder-existing-token";
const OFFICIAL_EXCHANGED_TOKEN = "placeholder-official-exchanged-token";
const ATTACKER_EXCHANGED_TOKEN = "placeholder-attacker-exchanged-token";
const UNTRUSTED_PACKAGE = "placeholder-untrusted-provider";
const MODEL_API = "https://attacker.example/model";
const PROVIDER_RECORD_ID = "llm_provider_placeholder";
const EXISTING_ORG_ID = "org_existing";

type RecordedRequest = {
  method: string;
  href: string;
  body: string;
};

type JsonResult = { status: number; json: unknown };

const recorded: RecordedRequest[] = [];
let realFetch: typeof fetch;
let attackerServer: Server | null = null;
let attackerPort = 0;
let domWindow: Window | null = null;
let reactRoot: Root | null = null;
let authProbe: { status: string } = { status: "unknown" };

function attackerOrigin() {
  return `http://127.0.0.1:${attackerPort}`;
}

function providerPayload(includeKey: boolean) {
  return {
    id: PROVIDER_RECORD_ID,
    source: "custom",
    providerId: "placeholder-provider",
    name: "Placeholder Provider",
    providerConfig: {
      npm: UNTRUSTED_PACKAGE,
      env: ["PLACEHOLDER_ENV"],
      api: MODEL_API,
      options: { baseURL: MODEL_API },
    },
    hasApiKey: includeKey,
    apiKey: includeKey ? "placeholder-provider-key" : undefined,
    models: [{ id: "placeholder-model", name: "Placeholder Model", config: {} }],
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
  };
}

function denResponse(method: string, pathname: string, body: string, issuedToken: string): JsonResult {
  const path = pathname.replace(/\/api\/den(?=\/)/, "");
  if (method === "POST" && path === "/v1/auth/desktop-handoff/exchange") {
    const parsed = body ? (JSON.parse(body) as { grant?: string }) : {};
    if (parsed.grant !== HANDOFF_GRANT) {
      return { status: 404, json: { error: "grant_not_found" } };
    }
    return {
      status: 200,
      json: {
        token: issuedToken,
        user: { id: "user_placeholder", email: "attacker@example.com", name: "Attacker" },
      },
    };
  }
  if (method === "GET" && path === "/v1/me") {
    return {
      status: 200,
      json: { user: { id: "user_placeholder", email: "attacker@example.com", name: "Attacker" } },
    };
  }
  if (method === "GET" && path === "/v1/me/orgs") {
    return {
      status: 200,
      json: {
        orgs: [{ id: "org_attacker", name: "Attacker Org", slug: "attacker-org", role: "owner" }],
        activeOrgId: null,
        activeOrgSlug: null,
      },
    };
  }
  if (method === "POST" && path === "/api/auth/organization/set-active") {
    return { status: 200, json: {} };
  }
  if (method === "GET" && path === "/v1/llm-providers") {
    return { status: 200, json: { llmProviders: [providerPayload(false)] } };
  }
  if (method === "GET" && path === `/v1/llm-providers/${PROVIDER_RECORD_ID}/connect`) {
    return { status: 200, json: { llmProvider: providerPayload(true) } };
  }
  return { status: 404, json: { error: "not_found", message: pathname } };
}

function existingSessionResponse(method: string, pathname: string): JsonResult | null {
  const path = pathname.replace(/\/api\/den(?=\/)/, "");
  if (method === "GET" && path === "/v1/me") {
    return {
      status: 200,
      json: { user: { id: "user_existing", email: "existing@example.com", name: "Existing" } },
    };
  }
  if (method === "GET" && path === "/v1/me/orgs") {
    return {
      status: 200,
      json: {
        orgs: [{ id: EXISTING_ORG_ID, name: "Existing Org", slug: "existing", role: "owner" }],
        activeOrgId: EXISTING_ORG_ID,
        activeOrgSlug: "existing",
      },
    };
  }
  return null;
}

function responseForOfficial(method: string, pathname: string, body: string, bearer: string): JsonResult {
  const path = pathname.replace(/\/api\/den(?=\/)/, "");
  const exchange = method === "POST" && path === "/v1/auth/desktop-handoff/exchange";
  if (!exchange && bearer !== EXISTING_TOKEN && bearer !== OFFICIAL_EXCHANGED_TOKEN) {
    return { status: 401, json: { error: "unauthorized" } };
  }
  if (bearer === EXISTING_TOKEN) {
    const preserved = existingSessionResponse(method, pathname);
    if (preserved) return preserved;
    if (method === "GET" && path === "/v1/llm-providers") {
      return { status: 200, json: { llmProviders: [] } };
    }
    return { status: 404, json: { error: "not_found", message: pathname } };
  }
  return denResponse(method, pathname, body, OFFICIAL_EXCHANGED_TOKEN);
}

async function readRequestBody(request: IncomingMessage) {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function sendJson(response: ServerResponse, status: number, json: unknown) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(json));
}

async function startAttackerServer() {
  const server = createServer(async (request, response) => {
    const body = await readRequestBody(request);
    const href = `http://127.0.0.1:${attackerPort}${request.url ?? "/"}`;
    recorded.push({ method: request.method ?? "GET", href, body });
    const url = new URL(request.url ?? "/", attackerOrigin());
    const result = denResponse(request.method ?? "GET", url.pathname, body, ATTACKER_EXCHANGED_TOKEN);
    sendJson(response, result.status, result.json);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Attacker stand-in did not bind a port.");
  }
  attackerPort = address.port;
  attackerServer = server;
}

function bearerToken(init?: RequestInit) {
  const headers = new Headers(init?.headers);
  return headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
}

function installFetch() {
  realFetch = globalThis.fetch.bind(globalThis);
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const href =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const url = new URL(href);
    const body = typeof init?.body === "string" ? init.body : "";
    const method = init?.method ?? "GET";
    if (url.hostname === "127.0.0.1" || url.hostname === "localhost") {
      return realFetch(input, init);
    }
    recorded.push({ method, href, body });
    const result =
      url.origin === OFFICIAL_ORIGIN
        ? responseForOfficial(method, url.pathname, body, bearerToken(init))
        : denResponse(method, url.pathname, body, ATTACKER_EXCHANGED_TOKEN);
    return new Response(JSON.stringify(result.json), {
      status: result.status,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

function installDom(url: string) {
  const win = new Window({ url, settings: { disableJavaScriptEvaluation: true, disableCSSFileLoading: true } });
  const assigned = globalThis as typeof globalThis & Record<string, unknown>;
  assigned.window = win;
  assigned.document = win.document;
  assigned.navigator = win.navigator;
  assigned.HTMLElement = win.HTMLElement;
  assigned.Element = win.Element;
  assigned.Node = win.Node;
  assigned.Document = win.Document;
  assigned.DocumentFragment = win.DocumentFragment;
  assigned.CustomEvent = win.CustomEvent;
  assigned.Event = win.Event;
  assigned.EventTarget = win.EventTarget;
  assigned.MutationObserver = win.MutationObserver;
  assigned.NodeFilter = win.NodeFilter;
  assigned.getComputedStyle = win.getComputedStyle.bind(win);
  assigned.requestAnimationFrame = win.requestAnimationFrame.bind(win);
  assigned.cancelAnimationFrame = win.cancelAnimationFrame.bind(win);
  assigned.localStorage = win.localStorage;
  assigned.IS_REACT_ACT_ENVIRONMENT = true;
  domWindow = win;
  return win;
}

function AuthProbe() {
  const auth = useDenAuth();
  useEffect(() => {
    authProbe = { status: auth.status };
  });
  return null;
}

async function mountAuth() {
  const container = document.createElement("div");
  document.body.appendChild(container);
  reactRoot = createRoot(container);
  await act(async () => {
    reactRoot?.render(createElement(DenAuthProvider, null, createElement(AuthProbe)));
  });
}

function workspaceFiles() {
  let opencode = '{\n  "$schema": "https://opencode.ai/config.json"\n}\n';
  let openwork: Record<string, unknown> = {};
  const writes: string[] = [];
  const client = {
    getConfig: async () => ({ opencode: {}, openwork }),
    patchConfig: async (_workspaceId: string, payload: { openwork?: Record<string, unknown> }) => {
      openwork = payload.openwork ?? openwork;
      return {};
    },
    readOpencodeConfigFile: async () => ({
      path: "opencode.jsonc",
      exists: true,
      content: opencode,
    }),
    writeOpencodeConfigFile: async (_workspaceId: string, _scope: string, content: string) => {
      opencode = content;
      writes.push(content);
      return { ok: true, status: 0, stdout: "", stderr: "" };
    },
  } as unknown as OpenworkServerClient;
  return { client, writes, readOpencode: () => opencode };
}

function createSyncStore(files: ReturnType<typeof workspaceFiles>, reloads: { count: number }) {
  const workspace = {
    id: "workspace_placeholder",
    name: "Placeholder",
    path: "/tmp/placeholder-workspace",
    preset: "default",
    workspaceType: "local",
  } as WorkspaceDisplay;
  const opencode = {
    auth: { set: async () => ({ data: {} }) },
    instance: { dispose: async () => ({ data: {} }) },
    global: { health: async () => ({ data: { healthy: true } }) },
    config: {
      get: async () => ({ data: {} }),
      providers: async () => ({ data: { providers: [], default: {} } }),
    },
    provider: {
      list: async () => ({ data: { all: [], connected: [], default: {} } }),
    },
  } as unknown as Client;
  const store = createProviderAuthStore({
    client: () => opencode,
    providers: () => [],
    providerDefaults: () => ({}),
    providerConnectedIds: () => [],
    disabledProviders: () => [],
    selectedWorkspaceDisplay: () => workspace,
    selectedWorkspaceRoot: () => workspace.path,
    runtimeWorkspaceId: () => workspace.id,
    openworkServer: {
      getSnapshot: () =>
        ({
          openworkServerStatus: "connected",
          openworkServerClient: files.client,
          openworkServerCapabilities: { config: { read: true, write: true } },
        }) as never,
    },
    setProviders: () => undefined,
    setProviderDefaults: () => undefined,
    setProviderConnectedIds: () => undefined,
    setDisabledProviders: () => undefined,
    markOpencodeConfigReloadRequired: () => {
      reloads.count += 1;
    },
  });
  store.start();
  return store;
}

async function waitUntilSettled() {
  const deadline = Date.now() + 3000;
  let previous = "";
  let stable = 0;
  while (Date.now() < deadline) {
    const settings = readDenSettings();
    const key = `${authProbe.status}:${settings.authToken ?? ""}:${settings.baseUrl}:${settings.activeOrgId ?? ""}`;
    if (authProbe.status === "signed_in" && key === previous) {
      stable += 1;
      if (stable >= 3) return;
    } else {
      stable = 0;
      previous = key;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error(`Cloud session did not settle: ${authProbe.status} ${readDenSettings().authToken ?? ""}`);
}

async function flushAuth() {
  const start = Date.now();
  while (Date.now() - start < 1500) {
    if (recorded.some((entry) => entry.href.includes("/v1/auth/desktop-handoff/exchange"))) break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  if (!recorded.some((entry) => entry.href.includes("/v1/auth/desktop-handoff/exchange"))) return;

  let previous = "";
  let stable = 0;
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const settings = readDenSettings();
    const key = `${authProbe.status}:${settings.authToken ?? ""}:${settings.baseUrl}:${settings.activeOrgId ?? ""}`;
    if (key === previous && authProbe.status !== "checking" && authProbe.status !== "unknown") {
      stable += 1;
      if (stable >= 4) return;
    } else {
      stable = 0;
      previous = key;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function syncProviders(store: ReturnType<typeof createProviderAuthStore>) {
  await store.runCloudProviderSync("sign_in");
  await store.runCloudProviderSync("settings_cloud_opened");
  await store.runCloudProviderSync("app_launch");
  store.syncFromOptions();
  await store.runCloudProviderSync("interval");
}

function seedExistingSession() {
  writeDenSettings({
    baseUrl: OFFICIAL_ORIGIN,
    authToken: EXISTING_TOKEN,
    activeOrgId: EXISTING_ORG_ID,
    activeOrgSlug: "existing",
    activeOrgName: "Existing",
  });
}

beforeEach(async () => {
  recorded.length = 0;
  authProbe = { status: "unknown" };
  installFetch();
  await startAttackerServer();
  installDom(`${OFFICIAL_ORIGIN}/`);
  window.localStorage.clear();
  await initializeDenBootstrapConfig();
});

afterEach(async () => {
  await act(async () => {
    reactRoot?.unmount();
  });
  reactRoot = null;
  attackerServer?.closeAllConnections?.();
  await new Promise<void>((resolve) => attackerServer?.close(() => resolve()) ?? resolve());
  attackerServer = null;
  domWindow?.close();
  domWindow = null;
  globalThis.fetch = realFetch;
});

describe.serial("unsolicited den-auth deep links", () => {
  test("does not adopt an arbitrary server URL or import its provider package", async () => {
    const files = workspaceFiles();
    const reloads = { count: 0 };
    const store = createSyncStore(files, reloads);
    seedExistingSession();
    await mountAuth();
    await waitUntilSettled();
    recorded.length = 0;
    const link = `openwork://den-auth?grant=${encodeURIComponent(HANDOFF_GRANT)}&denBaseUrl=${encodeURIComponent(attackerOrigin())}`;
    pushPendingDeepLinks(window, [link]);
    await flushAuth();
    await syncProviders(store);

    const settings = readDenSettings();
    expect(recorded.filter((entry) => entry.href.includes("/desktop-handoff/exchange")).map((entry) => entry.href)).toEqual([]);
    expect(settings.baseUrl).toBe(OFFICIAL_ORIGIN);
    expect(settings.apiBaseUrl).toBe(`${OFFICIAL_ORIGIN}/api/den`);
    expect(settings.authToken).toBe(EXISTING_TOKEN);
    expect(settings.activeOrgId).toBe(EXISTING_ORG_ID);
    expect(files.readOpencode()).not.toContain(UNTRUSTED_PACKAGE);
    expect(files.readOpencode()).not.toContain(MODEL_API);
    expect(reloads.count).toBe(0);
    store.dispose();
  });

  test("does not exchange a grant on the default cloud origin without a sign-in the app started", async () => {
    const files = workspaceFiles();
    const reloads = { count: 0 };
    const store = createSyncStore(files, reloads);
    seedExistingSession();
    await mountAuth();
    await waitUntilSettled();
    recorded.length = 0;
    pushPendingDeepLinks(window, [`openwork://den-auth?grant=${encodeURIComponent(HANDOFF_GRANT)}`]);
    await flushAuth();
    await syncProviders(store);

    const settings = readDenSettings();
    expect(
      recorded.some(
        (entry) => entry.href.startsWith(`${OFFICIAL_ORIGIN}/`) && entry.href.includes("/desktop-handoff/exchange"),
      ),
    ).toBe(false);
    expect(settings.baseUrl).toBe(OFFICIAL_ORIGIN);
    expect(settings.authToken).toBe(EXISTING_TOKEN);
    expect(settings.activeOrgId).toBe(EXISTING_ORG_ID);
    expect(files.readOpencode()).not.toContain(UNTRUSTED_PACKAGE);
    expect(files.readOpencode()).not.toContain(MODEL_API);
    expect(reloads.count).toBe(0);
    store.dispose();
  });

  test("does not treat a non-http denBaseUrl as permission to use the default origin", async () => {
    const files = workspaceFiles();
    const reloads = { count: 0 };
    const store = createSyncStore(files, reloads);
    seedExistingSession();
    await mountAuth();
    await waitUntilSettled();
    recorded.length = 0;
    pushPendingDeepLinks(window, [
      `openwork://den-auth?grant=${encodeURIComponent(HANDOFF_GRANT)}&denBaseUrl=${encodeURIComponent("javascript:placeholder")}`,
    ]);
    await flushAuth();
    await syncProviders(store);

    expect(recorded.some((entry) => entry.href.includes("/desktop-handoff/exchange"))).toBe(false);
    expect(readDenSettings().authToken).toBe(EXISTING_TOKEN);
    expect(readDenSettings().baseUrl).toBe(OFFICIAL_ORIGIN);
    expect(files.readOpencode()).not.toContain(UNTRUSTED_PACKAGE);
    expect(reloads.count).toBe(0);
    store.dispose();
  });

  test("does not send a public denBaseUrl host the handoff grant or keep that host", async () => {
    const files = workspaceFiles();
    const reloads = { count: 0 };
    const store = createSyncStore(files, reloads);
    seedExistingSession();
    await mountAuth();
    await waitUntilSettled();
    recorded.length = 0;
    const link = `openwork://den-auth?grant=${encodeURIComponent(HANDOFF_GRANT)}&denBaseUrl=${encodeURIComponent("https://attacker.example")}`;
    pushPendingDeepLinks(window, [link]);
    await flushAuth();
    await syncProviders(store);

    expect(recorded.map((entry) => entry.href)).not.toContain(
      "https://attacker.example/v1/auth/desktop-handoff/exchange",
    );
    expect(readDenSettings().baseUrl).toBe(OFFICIAL_ORIGIN);
    expect(readDenSettings().authToken).toBe(EXISTING_TOKEN);
    expect(files.readOpencode()).not.toContain(UNTRUSTED_PACKAGE);
    expect(files.readOpencode()).not.toContain(MODEL_API);
    expect(reloads.count).toBe(0);
    store.dispose();
  });

  test("does not adopt a den-auth URL loaded as the web app location", async () => {
    domWindow?.close();
    installDom(
      `${OFFICIAL_ORIGIN}/den-auth?grant=${encodeURIComponent(HANDOFF_GRANT)}&denBaseUrl=${encodeURIComponent(attackerOrigin())}`,
    );
    window.localStorage.clear();
    await initializeDenBootstrapConfig();
    seedExistingSession();
    const files = workspaceFiles();
    const reloads = { count: 0 };
    const store = createSyncStore(files, reloads);
    await mountAuth();
    await waitUntilSettled();
    recorded.length = 0;
    startDeepLinkBridge();
    await flushAuth();
    await syncProviders(store);

    expect(
      recorded.some((entry) => entry.href.startsWith(attackerOrigin()) && entry.href.includes("/desktop-handoff/exchange")),
    ).toBe(false);
    expect(readDenSettings().baseUrl).toBe(OFFICIAL_ORIGIN);
    expect(readDenSettings().authToken).toBe(EXISTING_TOKEN);
    expect(files.readOpencode()).not.toContain(UNTRUSTED_PACKAGE);
    expect(reloads.count).toBe(0);
    store.dispose();
  });
});
