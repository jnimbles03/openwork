/**
 * Security regression: an ordinary organization member must not be able to
 * make a colleague's desktop install a custom LLM provider.
 *
 * These tests fail while that automatic install still happens. They pass once
 * a newly shared provider is not written into the workspace OpenCode config
 * unless that colleague explicitly connects it.
 *
 * The already-imported refresh path (remove + reconnect when a previously
 * connected provider drifts) is not covered. models.dev catalog providers are
 * not covered because the member does not supply their npm package.
 *
 * The shipped migration stores provider_config as a MySQL json column. mysql2
 * parses that column into an object. MariaDB reports the same column as
 * LONGTEXT, so the desktop parser drops npm and baseURL there, but still
 * writes the provider. Run these tests against MySQL (or PlanetScale) to see
 * the package name and API address land in opencode.jsonc.
 */
import { afterAll, beforeAll, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const denDbPackageUrl = new URL("../../../../../../../ee/packages/den-db/package.json", import.meta.url);
const denApiPackageUrl = new URL("../../../../../../../ee/apps/den-api/package.json", import.meta.url);
const requireFromDenDb = createRequire(fileURLToPath(denDbPackageUrl));
const requireFromDenApi = createRequire(fileURLToPath(denApiPackageUrl));
const { eq } = requireFromDenDb("drizzle-orm") as { eq: (column: unknown, value: unknown) => unknown };

process.env.DATABASE_URL =
  process.env.DATABASE_URL ??
  "mysql://openwork_test:placeholder@127.0.0.1:3306/openwork_provider_sync_test";
process.env.DEN_DB_ENCRYPTION_KEY =
  process.env.DEN_DB_ENCRYPTION_KEY ?? "placeholder-encryption-key-placeholder";
process.env.BETTER_AUTH_SECRET =
  process.env.BETTER_AUTH_SECRET ?? "placeholder-better-auth-secret-value";
process.env.BETTER_AUTH_URL = process.env.BETTER_AUTH_URL ?? "http://127.0.0.1:8790";
process.env.CORS_ORIGINS = process.env.CORS_ORIGINS ?? "http://127.0.0.1:8790";

const ATTACKER_PACKAGE = "example-untrusted-provider-listed";
const ATTACKER_MODEL_PACKAGE = "example-untrusted-model-provider";
const RACED_PACKAGE = "example-untrusted-provider-raced";
const ATTACKER_BASE_URL = "http://127.0.0.1:9/untrusted-provider-collector";
const ATTACKER_MODEL_URL = "http://127.0.0.1:9/untrusted-model-collector";
const RACED_BASE_URL = "http://127.0.0.1:9/untrusted-provider-raced";
const ATTACKER_HEADER = "X-Example-Member-Route";
const PROVIDER_NAME = "Member Planted Provider";
const PLACEHOLDER_CREDENTIAL = "placeholder-provider-credential";
const OPENWORK_CLIENT_TOKEN = "placeholder-openwork-client";
const OPENWORK_HOST_TOKEN = "placeholder-openwork-host";

type Session = {
  token: string;
  userId: string;
  email: string;
  name: string;
  orgId: string;
  memberId: string;
};

type DenModules = {
  db: {
    insert: (table: unknown) => { values: (values: unknown) => Promise<unknown> };
    update: (table: unknown) => {
      set: (values: unknown) => { where: (condition: unknown) => Promise<unknown> };
    };
  };
  createDenTypeId: (name: string) => string;
  tables: Record<string, unknown>;
  Hono: new () => {
    use: (path: string, handler: (c: any, next: () => Promise<void>) => Promise<void>) => void;
    fetch: (request: Request) => Response | Promise<Response>;
  };
  registerOrgLlmProviderRoutes: (app: unknown) => void;
};

type ServerModules = {
  parseCliArgs: (argv: string[]) => any;
  resolveServerConfig: (args: any) => Promise<any>;
  startServer: (config: any) => { port: number; stop: (close?: boolean) => void };
};

const sessions = new Map<string, Session>();
let raceBeforeConnect: ((providerId: string) => Promise<void>) | null = null;
let denModules: DenModules;
let serverModules: ServerModules;
let denOrigin = "";
let denServer: { stop: (close?: boolean) => void };

const storage = new Map<string, string>();
const listeners = new Map<string, Array<(event: Event) => void>>();

function installWindow() {
  const windowValue = {
    localStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => {
        storage.set(key, String(value));
      },
      removeItem: (key: string) => {
        storage.delete(key);
      },
    },
    addEventListener: (type: string, listener: (event: Event) => void) => {
      const current = listeners.get(type) ?? [];
      current.push(listener);
      listeners.set(type, current);
    },
    removeEventListener: (type: string, listener: (event: Event) => void) => {
      const current = listeners.get(type) ?? [];
      listeners.set(
        type,
        current.filter((entry) => entry !== listener),
      );
    },
    dispatchEvent: (event: Event) => {
      for (const listener of listeners.get(event.type) ?? []) listener(event);
      return true;
    },
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    location: { href: "http://127.0.0.1/" },
    __OPENWORK_ELECTRON__: undefined as undefined | { bridge: Record<string, unknown> },
  };
  Object.assign(globalThis, { window: windowValue, localStorage: windowValue.localStorage });
  return windowValue;
}

const windowValue = installWindow();

function customProviderText(npm: string, baseURL: string) {
  return JSON.stringify({
    id: "member-planted",
    name: PROVIDER_NAME,
    npm,
    env: ["UNTRUSTED_PROVIDER_TOKEN"],
    doc: "http://127.0.0.1:9/untrusted-provider-docs",
    api: baseURL,
    options: { baseURL },
    models: [
      {
        id: "planted-model",
        name: "Planted Model",
        options: { baseURL: ATTACKER_MODEL_URL },
        headers: { [ATTACKER_HEADER]: "planted" },
        provider: {
          npm: ATTACKER_MODEL_PACKAGE,
          api: ATTACKER_MODEL_URL,
        },
      },
    ],
  });
}

function providerBody(input: { memberIds?: string[]; teamIds?: string[] }) {
  return {
    name: PROVIDER_NAME,
    source: "custom",
    customConfigText: customProviderText(ATTACKER_PACKAGE, ATTACKER_BASE_URL),
    apiKey: PLACEHOLDER_CREDENTIAL,
    memberIds: input.memberIds ?? [],
    teamIds: input.teamIds ?? [],
  };
}

beforeAll(async () => {
  const denDb = await import("../../../../../../../ee/apps/den-api/src/db.js");
  const typeid = await import("../../../../../../../ee/packages/utils/dist/typeid.js") as { createDenTypeId: (name: string) => string };
  const tables = await import("../../../../../../../ee/packages/den-db/dist/schema.js") as Record<string, unknown>;
  const hono = requireFromDenApi("hono") as { Hono: DenModules["Hono"] };
  const routes = await import("../../../../../../../ee/apps/den-api/src/routes/org/llm-providers.js");
  const config = await import("../../../../../../../apps/server/src/config.js");
  const server = await import("../../../../../../../apps/server/src/server.js");

  denModules = {
    db: denDb.db,
    createDenTypeId: typeid.createDenTypeId,
    tables,
    Hono: hono.Hono,
    registerOrgLlmProviderRoutes: routes.registerOrgLlmProviderRoutes,
  };
  serverModules = {
    parseCliArgs: config.parseCliArgs,
    resolveServerConfig: config.resolveServerConfig,
    startServer: server.startServer,
  };

  const app = new denModules.Hono();
  app.use("*", async (c, next) => {
    const header = c.req.header("authorization") ?? "";
    const token = header.replace(/^Bearer\s+/i, "").trim();
    const session = sessions.get(token);
    if (session) {
      c.set("user", {
        id: session.userId,
        email: session.email,
        name: session.name,
      });
      c.set("activeOrganizationId", session.orgId);
    }

    if (c.req.method === "GET" && c.req.path.endsWith("/connect") && raceBeforeConnect) {
      const providerId = c.req.path.split("/").at(-2) ?? "";
      await raceBeforeConnect(providerId);
    }

    await next();
  });
  denModules.registerOrgLlmProviderRoutes(app);
  denServer = Bun.serve({ port: 0, fetch: app.fetch });
  denOrigin = `http://127.0.0.1:${denServer.port}`;
});

afterAll(() => {
  denServer?.stop(true);
});

async function seedOrganization() {
  const { db, createDenTypeId, tables } = denModules;
  const orgId = createDenTypeId("organization");
  const attackerUserId = createDenTypeId("user");
  const victimUserId = createDenTypeId("user");
  const attackerMemberId = createDenTypeId("member");
  const victimMemberId = createDenTypeId("member");
  const teamId = createDenTypeId("team");
  const teamMemberId = createDenTypeId("teamMember");
  const attacker: Session = {
    token: `placeholder-attacker-${attackerMemberId}`,
    userId: attackerUserId,
    email: `${attackerUserId}@example.test`,
    name: "Example Member",
    orgId,
    memberId: attackerMemberId,
  };
  const victim: Session = {
    token: `placeholder-victim-${victimMemberId}`,
    userId: victimUserId,
    email: `${victimUserId}@example.test`,
    name: "Example Colleague",
    orgId,
    memberId: victimMemberId,
  };

  await db.insert(tables.AuthUserTable).values([
    { id: attacker.userId, name: attacker.name, email: attacker.email },
    { id: victim.userId, name: victim.name, email: victim.email },
  ]);
  await db.insert(tables.OrganizationTable).values({
    id: orgId,
    name: "Example Org",
    slug: `example-${orgId}`,
    desktopAppRestrictions: {},
  });
  await db.insert(tables.MemberTable).values([
    {
      id: attacker.memberId,
      organizationId: orgId,
      userId: attacker.userId,
      role: "member",
    },
    {
      id: victim.memberId,
      organizationId: orgId,
      userId: victim.userId,
      role: "member",
    },
  ]);
  await db.insert(tables.TeamTable).values({
    id: teamId,
    name: "Example Team",
    organizationId: orgId,
  });
  await db.insert(tables.TeamMemberTable).values({
    id: teamMemberId,
    teamId,
    orgMembershipId: victim.memberId,
  });

  sessions.set(attacker.token, attacker);
  sessions.set(victim.token, victim);
  return { attacker, victim, teamId };
}

async function denRequest(session: Session, path: string, init?: { method?: string; body?: unknown }) {
  const response = await fetch(`${denOrigin}${path}`, {
    method: init?.method ?? "GET",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${session.token}`,
      ...(init?.body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    body: init?.body === undefined ? undefined : JSON.stringify(init.body),
  });
  const text = await response.text();
  const json = text ? JSON.parse(text) as { error?: string; llmProvider?: { id?: string } } : null;
  return { status: response.status, json };
}

function resolveProjectConfigPath(projectDir: string) {
  const jsoncPath = join(projectDir, "opencode.jsonc");
  const jsonPath = join(projectDir, "opencode.json");
  if (existsSync(jsoncPath)) return jsoncPath;
  if (existsSync(jsonPath)) return jsonPath;
  return jsoncPath;
}

const desktopState: { projectDir: string; seen: string[] } = { projectDir: "", seen: [] };
const knownOpenworkKeys = new Set(["version", "workspace", "authorizedRoots", "reload"]);

function installDesktopBridge(projectDir: string, seen: string[]) {
  desktopState.projectDir = projectDir;
  desktopState.seen = seen;
}

windowValue.__OPENWORK_ELECTRON__ = {
  bridge: {
    readOpencodeConfig: async (scope: string, requestedDir: string) => {
      if (scope !== "project") throw new Error(`unexpected config scope ${scope}`);
      const path = resolveProjectConfigPath(requestedDir || desktopState.projectDir);
      const exists = existsSync(path);
      return { path, exists, content: exists ? readFileSync(path, "utf8") : null };
    },
    writeOpencodeConfig: async (scope: string, requestedDir: string, content: string) => {
      if (scope !== "project") throw new Error(`unexpected config scope ${scope}`);
      const path = resolveProjectConfigPath(requestedDir || desktopState.projectDir);
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, content);
      desktopState.seen.push(content);
      return { ok: true, status: 0, stdout: `Wrote ${path}`, stderr: "" };
    },
    workspaceOpenworkRead: async (workspacePath: string) => {
      const openworkPath = join(workspacePath || desktopState.projectDir, ".opencode", "openwork.json");
      if (!existsSync(openworkPath)) {
        return { version: 1, authorizedRoots: [workspacePath || desktopState.projectDir] };
      }
      return JSON.parse(readFileSync(openworkPath, "utf8"));
    },
    workspaceOpenworkWrite: async (workspacePath: string, config: Record<string, unknown>) => {
      const unknown = Object.keys(config).filter((key) => !knownOpenworkKeys.has(key));
      if (unknown.length > 0) {
        throw new Error(`unknown openwork config field: ${unknown.join(",")}`);
      }
      const openworkPath = join(workspacePath || desktopState.projectDir, ".opencode", "openwork.json");
      mkdirSync(dirname(openworkPath), { recursive: true });
      const content = JSON.stringify(config, null, 2);
      writeFileSync(openworkPath, content);
      desktopState.seen.push(content);
      return { ok: true, status: 0, stdout: `Wrote ${openworkPath}`, stderr: "" };
    },
  },
};

function collectFiles(projectDir: string) {
  return [
    join(projectDir, "opencode.jsonc"),
    join(projectDir, "opencode.json"),
    join(projectDir, ".opencode", "openwork.json"),
  ]
    .filter((path) => existsSync(path))
    .map((path) => readFileSync(path, "utf8"));
}

function assertNotInstalled(label: string, snapshots: string[], authProviderIds: string[], markers: string[]) {
  const hits = [...new Set(markers.filter((marker) => snapshots.some((snapshot) => snapshot.includes(marker))))];
  expect(
    hits,
    `${label} wrote untrusted provider material into the workspace config: ${hits.join(", ")}`,
  ).toEqual([]);
  expect(authProviderIds, `${label} stored a provider credential without an explicit connect`).toEqual([]);
}

async function runVictimSync(input: {
  victim: Session;
  transport: "openwork-server" | "desktop-bridge";
  markers: string[];
}) {
  const { createProviderAuthStore } = await import("./store.ts");
  const { createOpenworkServerClient } = await import("../../../../app/lib/openwork-server.ts");
  const { writeDenSettings } = await import("../../../../app/lib/den.ts");
  const { denSessionUpdatedEvent } = await import("../../../../app/lib/den-session-events.ts");

  const projectDir = mkdtempSync(join(tmpdir(), "openwork-provider-sync-"));
  const seen: string[] = [];
  writeFileSync(join(projectDir, "opencode.jsonc"), '{\n  "$schema": "https://opencode.ai/config.json"\n}\n');
  installDesktopBridge(projectDir, seen);

  writeDenSettings({
    baseUrl: denOrigin,
    apiBaseUrl: denOrigin,
    authToken: input.victim.token,
    activeOrgId: input.victim.orgId,
    activeOrgSlug: `example-${input.victim.orgId}`,
    activeOrgName: "Example Org",
  });

  const authProviderIds: string[] = [];
  const client = {
    auth: {
      set: async (options: { providerID: string }) => {
        authProviderIds.push(options.providerID);
        return { data: true };
      },
      remove: async () => ({ data: true }),
    },
    instance: { dispose: async () => ({ data: true }) },
    global: { health: async () => ({ data: { healthy: true } }) },
    config: {
      get: async () => ({ data: {} }),
      providers: async () => ({ data: { providers: [] } }),
    },
    provider: {
      list: async () => ({ data: { all: [], default: {}, connected: [] } }),
      auth: async () => ({ data: {} }),
    },
  };

  let openworkServer: { stop?: (close?: boolean) => void } | null = null;
  let runtimeWorkspaceId = "workspace-not-connected";
  let openworkClient: ReturnType<typeof createOpenworkServerClient> | null = null;
  let capabilities: { config?: { read?: boolean; write?: boolean } } | null = null;

  if (input.transport === "openwork-server") {
    const configPath = join(projectDir, "server.json");
    writeFileSync(configPath, "{}\n");
    const config = await serverModules.resolveServerConfig(serverModules.parseCliArgs([
      "--config",
      configPath,
      "--host",
      "127.0.0.1",
      "--port",
      "0",
      "--token",
      OPENWORK_CLIENT_TOKEN,
      "--host-token",
      OPENWORK_HOST_TOKEN,
      "--approval",
      "auto",
      "--no-log-requests",
      "--workspace",
      projectDir,
    ]));
    openworkServer = serverModules.startServer(config);
    const workspace = config.workspaces[0];
    if (!workspace) throw new Error("openwork server did not register the workspace");
    runtimeWorkspaceId = workspace.id;
    openworkClient = createOpenworkServerClient({
      baseUrl: `http://127.0.0.1:${(openworkServer as { port: number }).port}`,
      token: OPENWORK_CLIENT_TOKEN,
      hostToken: OPENWORK_HOST_TOKEN,
    });
    capabilities = await openworkClient.capabilities();
  }

  const store = createProviderAuthStore({
    client: () => client as never,
    providers: () => [],
    providerDefaults: () => ({}),
    providerConnectedIds: () => [],
    disabledProviders: () => [],
    selectedWorkspaceDisplay: () => ({ workspaceType: "local", name: "Example" }) as never,
    selectedWorkspaceRoot: () => projectDir,
    runtimeWorkspaceId: () => runtimeWorkspaceId,
    openworkServer: {
      getSnapshot: () => ({
        openworkServerStatus: input.transport === "openwork-server" ? "connected" : "disconnected",
        openworkServerClient: openworkClient,
        openworkServerCapabilities: capabilities,
      }),
    } as never,
    setProviders: () => undefined,
    setProviderDefaults: () => undefined,
    setProviderConnectedIds: () => undefined,
    setDisabledProviders: () => undefined,
    markOpencodeConfigReloadRequired: () => undefined,
  });

  try {
    store.start();
    for (const reason of ["interval", "app_launch", "sign_in", "settings_cloud_opened"] as const) {
      await store.runCloudProviderSync(reason);
    }
    store.syncFromOptions();
    await store.runCloudProviderSync("app_launch");
    windowValue.dispatchEvent(new CustomEvent(denSessionUpdatedEvent, {
      detail: { status: "success" },
    }));
    await store.runCloudProviderSync("sign_in");
    assertNotInstalled(input.transport, [...seen, ...collectFiles(projectDir)], authProviderIds, input.markers);
  } finally {
    store.dispose();
    openworkServer?.stop?.(true);
  }
}

async function shareAndSync(input: {
  label: string;
  transport: "openwork-server" | "desktop-bridge";
  share: "member" | "team" | "patch" | "race";
}) {
  const seeded = await seedOrganization();
  const markers = [
    ATTACKER_PACKAGE,
    ATTACKER_MODEL_PACKAGE,
    ATTACKER_BASE_URL,
    ATTACKER_MODEL_URL,
    ATTACKER_HEADER,
    PROVIDER_NAME,
    RACED_PACKAGE,
    RACED_BASE_URL,
  ];

  const created = await denRequest(seeded.attacker, "/v1/llm-providers", {
    method: "POST",
    body: providerBody(
      input.share === "member" || input.share === "race"
        ? { memberIds: [seeded.victim.memberId] }
        : input.share === "team"
          ? { teamIds: [seeded.teamId] }
          : {},
    ),
  });
  expect(
    created.status === 201 || created.status === 403,
    `${input.label} create returned ${created.status} ${created.json?.error ?? ""}`,
  ).toBe(true);

  let providerId = created.json?.llmProvider?.id ?? "";
  if (created.status === 201 && input.share === "patch") {
    const patched = await denRequest(seeded.attacker, `/v1/llm-providers/${providerId}`, {
      method: "PATCH",
      body: providerBody({ memberIds: [seeded.victim.memberId] }),
    });
    expect(
      patched.status === 200 || patched.status === 403,
      `${input.label} patch returned ${patched.status} ${patched.json?.error ?? ""}`,
    ).toBe(true);
  }

  if (created.status === 201 && input.share === "race") {
    markers.push(providerId);
    raceBeforeConnect = async (requestedId) => {
      if (requestedId !== providerId) return;
      await denModules.db
        .update(denModules.tables.LlmProviderTable)
        .set({
          providerConfig: {
            id: "member-planted",
            name: PROVIDER_NAME,
            npm: RACED_PACKAGE,
            env: ["UNTRUSTED_PROVIDER_TOKEN"],
            doc: "http://127.0.0.1:9/untrusted-provider-docs",
            api: RACED_BASE_URL,
            options: { baseURL: RACED_BASE_URL },
          },
          updatedAt: new Date(),
        })
        .where(eq(denModules.tables.LlmProviderTable.id, providerId as never));
    };
  } else if (providerId) {
    markers.push(providerId);
  }

  try {
    await runVictimSync({
      victim: seeded.victim,
      transport: input.transport,
      markers,
    });
  } finally {
    raceBeforeConnect = null;
  }
}

const cases = [
  ["member grant", "member"],
  ["team grant", "team"],
  ["later member grant", "patch"],
  ["connect payload changed after list", "race"],
] as const;

for (const transport of ["openwork-server", "desktop-bridge"] as const) {
  for (const [label, share] of cases) {
    test(`${transport} does not auto-install a custom provider shared by a member via ${label}`, async () => {
      await shareAndSync({ label: `${transport} ${label}`, transport, share });
    }, 30_000);
  }
}
