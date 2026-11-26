import { afterAll, beforeAll, expect, test } from "bun:test";
import { mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { dirname, join } from "node:path";

import { startServer } from "./server.js";
import type { ServerConfig } from "./types.js";

/**
 * Global OpenCode config reads must follow the same host gate as
 * GET /workspace/:id/commands?scope=global (requireHost).
 *
 * These tests fail while a viewer or collaborator bearer can read the host
 * user's global opencode config. They pass once that read is refused.
 *
 * os.homedir() in Bun 1.3.6 reads HOME from the process environment at
 * startup and ignores later process.env.HOME writes, so the cases run in a
 * child process whose HOME is a throwaway directory.
 *
 * Left untested, on purpose:
 * - POST /workspace/:id/opencode-config with scope=global. That write already
 *   requires collaborator scope and an approval before it creates the file.
 * - GET /workspace/:id/skills and GET /workspace/:id/skills/:name with
 *   includeGlobal=true. Those read global skill directories, not opencode.json(c).
 * - GET /workspace/:id/plugins?includeGlobal=true. That lists global plugin
 *   filenames, not the global config file.
 * - GET /workspace/:id/config. That reads the workspace project config only.
 */

const GLOBAL_PROVIDER = "placeholder-global-provider-value";
const GLOBAL_MCP = "placeholder-global-mcp-header";
const PROJECT_MARKER = "placeholder-project-config-value";
const HOST_TOKEN = "placeholder-host-token";
const CLIENT_TOKEN = "placeholder-client-token";
const WORKSPACE_ID = "ws_shared";

type Served = {
  port: number;
  stop: (closeActiveConnections?: boolean) => void | Promise<void>;
};

if (process.env.OPENWORK_TEST_ISOLATED_HOME !== "1") {
  test("global opencode config authorization (isolated home)", async () => {
    const home = mkdtempSync(join(tmpdir(), "openwork-opencode-config-auth-"));
    const proc = Bun.spawn({
      cmd: [process.execPath, "test", import.meta.path],
      cwd: dirname(import.meta.path),
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        OPENWORK_TEST_ISOLATED_HOME: "1",
        OPENWORK_TOKEN_STORE: join(home, "tokens.json"),
        OPENWORK_ENV_STORE: join(home, "env.json"),
      },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, code] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ]);
    try {
      if (code !== 0) {
        throw new Error(`isolated authorization tests exited ${code}\n${stdout}\n${stderr}`);
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 30_000);
} else {
  const home = homedir();
  if (!home.includes(`${join("tmp", "openwork-opencode-config-auth-")}`) && !home.includes("/openwork-opencode-config-auth-")) {
    throw new Error("refusing to run global config tests outside an isolated home directory");
  }

  const globalDir = join(home, ".config", "opencode");
  const jsoncPath = join(globalDir, "opencode.jsonc");
  const jsonPath = join(globalDir, "opencode.json");
  const globalContent = `${JSON.stringify(
    {
      provider: { example: { options: { apiKey: GLOBAL_PROVIDER } } },
      mcp: {
        example: {
          type: "remote",
          url: "http://127.0.0.1:9/mcp",
          headers: { Authorization: GLOBAL_MCP },
        },
      },
    },
    null,
    2,
  )}\n`;
  const jsonOnlyContent = `${JSON.stringify(
    {
      provider: { example: { options: { apiKey: GLOBAL_PROVIDER } } },
    },
    null,
    2,
  )}\n`;
  const projectContent = `${JSON.stringify({ provider: { example: { options: { apiKey: PROJECT_MARKER } } } }, null, 2)}\n`;

  const workspaceRoot = mkdtempSync(join(tmpdir(), "openwork-config-auth-workspace-"));
  let server: Served | null = null;
  let base = "";
  let viewerToken = "";
  let collaboratorToken = "";
  let ownerToken = "";

  function bearer(token: string) {
    return { authorization: `Bearer ${token}` };
  }

  async function expectGlobalReadRefused(response: Response, label: string) {
    const text = await response.text();
    if (text.includes(GLOBAL_PROVIDER) || text.includes(GLOBAL_MCP) || text.includes(home)) {
      throw new Error(`${label} returned host global config data`);
    }
    expect(response.status).toBe(401);
    const body = JSON.parse(text) as { code?: string };
    expect(body.code).toBe("unauthorized");
  }

  beforeAll(async () => {
    mkdirSync(globalDir, { recursive: true });
    writeFileSync(jsoncPath, globalContent, "utf8");
    mkdirSync(workspaceRoot, { recursive: true });
    writeFileSync(join(workspaceRoot, "opencode.jsonc"), projectContent, "utf8");

    const config: ServerConfig = {
      host: "127.0.0.1",
      port: 0,
      token: CLIENT_TOKEN,
      hostToken: HOST_TOKEN,
      approval: { mode: "manual", timeoutMs: 50 },
      corsOrigins: ["*"],
      workspaces: [
        {
          id: WORKSPACE_ID,
          name: "Shared",
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
    server = startServer(config) as Served;
    base = `http://127.0.0.1:${server.port}`;

    const hostHeaders = { "x-openwork-host-token": HOST_TOKEN, "content-type": "application/json" };
    for (const scope of ["viewer", "collaborator", "owner"] as const) {
      const issued = await fetch(`${base}/tokens`, {
        method: "POST",
        headers: hostHeaders,
        body: JSON.stringify({ scope, label: `test ${scope}` }),
      });
      expect(issued.status).toBe(201);
      const body = (await issued.json()) as { token?: string; scope?: string };
      expect(body.scope).toBe(scope);
      if (!body.token) throw new Error(`token issue for ${scope} returned no token`);
      if (scope === "viewer") viewerToken = body.token;
      if (scope === "collaborator") collaboratorToken = body.token;
      if (scope === "owner") ownerToken = body.token;
    }
  });

  afterAll(async () => {
    await server?.stop(true);
    rmSync(workspaceRoot, { recursive: true, force: true });
  });

  test.serial("owner token reads the global file outside the authorized workspace", async () => {
    const before = readFileSync(jsoncPath, "utf8");
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=Global`, {
      headers: bearer(ownerToken),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { path?: string; exists?: boolean; content?: string | null };
    expect(body.path).toBe(jsoncPath);
    expect(body.path?.startsWith(workspaceRoot)).toBe(false);
    expect(body.exists).toBe(true);
    expect(body.content).toBe(globalContent);
    expect(body.content).not.toContain(PROJECT_MARKER);
    expect(readFileSync(jsoncPath, "utf8")).toBe(before);
  });

  test.serial("viewer token cannot read global config", async () => {
    const before = readFileSync(jsoncPath, "utf8");
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=global`, {
      headers: bearer(viewerToken),
    });
    await expectGlobalReadRefused(response, "viewer scope=global");
    expect(readFileSync(jsoncPath, "utf8")).toBe(before);
  });

  test.serial("viewer token cannot read global config when scope is normalized to global", async () => {
    const response = await fetch(
      `${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=${encodeURIComponent(" GLOBAL ")}`,
      { headers: bearer(viewerToken) },
    );
    await expectGlobalReadRefused(response, "viewer scope=' GLOBAL '");
  });

  test.serial("viewer token cannot read global config through the mounted workspace path", async () => {
    const response = await fetch(
      `${base}/w/${WORKSPACE_ID}/workspace/${WORKSPACE_ID}/opencode-config?scope=global`,
      { headers: bearer(viewerToken) },
    );
    await expectGlobalReadRefused(response, "viewer mounted scope=global");
  });

  test.serial("collaborator token cannot read global config", async () => {
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=global`, {
      headers: bearer(collaboratorToken),
    });
    await expectGlobalReadRefused(response, "collaborator scope=global");
  });

  test.serial("server client token cannot read global config", async () => {
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=global`, {
      headers: bearer(CLIENT_TOKEN),
    });
    await expectGlobalReadRefused(response, "client token scope=global");
  });

  test.serial("unauthenticated request cannot read global config", async () => {
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=global`);
    await expectGlobalReadRefused(response, "unauthenticated scope=global");
  });

  test.serial("viewer token can still read the project config and not the global file", async () => {
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=project`, {
      headers: bearer(viewerToken),
    });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { path?: string; content?: string | null };
    expect(body.path).toBe(join(workspaceRoot, "opencode.jsonc"));
    expect(body.content).toBe(projectContent);
    expect(body.content).not.toContain(GLOBAL_PROVIDER);
    expect(body.content).not.toContain(GLOBAL_MCP);
  });

  test.serial("viewer token cannot read global opencode.json when jsonc is absent", async () => {
    const aside = `${jsoncPath}.aside`;
    renameSync(jsoncPath, aside);
    writeFileSync(jsonPath, jsonOnlyContent, "utf8");
    try {
      const owner = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=global`, {
        headers: bearer(ownerToken),
      });
      expect(owner.status).toBe(200);
      const ownerBody = (await owner.json()) as { path?: string; content?: string | null };
      expect(ownerBody.path).toBe(jsonPath);
      expect(ownerBody.content).toBe(jsonOnlyContent);

      const viewer = await fetch(`${base}/workspace/${WORKSPACE_ID}/opencode-config?scope=global`, {
        headers: bearer(viewerToken),
      });
      await expectGlobalReadRefused(viewer, "viewer json-only global config");
      expect(readFileSync(jsonPath, "utf8")).toBe(jsonOnlyContent);
    } finally {
      rmSync(jsonPath, { force: true });
      renameSync(aside, jsoncPath);
    }
  });

  test.serial("viewer token does not receive global mcp credentials from the host config", async () => {
    const before = readFileSync(jsoncPath, "utf8");
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/mcp`, {
      headers: bearer(viewerToken),
    });
    const text = await response.text();
    if (text.includes(GLOBAL_PROVIDER) || text.includes(GLOBAL_MCP)) {
      throw new Error("viewer mcp list returned host global config credentials");
    }
    expect(response.status).toBe(200);
    expect(readFileSync(jsoncPath, "utf8")).toBe(before);
  });

  test.serial("viewer token cannot list global commands", async () => {
    const response = await fetch(`${base}/workspace/${WORKSPACE_ID}/commands?scope=global`, {
      headers: bearer(viewerToken),
    });
    const text = await response.text();
    if (text.includes(home)) {
      throw new Error("viewer global command list returned the host home directory");
    }
    expect(response.status).toBe(401);
    const body = JSON.parse(text) as { code?: string };
    expect(body.code).toBe("unauthorized");
  });
}
