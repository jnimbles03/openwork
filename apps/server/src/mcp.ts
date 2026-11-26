import { existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { compileGlob, type GlobBudget } from "./glob-match.js";
import type { McpItem } from "./types.js";
import { readJsoncFile, updateJsoncPath, updateJsoncTopLevel } from "./jsonc.js";
import { opencodeConfigPath } from "./workspace-files.js";
import { validateMcpConfig, validateMcpName } from "./validators.js";

function globalOpenCodeConfigPath(): string {
  const base = join(homedir(), ".config", "opencode");
  const jsonc = join(base, "opencode.jsonc");
  const json = join(base, "opencode.json");
  if (existsSync(jsonc)) return jsonc;
  if (existsSync(json)) return json;
  return jsonc; // fall back to jsonc (readJsoncFile handles missing files gracefully)
}

function getMcpConfig(config: Record<string, unknown>): Record<string, Record<string, unknown>> {
  const mcp = config.mcp;
  if (!mcp || typeof mcp !== "object") return {};
  return mcp as Record<string, Record<string, unknown>>;
}

function getDeniedToolPatterns(config: Record<string, unknown>): string[] {
  const tools = config.tools;
  if (!tools || typeof tools !== "object") return [];
  const deny = (tools as { deny?: unknown }).deny;
  if (!Array.isArray(deny)) return [];
  return deny.filter((item) => typeof item === "string") as string[];
}

// Bounds the total deny-pattern matching work per listing. `disabledByTools` is
// informational, so entries past the budget are reported as not disabled.
const DENY_MATCH_BUDGET = 2_000_000;

function mcpDisabledByTools(
  config: Record<string, unknown>,
  budget: GlobBudget,
): (name: string) => boolean {
  const matchers = getDeniedToolPatterns(config).map((pattern) => compileGlob(pattern, budget));
  if (matchers.length === 0) return () => false;
  return (name) => {
    const candidates = [`mcp.${name}`, `mcp.${name}.*`, `mcp:${name}`, `mcp:${name}:*`, "mcp.*", "mcp:*"];
    return matchers.some((matches) => candidates.some((candidate) => matches(candidate)));
  };
}

export async function listMcp(workspaceRoot: string): Promise<McpItem[]> {
  const { data: config } = await readJsoncFile(opencodeConfigPath(workspaceRoot), {} as Record<string, unknown>);
  const { data: globalConfig } = await readJsoncFile(globalOpenCodeConfigPath(), {} as Record<string, unknown>);

  const projectMcpMap = getMcpConfig(config);
  const globalMcpMap = getMcpConfig(globalConfig);

  const budget: GlobBudget = { remaining: DENY_MATCH_BUDGET };
  const isDisabledByProject = mcpDisabledByTools(config, budget);
  const isDisabledByGlobal = mcpDisabledByTools(globalConfig, budget);

  const items: McpItem[] = [];

  // Global MCPs first; project-level entries override global ones with the same name.
  for (const [name, entry] of Object.entries(globalMcpMap)) {
    if (Object.prototype.hasOwnProperty.call(projectMcpMap, name)) continue;
    items.push({
      name,
      config: entry,
      source: "config.global",
      disabledByTools: (isDisabledByGlobal(name) || isDisabledByProject(name)) || undefined,
    });
  }

  // Project MCPs (highest priority).
  for (const [name, entry] of Object.entries(projectMcpMap)) {
    items.push({
      name,
      config: entry,
      source: "config.project",
      disabledByTools: isDisabledByProject(name) || undefined,
    });
  }

  return items;
}

export async function addMcp(
  workspaceRoot: string,
  name: string,
  config: Record<string, unknown>,
): Promise<{ action: "added" | "updated" }> {
  validateMcpName(name);
  validateMcpConfig(config);
  const { data } = await readJsoncFile(opencodeConfigPath(workspaceRoot), {} as Record<string, unknown>);
  const mcpMap = getMcpConfig(data);
  const existed = Object.prototype.hasOwnProperty.call(mcpMap, name);
  mcpMap[name] = config;
  await updateJsoncTopLevel(opencodeConfigPath(workspaceRoot), { mcp: mcpMap });
  return { action: existed ? "updated" : "added" };
}

export async function removeMcp(workspaceRoot: string, name: string): Promise<boolean> {
  const { data } = await readJsoncFile(opencodeConfigPath(workspaceRoot), {} as Record<string, unknown>);
  const mcpMap = getMcpConfig(data);
  if (!Object.prototype.hasOwnProperty.call(mcpMap, name)) return false;
  delete mcpMap[name];
  await updateJsoncTopLevel(opencodeConfigPath(workspaceRoot), { mcp: mcpMap });
  return true;
}

// Flips `enabled` on a workspace MCP entry. Returns false for "toggle does
// not apply": missing, non-object, or malformed enough that OpenCode would
// fail to load it. The HTTP layer maps false to 404. Globals are out of
// scope by design — only workspace-level entries.
//
// `updateJsoncPath` (vs `updateJsoncTopLevel`) preserves inline comments
// inside the MCP entry — see the regression that motivated #1444.
export async function setMcpEnabled(
  workspaceRoot: string,
  name: string,
  enabled: boolean,
): Promise<boolean> {
  validateMcpName(name);
  const { data } = await readJsoncFile(opencodeConfigPath(workspaceRoot), {} as Record<string, unknown>);
  const mcpMap = getMcpConfig(data);
  if (!Object.prototype.hasOwnProperty.call(mcpMap, name)) return false;
  const current = mcpMap[name];
  if (!current || typeof current !== "object" || Array.isArray(current)) return false;
  try {
    validateMcpConfig({ ...(current as Record<string, unknown>), enabled });
  } catch {
    return false;
  }
  await updateJsoncPath(opencodeConfigPath(workspaceRoot), ["mcp", name, "enabled"], enabled);
  return true;
}
