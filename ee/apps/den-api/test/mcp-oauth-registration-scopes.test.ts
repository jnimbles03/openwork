import { expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import path from "node:path"
import { fileURLToPath } from "node:url"

const here = path.dirname(fileURLToPath(import.meta.url))

test("dynamic registration and authorize do not grant mcp:write for a read-only client", () => {
  const result = spawnSync(process.execPath, ["test/mcp-oauth-registration-scopes.runner.ts"], {
    cwd: path.resolve(here, ".."),
    encoding: "utf8",
  })

  if (result.status !== 0) {
    throw new Error([result.stdout, result.stderr].filter(Boolean).join("\n"))
  }
  expect(result.status).toBe(0)
})
