import process from "node:process";
import { startServer } from "./bootstrap/server.js";

function printHelp() {
  process.stdout.write([
    "openwork-server-v2",
    "",
    "Options:",
    "  --host <host>   Hostname to bind. Defaults to 127.0.0.1.",
    "  --port <port>   Port to bind. Defaults to 3100.",
    "  --help          Show this help text.",
    "",
    "Authentication:",
    "  Every route except /, /system/health, and /openapi.json needs a token.",
    "  Set OPENWORK_SERVER_V2_HOST_TOKEN and/or OPENWORK_SERVER_V2_CLIENT_TOKEN, or use the",
    "  host token generated at startup (its file path is logged as auth.hostTokenFile).",
    "  OPENWORK_SERVER_V2_ALLOWED_HOSTS and OPENWORK_SERVER_V2_ALLOWED_ORIGINS (comma-separated)",
    "  extend the accepted Host and browser Origin headers beyond the bound loopback address.",
    "",
  ].join("\n"));
}

function parseArgs(argv: Array<string>) {
  let host: string | undefined;
  let port: number | undefined;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];

    if (argument === "--help") {
      printHelp();
      process.exit(0);
    }

    if (argument === "--host") {
      host = argv[index + 1];
      index += 1;
      continue;
    }

    if (argument === "--port") {
      const rawPort = argv[index + 1];
      if (!rawPort) {
        throw new Error("Missing value for --port.");
      }
      port = Number.parseInt(rawPort, 10);
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${argument}`);
  }

  return { host, port };
}

async function main() {
  const { host, port } = parseArgs(process.argv.slice(2));
  const runtime = startServer({ host, port });

  const shutdown = async (signal: NodeJS.Signals) => {
    console.info(JSON.stringify({ scope: "openwork-server-v2.stop", signal }));
    await runtime.stop();
    process.exit(0);
  };

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.on(signal, () => {
      void shutdown(signal);
    });
  }

  await new Promise(() => undefined);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exit(1);
});
