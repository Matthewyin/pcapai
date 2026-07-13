import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const apiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const testFiles = readdirSync(path.join(apiDir, "test"))
  .filter((file) => file.endsWith(".test.ts"))
  .sort()
  .map((file) => path.join("test", file));
const tsxCli = require.resolve("tsx/cli");

let runtime = process.execPath;
const env = { ...process.env, NODE_ENV: "test" };
try {
  const Database = require("better-sqlite3");
  const probe = new Database(":memory:");
  probe.close();
} catch {
  runtime = require("electron");
  env.ELECTRON_RUN_AS_NODE = "1";
}

const result = spawnSync(runtime, [tsxCli, "--test", ...testFiles], {
  cwd: apiDir,
  env,
  stdio: "inherit"
});
process.exit(result.status ?? 1);
