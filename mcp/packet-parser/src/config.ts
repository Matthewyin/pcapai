import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

function numberFromEnv(value: string | undefined, fallback: number) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function resolveWorkspaceRoot() {
  const candidates = [
    process.env.PCAPAI_ROOT ? path.resolve(process.env.PCAPAI_ROOT) : "",
    process.cwd(),
    path.resolve(process.cwd(), "../..")
  ].filter(Boolean);

  return candidates.find((candidate) => existsSync(path.join(candidate, "config/defaults.json"))) || process.cwd();
}

const workspaceRoot = resolveWorkspaceRoot();
const configPath = process.env.PCAPAI_CONFIG_PATH
  ? path.resolve(process.env.PCAPAI_CONFIG_PATH)
  : path.join(workspaceRoot, "config/defaults.json");
const defaults = JSON.parse(readFileSync(configPath, "utf8")) as {
  mcp: {
    packetParser: {
      tsharkCommand: string;
      maxBufferBytes: number;
    };
  };
};

export const parserConfig = {
  tsharkCommand: process.env.PCAPAI_TSHARK_COMMAND || defaults.mcp.packetParser.tsharkCommand,
  maxBufferBytes: numberFromEnv(process.env.PCAPAI_TSHARK_MAX_BUFFER_BYTES, defaults.mcp.packetParser.maxBufferBytes)
};
