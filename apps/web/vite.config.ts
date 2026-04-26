import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

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
  web: {
    host: string;
    port: number;
    apiTarget: string;
    defaultQuestion: string;
  };
};

const host = process.env.PCAPAI_WEB_HOST || defaults.web.host;
const port = Number(process.env.PCAPAI_WEB_PORT || defaults.web.port);
const apiTarget = process.env.PCAPAI_API_TARGET || defaults.web.apiTarget;

export default defineConfig({
  plugins: [react()],
  define: {
    __PCAPAI_WEB_CONFIG__: JSON.stringify({
      defaultQuestion: process.env.PCAPAI_DEFAULT_QUESTION || defaults.web.defaultQuestion
    })
  },
  server: {
    host,
    port,
    proxy: {
      "/api": apiTarget
    }
  }
});
