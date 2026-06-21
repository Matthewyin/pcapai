import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

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
    chatHistoryLimit: number;
    conversationDisplayLimit: number;
    keyPacketDisplayLimit: number;
    groupFailureModeDisplayLimit: number;
  };
};

const host = process.env.PCAPAI_WEB_HOST || defaults.web.host;
const port = Number(process.env.PCAPAI_WEB_PORT || defaults.web.port);
const apiTarget = process.env.PCAPAI_API_TARGET || defaults.web.apiTarget;

export default defineConfig(({ command }) => ({
  // Electron 生产模式用 loadFile 加载本地 HTML，需要相对路径（./assets/...）
  // dev server 模式用默认绝对路径（/assets/...）
  base: command === "build" ? "./" : "/",
  plugins: [react(), tailwindcss()],
  define: {
    __PCAPAI_WEB_CONFIG__: JSON.stringify({
      defaultQuestion: process.env.PCAPAI_DEFAULT_QUESTION || defaults.web.defaultQuestion,
      chatHistoryLimit: Number(process.env.PCAPAI_WEB_CHAT_HISTORY_LIMIT || defaults.web.chatHistoryLimit),
      conversationDisplayLimit: Number(process.env.PCAPAI_WEB_CONVERSATION_DISPLAY_LIMIT || defaults.web.conversationDisplayLimit),
      keyPacketDisplayLimit: Number(process.env.PCAPAI_WEB_KEY_PACKET_DISPLAY_LIMIT || defaults.web.keyPacketDisplayLimit),
      groupFailureModeDisplayLimit: Number(
        process.env.PCAPAI_WEB_GROUP_FAILURE_MODE_DISPLAY_LIMIT || defaults.web.groupFailureModeDisplayLimit
      )
    })
  },
  server: {
    host,
    port,
    strictPort: true,
    proxy: {
      "/api": apiTarget
    }
  }
}));
