import { MCPServerStdio } from "@openai/agents";
import { apiConfig } from "../config.js";

// tshark-query MCP 常驻单例：跨 agent 会话复用，避免每次请求重新 spawn 子进程。
// 会话失败时调用 resetTsharkQueryMcp，下一次请求会重新拉起。

let serverPromise: Promise<MCPServerStdio> | null = null;

export function getTsharkQueryMcp(): Promise<MCPServerStdio> {
  if (!serverPromise) {
    serverPromise = (async () => {
      const server = new MCPServerStdio({
        name: "tshark-query-mcp",
        command: apiConfig.tsharkQueryMcp.command,
        args: apiConfig.tsharkQueryMcp.args,
        cwd: apiConfig.tsharkQueryMcp.cwd,
        cacheToolsList: true
      });
      await server.connect();
      return server;
    })();
    serverPromise.catch(() => {
      serverPromise = null;
    });
  }
  return serverPromise;
}

export function resetTsharkQueryMcp() {
  const previous = serverPromise;
  serverPromise = null;
  previous?.then((server) => server.close()).catch(() => {});
}
