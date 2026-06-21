import { MCPServerStdio } from "@openai/agents";
import { apiConfig } from "../config.js";

// tshark-query MCP 常驻单例：跨 agent 会话复用，避免每次请求重新 spawn 子进程。
// 会话失败时调用 resetTsharkQueryMcp，下一次请求会重新拉起。
// connect 带重试：冷启动（spawn node + 加载 SDK）可能要数百毫秒到秒级，
// 首次请求若 connect 偶发失败不应让整条 agent 路径直接挂。

let serverPromise: Promise<MCPServerStdio> | null = null;

const CONNECT_MAX_ATTEMPTS = 3;
const CONNECT_RETRY_BASE_MS = 400;

async function connectWithRetry(): Promise<MCPServerStdio> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= CONNECT_MAX_ATTEMPTS; attempt += 1) {
    const server = new MCPServerStdio({
      name: "tshark-query-mcp",
      command: apiConfig.tsharkQueryMcp.command,
      args: apiConfig.tsharkQueryMcp.args,
      cwd: apiConfig.tsharkQueryMcp.cwd,
      cacheToolsList: true
    });
    try {
      await server.connect();
      return server;
    } catch (error) {
      lastError = error;
      // connect 失败要主动关闭半启动的子进程，避免泄漏
      try { await server.close(); } catch { /* 关闭失败忽略，重试会新建实例 */ }
      if (attempt < CONNECT_MAX_ATTEMPTS) {
        await new Promise((resolve) => setTimeout(resolve, CONNECT_RETRY_BASE_MS * attempt));
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error("tshark-query MCP connect failed");
}

export function getTsharkQueryMcp(): Promise<MCPServerStdio> {
  if (!serverPromise) {
    serverPromise = connectWithRetry();
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
