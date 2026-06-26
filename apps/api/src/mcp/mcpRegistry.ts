/**
 * mcpRegistry — MCP Server 注册制（插件化架构核心）。
 *
 * 替代旧的硬编码 tsharkQueryMcp/evidenceOpenerMcp，支持三种 server 类型：
 *   - local (stdio)：本地子进程（command + args），如 tshark-query
 *   - sse：远程 SSE 连接（url）
 *   - streamable-http：远程 HTTP 流式连接（url）
 *
 * 注册表来源（优先级从高到低）：
 *   1. userData/mcp-registries.json（用户编辑，设置页可视化）
 *   2. 环境变量 PCAPAI_TSHARK_QUERY_MCP_* / PCAPAI_EVIDENCE_OPENER_MCP_*（dev 模式覆盖）
 *   3. config/defaults.json 的 mcpServers 数组（内置默认）
 *
 * 路径变量替换：command/args/url 支持 ${resources}/${userData}/${workspace}
 *
 * 提供：
 *   - createAgentServers()：为 Agent runtime 创建 MCPServerStdio/SSE/Http 实例
 *   - createClient(serverId)：为确定性路径创建原生 MCP Client
 *   - listStatus()：列出所有 server 状态（设置页展示）
 *   - upsert/remove/toggle：CRUD（设置页 + API 路由调用）
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { MCPServerStdio, MCPServerSSE, MCPServerStreamableHttp } from "@openai/agents";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { apiConfig, resolvePathVars } from "../config.js";

export type McpServerConfig = {
  id: string;
  name: string;
  type: "local" | "sse" | "streamable-http";
  enabled: boolean;
  builtIn?: boolean;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
};

export type ServerStatus = {
  id: string;
  name: string;
  type: McpServerConfig["type"];
  enabled: boolean;
  builtIn: boolean;
  connected: boolean;
  toolCount?: number;
  toolNames?: string[];
  error?: string;
};

/** 注册表文件路径（userData/mcp-registries.json） */
function registryPath(): string {
  const userDataDir = process.env.PCAPAI_USERDATA_DIR;
  if (!userDataDir) return ""; // dev 模式无 userData，用 defaults
  return path.join(userDataDir, "mcp-registries.json");
}

/** 读取注册表（userData JSON 优先，fallback 到 apiConfig.mcpServers） */
export function loadServers(): McpServerConfig[] {
  const regPath = registryPath();
  if (regPath && existsSync(regPath)) {
    try {
      const reg = JSON.parse(readFileSync(regPath, "utf8"));
      if (Array.isArray(reg.servers)) return reg.servers as McpServerConfig[];
    } catch {
      // JSON 损坏，fallback
    }
  }
  // fallback: apiConfig.mcpServers（已含环境变量覆盖 + 路径替换）
  return apiConfig.mcpServers;
}

/** 保存注册表到 userData */
export function saveServers(servers: McpServerConfig[]): void {
  const regPath = registryPath();
  if (!regPath) throw new Error("userData 目录未配置（PCAPAI_USERDATA_DIR），无法保存注册表");
  mkdirSync(path.dirname(regPath), { recursive: true });
  writeFileSync(regPath, JSON.stringify({ servers }, null, 2), "utf8");
}

/** 获取所有 enabled 的 server 配置 */
export function getEnabledServers(): McpServerConfig[] {
  return loadServers().filter((s) => s.enabled);
}

/** 按 ID 查找 server 配置 */
export function findServer(id: string): McpServerConfig | undefined {
  return loadServers().find((s) => s.id === id);
}

// ===== Agent runtime 工厂：创建 MCPServer 实例 =====

const agentServerCache = new Map<string, { server: MCPServerStdio | MCPServerSSE | MCPServerStreamableHttp; config: McpServerConfig }>();

/**
 * 为 Agent runtime 创建所有 enabled server 的 MCPServer 实例。
 * 带缓存：同一 server 复用连接，避免每次 Agent 运行都重新 spawn。
 * 失败的 server 跳过（不阻断其他 server）。
 */
export async function createAgentServers(): Promise<Array<MCPServerStdio | MCPServerSSE | MCPServerStreamableHttp>> {
  const enabled = getEnabledServers();
  const result: Array<MCPServerStdio | MCPServerSSE | MCPServerStreamableHttp> = [];
  for (const config of enabled) {
    try {
      const cached = agentServerCache.get(config.id);
      if (cached && cached.config === config) {
        result.push(cached.server);
        continue;
      }
      // 创建新实例
      const server = createAgentServer(config);
      await connectAgentServer(server, config);
      agentServerCache.set(config.id, { server, config });
      result.push(server);
    } catch (error) {
      console.error(`[mcpRegistry] server ${config.id} 连接失败:`, error instanceof Error ? error.message : String(error));
      // 跳过失败的 server，不阻断其他 server
    }
  }
  return result;
}

function createAgentServer(config: McpServerConfig): MCPServerStdio | MCPServerSSE | MCPServerStreamableHttp {
  const common = { name: config.id, cacheToolsList: true };
  const cwd = process.env.PCAPAI_ROOT || process.cwd();
  if (config.type === "local") {
    return new MCPServerStdio({
      ...common,
      command: config.command || "node",
      args: config.args || [],
      cwd,
      env: {
        ...process.env,
        ELECTRON_RUN_AS_NODE: process.env.ELECTRON_RUN_AS_NODE || "1",
        ...config.env
      }
    });
  }
  if (config.type === "sse") {
    return new MCPServerSSE({ ...common, url: config.url || "" });
  }
  // streamable-http
  return new MCPServerStreamableHttp({ ...common, url: config.url || "" });
}

async function connectAgentServer(
  server: MCPServerStdio | MCPServerSSE | MCPServerStreamableHttp,
  config: McpServerConfig
): Promise<void> {
  // 本地 server 带重试（spawn 冷启动可能偶发失败）
  if (config.type === "local") {
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        await server.connect();
        return;
      } catch (error) {
        if (attempt >= maxAttempts) throw error;
        try { await server.close(); } catch { /* ignore */ }
        await new Promise((r) => setTimeout(r, 400 * attempt));
      }
    }
  } else {
    await server.connect();
  }
}

/** 重置所有缓存的 Agent server（配置变更后重连） */
export function resetAgentServers(): void {
  agentServerCache.clear();
}

// ===== 确定性路径工厂：创建原生 MCP Client =====

const clientCache = new Map<string, Promise<Client>>();

/**
 * 为确定性路径（tsharkQueryClient 等）创建原生 MCP Client。
 * 按 server ID 从注册表查找配置，创建对应 transport 的 Client。
 * 带缓存：同一 server 复用 Client 单例。
 */
export function createClient(serverId: string): Promise<Client> {
  const cached = clientCache.get(serverId);
  if (cached) return cached;
  const promise = (async () => {
    const config = findServer(serverId);
    if (!config) throw new Error(`MCP server "${serverId}" 未在注册表中找到。请在设置页检查 MCP 配置。`);
    if (!config.enabled) throw new Error(`MCP server "${serverId}" 已禁用。`);
    const client = new Client({ name: `pcapai-${serverId}`, version: "0.1.0" });
    const transport = createClientTransport(config);
    await client.connect(transport);
    return client;
  })();
  clientCache.set(serverId, promise);
  return promise;
}

function createClientTransport(config: McpServerConfig): StdioClientTransport | SSEClientTransport | StreamableHTTPClientTransport {
  const cwd = process.env.PCAPAI_ROOT || process.cwd();
  if (config.type === "local") {
    return new StdioClientTransport({
      command: config.command || "node",
      args: config.args || [],
      cwd,
      stderr: "pipe",
      env: {
        ...process.env,
        ELECTRON_RUN_AS_NODE: process.env.ELECTRON_RUN_AS_NODE || "1",
        ...config.env
      }
    });
  }
  if (config.type === "sse") {
    return new SSEClientTransport(new URL(config.url || ""));
  }
  return new StreamableHTTPClientTransport(new URL(config.url || ""));
}

/** 重置 Client 缓存（配置变更后重连） */
export function resetClient(serverId?: string): void {
  if (serverId) {
    clientCache.delete(serverId);
  } else {
    clientCache.clear();
  }
}

// ===== 状态查询 + CRUD（供 API 路由 + 设置页） =====

export async function listStatus(): Promise<ServerStatus[]> {
  const servers = loadServers();
  const results = await Promise.allSettled(
    servers.map(async (s): Promise<ServerStatus> => {
      if (!s.enabled) {
        return { id: s.id, name: s.name, type: s.type, enabled: false, builtIn: !!s.builtIn, connected: false };
      }
      try {
        // 主动连接获取真实状态 + 工具列表
        const server = createAgentServer(s);
        await connectAgentServer(server, s);
        let toolNames: string[] = [];
        try {
          const tools = await server.listTools();
          toolNames = tools.map((t: { name?: string }) => t.name || "").filter(Boolean);
        } catch { /* listTools 失败不阻塞状态查询 */ }
        // 连接后立即关闭（状态查询不需要常驻），缓存由 Agent 运行时填充
        try { await server.close(); } catch { /* ignore */ }
        return {
          id: s.id, name: s.name, type: s.type, enabled: true, builtIn: !!s.builtIn,
          connected: true, toolCount: toolNames.length, toolNames
        };
      } catch (error) {
        return {
          id: s.id, name: s.name, type: s.type, enabled: true, builtIn: !!s.builtIn,
          connected: false, error: error instanceof Error ? error.message : String(error)
        };
      }
    })
  );
  return results.map((r, i) => r.status === "fulfilled" ? r.value : {
    id: servers[i].id, name: servers[i].name, type: servers[i].type,
    enabled: servers[i].enabled, builtIn: !!servers[i].builtIn, connected: false,
    error: r.status === "rejected" ? String(r.reason) : "unknown error"
  });
}

/** 新增/更新 server（upsert by id） */
export function upsertServer(config: McpServerConfig): McpServerConfig[] {
  const servers = loadServers();
  const idx = servers.findIndex((s) => s.id === config.id);
  if (idx >= 0) {
    servers[idx] = config;
  } else {
    servers.push(config);
  }
  saveServers(servers);
  resetAgentServers();
  resetClient(config.id);
  return servers;
}

/** 删除 server（内置 server 不可删，只能禁用） */
export function removeServer(id: string): { removed: boolean; reason?: string } {
  const servers = loadServers();
  const target = servers.find((s) => s.id === id);
  if (!target) return { removed: false, reason: "not found" };
  if (target.builtIn) return { removed: false, reason: "built-in server 不可删除，只能禁用" };
  const filtered = servers.filter((s) => s.id !== id);
  saveServers(filtered);
  resetAgentServers();
  resetClient(id);
  return { removed: true };
}

/** 切换 server 启用/禁用 */
export function toggleServer(id: string): McpServerConfig | undefined {
  const servers = loadServers();
  const idx = servers.findIndex((s) => s.id === id);
  if (idx < 0) return undefined;
  servers[idx].enabled = !servers[idx].enabled;
  saveServers(servers);
  if (!servers[idx].enabled) {
    resetAgentServers();
    resetClient(id);
  }
  return servers[idx];
}
