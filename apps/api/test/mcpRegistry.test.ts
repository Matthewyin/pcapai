import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test, { after, afterEach } from "node:test";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { openInWiresharkWithMcp } from "../src/mcp/evidenceOpenerClient.js";
import { listProtocolsWithMcp } from "../src/mcp/tsharkQueryClient.js";
import {
  closeMcpResources,
  createAgentServers,
  createClient,
  loadServers,
  mcpRegistryTestHooks,
  removeServer,
  resetAgentServers,
  resetClient,
  toggleServer,
  upsertServer,
  type McpServerConfig
} from "../src/mcp/mcpRegistry.js";

const tempDir = mkdtempSync(path.join(tmpdir(), "pcapai-mcp-registry-"));
const previousUserDataDir = process.env.PCAPAI_USERDATA_DIR;
process.env.PCAPAI_USERDATA_DIR = tempDir;

type FakeCloseable = {
  id: string;
  closeCount: number;
  close(): Promise<void>;
};

function fakeCloseable(id: string): FakeCloseable {
  return {
    id,
    closeCount: 0,
    async close() {
      this.closeCount += 1;
    }
  };
}

function config(patch: Partial<McpServerConfig> = {}): McpServerConfig {
  return {
    id: "test-mcp",
    name: "测试 MCP",
    type: "local",
    enabled: true,
    builtIn: false,
    command: "node-a",
    args: ["${userData}/server.js"],
    env: { B: "2", A: "1" },
    ...patch
  };
}

function writeRegistry(servers: McpServerConfig[]) {
  writeFileSync(path.join(tempDir, "mcp-registries.json"), JSON.stringify({ servers }, null, 2), "utf8");
}

afterEach(async () => {
  await closeMcpResources();
  mcpRegistryTestHooks.restoreConnectors();
  writeRegistry([]);
});

after(() => {
  if (previousUserDataDir === undefined) delete process.env.PCAPAI_USERDATA_DIR;
  else process.env.PCAPAI_USERDATA_DIR = previousUserDataDir;
  rmSync(tempDir, { recursive: true, force: true });
});

test("重复读取内容相同的 JSON 配置时复用 Agent server", async () => {
  writeRegistry([config()]);
  const created: FakeCloseable[] = [];
  mcpRegistryTestHooks.setAgentServerConnector(async (serverConfig) => {
    const server = fakeCloseable(serverConfig.command || "unknown");
    created.push(server);
    return server as never;
  });

  const first = await createAgentServers();
  const second = await createAgentServers();

  assert.equal(created.length, 1);
  assert.equal(first[0], second[0]);
  assert.equal(loadServers()[0].args?.[0], path.join(tempDir, "server.js"));
});

test("并发初始化同一配置只创建一个 Agent server", async () => {
  writeRegistry([config()]);
  let created = 0;
  mcpRegistryTestHooks.setAgentServerConnector(async () => {
    created += 1;
    await new Promise((resolve) => setTimeout(resolve, 20));
    return fakeCloseable(`server-${created}`) as never;
  });

  const runs = await Promise.all([createAgentServers(), createAgentServers(), createAgentServers()]);

  assert.equal(created, 1);
  assert.equal(runs[0][0], runs[1][0]);
  assert.equal(runs[1][0], runs[2][0]);
});

test("配置变化会关闭旧 Agent server 并创建新连接", async () => {
  writeRegistry([config()]);
  const created: FakeCloseable[] = [];
  mcpRegistryTestHooks.setAgentServerConnector(async (serverConfig) => {
    const server = fakeCloseable(serverConfig.command || "unknown");
    created.push(server);
    return server as never;
  });

  await createAgentServers();
  writeRegistry([config({ command: "node-b" })]);
  await createAgentServers();

  assert.equal(created.length, 2);
  assert.equal(created[0].closeCount, 1);
  assert.equal(created[1].closeCount, 0);
});

test("Client 并发复用，配置变化和 reset 都会关闭旧连接", async () => {
  writeRegistry([config()]);
  const created: FakeCloseable[] = [];
  mcpRegistryTestHooks.setClientConnector(async (serverConfig) => {
    const client = fakeCloseable(serverConfig.command || "unknown");
    created.push(client);
    return client as unknown as Client;
  });

  const [first, second] = await Promise.all([createClient("test-mcp"), createClient("test-mcp")]);
  assert.equal(first, second);
  assert.equal(created.length, 1);

  writeRegistry([config({ command: "node-b" })]);
  await createClient("test-mcp");
  assert.equal(created.length, 2);
  assert.equal(created[0].closeCount, 1);

  await resetClient("test-mcp");
  assert.equal(created[1].closeCount, 1);
});

test("toggle、remove 和 upsert 会关闭对应的 Agent server 与 Client", async () => {
  writeRegistry([config()]);
  const agentServers: FakeCloseable[] = [];
  const clients: FakeCloseable[] = [];
  mcpRegistryTestHooks.setAgentServerConnector(async () => {
    const server = fakeCloseable(`agent-${agentServers.length}`);
    agentServers.push(server);
    return server as never;
  });
  mcpRegistryTestHooks.setClientConnector(async () => {
    const client = fakeCloseable(`client-${clients.length}`);
    clients.push(client);
    return client as unknown as Client;
  });

  await createAgentServers();
  await createClient("test-mcp");
  const disabled = await toggleServer("test-mcp");
  assert.equal(disabled?.enabled, false);
  assert.equal(agentServers[0].closeCount, 1);
  assert.equal(clients[0].closeCount, 1);

  await toggleServer("test-mcp");
  await createAgentServers();
  await createClient("test-mcp");
  await upsertServer(config({ command: "node-c" }));
  assert.equal(agentServers[1].closeCount, 1);
  assert.equal(clients[1].closeCount, 1);

  await createAgentServers();
  await createClient("test-mcp");
  const removed = await removeServer("test-mcp");
  assert.deepEqual(removed, { removed: true });
  assert.equal(agentServers[2].closeCount, 1);
  assert.equal(clients[2].closeCount, 1);
  assert.deepEqual(mcpRegistryTestHooks.cacheSizes(), { agentServers: 0, agentInFlight: 0, clients: 0 });
});

test("resetAgentServers 会关闭已缓存连接", async () => {
  writeRegistry([config()]);
  const server = fakeCloseable("agent");
  mcpRegistryTestHooks.setAgentServerConnector(async () => server as never);
  await createAgentServers();

  await resetAgentServers("test-mcp");

  assert.equal(server.closeCount, 1);
  assert.equal(mcpRegistryTestHooks.cacheSizes().agentServers, 0);
});

test("CRUD 持久化时保留未展开的路径变量", async () => {
  writeRegistry([
    config(),
    config({ id: "other-mcp", name: "其他 MCP", command: "node-b", args: ["other.js"] })
  ]);

  await toggleServer("other-mcp");

  const saved = JSON.parse(readFileSync(path.join(tempDir, "mcp-registries.json"), "utf8")) as {
    servers: McpServerConfig[];
  };
  assert.equal(saved.servers.find((server) => server.id === "test-mcp")?.args?.[0], "${userData}/server.js");
  assert.equal(loadServers().find((server) => server.id === "test-mcp")?.args?.[0], path.join(tempDir, "server.js"));
});

test("直接 Client 调用失败时关闭并移除对应连接", async () => {
  writeRegistry([
    config({ id: "tshark-query", name: "tshark-query" }),
    config({ id: "evidence-opener", name: "evidence-opener" })
  ]);
  const clients: Array<FakeCloseable & { callTool(): Promise<never> }> = [];
  mcpRegistryTestHooks.setClientConnector(async (serverConfig) => {
    const closeable = fakeCloseable(serverConfig.id);
    const client = {
      ...closeable,
      async callTool() {
        throw new Error(`${serverConfig.id} transport failed`);
      }
    };
    clients.push(client);
    return client as unknown as Client;
  });

  await assert.rejects(() => listProtocolsWithMcp({ captures: [] }), /tshark-query transport failed/);
  await assert.rejects(() => openInWiresharkWithMcp({ pcapPath: "/tmp/test.pcap", displayFilter: "tcp" }), /evidence-opener transport failed/);

  assert.deepEqual(clients.map((client) => client.closeCount), [1, 1]);
  assert.equal(mcpRegistryTestHooks.cacheSizes().clients, 0);
});
