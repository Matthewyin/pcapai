/*
 * McpServersPanel — MCP Server 注册制管理面板（设置页）。
 *
 * 自包含 fetch 驱动：展示注册表所有 server + 新增/编辑/删除/启停。
 * 支持 local(stdio)/sse/streamable-http 三种类型。
 */
import React from "react";
import { Plug, Plus, Trash2, Zap } from "lucide-react";

type ServerType = "local" | "sse" | "streamable-http" | "in-process";
type Server = {
  id: string;
  name: string;
  type: ServerType;
  enabled: boolean;
  builtIn: boolean;
  connected: boolean;
  command?: string;
  args?: string[];
  url?: string;
};

export function McpServersPanel() {
  const [servers, setServers] = React.useState<Server[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [showAddForm, setShowAddForm] = React.useState(false);
  const [newServer, setNewServer] = React.useState({
    id: "",
    name: "",
    type: "local" as "local" | "sse" | "streamable-http",
    command: "",
    args: "",
    url: ""
  });

  const refresh = React.useCallback(async () => {
    try {
      const res = await fetch("/api/mcp-servers");
      const data = await res.json();
      setServers(data.servers || []);
    } catch { /* ignore */ }
  }, []);

  React.useEffect(() => { void refresh(); }, [refresh]);

  const handleToggle = async (id: string) => {
    setLoading(true);
    try {
      await fetch(`/api/mcp-servers/${id}/toggle`, { method: "POST" });
      void refresh();
    } finally { setLoading(false); }
  };

  const handleDelete = async (id: string) => {
    if (!confirm(`确定删除 MCP server "${id}"？`)) return;
    setLoading(true);
    try {
      await fetch(`/api/mcp-servers/${id}`, { method: "DELETE" });
      void refresh();
    } finally { setLoading(false); }
  };

  const handleAdd = async () => {
    if (!newServer.id || !newServer.name) return;
    setLoading(true);
    try {
      const config = {
        id: newServer.id,
        name: newServer.name,
        type: newServer.type,
        enabled: true,
        builtIn: false,
        ...(newServer.type === "local"
          ? { command: newServer.command || "node", args: newServer.args.split(/\s+/).filter(Boolean) }
          : { url: newServer.url })
      };
      await fetch("/api/mcp-servers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config)
      });
      setNewServer({ id: "", name: "", type: "local", command: "", args: "", url: "" });
      setShowAddForm(false);
      void refresh();
    } finally { setLoading(false); }
  };

  return (
    <section className="settingsPanel mcpServersPanel">
      <div className="settingsPanelHeader">
        <h2>MCP Server（注册制）</h2>
        <button onClick={() => setShowAddForm(!showAddForm)} disabled={loading}>
          <Plus size={14} /> 添加
        </button>
      </div>

      {showAddForm ? (
        <div className="mcpAddForm">
          <input value={newServer.id} onChange={(e) => setNewServer({ ...newServer, id: e.target.value })} placeholder="ID（如 my-analyzer）" />
          <input value={newServer.name} onChange={(e) => setNewServer({ ...newServer, name: e.target.value })} placeholder="名称" />
          <select value={newServer.type} onChange={(e) => setNewServer({ ...newServer, type: e.target.value as typeof newServer.type })}>
            <option value="local">本地（stdio 子进程）</option>
            <option value="sse">远程（SSE）</option>
            <option value="streamable-http">远程（Streamable HTTP）</option>
          </select>
          {newServer.type === "local" ? (
            <>
              <input value={newServer.command} onChange={(e) => setNewServer({ ...newServer, command: e.target.value })} placeholder="command（如 node）" />
              <input value={newServer.args} onChange={(e) => setNewServer({ ...newServer, args: e.target.value })} placeholder="args（空格分隔，如 ${resources}/mcp/xxx/dist/index.js）" />
            </>
          ) : (
            <input value={newServer.url} onChange={(e) => setNewServer({ ...newServer, url: e.target.value })} placeholder="URL（如 http://localhost:8080/mcp）" />
          )}
          <div className="mcpAddFormActions">
            <button onClick={() => void handleAdd()} disabled={loading || !newServer.id || !newServer.name} className="primary">
              <Zap size={14} /> 保存
            </button>
            <button onClick={() => setShowAddForm(false)}>取消</button>
          </div>
        </div>
      ) : null}

      <div className="mcpServerList">
        {servers.map((server) => (
          <article key={server.id} className={`mcpServerItem ${server.enabled ? "enabled" : "disabled"}`}>
            <div className="mcpServerHeader">
              <div className="mcpServerName">
                <Plug size={14} className={server.connected ? "connected" : ""} />
                <strong>{server.name}</strong>
                {server.builtIn ? <span className="tag builtIn">内置</span> : null}
                <span className={`tag ${server.type}`}>{server.type}</span>
              </div>
              <div className="mcpServerActions">
                <button onClick={() => void handleToggle(server.id)} disabled={loading || server.type === "in-process"} title={server.enabled ? "禁用" : "启用"}>
                  {server.enabled ? "禁用" : "启用"}
                </button>
                {!server.builtIn && server.type !== "in-process" ? (
                  <button onClick={() => void handleDelete(server.id)} disabled={loading} className="dangerBtn">
                    <Trash2 size={13} />
                  </button>
                ) : null}
              </div>
            </div>
            {server.command ? <code className="mcpServerCommand">{server.command} {server.args?.join(" ")}</code> : null}
            {server.url ? <code className="mcpServerCommand">{server.url}</code> : null}
            <span className={`mcpServerStatus ${server.connected ? "online" : "offline"}`}>
              {server.connected ? "● 已连接" : "○ 未连接"}
            </span>
          </article>
        ))}
      </div>
    </section>
  );
}
