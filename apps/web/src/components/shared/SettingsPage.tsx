/*
 * SettingsPage — 设置页（阶段 1d 从 main.tsx 抽出）。
 *
 * 行为等价于原 main.tsx:1541-1646 的 <section className="settingsPage">。
 * 三大块：添加 LLM（含 runtime 摘要 + 表单 + 测试） / LLM 列表（CRUD） / MCP Server 列表。
 * 所有数据 + handler 通过 props 传入（涉及 API 调用的仍在 main.tsx）。
 */
import React from "react";
import { CheckCircle, Eye, EyeOff, Pencil, Save, Trash2 } from "lucide-react";
import type { LlmProfile, LlmRuntimeStatus, McpServerInfo } from "../../types";
import { RfcLibraryPanel } from "./RfcLibraryPanel";

type LlmFormState = {
  baseURL: string;
  model: string;
  apiKey: string;
  providerData: string;
};

type SettingsPageProps = {
  // ---- 添加 LLM 表单 ----
  llmForm: LlmFormState;
  setLlmForm: React.Dispatch<React.SetStateAction<LlmFormState>>;
  showLlmApiKey: boolean;
  setShowLlmApiKey: React.Dispatch<React.SetStateAction<boolean>>;
  llmStatus: string;
  llmRuntime: LlmRuntimeStatus | null;

  onSaveLlm: () => void;
  onTestLlm: () => void;
  onTestAgentCompatibility: () => void;
  onReloadLlmConfig: () => void;

  // ---- LLM 列表 ----
  llmProfiles: LlmProfile[];
  selectedProfileIds: string[];

  onToggleProfileSelect: (profileId: string) => void;
  onSelectAllProfiles: () => void;
  onClearProfileSelection: () => void;
  onDeleteSelectedProfiles: () => void;
  onEditProfile: (profile: LlmProfile) => void;
  onActivateProfile: (profileId: string) => void;

  // ---- MCP Server ----
  mcpServers: McpServerInfo[];
};

export function SettingsPage(props: SettingsPageProps) {
  const {
    llmForm,
    setLlmForm,
    showLlmApiKey,
    setShowLlmApiKey,
    llmStatus,
    llmRuntime,
    onSaveLlm,
    onTestLlm,
    onTestAgentCompatibility,
    onReloadLlmConfig,
    llmProfiles,
    selectedProfileIds,
    onToggleProfileSelect,
    onSelectAllProfiles,
    onClearProfileSelection,
    onDeleteSelectedProfiles,
    onEditProfile,
    onActivateProfile,
    mcpServers
  } = props;

  return (
    <section className="settingsPage">
      <section className="settingsPanel">
        <h2>添加 LLM</h2>
        {llmRuntime && (
          <dl className="runtimeSummary">
            <dt>当前模型</dt>
            <dd>{llmRuntime.settings.model || "-"}</dd>
            <dt>配置档案</dt>
            <dd>{llmRuntime.settings.activeProfileId || "手工配置"}</dd>
            <dt>Key 状态</dt>
            <dd>{llmRuntime.settings.hasKey ? "已配置" : "未配置"}</dd>
            <dt>调用模式</dt>
            <dd>{llmRuntime.useResponses ? "Responses API" : "Chat Completions"}</dd>
          </dl>
        )}
        <div className="savedConfigCard">
          <div>
            <strong>当前已保存配置</strong>
            <span>
              {llmForm.baseURL || "-"} / {llmForm.model || "-"} /{" "}
              {llmRuntime?.settings.hasKey ? "已保存 Key" : "未保存 Key"}
            </span>
          </div>
          <button onClick={onReloadLlmConfig}>查询配置</button>
        </div>
        <div className="form">
          <label>
            <span>Base URL</span>
            <input
              value={llmForm.baseURL}
              onChange={(event) => setLlmForm({ ...llmForm, baseURL: event.target.value })}
              placeholder="OpenAI 兼容 Base URL"
            />
          </label>
          <label>
            <span>模型名称</span>
            <input
              value={llmForm.model}
              onChange={(event) => setLlmForm({ ...llmForm, model: event.target.value })}
              placeholder="模型名称"
            />
          </label>
          <label>
            <span>兼容参数 JSON</span>
            <textarea
              rows={3}
              value={llmForm.providerData}
              onChange={(event) => setLlmForm({ ...llmForm, providerData: event.target.value })}
              placeholder='例如 DeepSeek V4 Flash: {"thinking":{"type":"disabled"}}'
            />
          </label>
          <label>
            <span>API Key</span>
            <div className="secretInput">
              <input
                type={showLlmApiKey ? "text" : "password"}
                value={llmForm.apiKey}
                onChange={(event) => setLlmForm({ ...llmForm, apiKey: event.target.value })}
                placeholder="已有同名档案可留空；新增配置请填写 Key"
              />
              <button
                type="button"
                onClick={() => setShowLlmApiKey((visible) => !visible)}
                title={showLlmApiKey ? "隐藏 API Key" : "显示 API Key"}
                aria-label={showLlmApiKey ? "隐藏 API Key" : "显示 API Key"}
              >
                {showLlmApiKey ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </label>
          <button className="primary" onClick={onSaveLlm} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
            <Save size={16} /> 保存配置
          </button>
          <button onClick={onTestLlm} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
            测试配置
          </button>
          <button onClick={onTestAgentCompatibility} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
            Agent 兼容测试
          </button>
          <span className="status">{llmStatus}</span>
          <p className="formHint">
            本地 Ollama 作为普通 OpenAI 兼容配置添加：Base URL 填本地 /v1 地址，模型名填已安装模型，API Key 按你的服务配置填写；常见本地默认可填 ollama。
          </p>
        </div>
      </section>

      <section className="settingsPanel llmListPanel">
        <h2>LLM 列表</h2>
        <div className="bulkActions">
          <button onClick={onSelectAllProfiles} disabled={!llmProfiles.length}>全选</button>
          <button onClick={onClearProfileSelection} disabled={!selectedProfileIds.length}>清空</button>
          <button className="danger" onClick={onDeleteSelectedProfiles} disabled={!selectedProfileIds.length}>
            <Trash2 size={16} /> 删除
          </button>
        </div>

        <div className="profileList">
          {llmProfiles.map((profile) => (
            <article className="profileItem" key={profile.profileId}>
              <input
                type="checkbox"
                checked={selectedProfileIds.includes(profile.profileId)}
                onChange={() => onToggleProfileSelect(profile.profileId)}
                aria-label={`选择 ${profile.name}`}
              />
              <div>
                <strong>{profile.name}</strong>
                <span>
                  {profile.baseURL} / {profile.model} / {profile.hasKey ? "已保存 Key" : "未保存 Key"}
                  {profile.providerData ? " / 有兼容参数" : ""}
                  {profile.active ? " / 当前启用" : ""}
                </span>
              </div>
              <button onClick={() => onEditProfile(profile)} title="编辑配置档案">
                <Pencil size={16} />
              </button>
              <button onClick={() => onActivateProfile(profile.profileId)} disabled={profile.active} title="启用配置档案">
                <CheckCircle size={16} />
              </button>
            </article>
          ))}
          {!llmProfiles.length && <div className="empty">暂无模型配置档案。</div>}
        </div>
      </section>

      <section className="settingsPanel">
        <h2>MCP Server</h2>
        <div className="mcpList">
          {mcpServers.map((server) => (
            <article key={server.id} className="mcpItem">
              <div className="mcpItemHeader">
                <strong>{server.name}</strong>
                <span className="mcpKind">{server.kind}</span>
              </div>
              <p className="mcpDescription">{server.description}</p>
              <div className="mcpMeta">{server.toolCount} 个工具</div>
            </article>
          ))}
        </div>
      </section>

      {/* 阶段 3a：RFC 双层库管理（精简库内置 + 完整库静默下载） */}
      <RfcLibraryPanel />
    </section>
  );
}
