/*
 * SettingsPage — 设置页（左菜单 + 右内容布局）。
 *
 * 4 个菜单：LLM 配置 / MCP Server / Skills / RFC 知识库。
 * 每个菜单独立页面，不混在同一个滚动页面里。
 */
import React from "react";
import { CheckCircle, Eye, EyeOff, Pencil, Save, Trash2 } from "lucide-react";
import type { LlmProfile, LlmRuntimeStatus, McpServerInfo } from "../../types";
import { RfcLibraryPanel } from "./RfcLibraryPanel";
import { McpServersPanel } from "./McpServersPanel";
import { SkillsPanel } from "./SkillsPanel";

type LlmFormState = {
  baseURL: string;
  model: string;
  apiKey: string;
  providerData: string;
};

type SettingsPageProps = {
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
  llmProfiles: LlmProfile[];
  selectedProfileIds: string[];
  onToggleProfileSelect: (profileId: string) => void;
  onSelectAllProfiles: () => void;
  onClearProfileSelection: () => void;
  onDeleteSelectedProfiles: () => void;
  onEditProfile: (profile: LlmProfile) => void;
  onActivateProfile: (profileId: string) => void;
  mcpServers: McpServerInfo[];
};

type SettingsTab = "llm" | "mcp" | "skills" | "rfc";

export function SettingsPage(props: SettingsPageProps) {
  const [activeTab, setActiveTab] = React.useState<SettingsTab>("llm");
  const {
    llmForm, setLlmForm, showLlmApiKey, setShowLlmApiKey,
    llmStatus, llmRuntime,
    onSaveLlm, onTestLlm, onTestAgentCompatibility, onReloadLlmConfig,
    llmProfiles, selectedProfileIds,
    onToggleProfileSelect, onSelectAllProfiles, onClearProfileSelection,
    onDeleteSelectedProfiles, onEditProfile, onActivateProfile,
  } = props;

  const tabs: Array<{ id: SettingsTab; label: string }> = [
    { id: "llm", label: "LLM 配置" },
    { id: "mcp", label: "MCP Server" },
    { id: "skills", label: "Skills" },
    { id: "rfc", label: "RFC 知识库" },
  ];

  return (
    <section className="settingsPage">
      {/* 内容区（中间） */}
      <div className="settingsContent">
        {activeTab === "llm" ? <LlmPanel {...props} /> : null}
        {activeTab === "mcp" ? <McpServersPanel /> : null}
        {activeTab === "skills" ? <SkillsPanel /> : null}
        {activeTab === "rfc" ? <RfcLibraryPanel /> : null}
      </div>

      {/* 右侧菜单 */}
      <nav className="settingsMenu">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`settingsMenuItem ${activeTab === tab.id ? "active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>
    </section>
  );
}

// ===== LLM 配置面板（表单 + 列表合为一个页面） =====
function LlmPanel(props: SettingsPageProps) {
  const {
    llmForm, setLlmForm, showLlmApiKey, setShowLlmApiKey,
    llmStatus, llmRuntime,
    onSaveLlm, onTestLlm, onTestAgentCompatibility, onReloadLlmConfig,
    llmProfiles, selectedProfileIds,
    onToggleProfileSelect, onSelectAllProfiles, onClearProfileSelection,
    onDeleteSelectedProfiles, onEditProfile, onActivateProfile,
  } = props;
  return (
    <>
      <section className="settingsPanel">
        <h2>添加 / 编辑 LLM</h2>
        {llmRuntime && (
          <dl className="runtimeSummary">
            <dt>当前模型</dt><dd>{llmRuntime.settings.model || "-"}</dd>
            <dt>配置档案</dt><dd>{llmRuntime.settings.activeProfileId || "手工配置"}</dd>
            <dt>Key 状态</dt><dd>{llmRuntime.settings.hasKey ? "已配置" : "未配置"}</dd>
            <dt>调用模式</dt><dd>{llmRuntime.useResponses ? "Responses API" : "Chat Completions"}</dd>
          </dl>
        )}
        <div className="savedConfigCard">
          <div>
            <strong>当前已保存配置</strong>
            <span>{llmForm.baseURL || "-"} / {llmForm.model || "-"} / {llmRuntime?.settings.hasKey ? "已保存 Key" : "未保存 Key"}</span>
          </div>
          <button onClick={onReloadLlmConfig}>查询配置</button>
        </div>
        <div className="form">
          <label>
            <span>Base URL</span>
            <input value={llmForm.baseURL} onChange={(e) => setLlmForm({ ...llmForm, baseURL: e.target.value })} placeholder="OpenAI 兼容 Base URL（如 https://api.moonshot.cn/v1）" />
          </label>
          <label>
            <span>模型名称</span>
            <input value={llmForm.model} onChange={(e) => setLlmForm({ ...llmForm, model: e.target.value })} placeholder="模型名称" />
          </label>
          <label>
            <span>兼容参数 JSON</span>
            <textarea rows={3} value={llmForm.providerData} onChange={(e) => setLlmForm({ ...llmForm, providerData: e.target.value })} placeholder='例如 {"thinking":{"type":"disabled"}}' />
          </label>
          <label>
            <span>API Key</span>
            <div className="secretInput">
              <input type={showLlmApiKey ? "text" : "password"} value={llmForm.apiKey} onChange={(e) => setLlmForm({ ...llmForm, apiKey: e.target.value })} placeholder="已有同名档案可留空；新增配置请填写 Key" />
              <button type="button" onClick={() => setShowLlmApiKey((v) => !v)} title={showLlmApiKey ? "隐藏" : "显示"}>
                {showLlmApiKey ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </label>
          <div className="llmFormActions">
            <button className="primary" onClick={onSaveLlm} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
              <Save size={16} /> 保存
            </button>
            <button onClick={onTestLlm} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>测试</button>
            <button onClick={onTestAgentCompatibility} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>兼容测试</button>
          </div>
          {llmStatus ? <span className="status">{llmStatus}</span> : null}
          <p className="formHint">
            OpenAI 兼容配置：Base URL 填 /v1 结尾的地址，模型名填文档中的精确名称。
          </p>
        </div>
      </section>

      <section className="settingsPanel">
        <h2>已配置模型列表</h2>
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
              <input type="checkbox" checked={selectedProfileIds.includes(profile.profileId)} onChange={() => onToggleProfileSelect(profile.profileId)} />
              <div>
                <strong>{profile.name}</strong>
                <span>{profile.baseURL} / {profile.model} / {profile.hasKey ? "Key ✓" : "Key ✗"}{profile.active ? " / 启用中" : ""}</span>
              </div>
              <button onClick={() => onEditProfile(profile)} title="编辑"><Pencil size={16} /></button>
              <button onClick={() => onActivateProfile(profile.profileId)} disabled={profile.active} title="启用"><CheckCircle size={16} /></button>
            </article>
          ))}
          {!llmProfiles.length && <div className="empty">暂无模型配置。</div>}
        </div>
      </section>
    </>
  );
}
