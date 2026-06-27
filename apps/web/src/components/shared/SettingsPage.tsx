/*
 * SettingsPage — 配置内容区（渲染在中栏）。
 *
 * 三栏布局：左栏（Sidebar）+ 中栏（本组件，配置内容）+ 右栏（SettingsMenu 菜单）。
 * 菜单组件由 main.tsx 渲染到 AppShell 的 agentPanel slot（右栏）。
 * activeTab 状态在 useUIStore 共享。
 */
import React from "react";
import { CheckCircle, Eye, EyeOff, Pencil, Save, Trash2 } from "lucide-react";
import type { LlmProfile, LlmRuntimeStatus, McpServerInfo } from "../../types";
import { RfcLibraryPanel } from "./RfcLibraryPanel";
import { McpServersPanel } from "./McpServersPanel";
import { SkillsPanel } from "./SkillsPanel";
import { useUIStore } from "../../store/useUIStore";

type LlmFormState = {
  baseURL: string;
  model: string;
  apiKey: string;
  thinkingDepth: string;
  reasoningDepth: string;
  temperature: string;
  maxTokens: string;
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

export function SettingsPage(props: SettingsPageProps) {
  const settingsTab = useUIStore((s) => s.settingsTab);
  return (
    <div className="settingsContent">
      {settingsTab === "llm" ? <LlmPanel {...props} /> : null}
      {settingsTab === "mcp" ? <McpServersPanel /> : null}
      {settingsTab === "skills" ? <SkillsPanel /> : null}
      {settingsTab === "rfc" ? <RfcLibraryPanel /> : null}
    </div>
  );
}

// ===== LLM 配置面板 =====
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
          <div className="formRow">
            <label>
              <span>思考深度</span>
              <select value={llmForm.thinkingDepth} onChange={(e) => setLlmForm({ ...llmForm, thinkingDepth: e.target.value })}>
                <option value="快速">快速</option>
                <option value="标准">标准</option>
                <option value="深入">深入</option>
              </select>
            </label>
            <label>
              <span>推理深度</span>
              <select value={llmForm.reasoningDepth} onChange={(e) => setLlmForm({ ...llmForm, reasoningDepth: e.target.value })}>
                <option value="低">低</option>
                <option value="标准">标准</option>
                <option value="高">高</option>
              </select>
            </label>
          </div>
          <div className="formRow">
            <label>
              <span>Temperature</span>
              <input type="number" step="0.1" min="0" max="2" value={llmForm.temperature} onChange={(e) => setLlmForm({ ...llmForm, temperature: e.target.value })} placeholder="留空用默认" />
            </label>
            <label>
              <span>Max Tokens</span>
              <input type="number" step="1" min="1" value={llmForm.maxTokens} onChange={(e) => setLlmForm({ ...llmForm, maxTokens: e.target.value })} placeholder="留空用默认" />
            </label>
          </div>
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
            OpenAI 兼容配置：Base URL 填 /v1 结尾的地址，模型名填文档中的精确名称。思考/推理深度会根据供应商自动适配（GLM → thinking + reasoning_effort，DeepSeek → reasoning_effort）。
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
