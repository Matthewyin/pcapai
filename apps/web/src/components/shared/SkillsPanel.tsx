/*
 * SkillsPanel — Skills 管理面板（设置页中栏）。
 *
 * 功能：
 * - 目录列表：主目录（不可删）+ 额外目录（内置不可删，用户添加的可删）
 * - 目录选择器：点击"添加目录"调用 Electron dialog 选择文件夹
 * - Skill 列表：每个 skill 有启用/禁用开关
 */
import React from "react";
import { FolderPlus, Trash2 } from "lucide-react";
import { skillProposalApproval, type SkillProposalStatus } from "./knowledgeUiState";

type SkillInfo = { name: string; description: string; enabled: boolean };
type SkillProposal = {
  proposalId: string;
  name: string;
  description: string;
  status: SkillProposalStatus;
  source: "agent" | "user";
  createdAt: string;
  rejectionReason?: string;
};
type LearnedPattern = {
  regex: string;
  adapterId: string;
  status: "pending" | "approved" | "rejected" | "disabled";
  hitCount: number;
  createdAt: string;
};

// 检测是否在 Electron 环境（可用目录选择器）
const isElectron = typeof window !== "undefined" && (window as unknown as { pcapaiDesktop?: unknown }).pcapaiDesktop;

export function SkillsPanel() {
  const [dirs, setDirs] = React.useState<{ main: string; extra: string[] }>({ main: "", extra: [] });
  const [skills, setSkills] = React.useState<SkillInfo[]>([]);
  const [proposals, setProposals] = React.useState<SkillProposal[]>([]);
  const [patterns, setPatterns] = React.useState<LearnedPattern[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [status, setStatus] = React.useState("");

  const refresh = React.useCallback(async () => {
    try {
      const [dirsRes, skillsRes, proposalsRes, patternsRes] = await Promise.all([
        fetch("/api/skills-dirs").then((r) => r.json()),
        fetch("/api/skills").then((r) => r.json()),
        fetch("/api/skill-proposals").then((r) => r.json()),
        fetch("/api/settings/learned-patterns").then((r) => r.json())
      ]);
      setDirs(dirsRes);
      setSkills(skillsRes.skills || []);
      setProposals(proposalsRes.proposals || []);
      setPatterns(patternsRes.patterns || []);
    } catch { /* ignore */ }
  }, []);

  React.useEffect(() => { void refresh(); }, [refresh]);

  const handleSelectDir = async () => {
    // Electron 环境：调用目录选择器
    if (isElectron) {
      const desktop = (window as unknown as { pcapaiDesktop: { selectDirectory: () => Promise<string | null> } }).pcapaiDesktop;
      const selected = await desktop.selectDirectory();
      if (!selected) return;
      await addDir(selected);
    }
    // 非 Electron（浏览器 dev）：无法选目录，忽略
  };

  const addDir = async (dir: string) => {
    setLoading(true);
    try {
      await fetch("/api/skills-dirs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ dir }) });
      void refresh();
    } finally { setLoading(false); }
  };

  const handleRemoveDir = async (dir: string) => {
    setLoading(true);
    try {
      await fetch(`/api/skills-dirs?dir=${encodeURIComponent(dir)}`, { method: "DELETE" });
      void refresh();
    } finally { setLoading(false); }
  };

  const handleToggleSkill = async (name: string) => {
    try {
      await fetch(`/api/skills/${encodeURIComponent(name)}/toggle`, { method: "POST" });
      void refresh();
    } catch { /* ignore */ }
  };

  const reviewProposal = async (proposal: SkillProposal, action: "approve" | "reject") => {
    setLoading(true);
    setStatus("");
    try {
      const response = await fetch(`/api/skill-proposals/${encodeURIComponent(proposal.proposalId)}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(action === "approve" ? { confirmOverwrite: skillProposalApproval(proposal.status).confirmOverwrite } : {})
      });
      const data = await response.json().catch(() => ({}));
      setStatus(response.ok ? "审批结果已保存。" : (data.reason || data.error || "审批失败。"));
      await refresh();
    } finally {
      setLoading(false);
    }
  };

  const reviewPattern = async (pattern: LearnedPattern, action: "approve" | "reject" | "toggle" | "delete", enabled?: boolean) => {
    setLoading(true);
    setStatus("");
    try {
      const response = await fetch(`/api/settings/learned-patterns${action === "delete" ? "" : `/${action}`}`, {
        method: action === "delete" ? "DELETE" : "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ regex: pattern.regex, adapterId: pattern.adapterId, enabled })
      });
      const data = await response.json().catch(() => ({}));
      setStatus(response.ok ? "学习规则状态已更新。" : (data.error || "操作失败。"));
      await refresh();
    } finally {
      setLoading(false);
    }
  };

  // 判断目录是否可删除：主目录不可删，内置目录（含 resources/app）不可删
  const isRemovable = (dir: string) => {
    if (dir === dirs.main) return false;
    if (dir.includes("/Resources/app/") || dir.includes("\\Resources\\app\\")) return false;
    return true;
  };

  return (
    <>
      <section className="settingsPanel">
        <h2>Skills 目录</h2>
        <p className="formHint">Agent 从以下目录加载 Skills（.md 文件）。后面的目录覆盖前面的同名 skill。</p>
        <div className="skillsDirList">
          <div className="skillsDirItem">
            <div>
              <strong>{dirs.main || "(未配置)"}</strong>
              <span className="tag builtIn">主目录（可写）</span>
            </div>
          </div>
          {dirs.extra.map((dir) => (
            <div className="skillsDirItem" key={dir}>
              <div>
                <strong>{dir}</strong>
                {!isRemovable(dir) ? <span className="tag builtIn">内置</span> : <span className="tag sse">用户添加</span>}
              </div>
              {isRemovable(dir) ? (
                <button onClick={() => void handleRemoveDir(dir)} disabled={loading} className="dangerBtn" title="移除目录">
                  <Trash2 size={13} />
                </button>
              ) : null}
            </div>
          ))}
        </div>
        <button onClick={() => void handleSelectDir()} disabled={loading} className="primary">
          <FolderPlus size={14} /> {isElectron ? "选择目录" : "添加目录"}
        </button>
      </section>

      <section className="settingsPanel">
        <h2>待审批 Skill 提案</h2>
        <p className="formHint">Agent 只能提交提案；批准前不会写入全局 Skills。覆盖已有 Skill 时需要连续两次确认。</p>
        <div className="skillsList">
          {proposals.filter((proposal) => proposal.status === "pending" || proposal.status === "overwrite_confirmation").map((proposal) => (
            <article className="skillItem" key={proposal.proposalId}>
              <div className="skillItemMain">
                <strong className="skillItemName">{proposal.name}</strong>
                <span className="skillItemDesc">{proposal.description}</span>
                <span className="skillReviewStatus">{proposal.status === "overwrite_confirmation" ? "等待二次确认覆盖" : "等待审批"}</span>
              </div>
              <div className="skillReviewActions">
                <button className="primary" disabled={loading} onClick={() => void reviewProposal(proposal, "approve")}>
                  {skillProposalApproval(proposal.status).label}
                </button>
                <button disabled={loading} onClick={() => void reviewProposal(proposal, "reject")}>拒绝</button>
              </div>
            </article>
          ))}
          {!proposals.some((proposal) => proposal.status === "pending" || proposal.status === "overwrite_confirmation") && <div className="empty">暂无待审批 Skill 提案。</div>}
        </div>
      </section>

      <section className="settingsPanel">
        <h2>已加载 Skills（{skills.length}）</h2>
        <p className="formHint">点击开关启用/禁用 skill。禁用的 skill 不会被 Agent 使用。</p>
        <div className="skillsList">
          {skills.map((skill) => (
            <article className={`skillItem ${skill.enabled ? "" : "disabled"}`} key={skill.name}>
              <div className="skillItemMain">
                <strong className="skillItemName">{skill.name}</strong>
                <span className="skillItemDesc">{skill.description}</span>
              </div>
              <button
                className={`skillToggle ${skill.enabled ? "on" : "off"}`}
                onClick={() => void handleToggleSkill(skill.name)}
                title={skill.enabled ? "禁用" : "启用"}
              >
                {skill.enabled ? "启用中" : "已禁用"}
              </button>
            </article>
          ))}
          {!skills.length && <div className="empty">暂无 Skills。在 skills 目录下创建 .md 文件即可。</div>}
        </div>
      </section>

      <section className="settingsPanel">
        <h2>Agent 学习规则（{patterns.length}）</h2>
        <p className="formHint">新规则先进入候选态，批准后才参与自动路由。已批准规则可随时禁用或删除。</p>
        <div className="skillsList">
          {patterns.map((pattern) => (
            <article className={`skillItem ${pattern.status === "approved" ? "" : "disabled"}`} key={`${pattern.adapterId}:${pattern.regex}`}>
              <div className="skillItemMain">
                <strong className="skillItemName">{pattern.adapterId}</strong>
                <span className="skillItemDesc">/{pattern.regex}/ · 命中 {pattern.hitCount} 次 · {pattern.status}</span>
              </div>
              <div className="skillReviewActions">
                {pattern.status === "pending" ? (
                  <>
                    <button className="primary" disabled={loading} onClick={() => void reviewPattern(pattern, "approve")}>批准</button>
                    <button disabled={loading} onClick={() => void reviewPattern(pattern, "reject")}>拒绝</button>
                  </>
                ) : null}
                {pattern.status === "approved" ? <button disabled={loading} onClick={() => void reviewPattern(pattern, "toggle", false)}>禁用</button> : null}
                {pattern.status === "disabled" ? <button disabled={loading} onClick={() => void reviewPattern(pattern, "toggle", true)}>启用</button> : null}
                <button disabled={loading} onClick={() => void reviewPattern(pattern, "delete")} title="删除"><Trash2 size={13} /></button>
              </div>
            </article>
          ))}
          {!patterns.length && <div className="empty">暂无 Agent 学习规则。</div>}
        </div>
        {status ? <span className="status">{status}</span> : null}
      </section>
    </>
  );
}
