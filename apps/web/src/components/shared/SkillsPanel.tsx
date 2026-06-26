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

type SkillInfo = { name: string; description: string; enabled: boolean };
type DirInfo = { path: string; label: string; removable: boolean };

// 检测是否在 Electron 环境（可用目录选择器）
const isElectron = typeof window !== "undefined" && (window as unknown as { pcapaiDesktop?: unknown }).pcapaiDesktop;

export function SkillsPanel() {
  const [dirs, setDirs] = React.useState<{ main: string; extra: string[] }>({ main: "", extra: [] });
  const [skills, setSkills] = React.useState<SkillInfo[]>([]);
  const [loading, setLoading] = React.useState(false);

  const refresh = React.useCallback(async () => {
    try {
      const [dirsRes, skillsRes] = await Promise.all([
        fetch("/api/skills-dirs").then((r) => r.json()),
        fetch("/api/skills").then((r) => r.json())
      ]);
      setDirs(dirsRes);
      setSkills(skillsRes.skills || []);
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
    </>
  );
}
