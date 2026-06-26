/*
 * SkillsPanel — Skills 管理面板（设置页）。
 *
 * 展示已注册的 skills 目录 + 各目录下的 skill 列表 + 添加/删除目录。
 */
import React from "react";
import { FolderPlus, Trash2 } from "lucide-react";

type SkillInfo = { name: string; description: string };

export function SkillsPanel() {
  const [dirs, setDirs] = React.useState<{ main: string; extra: string[] }>({ main: "", extra: [] });
  const [skills, setSkills] = React.useState<SkillInfo[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [newDir, setNewDir] = React.useState("");

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

  const handleAddDir = async () => {
    if (!newDir.trim()) return;
    setLoading(true);
    try {
      await fetch("/api/skills-dirs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ dir: newDir.trim() }) });
      setNewDir("");
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

  return (
    <>
      <section className="settingsPanel">
        <h2>Skills 目录</h2>
        <p className="formHint">Agent 从以下目录加载 Skills（.md 文件）。后面的目录覆盖前面的同名 skill。</p>
        <div className="skillsDirList">
          <div className="skillsDirItem">
            <strong>{dirs.main}</strong>
            <span className="tag local">主目录（可写）</span>
          </div>
          {dirs.extra.map((dir) => (
            <div className="skillsDirItem" key={dir}>
              <strong>{dir}</strong>
              <span className="tag sse">额外</span>
              <button onClick={() => void handleRemoveDir(dir)} disabled={loading} className="dangerBtn"><Trash2 size={13} /></button>
            </div>
          ))}
        </div>
        <div className="mcpAddForm">
          <input value={newDir} onChange={(e) => setNewDir(e.target.value)} placeholder="目录绝对路径（如 /Users/me/my-skills）" />
          <button onClick={() => void handleAddDir()} disabled={loading || !newDir.trim()}>
            <FolderPlus size={14} /> 添加目录
          </button>
        </div>
      </section>

      <section className="settingsPanel">
        <h2>已加载 Skills（{skills.length}）</h2>
        <div className="skillsList">
          {skills.map((skill) => (
            <article className="skillItem" key={skill.name}>
              <strong className="skillItemName">{skill.name}</strong>
              <span className="skillItemDesc">{skill.description}</span>
            </article>
          ))}
          {!skills.length && <div className="empty">暂无 Skills。在 skills 目录下创建 .md 文件即可。</div>}
        </div>
      </section>
    </>
  );
}
