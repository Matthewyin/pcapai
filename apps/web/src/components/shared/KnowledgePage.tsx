/*
 * KnowledgePage — 知识库管理页（阶段 1d 从 main.tsx 抽出）。
 *
 * 完全自包含：自己的 state（tab/notes/skills/status/loading/selectedSkill/skillBody/busy）
 * + fetch 逻辑（refresh/verifyNote/disputeNote/viewSkill/deleteSkillConfirm）。
 * 三层知识体系：实战笔记（案例层）· 技能 Skills（方法论层）· RFC 全文库（规范层）。
 */
import React from "react";

type FieldNote = {
  id: string;
  title: string;
  summary: string;
  protocols: string[];
  verifiedCount: number;
  disputedCount: number;
  lastVerifiedAt?: string;
  candidateCauses?: Array<{
    likelihood: string;
    cause: string;
    rfcDocId?: string;
    rfcSection?: string;
    skillIds?: string[];
  }>;
};

type Skill = {
  name: string;
  description: string;
};

type KnowledgeStatus = {
  rfc?: { built?: boolean; docCount?: number; sectionCount?: number; stale?: boolean };
  fieldNotes?: { built?: boolean; noteCount?: number };
  skills?: { built?: boolean; skillCount?: number };
};

export function KnowledgePage() {
  const [tab, setTab] = React.useState<"notes" | "skills" | "status">("notes");
  const [notes, setNotes] = React.useState<FieldNote[]>([]);
  const [skills, setSkills] = React.useState<Skill[]>([]);
  const [status, setStatus] = React.useState<KnowledgeStatus>({});
  const [loading, setLoading] = React.useState(false);
  const [selectedSkill, setSelectedSkill] = React.useState<string | null>(null);
  const [skillBody, setSkillBody] = React.useState<string>("");
  const [busy, setBusy] = React.useState<string>("");

  async function refresh() {
    setLoading(true);
    try {
      const [notesRes, skillsRes, statusRes] = await Promise.all([
        fetch("/api/field-notes").then((r) => r.json()),
        fetch("/api/skills").then((r) => r.json()),
        fetch("/api/rag/status").then((r) => r.json())
      ]);
      setNotes(notesRes.notes || []);
      setSkills(skillsRes.skills || []);
      setStatus({ rfc: statusRes, fieldNotes: notesRes.status, skills: skillsRes.status });
    } catch (e) {
      console.error("知识库加载失败", e);
    }
    setLoading(false);
  }

  React.useEffect(() => {
    void refresh();
  }, []);

  async function verifyNote(id: string) {
    setBusy(`verify-${id}`);
    await fetch(`/api/field-notes/${id}/verify`, { method: "POST" });
    refresh();
    setBusy("");
  }

  async function disputeNote(id: string) {
    const correction = window.prompt("请描述实际根因（纠正内容）");
    if (correction === null) return;
    setBusy(`dispute-${id}`);
    await fetch(`/api/field-notes/${id}/dispute`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ correction })
    });
    refresh();
    setBusy("");
  }

  async function viewSkill(name: string) {
    setBusy(`skill-${name}`);
    const res = await fetch(`/api/skills/${name}`);
    const data = await res.json();
    setSelectedSkill(name);
    setSkillBody(data.body || "");
    setBusy("");
  }

  async function deleteSkillConfirm(name: string) {
    if (!window.confirm(`确认删除技能 ${name}？`)) return;
    setBusy(`del-${name}`);
    await fetch(`/api/skills/${name}`, { method: "DELETE" });
    if (selectedSkill === name) {
      setSelectedSkill(null);
      setSkillBody("");
    }
    refresh();
    setBusy("");
  }

  return (
    <section className="historyPage">
      <section className="historyToolbar">
        <div>
          <h2>知识库管理</h2>
          <p>三层知识体系：实战笔记（案例层）· 技能 Skills（方法论层）· RFC 全文库（规范层）。沉淀越多，Agent 排障越准。</p>
        </div>
        <div className="toolbarActions">
          <button onClick={() => void refresh()} disabled={loading}>
            {loading ? "刷新中..." : "刷新"}
          </button>
        </div>
      </section>

      <nav className="settingsTabs">
        <button className={tab === "notes" ? "active" : ""} onClick={() => setTab("notes")}>
          实战笔记（{notes.length}）
        </button>
        <button className={tab === "skills" ? "active" : ""} onClick={() => setTab("skills")}>
          技能 Skills（{skills.length}）
        </button>
        <button className={tab === "status" ? "active" : ""} onClick={() => setTab("status")}>
          索引状态
        </button>
      </nav>

      {tab === "notes" && (
        <div className="knowledgeList">
          {notes.length === 0 ? (
            <p className="empty">
              暂无实战笔记。运行 <code>npm run fieldnotes:build</code> 导入种子。
            </p>
          ) : (
            notes.map((note) => (
              <article key={note.id} className="knowledgeCard">
                <header>
                  <h3>{note.title}</h3>
                  <div className="knowledgeMeta">
                    <span>协议: {note.protocols.join(", ")}</span>
                    <span title="用户确认次数">✓ {note.verifiedCount}</span>
                    <span title="用户纠正次数">✗ {note.disputedCount}</span>
                    {note.lastVerifiedAt && <small>最近确认: {new Date(note.lastVerifiedAt).toLocaleString()}</small>}
                  </div>
                </header>
                <p>{note.summary}</p>
                {note.candidateCauses && note.candidateCauses.length > 0 && (
                  <ul className="causeList">
                    {note.candidateCauses.map((cause, i) => (
                      <li key={i}>
                        <strong>[{cause.likelihood}]</strong> {cause.cause}
                        {cause.rfcDocId && (
                          <em>
                            {" "}
                            RFC {cause.rfcDocId}
                            {cause.rfcSection ? `§${cause.rfcSection}` : ""}
                          </em>
                        )}
                        {cause.skillIds && cause.skillIds.length > 0 && <small> 技能: {cause.skillIds.join(", ")}</small>}
                      </li>
                    ))}
                  </ul>
                )}
                <footer className="knowledgeActions">
                  <button onClick={() => void verifyNote(note.id)} disabled={busy === `verify-${note.id}`}>
                    ✓ 确认正确
                  </button>
                  <button onClick={() => void disputeNote(note.id)} disabled={busy === `dispute-${note.id}`}>
                    ✗ 纠正
                  </button>
                </footer>
              </article>
            ))
          )}
        </div>
      )}

      {tab === "skills" && (
        <div className="knowledgeList">
          <div className="skillLayout">
            <div className="skillList">
              {skills.length === 0 ? (
                <p className="empty">暂无技能。</p>
              ) : (
                skills.map((skill) => (
                  <button
                    key={skill.name}
                    className={`skillItem ${selectedSkill === skill.name ? "active" : ""}`}
                    onClick={() => void viewSkill(skill.name)}
                  >
                    <strong>{skill.name}</strong>
                    <span>{skill.description}</span>
                  </button>
                ))
              )}
            </div>
            <div className="skillDetail">
              {selectedSkill ? (
                <>
                  <div className="skillDetailHeader">
                    <h3>{selectedSkill}</h3>
                    <button onClick={() => void deleteSkillConfirm(selectedSkill)} disabled={busy === `del-${selectedSkill}`}>
                      删除
                    </button>
                  </div>
                  <pre className="skillBody">{skillBody || "(空)"}</pre>
                </>
              ) : (
                <p className="empty">选择左侧技能查看操作 SOP 详情。</p>
              )}
            </div>
          </div>
        </div>
      )}

      {tab === "status" && (
        <div className="knowledgeList">
          <dl className="statusList">
            <dt>RFC 全文库</dt>
            <dd>
              {status.rfc?.built
                ? `已构建 · ${status.rfc.docCount} 篇 · ${status.rfc.sectionCount} 节`
                : "未构建"}{" "}
              {status.rfc?.stale && <em className="warn">语料已更新，需重建</em>}
            </dd>
            <dt>实战笔记库</dt>
            <dd>
              {status.fieldNotes?.built
                ? `已构建 · ${status.fieldNotes.noteCount} 条`
                : "未构建（运行 npm run fieldnotes:build）"}
            </dd>
            <dt>Skills 库</dt>
            <dd>{status.skills?.built ? `已就绪 · ${status.skills.skillCount} 个技能` : "未就绪"}</dd>
          </dl>
        </div>
      )}
    </section>
  );
}
