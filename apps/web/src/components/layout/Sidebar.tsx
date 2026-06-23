/*
 * Sidebar — 左栏组件（阶段 1a 从 main.tsx 抽出）。
 *
 * 设计：props 接收数据 + handler，本地 UI 态（菜单开关 / 重命名草稿 / 设置菜单）放组件内 useState。
 * 样式保留现有 styles.css 的 className（避免一次性改坏 200+ 行 CSS），新写部分用 Tailwind utility。
 * 阶段 2 三栏新 UI 时再做：(1) 状态迁 useUIStore/useCaseStore (2) 样式完全 Tailwind 化 (3) 加拖拽手柄。
 *
 * 行为完全等价于原 main.tsx:1565-1652 的 <aside className="appSidebar panel">。
 */
import React from "react";
import { Activity, BookOpen, Clock, Library, Moon, MoreHorizontal, Pencil, Pin, PinOff, Plus, Settings, SlidersHorizontal, SquarePen, Sun, Trash2 } from "lucide-react";
import type { CaseGraph, CaseSummary, QueryRun } from "../../types";
import { formatPacketTime } from "../../lib/format";

export type SettingsMenuPage = "history" | "settings" | "help" | "knowledge";

type SidebarProps = {
  /** 当前案例图（用于显示"当前会话" + 高亮列表项） */
  graph: CaseGraph | null;
  /** 当前活动 QueryRun（"当前会话"副标题用） */
  activeQueryRun?: QueryRun | undefined;
  /** 已排序的会话列表（main.tsx 的 displayedCaseHistory：置顶在前、再按 updatedAt 降序） */
  displayedCaseHistory: CaseSummary[];
  /** 置顶 caseId 集合 */
  pinnedCaseIds: string[];
  /** 当前页面（设置按钮 active 状态用） */
  page: "workbench" | "history" | "settings" | "help" | "knowledge";
  /** 主题 */
  theme: "dark" | "light";
  /** 迷你栏模式（左栏折叠时，渲染图标版快捷入口） */
  mini?: boolean;

  // ---- 行为回调（main.tsx 仍是权威，涉及 API 调用）----
  /** 新建会话 */
  onCreateNewChat: () => void;
  /** 打开某会话 */
  onOpenCase: (caseId: string) => void;
  /** 置顶/取消置顶 */
  onTogglePinned: (caseId: string) => void;
  /** 重命名提交（已 trim + 非空校验由调用方负责） */
  onRename: (caseId: string, newTitle: string) => void | Promise<void>;
  /** 删除 */
  onDelete: (caseId: string) => void | Promise<void>;
  /** 打开设置子页 */
  onOpenSettingsPage: (page: SettingsMenuPage) => void;
  /** 切换主题 */
  onToggleTheme: () => void;
};

export function Sidebar(props: SidebarProps) {
  const {
    graph,
    activeQueryRun,
    displayedCaseHistory,
    pinnedCaseIds,
    page,
    theme,
    mini,
    onCreateNewChat,
    onOpenCase,
    onTogglePinned,
    onRename,
    onDelete,
    onOpenSettingsPage,
    onToggleTheme
  } = props;

  // 本地 UI 态：右键/更多按钮展开的会话操作菜单
  const [caseMenuId, setCaseMenuId] = React.useState("");
  // 重命名态：进入编辑的 caseId + 草稿
  const [renamingCaseId, setRenamingCaseId] = React.useState("");
  const [renameDraft, setRenameDraft] = React.useState("");
  // 设置菜单（底部）展开态
  const [settingsMenuOpen, setSettingsMenuOpen] = React.useState(false);

  // 点击外部关闭会话/设置菜单（从 main.tsx 迁入；逻辑等价）
  React.useEffect(() => {
    function closeMenusOnOutsideClick(event: PointerEvent) {
      const target = event.target;
      if (!(target instanceof Element)) return;
      if (target.closest(".caseActionMenu, .caseMoreButton, .settingsMenu, .settingsMenuButton")) return;
      setCaseMenuId("");
      setSettingsMenuOpen(false);
    }
    document.addEventListener("pointerdown", closeMenusOnOutsideClick);
    return () => document.removeEventListener("pointerdown", closeMenusOnOutsideClick);
  }, []);

  function submitRename(caseId: string) {
    const title = renameDraft.trim();
    if (!title) {
      setRenamingCaseId("");
      return;
    }
    void onRename(caseId, title);
    // 注意：main.tsx 的 renameCase 会异步刷 history，成功后清 renamingCaseId；
    // 但因为 renamingCaseId 现在在 Sidebar 内部，这里主动清，避免等待异步。
    // 失败时 main.tsx 会 setStatus，菜单态用户可重试。
    setRenamingCaseId("");
    setCaseMenuId("");
  }

  function startRename(item: CaseSummary) {
    setRenameDraft(item.title);
    setRenamingCaseId(item.caseId);
    setCaseMenuId("");
  }

  // 迷你栏模式：左栏折叠时渲染图标版快捷入口（logo 已在 AppShell 顶部品牌区）
  // 专业图标 + hover tooltip（title 属性原生提示）+ 加大尺寸
  if (mini) {
    return (
      <aside className="appSidebarMini">
        <button className="miniIconBtn" onClick={() => void onCreateNewChat()} title="新建会话" aria-label="新建会话">
          <SquarePen size={22} />
        </button>
        <button
          className={`miniIconBtn ${page === "history" ? "active" : ""}`}
          onClick={() => onOpenSettingsPage("history")}
          title="历史案例"
          aria-label="历史案例"
        >
          <Clock size={22} />
        </button>
        <button
          className={`miniIconBtn ${page === "knowledge" ? "active" : ""}`}
          onClick={() => onOpenSettingsPage("knowledge")}
          title="知识库"
          aria-label="知识库"
        >
          <Library size={22} />
        </button>
        <button
          className={`miniIconBtn ${page === "settings" ? "active" : ""}`}
          onClick={() => onOpenSettingsPage("settings")}
          title="模型配置"
          aria-label="模型配置"
        >
          <SlidersHorizontal size={22} />
        </button>
        <div className="miniSpacer" />
        <button className="miniIconBtn" onClick={onToggleTheme} title={theme === "dark" ? "切换亮色" : "切换暗色"} aria-label="切换主题">
          {theme === "dark" ? <Sun size={22} /> : <Moon size={22} />}
        </button>
      </aside>
    );
  }

  return (
    <aside className="appSidebar panel">
      {/* 新建按钮：独立一行（logo 已移到 AppShell 顶部） */}
      <button className="newCaseButton" onClick={() => void onCreateNewChat()}>
        <Plus size={16} /> 新建会话
      </button>

      {/* 当前会话概览 */}
      <section className="currentSession">
        <span>当前会话</span>
        <strong>{graph ? graph.spec.title : "尚未选择会话"}</strong>
        <small>
          {graph
            ? `${graph.captures.length} 文件 · ${graph.rawPackets.length || graph.packets.length} 包${
                activeQueryRun ? ` · ${activeQueryRun.protocol || "query"}` : ""
              }`
            : "新建会话后上传 pcap 开始分析"}
        </small>
      </section>

      {/* 会话列表 */}
      <section className="sidebarCases">
        <div className="sidebarSectionTitle">
          <h2>最近会话</h2>
        </div>
        {displayedCaseHistory.map((item) => {
          const isActive = graph?.spec.caseId === item.caseId;
          const isPinned = pinnedCaseIds.includes(item.caseId);
          const isRenaming = renamingCaseId === item.caseId;
          return (
            <article
              className={`sidebarCase ${isActive ? "active" : ""}`}
              key={item.caseId}
              onContextMenu={(event) => {
                event.preventDefault();
                setCaseMenuId(item.caseId);
              }}
            >
              {isRenaming ? (
                <form
                  className="caseRenameForm"
                  onSubmit={(event) => {
                    event.preventDefault();
                    submitRename(item.caseId);
                  }}
                >
                  <input
                    value={renameDraft}
                    autoFocus
                    onChange={(event) => setRenameDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Escape") setRenamingCaseId("");
                    }}
                  />
                  <button type="submit">保存</button>
                </form>
              ) : (
                <>
                  <button className="sessionOpenButton" onClick={() => onOpenCase(item.caseId)}>
                    <span className="caseTitle">{isPinned ? "置顶 · " : ""}{item.title}</span>
                    <span className="caseMeta">
                      {item.captureCount} 文件 · {item.rawPacketCount || item.packetCount} 包 · {item.runCount} 查询
                    </span>
                    <span className="caseTime">{formatPacketTime(item.updatedAt)}</span>
                  </button>
                  <button
                    className="caseMoreButton"
                    onClick={(event) => {
                      event.stopPropagation();
                      setCaseMenuId((id) => (id === item.caseId ? "" : item.caseId));
                    }}
                    aria-label="会话操作"
                  >
                    <MoreHorizontal size={16} />
                  </button>
                  {caseMenuId === item.caseId && (
                    <div className="caseActionMenu">
                      <button onClick={() => startRename(item)}>
                        <Pencil size={14} /> 重命名
                      </button>
                      <button onClick={() => { onTogglePinned(item.caseId); setCaseMenuId(""); }}>
                        {isPinned ? <PinOff size={14} /> : <Pin size={14} />}
                        {isPinned ? "取消置顶" : "置顶"}
                      </button>
                      <button className="dangerAction" onClick={() => { void onDelete(item.caseId); setCaseMenuId(""); }}>
                        <Trash2 size={14} /> 删除
                      </button>
                    </div>
                  )}
                </>
              )}
            </article>
          );
        })}
        {!displayedCaseHistory.length && <div className="empty">暂无历史案例。</div>}
      </section>

      {/* 底部设置 */}
      <div className="sidebarFooter">
        <button
          className={`settingsMenuButton ${page !== "workbench" || settingsMenuOpen ? "active" : ""}`}
          onClick={() => setSettingsMenuOpen((open) => !open)}
        >
          <Settings size={16} /> 设置
        </button>
        {settingsMenuOpen && (
          <div className="settingsMenu">
            <button onClick={() => { onOpenSettingsPage("history"); setSettingsMenuOpen(false); }}>
              <Clock size={15} /> 历史案例
            </button>
            <button onClick={() => { onOpenSettingsPage("settings"); setSettingsMenuOpen(false); }}>
              <SlidersHorizontal size={15} /> 模型配置
            </button>
            <button onClick={() => { onOpenSettingsPage("knowledge"); setSettingsMenuOpen(false); }}>
              <Library size={15} /> 知识库
            </button>
            <button onClick={() => { onOpenSettingsPage("help"); setSettingsMenuOpen(false); }}>
              <BookOpen size={15} /> 帮助
            </button>
            <button
              onClick={() => {
                onToggleTheme();
                setSettingsMenuOpen(false);
              }}
            >
              {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}{" "}
              {theme === "dark" ? "亮色主题" : "暗色主题"}
            </button>
          </div>
        )}
      </div>
    </aside>
  );
}
