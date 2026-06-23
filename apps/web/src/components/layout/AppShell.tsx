/*
 * AppShell — 三栏容器（左历史 / 中交互 / 右 Agent 个性化）。
 *
 * 阶段 2 三栏新 UI 第 1 步：替换 main.tsx 的 `<section className="appShell">` grid 布局
 * 为 flex 布局 + 拖拽手柄。
 *
 * 设计取自 docs/ui-design/three-column-light.html：
 *   <div class="app" style="display:flex;height:100vh">
 *     <aside class="sidebar" />            ← sidebar slot
 *     <div class="resizer" />              ← 左/中分隔
 *     <main class="main" flex:1 />         ← children（中栏，含 page 分发）
 *     <div class="resizer" />              ← 中/右分隔（仅 agentPanel 存在时渲染）
 *     <aside class="agent-panel" />        ← agentPanel slot
 *   </div>
 *
 * 宽度来源：useUIStore（sidebarWidth / agentPanelWidth），persist 到 localStorage["pcapai-ui"]。
 * 拖拽：
 *   - 拖拽中用本地 state 实时渲染（避免高频写 localStorage）
 *   - mouseup 才写 store 落库
 *   - clamp 由 store setter 处理（SIDEBAR_MIN/MAX、AGENT_PANEL_MIN/MAX）
 *
 * 本组件只负责布局壳，不关心 children 内容。
 * agentPanel 传 null 时不渲染右栏（非 workbench 页面：history/settings/help/knowledge）。
 */
import React from "react";
import { PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen } from "lucide-react";
import { Resizer } from "./Resizer";
import {
  useUIStore,
  SIDEBAR_MIN,
  SIDEBAR_MAX,
  AGENT_PANEL_MIN,
  AGENT_PANEL_MAX,
} from "../../store/useUIStore";

type AppShellProps = {
  /** 左栏：历史会话列表 + 设置入口（Sidebar 组件） */
  sidebar: React.ReactNode;
  /** 中栏：page 分发后的内容（workbench / history / settings / help / knowledge） */
  children: React.ReactNode;
  /** 右栏：Agent 个性化面板（insightDock / 三 Tab）；传 null 则隐藏右栏（非 workbench 页面） */
  agentPanel?: React.ReactNode;
};

export function AppShell({ sidebar, children, agentPanel }: AppShellProps) {
  // 初始宽度从 store 读（已 persist）
  const storeSidebarWidth = useUIStore((s) => s.sidebarWidth);
  const storeAgentPanelWidth = useUIStore((s) => s.agentPanelWidth);
  const setSidebarWidth = useUIStore((s) => s.setSidebarWidth);
  const setAgentPanelWidth = useUIStore((s) => s.setAgentPanelWidth);
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed);
  const agentPanelCollapsed = useUIStore((s) => s.agentPanelCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);
  const toggleAgentPanel = useUIStore((s) => s.toggleAgentPanel);

  // 拖拽中本地 state（实时更新，mouseup 才落库 store）
  const [sidebarWidth, setSidebarWidthLocal] = React.useState(storeSidebarWidth);
  const [agentPanelWidth, setAgentPanelWidthLocal] = React.useState(storeAgentPanelWidth);

  // store 变化（如外部重置）同步到本地
  React.useEffect(() => setSidebarWidthLocal(storeSidebarWidth), [storeSidebarWidth]);
  React.useEffect(() => setAgentPanelWidthLocal(storeAgentPanelWidth), [storeAgentPanelWidth]);

  // 拖拽中本地 clamp（store setter 的 mirror，避免拖拽瞬间越界）
  const clampSidebar = (w: number) => Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, w));
  const clampAgent = (w: number) => Math.min(AGENT_PANEL_MAX, Math.max(AGENT_PANEL_MIN, w));

  const hasAgentPanel = agentPanel !== null && agentPanel !== undefined && !agentPanelCollapsed;

  return (
    <section className={`appShell ${hasAgentPanel ? "" : "appShellTwoCol"} ${sidebarCollapsed ? "sidebarCollapsed" : ""}`}>
      {/* 顶部拖拽条：覆盖三栏顶部 52px，让用户按住空白区拖动窗口。
          traffic light 按钮在左上角（系统绘制，z-index 高于此条，不会被遮挡）。
          交互元素（折叠按钮/composer 等）用 no-drag 覆盖。 */}
      <div className="titleBarDrag" />
      {/* 左栏：折叠时不渲染 aside + resizer，只渲染边缘展开按钮 */}
      {sidebarCollapsed ? (
        <button className="sidebarExpandBtn" onClick={toggleSidebar} title="展开侧栏" aria-label="展开侧栏">
          <PanelLeftOpen size={18} />
        </button>
      ) : (
        <>
          <aside className="appShellCol appSidebarWrap" style={{ width: sidebarWidth, flexShrink: 0 }}>
            {sidebar}
            {/* 折叠按钮：浮在 sidebar 右上角 */}
            <button className="sidebarCollapseBtn" onClick={toggleSidebar} title="收起侧栏" aria-label="收起侧栏">
              <PanelLeftClose size={18} />
            </button>
          </aside>
          <Resizer
            direction={1}
            getWidth={() => sidebarWidth}
            onDrag={(w) => setSidebarWidthLocal(clampSidebar(w))}
            onCommit={(w) => setSidebarWidth(w)}
          />
        </>
      )}

      <section className="appShellCol appContent">{children}</section>

      {/* 右栏：折叠时只渲染边缘展开按钮 */}
      {agentPanel !== null && agentPanel !== undefined ? (
        agentPanelCollapsed ? (
          <button className="agentPanelExpandBtn" onClick={toggleAgentPanel} title="展开右栏" aria-label="展开右栏">
            <PanelRightOpen size={18} />
          </button>
        ) : (
          <>
            <Resizer
              direction={-1}
              getWidth={() => agentPanelWidth}
              onDrag={(w) => setAgentPanelWidthLocal(clampAgent(w))}
              onCommit={(w) => setAgentPanelWidth(w)}
            />
            <aside className="appShellCol appAgentPanel" style={{ width: agentPanelWidth, flexShrink: 0 }}>
              {agentPanel}
              {/* 折叠按钮：浮在右栏左上角 */}
              <button className="agentPanelCollapseBtn" onClick={toggleAgentPanel} title="收起右栏" aria-label="收起右栏">
                <PanelRightClose size={18} />
              </button>
            </aside>
          </>
        )
      ) : null}
    </section>
  );
}
