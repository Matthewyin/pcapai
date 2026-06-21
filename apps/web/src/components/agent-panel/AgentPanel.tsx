/*
 * AgentPanel — 右栏 Agent 个性化面板（阶段 2c 从 main.tsx 的 insightDock 抽出）。
 *
 * 三 Tab 结构（来自 docs/ui-design/three-column-light.html）：
 *   - 知识脉络 (knowledge): 实战库命中 / Skills / RFC 引用 / Agent 自我进化（占位,第 3 步 RFC 库填充）
 *   - 推理轨迹 (trace):    执行轨迹 + 数据包洞察（工具调用 timeline）
 *   - 诊断档案 (diagnosis): 当前查询 + 证据 + L7 关联 + 候选链路 + 选中通讯对 + 根因卡 + 统计 + 报告
 *
 * 状态策略（避免 40+ props 爆炸）：
 *   - UI 态（activeTab / toolTraceOpen / insightsOpen）从 useAgentStore 读
 *   - 业务数据 + handlers 通过聚合 props 传入（main.tsx 闭包派生值 + API 调用）
 *
 * 阶段 2c 是结构抽离,内容 1:1 复制自原 insightDock,不改变功能。
 * Tailwind 化 + 亮色主题调色留第 5 步。
 */
import React from "react";
import { ChevronDown } from "lucide-react";
import { useAgentStore, type AgentPanelTab } from "../../store/useAgentStore";
import type {
  CaseGraph,
  Conversation,
  EvidenceCard,
  ProtocolCorrelation,
  QueryRun,
  ToolRun,
  PacketSummary,
  QueryDiagnosis,
  AccessCandidateGroup,
  DiagnosticTag,
  DetailView,
  RootCauseEntry,
} from "../../types";
import {
  formatPacketTime,
  formatShortPacketTime,
  formatDuration,
  formatEndpoint,
} from "../../lib/format";
import { webConfig } from "../../config";
import { WaterfallChart } from "../Charts";
import { CaseStatusBar } from "./CaseStatusBar";
import { EvidenceDeck } from "./EvidenceDeck";
import { ReportPanel } from "./ReportPanel";
import { RootCauseList, Flywheel } from "./RootCauseCard";

// ===== Helper 类型（main.tsx 里的小工具签名）=====
type ConversationState = { className: string; label: string };
type GroupState = { className: string; label: string };
type DiagnosisCheckState = { className: string; label: string };

/** AgentPanel 接收的所有业务数据 + handlers（聚合对象,避免 props 爆炸） */
export type AgentPanelProps = {
  // 案例数据
  graph: CaseGraph | null;
  activeQueryRun: QueryRun | undefined;
  report: string;
  /** 阶段 2d：最后一条 assistant 消息的根因列表（rfcVerified 分层渲染） */
  rootCauses: RootCauseEntry[];

  // 派生值
  activeCandidateGroups: AccessCandidateGroup[];
  selectedCandidateGroup: AccessCandidateGroup | undefined;
  visibleConversations: Conversation[];
  filteredConversationCount: number;
  keyConversationPackets: PacketSummary[];

  // 选中态
  selectedEvidenceCard: EvidenceCard | undefined;
  selectedEvidencePacket: PacketSummary | undefined;
  selectedConversation: Conversation | null | undefined;
  selectedDiagnosis: QueryDiagnosis | undefined;
  conversationPackets: PacketSummary[];
  conversationPacketsStatus: string;
  rightPanelHighlight: "evidence" | "conversation" | "";

  // 搜索/排序
  conversationSearch: string;
  conversationSort: "anomaly" | "time" | "packets";

  // Refs（main.tsx 用 useRef<HTMLElement | null>）
  evidenceContextRef: React.RefObject<HTMLElement | null>;
  selectedConversationRef: React.RefObject<HTMLElement | null>;

  // Handlers（涉及 API 调用,留在 main.tsx）
  onOpenToolRun: (run: ToolRun) => void;
  onOpenEvidenceCard: (card: EvidenceCard) => void;
  onCopyEvidenceFilter: (card: EvidenceCard) => void;
  onOpenProtocolCorrelation: (correlation: ProtocolCorrelation) => void;
  onCopyProtocolCorrelationFilter: (correlation: ProtocolCorrelation) => void;
  onOpenSelectedInWireshark: () => void;
  onSelectConversation: (queryRunId: string, conversationId: string) => void;
  onOpenDiagnosisPacket: (packetId: string) => void;
  onExportReport: () => void;
  onCopyReport: () => void;
  onSetDetailView: (view: DetailView) => void;
  onSetConversationSearch: (value: string) => void;
  onSetConversationSort: (value: "anomaly" | "time" | "packets") => void;
  onSetSelectedCandidateGroupId: (id: string) => void;

  // 阶段 2d 飞轮：用户反馈诊断是否正确（verify=正确沉淀 / dispute=纠正）
  // 留 main.tsx 实现（涉及 field-notes 写入 API）
  onFlywheel?: (action: "verify" | "dispute", causeId?: string) => void;

  // Helpers（main.tsx 里的纯函数）
  toolRunTitle: (run: ToolRun) => string;
  toolRunDetail: (run: ToolRun) => string;
  toolRunKindLabel: (run: ToolRun) => string;
  toolRunStatusLabel: (status: ToolRun["status"]) => string;
  toolRunActionLabel: (run: ToolRun) => string;
  groupState: (group: AccessCandidateGroup) => GroupState;
  conversationState: (conversation: Conversation) => ConversationState;
  diagnosisCheckState: (status: QueryDiagnosis["checks"][number]["status"]) => DiagnosisCheckState;
  packetMarkers: (packet: PacketSummary) => string[];

  // 折叠态 setter（迁 useAgentStore 后由组件内部用,但 main.tsx 仍可能外部控制）
};

export function AgentPanel(props: AgentPanelProps) {
  const activeTab = useAgentStore((s) => s.activeTab);
  const setActiveTab = useAgentStore((s) => s.setActiveTab);

  const tabs: Array<{ id: AgentPanelTab; label: string; count?: number }> = [
    { id: "knowledge", label: "知识脉络" },
    { id: "trace", label: "推理轨迹", count: props.graph?.toolRuns?.length || 0 },
    { id: "diagnosis", label: "诊断档案" },
  ];

  return (
    <aside className="insightDock panel agentPanel">
      <nav className="panelTabs" role="tablist">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === tab.id}
            className={`panelTab ${activeTab === tab.id ? "active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
            {tab.count !== undefined ? <span className="tabCount">{tab.count}</span> : null}
          </button>
        ))}
      </nav>

      <div className="panelBody" role="tabpanel">
        {activeTab === "knowledge" ? <KnowledgeTab caseId={props.graph?.spec.caseId} /> : null}
        {activeTab === "trace" ? <TraceTab {...props} /> : null}
        {activeTab === "diagnosis" ? <DiagnosisTab {...props} /> : null}
      </div>
    </aside>
  );
}

// ===== 知识脉络 Tab：当前 case 的三层知识体系（实战库命中 + Skills + RFC 引用）=====
function KnowledgeTab({ caseId }: { caseId?: string }) {
  // 优先用 case 专属知识脉络（命中当前 packetFeatures 的实战笔记 + Agent 调过的 RFC）
  const [knowledge, setKnowledge] = React.useState<{
    fieldNoteHits: Array<{ id: string; title: string; summary: string; featureScore: number; verifiedCount: number; disputedCount: number }>;
    skills: Array<{ name: string; description?: string }>;
    rfcRefs: Array<{ docId?: number; section?: string; title?: string }>;
    rfcTier?: "full" | "curated" | "none";
  } | null>(null);

  React.useEffect(() => {
    if (!caseId) return;
    let cancelled = false;
    fetch(`/api/cases/${caseId}/knowledge`)
      .then((r) => r.json())
      .then((data) => {
        if (!cancelled) setKnowledge(data);
      })
      .catch(() => {
        // 降级：case 不存在或 API 未就绪时保持空
      });
    return () => { cancelled = true; };
  }, [caseId]);

  const tierLabel = knowledge?.rfcTier === "full" ? "完整库" : knowledge?.rfcTier === "curated" ? "精简库" : "未就绪";
  const fieldHits = knowledge?.fieldNoteHits || [];
  const skills = knowledge?.skills || [];
  const rfcRefs = knowledge?.rfcRefs || [];

  return (
    <div className="knowledgeTab">
      {/* 三层知识体系总览（Agent 个性化核心） */}
      <section className="panelSection">
        <div className="panelSectionTitle">📖 RFC 知识库（防幻觉锚）</div>
        {knowledge?.rfcTier && knowledge.rfcTier !== "none" ? (
          <div className="rfcRefRow">
            <span className="rfcNum">{tierLabel}</span>
            <span className="rfcSec">Agent 可引用任意 RFC 章节</span>
            <span className="rfcVerifiedTag">✓ 就绪</span>
          </div>
        ) : (
          <div className="empty">RFC 库未构建。请在设置页下载完整库或构建精简库。</div>
        )}
        {rfcRefs.length > 0 ? (
          <>
            <div className="panelSectionTitle" style={{ marginTop: "10px" }}>本次引用</div>
            {rfcRefs.map((ref, i) => (
              <div className="rfcRefRow" key={i}>
                <span className="rfcNum">{ref.docId ? `RFC ${ref.docId}` : "RFC"}</span>
                <span className="rfcSec">{ref.title || ref.section || ""}</span>
              </div>
            ))}
          </>
        ) : null}
      </section>

      <section className="panelSection">
        <div className="panelSectionTitle">🔧 技能 Skills（{skills.length}）</div>
        {skills.length ? (
          skills.map((skill) => (
            <div className="skillMini" key={skill.name}>
              <div className="skName">{skill.name}</div>
              {skill.description ? <div className="skDesc">{skill.description}</div> : null}
            </div>
          ))
        ) : (
          <div className="empty">暂无技能。Agent 在排障过程中会沉淀新技能到此。</div>
        )}
      </section>

      <section className="panelSection">
        <div className="panelSectionTitle">🎯 实战库命中（{fieldHits.length}）</div>
        {fieldHits.length ? (
          fieldHits.map((hit) => (
            <div className="fnHit" key={hit.id}>
              <div className="fnTitle">{hit.title}</div>
              <div className="fnMeta">
                <span className="fnScore">匹配 {hit.featureScore}</span>
                {hit.verifiedCount > 0 ? <span className="fnVerified">✓ 已验证 {hit.verifiedCount}</span> : null}
                {hit.disputedCount > 0 ? <span style={{ color: "var(--danger)" }}>✗ 纠正 {hit.disputedCount}</span> : null}
              </div>
            </div>
          ))
        ) : (
          <div className="empty">当前抓包特征未命中实战笔记。诊断正确时点击"正确，沉淀"会新增笔记。</div>
        )}
      </section>
    </div>
  );
}

// ===== 推理轨迹 Tab：执行轨迹 + 数据包洞察 =====
function TraceTab(props: AgentPanelProps) {
  const { graph } = props;
  const toolTraceOpen = useAgentStore((s) => s.toolTraceOpen);
  const setToolTraceOpen = useAgentStore((s) => s.setToolTraceOpen);
  const insightsOpen = useAgentStore((s) => s.insightsOpen);
  const setInsightsOpen = useAgentStore((s) => s.setInsightsOpen);

  return (
    <div className="traceTab">
      <section className="toolTracePanel">
        <button
          type="button"
          className="toolTraceToggle"
          onClick={() => setToolTraceOpen(!toolTraceOpen)}
          aria-expanded={toolTraceOpen}
        >
          <span>
            <strong>执行轨迹</strong>
            <small>Agent / MCP / Wireshark 动作记录</small>
          </span>
          <span className="toolTraceToggleMeta">
            <span className="statusBadge neutral">{graph?.toolRuns?.length || 0}</span>
            <ChevronDown className={toolTraceOpen ? "open" : ""} size={18} />
          </span>
        </button>
        {toolTraceOpen ? <p className="panelHint">用于复盘 Agent 调用了什么工具；点击记录可跳转 QueryRun、证据卡或打开过滤器。</p> : null}
        {toolTraceOpen && graph?.toolRuns?.length ? (
          <div className="toolTraceList">
            {graph.toolRuns.slice(0, 8).map((run) => (
              <button
                type="button"
                key={run.toolRunId}
                className={`toolTraceRow ${run.status}`}
                onClick={() => props.onOpenToolRun(run)}
                title={props.toolRunDetail(run) || run.summary}
              >
                <div className="toolTraceRowMain">
                  <div className="toolTraceRowHeader">
                    <strong>{props.toolRunTitle(run)}</strong>
                    <span className={`toolTraceStatus ${run.status}`}>{props.toolRunStatusLabel(run.status)}</span>
                  </div>
                  <p>{run.summary}</p>
                  <div className="toolTraceMeta">
                    <span>{props.toolRunKindLabel(run)}</span>
                    <span>{run.target}</span>
                    {run.durationMs !== undefined ? <span>{Math.round(run.durationMs)}ms</span> : null}
                    {run.queryRunId ? <span>QueryRun</span> : null}
                    {run.evidenceCardIds?.length ? <span>{run.evidenceCardIds.length} 证据</span> : null}
                  </div>
                </div>
                <span className="toolTraceAction">{props.toolRunActionLabel(run)}</span>
              </button>
            ))}
          </div>
        ) : toolTraceOpen ? <div className="empty">尚无持久化执行轨迹。</div> : null}
      </section>

      <section className="insightsPanel">
        <button
          type="button"
          className="toolTraceToggle"
          onClick={() => setInsightsOpen(!insightsOpen)}
          aria-expanded={insightsOpen}
        >
          <span>
            <strong>数据包洞察</strong>
            <small>自动检测的连接异常和时序问题</small>
          </span>
          <span className="toolTraceToggleMeta">
            {(() => {
              const critical = (graph?.insights || []).filter((i) => i.severity === "critical").length;
              const warning = (graph?.insights || []).filter((i) => i.severity === "warning").length;
              return (
                <>
                  {critical ? <span className="statusBadge error">{critical}</span> : null}
                  {warning ? <span className="statusBadge warn">{warning}</span> : null}
                  {!critical && !warning ? <span className="statusBadge neutral">{graph?.insights?.length || 0}</span> : null}
                </>
              );
            })()}
            <ChevronDown className={insightsOpen ? "open" : ""} size={18} />
          </span>
        </button>
        {insightsOpen && graph?.insights?.length ? (
          <div className="insightList">
            {graph.insights.map((insight) => (
              <div key={insight.insightId} className={`insightRow ${insight.severity}`}>
                <span className={`insightSev ${insight.severity}`}>
                  {insight.severity === "critical" ? "严重" : insight.severity === "warning" ? "警告" : "信息"}
                </span>
                <div className="insightContent">
                  <p>{insight.description}</p>
                  {insight.type === "cross_protocol_chain" && (insight.detail as Record<string, unknown>)?.stages ? (
                    <WaterfallChart stages={(insight.detail as Record<string, unknown>).stages as Array<{ stage: string; timestamp: number; deltaMs: number; summary: string }>} />
                  ) : null}
                  {insight.scenario ? <small className="insightScenario">可能场景：{insight.scenario}</small> : null}
                </div>
              </div>
            ))}
          </div>
        ) : insightsOpen ? <div className="empty">暂无洞察结果，请先向 Agent 提问以触发分析。</div> : null}
      </section>
    </div>
  );
}

// ===== 诊断档案 Tab：查询 + 证据 + L7 关联 + 候选链路 + 选中通讯对 + 统计 + 报告 =====
function DiagnosisTab(props: AgentPanelProps) {
  const {
    graph,
    activeQueryRun,
    report,
    rootCauses,
    activeCandidateGroups,
    selectedCandidateGroup,
    visibleConversations,
    filteredConversationCount,
    keyConversationPackets,
    selectedEvidenceCard,
    selectedEvidencePacket,
    selectedConversation,
    selectedDiagnosis,
    conversationPackets,
    conversationPacketsStatus,
    rightPanelHighlight,
    conversationSearch,
    conversationSort,
    evidenceContextRef,
    selectedConversationRef,
  } = props;

  return (
    <div className="diagnosisTab">
      <section className="queryPanel">
        <h2>当前查询</h2>
        {activeQueryRun ? (
          <>
            <p>{activeQueryRun.question || "按条件查询"}</p>
            <code>{activeQueryRun.displayFilter}</code>
            <span>链路组 {activeCandidateGroups.length} / 通讯对 {activeQueryRun.totalConversationCount || activeQueryRun.conversations.length} / {activeQueryRun.path?.confidence || "-"}</span>
          </>
        ) : <div className="empty">向 Agent 提问，例如“分析 18:05:00 到 18:07:00，A 到 B 的 443”。</div>}
      </section>

      {/* 阶段 2d：根因结论（防幻觉分层：RFC 验证=绿色 / 经验推测=琥珀色）+ 飞轮反馈 */}
      <RootCauseList causes={rootCauses} />
      {rootCauses.length > 0 ? (
        <Flywheel onAction={(action) => props.onFlywheel?.(action)} />
      ) : null}

      {selectedEvidenceCard ? (
        <section ref={evidenceContextRef} className={`evidenceContextPanel ${rightPanelHighlight === "evidence" ? "traceFocus" : ""}`}>
          <div className="panelTitleRow">
            <h2>当前证据</h2>
            <span className="statusBadge neutral">{selectedEvidenceCard.kind}</span>
          </div>
          <article className={`evidenceContextCard ${selectedEvidenceCard.kind}`}>
            <strong>{selectedEvidenceCard.title}</strong>
            <p>{selectedEvidenceCard.summary}</p>
            <div className="selectedFilterBox">
              <span>完整过滤器</span>
              <code>{selectedEvidenceCard.displayFilter || "-"}</code>
            </div>
            {selectedEvidenceCard.packetDisplayFilter || selectedEvidenceCard.frameNumber ? (
              <div className="selectedFilterBox">
                <span>定位帧</span>
                <code>{selectedEvidenceCard.packetDisplayFilter || `frame.number == ${selectedEvidenceCard.frameNumber}`}</code>
              </div>
            ) : null}
            {selectedEvidencePacket ? (
              <div className="evidencePacketSummary">
                <span>Frame {selectedEvidencePacket.frameNumber}</span>
                <span>{selectedEvidencePacket.srcIp}:{selectedEvidencePacket.srcPort}{" -> "}{selectedEvidencePacket.dstIp}:{selectedEvidencePacket.dstPort}</span>
                <span>{props.packetMarkers(selectedEvidencePacket).join("，") || selectedEvidencePacket.protocol.toUpperCase()}</span>
              </div>
            ) : null}
            <div className="evidenceContextActions">
              {selectedEvidenceCard.pcapFilename && (selectedEvidenceCard.displayFilter || selectedEvidenceCard.frameNumber) ? <button type="button" onClick={() => props.onOpenEvidenceCard(selectedEvidenceCard)}>Wireshark</button> : null}
              {selectedEvidenceCard.displayFilter || selectedEvidenceCard.packetDisplayFilter ? <button type="button" onClick={() => props.onCopyEvidenceFilter(selectedEvidenceCard)}>复制过滤器</button> : null}
            </div>
          </article>
        </section>
      ) : null}

      {activeQueryRun?.protocolCorrelations?.length ? (
        <section className="protocolCorrelationPanel">
          <div className="panelTitleRow">
            <h2>L7 关联</h2>
            <span className="statusBadge neutral">{activeQueryRun.protocolCorrelations.length}</span>
          </div>
          <div className="protocolCorrelationList">
            {activeQueryRun.protocolCorrelations.map((correlation) => (
              <article key={correlation.correlationId}>
                <div>
                  <strong>{correlation.summary}</strong>
                  <span>{correlation.kind} / {correlation.confidence}</span>
                </div>
                <code>{correlation.targetDisplayFilter}</code>
                {correlation.reasons.length ? <p>{correlation.reasons.join("；")}</p> : null}
                <div className="evidenceContextActions">
                  <button type="button" onClick={() => props.onOpenProtocolCorrelation(correlation)}>Wireshark</button>
                  <button type="button" onClick={() => props.onCopyProtocolCorrelationFilter(correlation)}>复制过滤器</button>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="conversationPanel">
        <div className="panelTitleRow">
          <h2>候选访问链路</h2>
          <button onClick={props.onOpenSelectedInWireshark} disabled={!selectedConversation}>打开 Wireshark</button>
        </div>
        {activeCandidateGroups.length ? (
          <div className="accessGroupList">
            {activeCandidateGroups.map((group) => (
              <button
                className={group.groupId === selectedCandidateGroup?.groupId ? "active" : ""}
                key={group.groupId}
                onClick={() => props.onSetSelectedCandidateGroupId(group.groupId)}
              >
                <div className="accessGroupHeader">
                  <strong>{group.srcIp || "*"}{" -> "}{group.dstIp || "*"}:{group.dstPort ?? "*"}</strong>
                  <span className={`statusBadge ${props.groupState(group).className}`}>{props.groupState(group).label}</span>
                </div>
                <div className="accessGroupMetrics">
                  <span><b>{group.conversationCount}</b>通讯对</span>
                  <span><b>{group.successCount}</b>成功</span>
                  <span><b>{group.failureCount}</b>异常</span>
                  <span><b>{group.rstCount}</b>RST</span>
                  <span><b>{group.retransmissionCount}</b>重传</span>
                  <span><b>{group.zeroWindowCount}</b>零窗</span>
                </div>
                <div className="failureModeLine" title={group.failureModes?.map((mode) => `${mode.label} ${mode.count}`).join("，") || "暂无"}>
                  {group.failureModes?.length
                    ? group.failureModes
                      .slice(0, webConfig.groupFailureModeDisplayLimit)
                      .map((mode) => <span key={mode.kind}>{mode.label} {mode.count}</span>)
                    : <span>暂无形态</span>}
                </div>
              </button>
            ))}
          </div>
        ) : null}
        <div className="conversationTools">
          <input
            value={conversationSearch}
            onChange={(event) => props.onSetConversationSearch(event.target.value)}
            placeholder="搜索 IP、端口、节点"
          />
          <select value={conversationSort} onChange={(event) => props.onSetConversationSort(event.target.value as typeof conversationSort)}>
            <option value="anomaly">异常优先</option>
            <option value="packets">包数优先</option>
            <option value="time">时间顺序</option>
          </select>
        </div>
        {activeQueryRun?.conversations.length ? (
          <p className="conversationCount">
            当前链路组：{selectedCandidateGroup?.summary || "未选择"}；显示 {visibleConversations.length}/{filteredConversationCount} 条具体 conversation
          </p>
        ) : null}
        {activeQueryRun?.conversations.length ? (
          <div className="conversationList">
            {visibleConversations.map((conversation) => {
              const state = props.conversationState(conversation);
              return (
                <button
                  className={conversation.conversationId === activeQueryRun.selectedConversationId ? "active" : ""}
                  onClick={() => props.onSelectConversation(activeQueryRun.queryRunId, conversation.conversationId)}
                  key={conversation.conversationId}
                >
                  <div className="conversationRowTop">
                    <span className={`statusBadge ${state.className}`}>{state.label}</span>
                    <strong>{formatEndpoint(conversation.srcIp, conversation.srcPort)}{" -> "}{formatEndpoint(conversation.dstIp, conversation.dstPort)}</strong>
                  </div>
                  <div className="conversationMetricRow">
                    <span>{conversation.nodeId}</span>
                    <span>{conversation.packetCount} 包</span>
                    <span>{conversation.byteCount} B</span>
                    <span>RST {conversation.rstCount}</span>
                    <span>重传 {conversation.retransmissionCount}</span>
                  </div>
                  <div className="conversationMetaRow">
                    <span>{formatShortPacketTime(conversation.startTime)} - {formatShortPacketTime(conversation.endTime)}</span>
                    <span>持续 {formatDuration(conversation.startTime, conversation.endTime)}</span>
                  </div>
                  <span className="rankReasonLine" title={conversation.rankReasons?.join("，") || "符合当前查询条件"}>
                    {conversation.rankReasons?.join("，") || "符合当前查询条件"}
                  </span>
                </button>
              );
            })}
            {filteredConversationCount > visibleConversations.length ? <div className="conversationMore">还有 {filteredConversationCount - visibleConversations.length} 个候选，请继续搜索或调整排序。</div> : null}
          </div>
        ) : <div className="empty">暂无通讯对。</div>}
      </section>

      {selectedConversation && (
        <section ref={selectedConversationRef} className={`selectedConversationPanel ${rightPanelHighlight === "conversation" ? "traceFocus" : ""}`}>
          <h2>选中通讯对</h2>
          <dl>
            <dt>协议</dt><dd>{selectedConversation.protocol.toUpperCase()}</dd>
            <dt>包数</dt><dd>{selectedConversation.packetCount}</dd>
            <dt>字节</dt><dd>{selectedConversation.byteCount}</dd>
            <dt>RST</dt><dd>{selectedConversation.rstCount}</dd>
            <dt>重传</dt><dd>{selectedConversation.retransmissionCount}</dd>
            <dt>Zero Window</dt><dd>{selectedConversation.zeroWindowCount}</dd>
          </dl>
          <div className="selectedFilterBox">
            <span>Wireshark filter</span>
            <code>{selectedConversation.displayFilter}</code>
          </div>
          {selectedDiagnosis && (
            <div className="diagnosisPanel">
              <h3>确定性诊断</h3>
              <p>{selectedDiagnosis.summary}</p>
              <span>置信度：{selectedDiagnosis.confidence}</span>
              {selectedDiagnosis.checks?.length ? (
                <div className="diagnosisCheckGrid">
                  {selectedDiagnosis.checks.map((check) => {
                    const state = props.diagnosisCheckState(check.status);
                    return (
                      <article key={check.key}>
                        <div>
                          <strong>{check.label}</strong>
                          <span className={`statusBadge ${state.className}`}>{state.label}</span>
                        </div>
                        <p>{check.summary}</p>
                        {check.packetIds.length ? (
                          <div className="diagnosisEvidenceActions">
                            {check.packetIds.map((packetId) => {
                              const packet = [...conversationPackets, ...(graph?.packets || [])].find((item) => item.packetId === packetId);
                              return (
                                <button key={packetId} type="button" onClick={() => props.onOpenDiagnosisPacket(packetId)}>
                                  {packet?.frameNumber ? `Frame ${packet.frameNumber}` : packetId}
                                </button>
                              );
                            })}
                          </div>
                        ) : null}
                      </article>
                    );
                  })}
                </div>
              ) : null}
              {selectedDiagnosis.diagnosticTags.length ? (
                <div className="diagnosisTags">
                  {selectedDiagnosis.diagnosticTags.map((tag: DiagnosticTag) => (
                    <article key={tag.tagId}>
                      <strong>{tag.kind}</strong>
                      <span>{tag.summary}</span>
                    </article>
                  ))}
                </div>
              ) : null}
              {selectedDiagnosis.nextSteps.length ? <ul>{selectedDiagnosis.nextSteps.map((step) => <li key={step}>{step}</li>)}</ul> : null}
            </div>
          )}
          <div className="keyPacketPanel">
            <h3>关键包</h3>
            {conversationPacketsStatus ? <p>{conversationPacketsStatus}</p> : null}
            {keyConversationPackets.length ? (
              <div className="keyPacketList">
                {keyConversationPackets.map((packet) => (
                  <article key={packet.packetId}>
                    <strong>#{packet.frameNumber}</strong>
                    <span>{packet.srcIp}:{packet.srcPort}{" -> "}{packet.dstIp}:{packet.dstPort}</span>
                    <span>{props.packetMarkers(packet).join("，") || packet.protocol.toUpperCase()}</span>
                    <small>{formatPacketTime(packet.timestamp)}</small>
                  </article>
                ))}
              </div>
            ) : conversationPacketsStatus ? null : <div className="empty">暂无关键包。</div>}
          </div>
        </section>
      )}

      <CaseStatusBar graph={graph} />

      <EvidenceDeck graph={graph} onSelectView={(view) => props.onSetDetailView(view)} />

      <ReportPanel
        hasGraph={!!graph}
        report={report}
        onGenerate={() => void props.onExportReport()}
        onCopy={() => void props.onCopyReport()}
      />
    </div>
  );
}
