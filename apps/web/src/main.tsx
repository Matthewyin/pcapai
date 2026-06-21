import React from "react";
import ReactDOM from "react-dom/client";
import { ArrowUp, CheckCircle, ChevronDown, Copy, Eye, EyeOff, Maximize2, Minimize2, Paperclip, Pencil, Save, Square, Trash2, X } from "lucide-react";
import { webConfig } from "./config";
import "./styles.css";
import "./tailwind.css";
import { friendlyAgentName, normalizeThoughtForDisplay, appendThought, displayThoughts } from "./lib/markdown";
import { formatPacketTime, formatShortPacketTime, formatDuration, formatEndpoint, capturePacketTotal } from "./lib/format";
import { Sidebar, type SettingsMenuPage } from "./components/layout/Sidebar";
import { AppShell } from "./components/layout/AppShell";
import { useUIStore } from "./store/useUIStore";
import { MessageList } from "./components/chat/MessageList";
import { ReportPanel } from "./components/agent-panel/ReportPanel";
import { EvidenceDeck } from "./components/agent-panel/EvidenceDeck";
import { CaseStatusBar } from "./components/agent-panel/CaseStatusBar";
import { AgentPanel } from "./components/agent-panel/AgentPanel";
import { HelpPage } from "./components/shared/HelpPage";
import { HistoryPage } from "./components/shared/HistoryPage";
import { SettingsPage } from "./components/shared/SettingsPage";
import { KnowledgePage } from "./components/shared/KnowledgePage";

import type { PacketSummary, CaseGraph, PacketInsight, Conversation, QueryDiagnosis, EvidenceCard, ProtocolCorrelation, AccessCandidateGroup, QueryPath, QueryRun, AnalysisRun, ToolRun, MappingHint, TimeOffsetHint, DiagnosticTag, CaseSummary, LlmProfile, LlmRuntimeStatus, McpServerInfo, CaptureDraft, DetailView, DiagnosticHypothesis, ChatMessage } from "./types";
import { WaterfallChart, TopologyDiagram } from "./components/Charts";

function fileStem(filename: string) {
  return filename.replace(/\.[^.]+$/, "");
}

function formatApiError(data: unknown) {
  if (typeof data === "object" && data !== null && "error" in data) {
    const error = data.error;
    if (typeof error === "string") return error;
    if (typeof error === "object" && error !== null && "fieldErrors" in error) {
      const fieldErrors = error.fieldErrors as Record<string, string[]>;
      return Object.entries(fieldErrors)
        .flatMap(([field, messages]) => messages.map((message) => `${field}: ${message}`))
        .join("；");
    }
  }
  return JSON.stringify(data);
}

function runKindLabel(kind: AnalysisRun["kind"]) {
  if (kind === "capture_update") return "数据更新";
  if (kind === "parse") return "原始解析";
  return "条件分析";
}

function detailTitle(view: DetailView) {
  if (view === "path") return "访问路径";
  if (view === "findings") return "判断结果";
  if (view === "sessions") return "会话片段";
  if (view === "links") return "跨节点关联";
  if (view === "packets") return "数据包";
  return "关键事件";
}

function conversationState(conversation: Conversation) {
  if (conversation.rstCount) return { label: "RST", className: "danger" };
  if (conversation.zeroWindowCount) return { label: "Zero Window", className: "warn" };
  if (conversation.retransmissionCount) return { label: "重传", className: "warn" };
  if (conversation.rankReasons?.some((reason) => reason.includes("包数很少"))) return { label: "短流", className: "muted" };
  return { label: "已观察", className: "ok" };
}

function groupState(group: AccessCandidateGroup) {
  if (group.failureCount) return { label: `${group.failureCount} 条异常`, className: "danger" };
  if (group.retransmissionCount || group.zeroWindowCount) return { label: "有传输异常", className: "warn" };
  return { label: "未见明显异常", className: "ok" };
}

function diagnosisCheckState(status: QueryDiagnosis["checks"][number]["status"]) {
  if (status === "problem") return { label: "异常", className: "danger" };
  if (status === "warn") return { label: "复核", className: "warn" };
  if (status === "ok") return { label: "正常", className: "ok" };
  return { label: "未知", className: "muted" };
}

function packetMarkers(packet: PacketSummary) {
  return [
    ...packet.tcpFlags,
    packet.tcpAnalysis?.retransmission || packet.tcpAnalysis?.fastRetransmission ? "重传" : "",
    packet.tcpAnalysis?.duplicateAck ? "Dup ACK" : "",
    packet.tcpAnalysis?.zeroWindow ? "Zero Window" : "",
    packet.tcpAnalysis?.lostSegment ? "Lost Segment" : ""
  ].filter(Boolean);
}

function isKeyPacket(packet: PacketSummary) {
  const markers = packetMarkers(packet);
  return markers.some((marker) => ["SYN", "RST", "FIN", "重传", "Dup ACK", "Zero Window", "Lost Segment"].includes(marker));
}

const LAST_CASE_ID_KEY = "pcapai-last-active-case-id";
const LAST_RUN_ID_KEY = "pcapai-last-active-run-id";
const PINNED_CASES_KEY = "pcapai-pinned-case-ids";
const CHAT_PROFILE_ID_KEY = "pcapai-chat-profile-id";
const THINKING_DEPTH_KEY = "pcapai-thinking-depth";
const REASONING_DEPTH_KEY = "pcapai-reasoning-depth";
const THINKING_DEPTHS = ["快速", "标准", "深入"];
const REASONING_DEPTHS = ["低", "标准", "高"];

async function loadChatMessages(caseId: string): Promise<ChatMessage[]> {
  try {
    const res = await fetch(`/api/cases/${caseId}/chat`);
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.messages) ? data.messages : [];
  } catch { return []; }
}

async function saveChatMessages(caseId: string, messages: ChatMessage[]): Promise<void> {
  const clean = messages
    .map((m) => ({ ...m, streaming: false }))
    .filter((m) => m.content?.trim() || m.thoughts?.length)
    .slice(-200);
  try {
    await fetch(`/api/cases/${caseId}/chat`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: clean })
    });
  } catch { /* non-critical */ }
}

async function loadTcpStreams(caseId: string) {
  try {
    const res = await fetch(`/api/cases/${caseId}/tcp-streams`);
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data.streams) ? data.streams : [];
  } catch { return []; }
}

async function loadTcpStreamContent(caseId: string, streamIndex: number, format: string = "ascii") {
  try {
    const res = await fetch(`/api/cases/${caseId}/tcp-streams/${streamIndex}/content?format=${format}`);
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

function loadPinnedCaseIds() {
  try {
    const value = JSON.parse(localStorage.getItem(PINNED_CASES_KEY) || "[]");
    return Array.isArray(value) ? value.map(String) : [];
  } catch {
    return [];
  }
}

function loadStoredChoice(key: string, allowedValues: string[], fallback: string) {
  const value = localStorage.getItem(key);
  return value && allowedValues.includes(value) ? value : fallback;
}

function App() {
  // 阶段 2：page/theme/detailView 接入 useUIStore（persist 落 localStorage["pcapai-ui"]）
  const page = useUIStore((s) => s.page);
  const setPage = useUIStore((s) => s.setPage);
  const theme = useUIStore((s) => s.theme);
  const toggleTheme = useUIStore((s) => s.toggleTheme);
  const detailView = useUIStore((s) => s.detailView);
  const setDetailView = useUIStore((s) => s.setDetailView);
  const [tcpStreams, setTcpStreams] = React.useState<Array<{ streamIndex: number; srcIp?: string; srcPort?: number; dstIp?: string; dstPort?: number; packetCount: number; byteCount: number; displayFilter: string }>>([]);
  const [tcpStreamContent, setTcpStreamContent] = React.useState<{ clientData: string; serverData: string; streamIndex: number; format: string; totalBytes: number; truncated: boolean } | null>(null);
  const [tcpStreamLoading, setTcpStreamLoading] = React.useState(false);
  const [graph, setGraph] = React.useState<CaseGraph | null>(null);
  const [answer, setAnswer] = React.useState("");
  const [chatMessages, setChatMessages] = React.useState<ChatMessage[]>([]);
  const [report, setReport] = React.useState("");
  const [question, setQuestion] = React.useState("");
  const [status, setStatus] = React.useState("请先新建案例，再上传 pcap。");
  const [caseForm, setCaseForm] = React.useState({ title: "新建离线排障案例" });
  const [createFlowOpen, setCreateFlowOpen] = React.useState(false);
  const [createStep, setCreateStep] = React.useState(1);
  const [analysisFilter, setAnalysisFilter] = React.useState({ client: "", server: "", protocol: "", port: "" });
  const [createAnalysisFilter, setCreateAnalysisFilter] = React.useState({ client: "", server: "", protocol: "", port: "" });
  const [caseHistory, setCaseHistory] = React.useState<CaseSummary[]>([]);
  const [mappingHints, setMappingHints] = React.useState<MappingHint[]>([]);
  const [timeOffsetHints, setTimeOffsetHints] = React.useState<TimeOffsetHint[]>([]);
  const [captureDrafts, setCaptureDrafts] = React.useState<CaptureDraft[]>([]);
  const [llmForm, setLlmForm] = React.useState({ baseURL: "", model: "", apiKey: "", providerData: "" });
  const [showLlmApiKey, setShowLlmApiKey] = React.useState(false);
  const [llmProfileForm, setLlmProfileForm] = React.useState({ profileId: "", name: "", baseURL: "", model: "", apiKey: "", providerData: "" });
  const [llmProfiles, setLlmProfiles] = React.useState<LlmProfile[]>([]);
  const [mcpServers, setMcpServers] = React.useState<McpServerInfo[]>([]);
  const [chatProfileId, setChatProfileId] = React.useState(() => localStorage.getItem(CHAT_PROFILE_ID_KEY) ?? "");
  const [copiedMessageId, setCopiedMessageId] = React.useState("");
  const [thinkingDepth, setThinkingDepth] = React.useState(() => loadStoredChoice(THINKING_DEPTH_KEY, THINKING_DEPTHS, "标准"));
  const [reasoningDepth, setReasoningDepth] = React.useState(() => loadStoredChoice(REASONING_DEPTH_KEY, REASONING_DEPTHS, "标准"));
  const [llmRuntime, setLlmRuntime] = React.useState<LlmRuntimeStatus | null>(null);
  const [selectedCaseIds, setSelectedCaseIds] = React.useState<string[]>([]);
  const [selectedProfileIds, setSelectedProfileIds] = React.useState<string[]>([]);
  const [conversationSearch, setConversationSearch] = React.useState("");
  const [conversationSort, setConversationSort] = React.useState<"anomaly" | "time" | "packets">("anomaly");
  const [selectedCandidateGroupId, setSelectedCandidateGroupId] = React.useState("");
  const [conversationPackets, setConversationPackets] = React.useState<PacketSummary[]>([]);
  const [conversationPacketsStatus, setConversationPacketsStatus] = React.useState("");
  const [llmStatus, setLlmStatus] = React.useState("");
  const [composerFiles, setComposerFiles] = React.useState<File[]>([]);
  const [composerExpanded, setComposerExpanded] = React.useState(false);
  const [dragActive, setDragActive] = React.useState(false);
  const [toolTraceOpen, setToolTraceOpen] = React.useState(false);
  const [insightsOpen, setInsightsOpen] = React.useState(false);
  const [pinnedCaseIds, setPinnedCaseIds] = React.useState<string[]>(() => loadPinnedCaseIds());
  const [rightPanelHighlight, setRightPanelHighlight] = React.useState<"evidence" | "conversation" | "">("");
  const chatMessagesRef = React.useRef<HTMLDivElement | null>(null);
  const chatSaveTimerRef = React.useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const composerFileInputRef = React.useRef<HTMLInputElement | null>(null);
  const evidenceContextRef = React.useRef<HTMLElement | null>(null);
  const selectedConversationRef = React.useRef<HTMLElement | null>(null);
  const rightPanelHighlightTimerRef = React.useRef<number | undefined>(undefined);
  const abortControllerRef = React.useRef<AbortController | null>(null);
  const [isAsking, setIsAsking] = React.useState(false);
  const uploadDisabledReason = !graph ? "请先新建案例。" : !captureDrafts.length ? "请选择一个或多个 pcap/pcapng 文件。" : "";

  function focusRightPanel(target: "evidence" | "conversation") {
    if (rightPanelHighlightTimerRef.current) clearTimeout(rightPanelHighlightTimerRef.current);
    setRightPanelHighlight(target);
    window.setTimeout(() => {
      const node = target === "evidence" ? evidenceContextRef.current : selectedConversationRef.current;
      node?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 80);
    rightPanelHighlightTimerRef.current = window.setTimeout(() => setRightPanelHighlight(""), 1800);
  }

  function resetCreateFlow() {
    setCreateStep(1);
    setCaseForm({ title: "新建离线排障案例" });
    setCaptureDrafts([]);
    setCreateAnalysisFilter({ client: "", server: "", protocol: "", port: "" });
  }

  async function loadCaseHistory() {
    try {
      const response = await fetch("/api/cases");
      const data = await response.json();
      if (response.ok) {
        const cases = data.cases || [];
        setCaseHistory(cases);
        setSelectedCaseIds((ids) => ids.filter((id) => cases.some((item: CaseSummary) => item.caseId === id)));
        return cases as CaseSummary[];
      }
    } catch {
      setStatus("加载历史会话失败。");
    }
    return [] as CaseSummary[];
  }

  function findMostRecentCase(cases: CaseSummary[]) {
    return [...cases].sort((left, right) => right.updatedAt - left.updatedAt)[0];
  }

  function toggleCaseSelection(caseId: string) {
    setSelectedCaseIds((ids) => ids.includes(caseId) ? ids.filter((id) => id !== caseId) : [...ids, caseId]);
  }

  function savePinnedCaseIds(caseIds: string[]) {
    setPinnedCaseIds(caseIds);
    localStorage.setItem(PINNED_CASES_KEY, JSON.stringify(caseIds));
  }

  function togglePinnedCase(caseId: string) {
    savePinnedCaseIds(pinnedCaseIds.includes(caseId) ? pinnedCaseIds.filter((id) => id !== caseId) : [caseId, ...pinnedCaseIds]);
  }

  async function renameCase(caseId: string, title: string) {
    const trimmed = title.trim();
    if (!trimmed) return;
    const response = await fetch(`/api/cases/${caseId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: trimmed })
    });
    const data = await response.json();
    if (response.ok) {
      if (graph?.spec.caseId === caseId) setGraph(data);
      await loadCaseHistory();
    }
    setStatus(response.ok ? "会话已重命名。" : formatApiError(data));
  }

  async function deleteCaseFromSidebar(caseId: string) {
    const response = await fetch("/api/cases", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ caseIds: [caseId] })
    });
    const data = await response.json();
    if (response.ok) {
      savePinnedCaseIds(pinnedCaseIds.filter((id) => id !== caseId));
      if (graph?.spec.caseId === caseId) {
        setGraph(null);
        setChatMessages([]);
        localStorage.removeItem(LAST_CASE_ID_KEY);
        localStorage.removeItem(LAST_RUN_ID_KEY);
      }
      setCaseHistory(data.cases || []);
      setSelectedCaseIds((ids) => ids.filter((id) => id !== caseId));
    }
    setStatus(response.ok ? "会话已删除。" : formatApiError(data));
  }

  async function deleteSelectedCases() {
    if (!selectedCaseIds.length) return;
    const response = await fetch("/api/cases", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ caseIds: selectedCaseIds })
    });
    const data = await response.json();
    if (response.ok) {
      if (graph && selectedCaseIds.includes(graph.spec.caseId)) {
        setGraph(null);
        setChatMessages([]);
        localStorage.removeItem(LAST_CASE_ID_KEY);
        localStorage.removeItem(LAST_RUN_ID_KEY);
      }
      savePinnedCaseIds(pinnedCaseIds.filter((id) => !selectedCaseIds.includes(id)));
      setCaseHistory(data.cases || []);
      setSelectedCaseIds([]);
    }
    setStatus(response.ok ? "已删除选中的历史案例。" : formatApiError(data));
  }

  async function openCase(caseId: string, restoreRunId?: string | null) {
    const response = await fetch(`/api/cases/${caseId}`);
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
      setTimeOffsetHints(data.timeOffsetHints || []);
      setAnalysisFilter({
        client: data.analysisFilter?.client || "",
        server: data.analysisFilter?.server || "",
        protocol: data.analysisFilter?.protocol || "",
        port: data.analysisFilter?.port ? String(data.analysisFilter.port) : ""
      });
      localStorage.setItem(LAST_CASE_ID_KEY, data.spec.caseId);
      if (data.activeRunId) localStorage.setItem(LAST_RUN_ID_KEY, data.activeRunId);
      else localStorage.removeItem(LAST_RUN_ID_KEY);
      setChatMessages(await loadChatMessages(data.spec.caseId));
      setPage("workbench");
      if (restoreRunId && restoreRunId !== data.activeRunId) {
        window.setTimeout(() => void openAnalysisRunByCaseId(data.spec.caseId, restoreRunId), 0);
      }
      setStatus("历史案例已加载。");
      return true;
    } else {
      localStorage.removeItem(LAST_CASE_ID_KEY);
      localStorage.removeItem(LAST_RUN_ID_KEY);
    }
    setStatus(formatApiError(data));
    return false;
  }

  function openSettingsMenuPage(nextPage: SettingsMenuPage) {
    setPage(nextPage);
  }

  async function createNewChat() {
    const response = await fetch("/api/cases/new-chat", { method: "POST" });
    const data = await response.json();
    if (!response.ok) {
      setStatus(formatApiError(data));
      return null;
    }
    setGraph(data);
    setChatMessages([]);
    setQuestion("");
    setComposerFiles([]);
    setMappingHints([]);
    setTimeOffsetHints([]);
    localStorage.setItem(LAST_CASE_ID_KEY, data.spec.caseId);
    localStorage.removeItem(LAST_RUN_ID_KEY);
    setPage("workbench");
    await loadCaseHistory();
    setStatus("已创建新的数据包分析会话。");
    return data as CaseGraph;
  }

  async function refreshGraph(caseId: string) {
    const response = await fetch(`/api/cases/${caseId}`);
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
      setTimeOffsetHints(data.timeOffsetHints || []);
      if (data.activeRunId) localStorage.setItem(LAST_RUN_ID_KEY, data.activeRunId);
    }
  }

  async function selectConversation(queryRunId: string, conversationId: string) {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/query-runs/${queryRunId}/conversations/${conversationId}/select`, {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data.graph);
      setStatus("已精读选中 TCP session，并更新诊断。");
      await loadConversationPackets(data.graph.spec.caseId, queryRunId, conversationId);
    } else {
      setStatus(formatApiError(data));
    }
  }

  async function loadConversationPackets(caseId: string, queryRunId: string, conversationId: string) {
    setConversationPacketsStatus("正在读取关键包...");
    const response = await fetch(`/api/cases/${caseId}/query-runs/${queryRunId}/conversations/${conversationId}/packets`);
    const data = await response.json();
    if (response.ok) {
      setConversationPackets(data.packets || []);
      setConversationPacketsStatus("");
    } else {
      setConversationPackets([]);
      setConversationPacketsStatus(formatApiError(data));
    }
  }

  async function openConversationInWireshark(caseId: string, queryRunId: string, conversationId: string, successMessage = "已请求本地 Wireshark 打开当前通讯对。") {
    const response = await fetch(`/api/cases/${caseId}/query-runs/${queryRunId}/open-wireshark`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ conversationId })
    });
    const data = await response.json();
    setStatus(response.ok ? successMessage : formatApiError(data));
  }

  async function openEvidenceCard(card: EvidenceCard) {
    if (!graph) return;
    if (card.kind === "conversation" && card.queryRunId && card.conversationId) {
      await selectConversation(card.queryRunId, card.conversationId);
      await openConversationInWireshark(graph.spec.caseId, card.queryRunId, card.conversationId, "已请求本地 Wireshark 打开该 TCP session。");
      return;
    }
    const displayFilter = card.displayFilter || card.packetDisplayFilter || (card.frameNumber ? `frame.number == ${card.frameNumber}` : "");
    if (!card.pcapFilename || !displayFilter) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/evidence/open`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcapFilename: card.pcapFilename, displayFilter, frameNumber: card.frameNumber, queryRunId: card.queryRunId, cardId: card.cardId })
    });
    const data = await response.json();
    if (response.ok) void refreshGraph(graph.spec.caseId);
    setStatus(response.ok ? "已请求本地 Wireshark 打开证据过滤器并定位对应 frame。" : formatApiError(data));
  }

  function evidenceCardFromToolRun(run: ToolRun) {
    const cardIds = new Set(run.evidenceCardIds || []);
    return graph?.queryRuns.flatMap((queryRun) => queryRun.evidenceCards).find((card) => cardIds.has(card.cardId));
  }

  async function activateQueryRun(queryRunId: string, cardId?: string) {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/query-runs/${queryRunId}/activate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cardId })
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setStatus(cardId ? "已跳转到轨迹关联的 QueryRun 和证据卡。" : "已跳转到轨迹关联的 QueryRun。");
      focusRightPanel(cardId ? "evidence" : "conversation");
    } else {
      setStatus(formatApiError(data));
    }
  }

  async function openToolRun(run: ToolRun) {
    if (!graph) return;
    const card = evidenceCardFromToolRun(run);
    const runDisplayFilter = run.displayFilter || run.packetDisplayFilter || (run.frameNumber ? `frame.number == ${run.frameNumber}` : "");
    if (run.pcapFilename && runDisplayFilter) {
      const response = await fetch(`/api/cases/${graph.spec.caseId}/evidence/open`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pcapFilename: run.pcapFilename,
          displayFilter: runDisplayFilter,
          frameNumber: run.frameNumber,
          queryRunId: run.queryRunId,
          cardId: card?.cardId
        })
      });
      const data = await response.json();
      if (response.ok) void refreshGraph(graph.spec.caseId);
      setStatus(response.ok ? "已按执行轨迹打开 Wireshark 证据。" : formatApiError(data));
      return;
    }
    if (card && (card.pcapFilename || card.queryRunId)) {
      if (card.pcapFilename && (card.displayFilter || card.frameNumber || card.packetDisplayFilter)) {
        await openEvidenceCard(card);
      } else if (card.queryRunId) {
        await activateQueryRun(card.queryRunId, card.cardId);
      }
      return;
    }
    if (run.queryRunId) {
      await activateQueryRun(run.queryRunId);
      return;
    }
    setStatus("这条执行轨迹没有可跳转的 QueryRun、证据卡或 Wireshark filter。");
  }

  function toolRunStatusLabel(status: ToolRun["status"]) {
    if (status === "success") return "成功";
    if (status === "error") return "失败";
    return "跳过";
  }

  function toolRunTitle(run: ToolRun) {
    if (run.status === "error") return "执行失败";
    if (run.kind === "planner") return "规划";
    if (run.kind === "mcp") return run.target === "open_in_wireshark" ? "Wireshark" : "工具查询";
    if (run.kind === "agent") return "综合解读";
    return run.intent || run.target;
  }

  function toolRunKindLabel(run: ToolRun) {
    if (run.kind === "planner") return "规划";
    if (run.kind === "tool") return "Agent 工具";
    if (run.kind === "mcp") return "MCP";
    return "Agent";
  }

  function toolRunActionLabel(run: ToolRun) {
    const card = evidenceCardFromToolRun(run);
    if (run.pcapFilename && (run.displayFilter || run.packetDisplayFilter || run.frameNumber)) return "打开 Wireshark";
    if (card?.pcapFilename && (card.displayFilter || card.packetDisplayFilter || card.frameNumber)) return "打开证据";
    if (run.queryRunId || card?.queryRunId) return "跳转 QueryRun";
    return "查看";
  }

  function toolRunDetail(run: ToolRun) {
    return [run.inputSummary, run.outputSummary, run.displayFilter, run.error].filter(Boolean).join("\n");
  }

  async function copyEvidenceFilter(card: EvidenceCard) {
    const displayFilter = card.displayFilter || card.packetDisplayFilter || (card.frameNumber ? `frame.number == ${card.frameNumber}` : "");
    if (!displayFilter) return;
    try {
      await navigator.clipboard.writeText(displayFilter);
      setStatus("已复制 Wireshark display filter。");
    } catch {
      setStatus("复制失败，请检查浏览器剪贴板权限。");
    }
  }

  async function openProtocolCorrelation(correlation: ProtocolCorrelation) {
    if (!graph || !activeQueryRun) return;
    const sourceCard = activeQueryRun.evidenceCards.find((card) => card.cardId === correlation.sourceEvidenceCardId)
      || activeQueryRun.evidenceCards.find((card) => card.frameNumber && graph.packets.some((packet) => packet.packetId === correlation.sourcePacketId && packet.frameNumber === card.frameNumber));
    const pcapFilename = sourceCard?.pcapFilename || graph.packets.find((packet) => packet.packetId === correlation.sourcePacketId)?.pcapFilename || graph.captures.find((capture) => capture.pcapFilename)?.pcapFilename;
    if (!pcapFilename) {
      setStatus("当前关联缺少 pcap 文件信息，无法打开 Wireshark。");
      return;
    }
    const response = await fetch(`/api/cases/${graph.spec.caseId}/evidence/open`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pcapFilename, displayFilter: correlation.targetDisplayFilter, queryRunId: activeQueryRun.queryRunId, cardId: sourceCard?.cardId })
    });
    const data = await response.json();
    if (response.ok) void refreshGraph(graph.spec.caseId);
    setStatus(response.ok ? "已请求 Wireshark 打开 L7 关联的 TCP 过滤器。" : formatApiError(data));
  }

  async function copyProtocolCorrelationFilter(correlation: ProtocolCorrelation) {
    try {
      await navigator.clipboard.writeText(correlation.targetDisplayFilter);
      setStatus("已复制 L7 关联的 TCP display filter。");
    } catch {
      setStatus("复制失败，请检查浏览器剪贴板权限。");
    }
  }

  async function openDiagnosisPacket(packetId: string) {
    if (!graph || !selectedConversation) return;
    const packet = [...conversationPackets, ...(graph.packets || [])].find((item) => item.packetId === packetId);
    if (!packet?.frameNumber) {
      setStatus("当前没有找到该证据包的 frame 信息，请重新选择 TCP session 后再试。");
      return;
    }
    const response = await fetch(`/api/cases/${graph.spec.caseId}/evidence/open`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        pcapFilename: packet.pcapFilename || selectedConversation.pcapFilename,
        displayFilter: selectedConversation.displayFilter,
        frameNumber: packet.frameNumber
      })
    });
    const data = await response.json();
    setStatus(response.ok ? `已请求 Wireshark 打开当前 TCP session，并定位 frame ${packet.frameNumber}。` : formatApiError(data));
  }

  async function openSelectedInWireshark() {
    if (!graph) return;
    const activeQueryRun = graph.queryRuns?.find((run) => run.queryRunId === graph.activeQueryRunId) || graph.queryRuns?.[0];
    if (!activeQueryRun?.selectedConversationId) return;
    await openConversationInWireshark(graph.spec.caseId, activeQueryRun.queryRunId, activeQueryRun.selectedConversationId);
  }

  async function openAnalysisRun(runId: string) {
    if (!graph) return;
    await openAnalysisRunByCaseId(graph.spec.caseId, runId);
  }

  async function openAnalysisRunByCaseId(caseId: string, runId: string) {
    const response = await fetch(`/api/cases/${caseId}/analysis-runs/${runId}`);
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
      setTimeOffsetHints(data.timeOffsetHints || []);
      setAnalysisFilter({
        client: data.analysisFilter?.client || "",
        server: data.analysisFilter?.server || "",
        protocol: data.analysisFilter?.protocol || "",
        port: data.analysisFilter?.port ? String(data.analysisFilter.port) : ""
      });
      localStorage.setItem(LAST_CASE_ID_KEY, data.spec.caseId);
      localStorage.setItem(LAST_RUN_ID_KEY, runId);
    }
    setStatus(response.ok ? "已切换到该分析版本快照。" : formatApiError(data));
  }

  async function loadLlmSettings() {
    const response = await fetch("/api/settings/llm");
    const data = await response.json();
    setLlmForm({ baseURL: data.baseURL || "", model: data.model || "", apiKey: "", providerData: data.providerData || "" });
    setLlmStatus(data.hasKey ? "已配置 Key。" : "未配置 Key。");
  }

  async function loadLlmProfiles() {
    const response = await fetch("/api/settings/llm/profiles");
    const data = await response.json();
    if (response.ok) {
      const profiles = data.profiles || [];
      setLlmProfiles(profiles);
      setSelectedProfileIds((ids) => ids.filter((id) => profiles.some((profile: LlmProfile) => profile.profileId === id)));
    }
  }

  async function loadLlmRuntime() {
    const response = await fetch("/api/settings/llm/runtime");
    const data = await response.json();
    if (response.ok) setLlmRuntime(data);
  }

  async function loadMcpServers() {
    const response = await fetch("/api/settings/mcp");
    const data = await response.json();
    if (response.ok) setMcpServers(data.servers || []);
  }

  async function saveLlmSettings() {
    if (!llmForm.baseURL.trim() || !llmForm.model.trim()) {
      setLlmStatus("Base URL 和模型名称不能为空。");
      return;
    }
    const response = await fetch("/api/settings/llm", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmForm)
    });
    const data = await response.json();
    setLlmStatus(response.ok ? (data.hasKey ? "LLM 配置已保存，并已自动生成模型档案。" : "LLM 配置已保存，并已自动生成模型档案，尚未配置 Key。") : formatApiError(data));
    if (response.ok) setLlmForm({ baseURL: data.baseURL, model: data.model, apiKey: "", providerData: data.providerData || "" });
    if (response.ok && data.activeProfileId) setChatProfileId(data.activeProfileId);
    if (response.ok && data.profiles) setLlmProfiles(data.profiles);
    if (response.ok) {
      await loadLlmProfiles();
      await loadLlmRuntime();
    }
  }

  async function testLlmSettings() {
    if (!llmForm.baseURL.trim() || !llmForm.model.trim()) {
      setLlmStatus("Base URL 和模型名称不能为空。");
      return;
    }
    setLlmStatus("正在测试模型配置...");
    const response = await fetch("/api/settings/llm/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmForm)
    });
    const data = await response.json();
    setLlmStatus(response.ok && data.ok ? "模型配置测试通过。" : `模型配置测试失败：${formatApiError(data)}`);
  }

  async function testAgentCompatibility() {
    if (!llmForm.baseURL.trim() || !llmForm.model.trim()) {
      setLlmStatus("Base URL 和模型名称不能为空。");
      return;
    }
    setLlmStatus("正在测试 Agent 兼容性...");
    const response = await fetch("/api/settings/llm/agent-test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmForm)
    });
    const data = await response.json();
    setLlmStatus(response.ok && data.ok ? "Agent 兼容性测试通过。" : `Agent 兼容性测试失败：${formatApiError(data)}`);
  }

  function editLlmProfile(profile: LlmProfile) {
    setLlmForm({ baseURL: profile.baseURL, model: profile.model, apiKey: "", providerData: profile.providerData || "" });
    setLlmStatus(`已加载 ${profile.name} 到左侧表单。`);
  }

  function toggleProfileSelection(profileId: string) {
    setSelectedProfileIds((ids) => ids.includes(profileId) ? ids.filter((id) => id !== profileId) : [...ids, profileId]);
  }

  async function saveLlmProfile() {
    if (!llmProfileForm.name.trim() || !llmProfileForm.baseURL.trim() || !llmProfileForm.model.trim()) {
      setLlmStatus("配置名称、Base URL 和模型名称不能为空。");
      return;
    }
    const response = await fetch("/api/settings/llm/profiles", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmProfileForm)
    });
    const data = await response.json();
    if (response.ok) {
      setLlmProfiles(data.profiles || []);
      setLlmForm({ baseURL: data.settings.baseURL || "", model: data.settings.model || "", apiKey: "", providerData: data.settings.providerData || "" });
      setLlmProfileForm({ profileId: "", name: "", baseURL: "", model: "", apiKey: "", providerData: "" });
      setChatProfileId(data.settings.activeProfileId || "");
      await loadLlmRuntime();
    }
    setLlmStatus(response.ok ? "模型配置档案已保存并启用。" : formatApiError(data));
  }

  async function testLlmProfile() {
    if (!llmProfileForm.baseURL.trim() || !llmProfileForm.model.trim()) {
      setLlmStatus("Base URL 和模型名称不能为空。");
      return;
    }
    setLlmStatus("正在测试模型配置档案...");
    const response = await fetch("/api/settings/llm/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(llmProfileForm)
    });
    const data = await response.json();
    setLlmStatus(response.ok && data.ok ? "模型配置档案测试通过。" : `模型配置档案测试失败：${formatApiError(data)}`);
  }

  async function activateProfile(profileId: string) {
    const response = await fetch(`/api/settings/llm/profiles/${profileId}/activate`, { method: "POST" });
    const data = await response.json();
    if (response.ok) {
      setLlmProfiles(data.profiles || []);
      setLlmForm({ baseURL: data.settings.baseURL || "", model: data.settings.model || "", apiKey: "", providerData: data.settings.providerData || "" });
      setChatProfileId(profileId);
      await loadLlmRuntime();
    }
    setLlmStatus(response.ok ? "模型配置档案已启用。" : formatApiError(data));
  }

  async function deleteSelectedProfiles() {
    if (!selectedProfileIds.length) return;
    const response = await fetch("/api/settings/llm/profiles", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profileIds: selectedProfileIds })
    });
    const data = await response.json();
    if (response.ok) {
      setLlmProfiles(data.profiles || []);
      setSelectedProfileIds([]);
      setLlmForm({ baseURL: data.settings.baseURL || "", model: data.settings.model || "", apiKey: "", providerData: data.settings.providerData || "" });
      setChatProfileId(data.settings.activeProfileId || "");
      await loadLlmRuntime();
    }
    setLlmStatus(response.ok ? "已删除选中的模型配置档案。" : formatApiError(data));
  }

  async function createCase() {
    if (!caseForm.title.trim()) {
      setStatus("案例名称不能为空。");
      return;
    }
    setStatus("正在创建案例...");
    const response = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(caseForm)
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
      setTimeOffsetHints(data.timeOffsetHints || []);
      localStorage.setItem(LAST_CASE_ID_KEY, data.spec.caseId);
      localStorage.removeItem(LAST_RUN_ID_KEY);
      setChatMessages([]);
      await loadCaseHistory();
    }
    setStatus(response.ok ? "案例已创建。" : formatApiError(data));
  }

  async function createCaseFromFlow() {
    if (!caseForm.title.trim()) {
      setStatus("案例名称不能为空。");
      return;
    }
    setStatus("正在创建案例...");
    const response = await fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(caseForm)
    });
    const data = await response.json();
    if (!response.ok) {
      setStatus(formatApiError(data));
      return;
    }
    setGraph(data);
    setMappingHints(data.mappingHints || []);
    setTimeOffsetHints(data.timeOffsetHints || []);
    localStorage.setItem(LAST_CASE_ID_KEY, data.spec.caseId);
    localStorage.removeItem(LAST_RUN_ID_KEY);
    setChatMessages([]);
    let nextGraph = data;
    if (captureDrafts.length) nextGraph = await uploadAndParseCase(data.spec.caseId);
    if (nextGraph && (createAnalysisFilter.client.trim() || createAnalysisFilter.server.trim() || createAnalysisFilter.protocol.trim() || createAnalysisFilter.port.trim())) {
      setAnalysisFilter(createAnalysisFilter);
      await analyzeCase(data.spec.caseId, createAnalysisFilter);
    }
    await loadCaseHistory();
    setCreateFlowOpen(false);
    resetCreateFlow();
    setPage("workbench");
    setStatus("案例创建流程已完成。");
  }

  async function uploadAndParseCase(caseId: string) {
    if (!captureDrafts.length) return null;
    setStatus("正在上传抓包文件...");
    const formData = new FormData();
    captureDrafts.forEach(({ file }) => formData.append("pcap", file));

    const uploadResponse = await fetch(`/api/cases/${caseId}/attachments`, { method: "POST", body: formData });
    const uploadData = await uploadResponse.json();
    if (!uploadResponse.ok) {
      setStatus(formatApiError(uploadData));
      return null;
    }

    setGraph(uploadData.graph);
    setMappingHints(uploadData.graph.mappingHints || []);
    setTimeOffsetHints(uploadData.graph.timeOffsetHints || []);
    setCaptureDrafts([]);
    await loadCaseHistory();
    setStatus(`附件已上传，已读取抓包元信息 ${capturePacketTotal(uploadData.graph)} 个包；未进行全量 packet summary 解析。`);
    return uploadData.graph as CaseGraph;
  }

  async function uploadAndParse() {
    if (!graph || !captureDrafts.length) return;
    await uploadAndParseCase(graph.spec.caseId);
  }

  async function analyzeCase(caseId: string, filter = analysisFilter) {
    setStatus("正在创建 QueryRun...");
    const analyzeResponse = await fetch(`/api/cases/${caseId}/query-runs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question: `分析 ${filter.client.trim() || "*"} 到 ${filter.server.trim() || "*"} ${filter.port.trim() || "*"} 端口的通信`,
        srcIp: filter.client.trim() || undefined,
        dstIp: filter.server.trim() || undefined,
        protocol: filter.protocol.trim() || undefined,
        port: filter.port.trim() ? Number(filter.port) : undefined
      })
    });
    const analyzeData = await analyzeResponse.json();
    if (analyzeResponse.ok) {
      setGraph(analyzeData.graph);
      setMappingHints(analyzeData.graph.mappingHints || []);
      setTimeOffsetHints(analyzeData.graph.timeOffsetHints || []);
      await loadCaseHistory();
    }
    setStatus(analyzeResponse.ok ? `QueryRun 已创建，返回 ${analyzeData.queryRun?.conversations?.length || 0} 个候选通信。` : formatApiError(analyzeData));
    return analyzeResponse.ok ? analyzeData.graph : null;
  }

  async function analyzeCurrentFilter() {
    if (!graph) return;
    await analyzeCase(graph.spec.caseId);
  }

  function setSelectedFiles(files: File[]) {
    setCaptureDrafts(files.map((file, index) => ({
      file,
      nodeId: `node-${index + 1}`,
      name: fileStem(file.name) || `抓包节点 ${index + 1}`,
      role: "未知节点",
      interfaceDirection: "unknown",
      capturePosition: ""
    })));
  }

  function pcapFiles(files: File[]) {
    return files.filter((file) => /\.(pcap|pcapng|cap)$/i.test(file.name));
  }

  function addComposerFiles(files: File[]) {
    const accepted = pcapFiles(files);
    if (accepted.length !== files.length) setStatus("只支持 pcap、pcapng、cap 文件。");
    setComposerFiles((current) => [...current, ...accepted]);
  }

  async function uploadComposerFiles(targetGraph: CaseGraph, files: File[]) {
    if (!files.length) return null;
    const formData = new FormData();
    files.forEach((file) => formData.append("pcap", file));
    const response = await fetch(`/api/cases/${targetGraph.spec.caseId}/attachments`, { method: "POST", body: formData });
    const data = await response.json();
    if (!response.ok) throw new Error(formatApiError(data));
    setGraph(data.graph);
    setComposerFiles([]);
    await loadCaseHistory();
    return data as { graph: CaseGraph; agentAnswer?: { answer: string; thoughts?: string[]; evidenceCards?: EvidenceCard[]; protocolCorrelations?: ProtocolCorrelation[] } };
  }

  function updateCaptureDraft(index: number, patch: Partial<Omit<CaptureDraft, "file">>) {
    setCaptureDrafts((drafts) => drafts.map((draft, draftIndex) => (draftIndex === index ? { ...draft, ...patch } : draft)));
  }

  function addMappingHint() {
    setMappingHints((hints) => [...hints, { hintId: `hint-${hints.length + 1}`, kind: "nat", note: "" }]);
  }

  function updateMappingHint(index: number, patch: Partial<MappingHint>) {
    setMappingHints((hints) => hints.map((hint, hintIndex) => (hintIndex === index ? { ...hint, ...patch } : hint)));
  }

  function removeMappingHint(index: number) {
    setMappingHints((hints) => hints.filter((_, hintIndex) => hintIndex !== index));
  }

  function numberOrUndefined(value: string) {
    return value ? Number(value) : undefined;
  }

  async function saveMappingHints() {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/mapping-hints`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mappingHints })
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setMappingHints(data.mappingHints || []);
    }
    setStatus(response.ok ? "地址转换线索已保存。" : formatApiError(data));
  }

  function addTimeOffsetHint() {
    setTimeOffsetHints((hints) => [...hints, { hintId: `time-${hints.length + 1}`, offsetSeconds: 0, note: "" }]);
  }

  function updateTimeOffsetHint(index: number, patch: Partial<TimeOffsetHint>) {
    setTimeOffsetHints((hints) => hints.map((hint, hintIndex) => (hintIndex === index ? { ...hint, ...patch } : hint)));
  }

  function removeTimeOffsetHint(index: number) {
    setTimeOffsetHints((hints) => hints.filter((_, hintIndex) => hintIndex !== index));
  }

  async function saveTimeOffsetHints() {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/time-offset-hints`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ timeOffsetHints })
    });
    const data = await response.json();
    if (response.ok) {
      setGraph(data);
      setTimeOffsetHints(data.timeOffsetHints || []);
    }
    setStatus(response.ok ? "时间偏移线索已保存。" : formatApiError(data));
  }

  async function ask() {
    const prompt = question.trim();
    if (!prompt && !composerFiles.length) return;
    let targetGraph = graph || await createNewChat();
    if (!targetGraph) return;
    const abortController = new AbortController();
    abortControllerRef.current = abortController;
    setIsAsking(true);
    const filesToUpload = [...composerFiles];
    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: [prompt, filesToUpload.length ? `附件：${filesToUpload.map((file) => file.name).join("，")}` : ""].filter(Boolean).join("\n")
    };
    const assistantId = `assistant-${Date.now()}`;
    const chatHistory = chatMessages
      .filter((message) => !message.streaming && message.content.trim())
      .slice(-webConfig.chatHistoryLimit)
      .map((message) => ({ role: message.role, content: message.content }));
    setChatMessages((messages) => [...messages, userMessage, { id: assistantId, role: "assistant", content: "", thoughts: [], streaming: true }]);
    setQuestion("");
    setAnswer("");

    if (filesToUpload.length) {
      try {
        const uploadResult = await uploadComposerFiles(targetGraph, filesToUpload);
        // 上传成功后用返回的 graph 作为后续 agent 请求的基准，避免闭包里的旧 graph 导致
        // agent 读到上传前的空 case（captures=0 → needs_clarification）
        if (uploadResult?.graph) targetGraph = uploadResult.graph;
        if (uploadResult?.agentAnswer && !prompt) {
          setAnswer(uploadResult.agentAnswer.answer);
          setChatMessages((messages) => messages.map((message) => message.id === assistantId ? {
            ...message,
            content: uploadResult.agentAnswer?.answer || "",
            thoughts: (uploadResult.agentAnswer?.thoughts || []).map(normalizeThoughtForDisplay).filter((item): item is string => Boolean(item)),
            evidenceCards: uploadResult.agentAnswer?.evidenceCards || [],
            protocolCorrelations: uploadResult.agentAnswer?.protocolCorrelations || [],
            streaming: false
          } : message));
          await loadLlmRuntime();
          return;
        }
      } catch (error) {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: error instanceof Error ? error.message : String(error), streaming: false } : message));
        abortControllerRef.current = null;
        setIsAsking(false);
        return;
      }
    }

    if (!prompt) {
      abortControllerRef.current = null;
      setIsAsking(false);
      return;
    }

    // 用 targetGraph 而非闭包里的 graph：上传后 targetGraph 是最新的（含 captures），
    // 而 graph 是 React state 快照，在当前 ask() 闭包里可能是上传前的旧值
    const currentCaseId = targetGraph.spec.caseId;
    const response = await fetch(`/api/cases/${currentCaseId}/agent/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: prompt, chatHistory, profileId: chatProfileId || undefined, thinkingDepth, reasoningDepth }),
      signal: abortController.signal
    });
    if (!response.ok || !response.body) {
      const data = await response.json();
      const error = formatApiError(data);
      setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: error, streaming: false } : message));
      await loadLlmRuntime();
      abortControllerRef.current = null;
      setIsAsking(false);
      return;
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    const applyEvent = (rawEvent: string) => {
      const event = rawEvent.match(/^event: (.+)$/m)?.[1];
      const dataLine = rawEvent.match(/^data: (.+)$/m)?.[1];
      if (!event || !dataLine) return;
      const data = JSON.parse(dataLine);
      if (event === "thought") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? appendThought(message, data.text || "") : message));
      } else if (event === "chain_start") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? appendThought(message, `规划：开始分析链（共 ${data.stepCount} 步）。`) : message));
      } else if (event === "step_start") {
        const phase = data.intent === "llm_explain" ? "综合解读" : "工具查询";
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? appendThought(message, `${phase}：步骤 ${data.index + 1}/${data.total}，${data.purpose}`) : message));
      } else if (event === "step_done") {
        const stepCards = Array.isArray(data.evidenceCards) ? data.evidenceCards : [];
        setChatMessages((messages) => messages.map((message) => {
          if (message.id !== assistantId) return message;
          let updated = { ...message };
          if (data.status === "error") {
            updated = appendThought(updated, `执行失败：步骤 ${data.index + 1}，${data.summary}`);
          }
          if (stepCards.length) {
            const se = { ...(updated.stepEvidence || {}) };
            se[data.index] = { purpose: data.purpose || `步骤 ${data.index + 1}`, evidenceCards: stepCards };
            updated.stepEvidence = se;
          }
          return updated;
        }));
      } else if (event === "chain_done") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? appendThought(message, "综合解读：分析链完成。") : message));
      } else if (event === "delta") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: message.content + data.text } : message));
      } else if (event === "done") {
        setAnswer(data.answer || "");
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: data.answer || message.content, evidenceCards: data.evidenceCards || [], suggestedQueries: data.suggestedQueries || [], evidenceIds: data.evidenceIds || [], packetIds: data.packetIds || [], findingIds: data.findingIds || [], sessionLinkIds: data.sessionLinkIds || [], handoffAgent: friendlyAgentName(data.handoffAgent) || undefined, confidence: data.confidence || undefined, missingContext: data.missingContext || [], suggestedActions: data.suggestedActions || [], protocolCorrelations: data.protocolCorrelations || [], followUpQuestions: data.followUpQuestions || [], diagnosticPhase: data.diagnosticPhase || undefined, hypotheses: data.hypotheses || [], streaming: false } : message));
        void refreshGraph(currentCaseId);
      } else if (event === "error") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: data.error, streaming: false } : message));
      }
    };

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const events = buffer.split("\n\n");
        buffer = events.pop() || "";
        events.forEach(applyEvent);
      }
      if (buffer.trim()) applyEvent(buffer);
    } catch {
      // 用户中止或连接断开：保留已收到的内容，标记 streaming 结束
    }
    setChatMessages((messages) => {
      const updated = messages.map((message) => message.id === assistantId ? { ...message, streaming: false } : message);
      saveChatMessages(currentCaseId, updated);
      return updated;
    });
    await loadLlmRuntime();
    abortControllerRef.current = null;
    setIsAsking(false);
  }

  function openEvidenceDetail(message: ChatMessage, caseId: string, stepIndex?: number) {
    const allCards = message.evidenceCards || [];
    const correlations = message.protocolCorrelations || [];
    const stepEvidence = message.stepEvidence;
    const cards = stepIndex !== undefined && stepEvidence?.[stepIndex] ? stepEvidence[stepIndex].evidenceCards : allCards;
    const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    const cardSections = cards.map((card) => {
      const reviewQuery = card.reviewQuery || card.packetDisplayFilter || card.displayFilter || (card.frameNumber ? `frame.number == ${card.frameNumber}` : "");
      const coverage = card.coverage || [
        card.queryRunId ? `QueryRun ${card.queryRunId}` : "",
        card.pcapFilename ? `文件 ${card.pcapFilename}` : "",
        card.conversationId ? `会话 ${card.conversationId}` : "",
        card.frameNumber ? `Frame ${card.frameNumber}` : ""
      ].filter(Boolean).join("；") || "当前证据卡未声明覆盖范围。";
      return `
      <div class="ev-card">
        <div class="ev-card-title">${esc(card.title)}</div>
        <div class="ev-card-summary">${esc(card.summary)}</div>
        <div class="ev-meta">覆盖范围：${esc(coverage)}</div>
        ${card.pcapFilename ? `<div class="ev-meta">文件：${esc(card.pcapFilename)}${card.frameNumber ? ` / Frame ${card.frameNumber}` : ""}</div>` : ""}
        ${card.displayFilter ? `<div class="ev-filter"><code>${esc(card.displayFilter)}</code><button onclick="copyFilter(this)" title="复制过滤器">复制</button>${card.pcapFilename ? `<button onclick="openWireshark('${esc(card.pcapFilename)}','${esc(card.displayFilter)}')" title="在 Wireshark 中打开">Wireshark</button>` : ""}</div>` : ""}
        ${card.packetDisplayFilter && card.packetDisplayFilter !== card.displayFilter ? `<div class="ev-filter"><span>包级过滤器：</span><code>${esc(card.packetDisplayFilter)}</code><button onclick="copyFilter(this)">复制</button></div>` : ""}
        ${reviewQuery ? `<div class="ev-filter"><span>复核查询：</span><code>${esc(reviewQuery)}</code><button onclick="copyFilter(this)">复制</button></div>` : ""}
        ${card.reviewNotes?.length ? `<div class="ev-reasons">${card.reviewNotes.map((note) => `<span>${esc(note)}</span>`).join("")}</div>` : ""}
      </div>`;
    }).join("");
    const corrSections = correlations.map((corr) => `
      <div class="ev-card">
        <div class="ev-card-title">${esc(corr.kind.replace(/_/g, " ").toUpperCase())}</div>
        <div class="ev-card-summary">${esc(corr.summary)}</div>
        <div class="ev-meta">关系：${esc(corr.relation)} / 置信度：${esc(corr.confidence)}</div>
        ${corr.targetDisplayFilter ? `<div class="ev-filter"><code>${esc(corr.targetDisplayFilter)}</code><button onclick="copyFilter(this)">复制</button></div>` : ""}
        ${corr.reasons.length ? `<div class="ev-reasons">${corr.reasons.map((r) => `<span>${esc(r)}</span>`).join("")}</div>` : ""}
      </div>`).join("");
    const diagSections: string[] = [];
    if (message.confidence) diagSections.push(`<div class="diag-item"><strong>置信度</strong><span>${esc(message.confidence)}</span></div>`);
    const agentLabel = friendlyAgentName(message.handoffAgent);
    if (agentLabel) diagSections.push(`<div class="diag-item"><strong>Agent</strong><span>${esc(agentLabel)}</span></div>`);
    if (message.missingContext?.length) diagSections.push(`<div class="diag-item"><strong>缺失上下文</strong><ul>${message.missingContext.map((c) => `<li>${esc(c)}</li>`).join("")}</ul></div>`);
    if (message.suggestedActions?.length) diagSections.push(`<div class="diag-item"><strong>建议动作</strong><ul>${message.suggestedActions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul></div>`);
    if (message.findingIds?.length) diagSections.push(`<div class="diag-item"><strong>Findings</strong><div class="id-list">${message.findingIds.map((id) => `<code>${esc(id)}</code>`).join(" ")}</div></div>`);
    if (message.evidenceIds?.length) diagSections.push(`<div class="diag-item"><strong>Evidence</strong><div class="id-list">${message.evidenceIds.map((id) => `<code>${esc(id)}</code>`).join(" ")}</div></div>`);
    if (message.packetIds?.length) diagSections.push(`<div class="diag-item"><strong>Packets</strong><div class="id-list">${message.packetIds.slice(0, 20).map((id) => `<code>${esc(id)}</code>`).join(" ")}${message.packetIds.length > 20 ? ` ...共 ${message.packetIds.length} 个` : ""}</div></div>`);
    if (message.sessionLinkIds?.length) diagSections.push(`<div class="diag-item"><strong>Session Links</strong><div class="id-list">${message.sessionLinkIds.map((id) => `<code>${esc(id)}</code>`).join(" ")}</div></div>`);
    const html = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>证据详情</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#f8f9fa;color:#1a1a2e;padding:24px;max-width:900px;margin:0 auto}
h1{font-size:1.4em;margin-bottom:8px}
h2{font-size:1.15em;margin:24px 0 12px;padding-bottom:6px;border-bottom:1px solid #e0e0e0;color:#333}
.ev-card{background:#fff;border:1px solid #e0e0e0;border-radius:8px;padding:14px 16px;margin-bottom:10px}
.ev-card-title{font-weight:700;font-size:.95em;margin-bottom:4px}
.ev-card-summary{color:#555;font-size:.88em;margin-bottom:8px}
.ev-meta{font-size:.8em;color:#888;margin-bottom:6px}
.ev-filter{display:flex;align-items:center;gap:6px;margin-top:4px}
.ev-filter code{background:#f0f2f5;padding:3px 8px;border-radius:4px;font-size:.82em;flex:1;overflow-x:auto;white-space:nowrap}
.ev-filter button{padding:3px 10px;border:1px solid #ccc;border-radius:4px;background:#fafafa;cursor:pointer;font-size:.78em;white-space:nowrap}
.ev-filter button:hover{background:#eee}
.ev-reasons{margin-top:6px;display:flex;flex-wrap:wrap;gap:4px}
.ev-reasons span{background:#e8f0fe;color:#1a73e8;padding:2px 8px;border-radius:10px;font-size:.75em}
.diag-item{margin-bottom:8px;font-size:.85em}
.diag-item strong{display:inline-block;width:100px;color:#666}
.diag-item ul{padding-left:1.5em;margin-top:4px}
.diag-item li{margin:2px 0;color:#444}
.id-list code{background:#f0f0f0;padding:1px 4px;border-radius:3px;font-size:.78em;margin:2px}
.empty{color:#999;font-size:.9em;font-style:italic}
.section-label{font-size:.8em;color:#888;margin-bottom:8px}
</style></head><body>
<h1>证据详情${stepIndex !== undefined && stepEvidence?.[stepIndex] ? ` — ${esc(stepEvidence[stepIndex].purpose)}` : ""}</h1>
<p class="section-label">${cards.length} 张证据卡片${correlations.length ? `，${correlations.length} 条协议关联` : ""}${stepIndex !== undefined ? `（步骤 ${stepIndex + 1}）` : allCards.length !== cards.length ? `（全部 ${allCards.length} 张）` : ""}</p>
<h2>证据卡片</h2>
${cards.length ? cardSections : '<p class="empty">无证据卡片</p>'}
${correlations.length ? `<h2>协议关联</h2>${corrSections}` : ""}
${diagSections.length ? `<h2>诊断详情</h2>${diagSections.join("")}` : ""}
<script>
function copyFilter(btn){const code=btn.parentElement.querySelector("code");navigator.clipboard.writeText(code.textContent).then(()=>{btn.textContent="已复制";setTimeout(()=>btn.textContent="复制",1200)}).catch(()=>btn.textContent="失败")}
function openWireshark(pcap,filter){fetch("${window.location.origin}/api/cases/${esc(caseId)}/evidence/open",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({pcapFilename:pcap,displayFilter:filter})}).catch(()=>{})}
</script></body></html>`;
    const blob = new Blob([html], { type: "text/html" });
    window.open(URL.createObjectURL(blob), "_blank");
  }

  async function copyMessage(message: ChatMessage) {
    const traceItems = displayThoughts(message);
    const text = [
      `${message.role === "user" ? "你" : "Agent"}：`,
      traceItems.length ? `执行轨迹：\n${traceItems.map((thought, index) => `${index + 1}. ${thought}`).join("\n")}` : "",
      message.content || (message.streaming ? "等待模型返回..." : ""),
      message.evidenceCards?.length ? `证据卡片：\n${message.evidenceCards.map((card) => `- ${card.title}: ${card.summary}`).join("\n")}` : ""
    ].filter(Boolean).join("\n\n");
    try {
      await navigator.clipboard.writeText(text);
      setCopiedMessageId(message.id);
      window.setTimeout(() => {
        setCopiedMessageId((id) => id === message.id ? "" : id);
      }, 1200);
    } catch {
      setStatus("复制失败，请检查浏览器剪贴板权限。");
    }
  }

  async function exportReport() {
    if (!graph) return;
    const response = await fetch(`/api/cases/${graph.spec.caseId}/report`);
    const data = await response.json();
    setReport(response.ok ? data.markdown || "" : formatApiError(data));
  }

  async function copyReport() {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(report);
      setStatus("报告已复制。");
    } catch {
      setStatus("复制失败，请检查浏览器剪贴板权限。");
    }
  }

  // theme 持久化已由 useUIStore persist 接管（localStorage["pcapai-ui"]），原 pcapai-theme effect 删除

  // 桌面端双击 .pcap：每次新建 case 后按本地路径导入（绝不动用户原文件，后端 copy）
  async function openPcapFromPaths(paths: string[]) {
    if (!paths.length) return;
    const created = await createNewChat();
    const caseId = created?.spec?.caseId;
    if (!caseId) return;
    setStatus("正在导入数据包...");
    try {
      const response = await fetch(`/api/cases/${caseId}/attachments-by-path`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ paths })
      });
      const data = await response.json();
      if (!response.ok) { setStatus(formatApiError(data)); return; }
      setGraph(data.graph);
      setMappingHints(data.graph.mappingHints || []);
      setTimeOffsetHints(data.graph.timeOffsetHints || []);
      await loadCaseHistory();
      setStatus(`已导入数据包，读取到 ${capturePacketTotal(data.graph)} 个包。`);
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    }
  }

  // Electron 主进程菜单与文件关联事件（Web 模式下不触发）
  React.useEffect(() => {
    const onNewCase = () => { void createNewChat(); };
    const onOpenPcap = () => { composerFileInputRef.current?.click(); };
    const onOpenPcapFile = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail;
      if (typeof detail === "string" && detail) void openPcapFromPaths([detail]);
    };
    window.addEventListener("pcapai:new-case", onNewCase);
    window.addEventListener("pcapai:open-pcap", onOpenPcap);
    window.addEventListener("pcapai:open-pcap-file", onOpenPcapFile as EventListener);
    return () => {
      window.removeEventListener("pcapai:new-case", onNewCase);
      window.removeEventListener("pcapai:open-pcap", onOpenPcap);
      window.removeEventListener("pcapai:open-pcap-file", onOpenPcapFile as EventListener);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    void loadLlmSettings();
    void loadLlmProfiles();
    void loadLlmRuntime();
    void loadMcpServers();
    const restoreCase = async () => {
      const cases = await loadCaseHistory();
      const lastCaseId = localStorage.getItem(LAST_CASE_ID_KEY);
      const lastRunId = localStorage.getItem(LAST_RUN_ID_KEY);
      if (lastCaseId && cases.some((item) => item.caseId === lastCaseId)) {
        if (await openCase(lastCaseId, lastRunId)) return;
      }
      localStorage.removeItem(LAST_CASE_ID_KEY);
      localStorage.removeItem(LAST_RUN_ID_KEY);
      const fallbackCase = findMostRecentCase(cases);
      if (fallbackCase) await openCase(fallbackCase.caseId, null);
    };
    void restoreCase();
  }, []);

  React.useEffect(() => {
    if (chatMessagesRef.current) {
      chatMessagesRef.current.scrollTop = chatMessagesRef.current.scrollHeight;
    }
  }, [chatMessages]);

  React.useEffect(() => {
    if (!graph) return;
    if (chatSaveTimerRef.current) clearTimeout(chatSaveTimerRef.current);
    chatSaveTimerRef.current = setTimeout(() => {
      saveChatMessages(graph.spec.caseId, chatMessages);
    }, 1000);
    return () => { if (chatSaveTimerRef.current) clearTimeout(chatSaveTimerRef.current); };
  }, [graph?.spec.caseId, chatMessages]);

  React.useEffect(() => {
    const activeProfileId = llmRuntime?.settings.activeProfileId;
    setChatProfileId((current) => {
      const stored = localStorage.getItem(CHAT_PROFILE_ID_KEY) ?? "";
      if (current && llmProfiles.some((profile) => profile.profileId === current)) return current;
      if (stored && llmProfiles.some((profile) => profile.profileId === stored)) return stored;
      if (activeProfileId && llmProfiles.some((profile) => profile.profileId === activeProfileId)) return activeProfileId;
      return "";
    });
  }, [llmProfiles, llmRuntime?.settings.activeProfileId]);

  React.useEffect(() => {
    localStorage.setItem(CHAT_PROFILE_ID_KEY, chatProfileId);
  }, [chatProfileId]);

  React.useEffect(() => {
    localStorage.setItem(THINKING_DEPTH_KEY, thinkingDepth);
  }, [thinkingDepth]);

  React.useEffect(() => {
    localStorage.setItem(REASONING_DEPTH_KEY, reasoningDepth);
  }, [reasoningDepth]);

  const activeQueryRun = graph?.queryRuns?.find((run) => run.queryRunId === graph.activeQueryRunId) || graph?.queryRuns?.[0];
  // 阶段 2d：从最后一条带 rootCauses 的 assistant 消息提取根因列表（防幻觉分层渲染）
  const lastRootCauses = (() => {
    for (let i = chatMessages.length - 1; i >= 0; i--) {
      const msg = chatMessages[i];
      if (msg.role === "assistant" && msg.rootCauses && msg.rootCauses.length) return msg.rootCauses;
    }
    return [];
  })();
  const displayedCaseHistory = [...caseHistory].sort((left, right) => {
    const leftPinned = pinnedCaseIds.includes(left.caseId);
    const rightPinned = pinnedCaseIds.includes(right.caseId);
    if (leftPinned !== rightPinned) return leftPinned ? -1 : 1;
    return right.updatedAt - left.updatedAt;
  });
  const manualModelOption = !llmProfiles.length && (llmRuntime?.settings.model || llmForm.model);
  const activeCandidateGroups = activeQueryRun?.candidateGroups || [];
  const selectedCandidateGroup = activeCandidateGroups.find((group) => group.groupId === selectedCandidateGroupId)
    || activeCandidateGroups.find((group) => group.groupId === activeQueryRun?.selectedCandidateGroupId)
    || activeCandidateGroups.find((group) => activeQueryRun?.selectedConversationId && group.conversationIds.includes(activeQueryRun.selectedConversationId))
    || activeCandidateGroups[0];
  const selectedConversation = activeQueryRun?.conversations.find((conversation) => conversation.conversationId === activeQueryRun.selectedConversationId);
  const selectedEvidenceCard = activeQueryRun?.evidenceCards.find((card) => card.cardId === activeQueryRun.selectedEvidenceCardId) || activeQueryRun?.evidenceCards[0];
  const selectedEvidencePacket = selectedEvidenceCard?.frameNumber
    ? [...conversationPackets, ...(graph?.packets || [])].find((packet) => packet.frameNumber === selectedEvidenceCard.frameNumber && packet.pcapFilename === selectedEvidenceCard.pcapFilename)
    : undefined;
  const selectedDiagnosis = activeQueryRun?.selectedDiagnosis;
  React.useEffect(() => {
    setSelectedCandidateGroupId(activeQueryRun?.selectedCandidateGroupId || selectedCandidateGroup?.groupId || "");
  }, [activeQueryRun?.queryRunId, activeQueryRun?.selectedCandidateGroupId, selectedCandidateGroup?.groupId]);
  React.useEffect(() => {
    if (!graph || !activeQueryRun?.selectedConversationId) {
      setConversationPackets([]);
      setConversationPacketsStatus("");
      return;
    }
    void loadConversationPackets(graph.spec.caseId, activeQueryRun.queryRunId, activeQueryRun.selectedConversationId);
  }, [graph?.spec.caseId, activeQueryRun?.queryRunId, activeQueryRun?.selectedConversationId]);
  const visibleConversations = (() => {
    const keyword = conversationSearch.trim().toLowerCase();
    const groupConversationIds = new Set(selectedCandidateGroup?.conversationIds || []);
    const conversations = (activeQueryRun?.conversations || []).filter((conversation) => {
      if (groupConversationIds.size && !groupConversationIds.has(conversation.conversationId)) return false;
      if (!keyword) return true;
      return [
        conversation.nodeId,
        conversation.pcapFilename,
        conversation.protocol,
        conversation.srcIp,
        conversation.srcPort,
        conversation.dstIp,
        conversation.dstPort
      ].some((value) => String(value ?? "").toLowerCase().includes(keyword));
    });
    const anomalyScore = (conversation: Conversation) => (
      (conversation.rankScore || 0) +
      conversation.rstCount * 1000 +
      conversation.zeroWindowCount * 500 +
      conversation.retransmissionCount * 100 +
      conversation.packetCount
    );
    return [...conversations].sort((left, right) => {
      if (left.conversationId === activeQueryRun?.selectedConversationId) return -1;
      if (right.conversationId === activeQueryRun?.selectedConversationId) return 1;
      if (conversationSort === "packets") return right.packetCount - left.packetCount;
      if (conversationSort === "time") return left.startTime - right.startTime;
      return anomalyScore(right) - anomalyScore(left);
    }).slice(0, webConfig.conversationDisplayLimit);
  })();
  const filteredConversationCount = (activeQueryRun?.conversations || []).filter((conversation) => {
    const groupConversationIds = new Set(selectedCandidateGroup?.conversationIds || []);
    if (groupConversationIds.size && !groupConversationIds.has(conversation.conversationId)) return false;
    const keyword = conversationSearch.trim().toLowerCase();
    if (!keyword) return true;
    return [
      conversation.nodeId,
      conversation.pcapFilename,
      conversation.protocol,
      conversation.srcIp,
      conversation.srcPort,
      conversation.dstIp,
      conversation.dstPort
    ].some((value) => String(value ?? "").toLowerCase().includes(keyword));
  }).length;
  const keyConversationPackets = (() => {
    const keyPackets = conversationPackets.filter(isKeyPacket);
    return (keyPackets.length ? keyPackets : conversationPackets).slice(0, webConfig.keyPacketDisplayLimit);
  })();


  // 阶段 2b：insightDock 移到 AppShell 右栏 slot（三栏布局启用右栏拖拽）
  // JSX 保留在 main.tsx 内（依赖闭包 30+ handler/state，抽组件 props 会爆炸，留第 3 步三 Tab 重构）
  // 阶段 2c：右栏抽成 AgentPanel 组件（三 Tab：知识脉络/推理轨迹/诊断档案）
  // 业务数据 + handlers 通过 props 聚合传入；UI 态（activeTab/toolTraceOpen/insightsOpen）在组件内读 useAgentStore
  const agentPanelNode: React.ReactNode = page === "workbench" ? (
    <AgentPanel
      graph={graph}
      activeQueryRun={activeQueryRun}
      rootCauses={lastRootCauses}
      report={report}
      activeCandidateGroups={activeCandidateGroups}
      selectedCandidateGroup={selectedCandidateGroup}
      visibleConversations={visibleConversations}
      filteredConversationCount={filteredConversationCount}
      keyConversationPackets={keyConversationPackets}
      selectedEvidenceCard={selectedEvidenceCard}
      selectedEvidencePacket={selectedEvidencePacket}
      selectedConversation={selectedConversation}
      selectedDiagnosis={selectedDiagnosis}
      conversationPackets={conversationPackets}
      conversationPacketsStatus={conversationPacketsStatus}
      rightPanelHighlight={rightPanelHighlight}
      conversationSearch={conversationSearch}
      conversationSort={conversationSort}
      evidenceContextRef={evidenceContextRef}
      selectedConversationRef={selectedConversationRef}
      onOpenToolRun={(run) => void openToolRun(run)}
      onOpenEvidenceCard={(card) => void openEvidenceCard(card)}
      onCopyEvidenceFilter={(card) => void copyEvidenceFilter(card)}
      onOpenProtocolCorrelation={(correlation) => void openProtocolCorrelation(correlation)}
      onCopyProtocolCorrelationFilter={(correlation) => void copyProtocolCorrelationFilter(correlation)}
      onOpenSelectedInWireshark={() => void openSelectedInWireshark()}
      onSelectConversation={(queryRunId, conversationId) => void selectConversation(queryRunId, conversationId)}
      onOpenDiagnosisPacket={(packetId) => void openDiagnosisPacket(packetId)}
      onExportReport={() => void exportReport()}
      onCopyReport={() => void copyReport()}
      onSetDetailView={(view) => setDetailView(view)}
      onSetConversationSearch={(value) => setConversationSearch(value)}
      onSetConversationSort={(value) => setConversationSort(value)}
      onSetSelectedCandidateGroupId={(id) => setSelectedCandidateGroupId(id)}
      onFlywheel={(action) => void (async () => {
        // 阶段 2：飞轮反馈接入后端（verify→沉淀 field-note / dispute→标记错误）
        const caseId = graph?.spec.caseId;
        if (!caseId) return;
        try {
          const resp = await fetch(`/api/cases/${caseId}/flywheel`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action, rootCauses: lastRootCauses })
          });
          if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            console.error("[flywheel] 失败", err);
          }
        } catch (e) {
          console.error("[flywheel] 网络错误", e);
        }
      })()}
      toolRunTitle={toolRunTitle}
      toolRunDetail={toolRunDetail}
      toolRunKindLabel={toolRunKindLabel}
      toolRunStatusLabel={toolRunStatusLabel}
      toolRunActionLabel={toolRunActionLabel}
      groupState={groupState}
      conversationState={conversationState}
      diagnosisCheckState={diagnosisCheckState}
      packetMarkers={packetMarkers}
    />
  ) : null;


  return (
    <main className="app" data-theme={theme}>
      <AppShell
        sidebar={
          <Sidebar
            graph={graph}
            activeQueryRun={activeQueryRun}
            displayedCaseHistory={displayedCaseHistory}
            pinnedCaseIds={pinnedCaseIds}
            page={page}
            theme={theme}
            onCreateNewChat={() => void createNewChat()}
            onOpenCase={(caseId) => openCase(caseId)}
            onTogglePinned={(caseId) => togglePinnedCase(caseId)}
            onRename={(caseId, title) => renameCase(caseId, title)}
            onDelete={(caseId) => deleteCaseFromSidebar(caseId)}
            onOpenSettingsPage={(nextPage) => openSettingsMenuPage(nextPage)}
            onToggleTheme={toggleTheme}
          />
        }
        agentPanel={agentPanelNode}
      >
        <section className={`appContent ${page === "workbench" ? "workbenchContent" : "pageContent"}`}>
      {page === "help" ? (
        <HelpPage />
      ) : page === "knowledge" ? (
        <KnowledgePage />
      ) : page === "history" ? (
        <HistoryPage
          caseHistory={caseHistory}
          selectedCaseIds={selectedCaseIds}
          onToggleSelect={(caseId) => toggleCaseSelection(caseId)}
          onSelectAll={() => setSelectedCaseIds(caseHistory.map((item) => item.caseId))}
          onClearSelection={() => setSelectedCaseIds([])}
          onDeleteSelected={() => void deleteSelectedCases()}
          onOpenCase={(caseId) => openCase(caseId)}
        />
      ) : page === "settings" ? (
        <SettingsPage
          llmForm={llmForm}
          setLlmForm={setLlmForm}
          showLlmApiKey={showLlmApiKey}
          setShowLlmApiKey={setShowLlmApiKey}
          llmStatus={llmStatus}
          llmRuntime={llmRuntime}
          onSaveLlm={() => void saveLlmSettings()}
          onTestLlm={() => void testLlmSettings()}
          onTestAgentCompatibility={() => void testAgentCompatibility()}
          onReloadLlmConfig={() => { void loadLlmSettings(); void loadLlmProfiles(); void loadLlmRuntime(); }}
          llmProfiles={llmProfiles}
          selectedProfileIds={selectedProfileIds}
          onToggleProfileSelect={(profileId) => toggleProfileSelection(profileId)}
          onSelectAllProfiles={() => setSelectedProfileIds(llmProfiles.map((profile) => profile.profileId))}
          onClearProfileSelection={() => setSelectedProfileIds([])}
          onDeleteSelectedProfiles={() => void deleteSelectedProfiles()}
          onEditProfile={(profile) => editLlmProfile(profile)}
          onActivateProfile={(profileId) => void activateProfile(profileId)}
          mcpServers={mcpServers}
        />
      ) : (
      <section className="workbenchShell">
        <aside className="caseRail panel">
          <h2>案例</h2>
          <div className="form">
            <input value={caseForm.title} onChange={(event) => setCaseForm({ ...caseForm, title: event.target.value })} placeholder="案例名称" />
            <button className="primary" onClick={createCase} disabled={!caseForm.title.trim()}>新建案例</button>
          </div>

          {graph && (
            <dl>
              <dt>案例 ID</dt>
              <dd>{graph.spec.caseId}</dd>
              <dt>筛选</dt>
              <dd>{`${graph.analysisFilter?.client || "*"} -> ${graph.analysisFilter?.server || "*"}:${graph.analysisFilter?.port ?? "*"}`}</dd>
              <dt>包数</dt>
              <dd>{capturePacketTotal(graph)} 捕获 / {graph.packets.length} 当前样本</dd>
              <dt>版本</dt>
              <dd>{graph.analysisRuns?.length || 0} 个 run / {graph.activeRunId || "-"}</dd>
            </dl>
          )}

          {graph?.analysisRuns?.length ? (
            <>
              <h2>分析版本</h2>
              <div className="runList">
                {graph.analysisRuns.map((run) => (
                  <button className={`runItem ${run.runId === graph.activeRunId ? "active" : ""}`} key={run.runId} onClick={() => openAnalysisRun(run.runId)}>
                    <strong>{runKindLabel(run.kind)} · {new Date(run.createdAt).toLocaleString()}</strong>
                    <span>{run.summary}</span>
                    <small>{run.rawPacketCount} 历史原始包 / {run.packetCount} 筛选包 / {run.findingCount} 判断</small>
                  </button>
                ))}
              </div>
            </>
          ) : null}

          <h2>抓包节点</h2>
          <div className="form">
            <input type="file" accept=".pcap,.pcapng,.cap" multiple onChange={(event) => setSelectedFiles(Array.from(event.target.files || []))} />
            {captureDrafts.length ? (
              <div className="captureTable">
                <div className="captureHeader">
                  <span>文件名</span>
                  <span>节点名</span>
                  <span>节点角色</span>
                  <span>入/出方向</span>
                  <span>抓包位置</span>
                </div>
                {captureDrafts.map((draft, index) => (
                  <div className="captureRow" key={`${draft.file.name}-${index}`}>
                    <span title={draft.file.name}>{draft.file.name}</span>
                    <input value={draft.name} onChange={(event) => updateCaptureDraft(index, { name: event.target.value })} placeholder="节点名" />
                    <input value={draft.role} onChange={(event) => updateCaptureDraft(index, { role: event.target.value })} placeholder="节点角色" />
                    <select value={draft.interfaceDirection} onChange={(event) => updateCaptureDraft(index, { interfaceDirection: event.target.value as CaptureDraft["interfaceDirection"] })}>
                      <option value="unknown">未知方向</option>
                      <option value="ingress">入方向</option>
                      <option value="egress">出方向</option>
                      <option value="bidirectional">双向</option>
                    </select>
                    <input value={draft.capturePosition} onChange={(event) => updateCaptureDraft(index, { capturePosition: event.target.value })} placeholder="抓包位置" />
                  </div>
                ))}
              </div>
            ) : null}
            <span className="status">{captureDrafts.length ? `已选择 ${captureDrafts.length} 个文件。` : uploadDisabledReason}</span>
            <button className="primary" onClick={uploadAndParse} disabled={Boolean(uploadDisabledReason)} title={uploadDisabledReason || "上传 pcap 并通过 tshark-query 读取基础信息"}>上传给 Agent</button>
            <span className="status">{status}</span>
          </div>

          <h2>分析筛选</h2>
          <div className="form">
            <input value={analysisFilter.client} onChange={(event) => setAnalysisFilter({ ...analysisFilter, client: event.target.value })} placeholder="客户端地址，可留空" />
            <input value={analysisFilter.server} onChange={(event) => setAnalysisFilter({ ...analysisFilter, server: event.target.value })} placeholder="服务端地址，可留空" />
            <input value={analysisFilter.port} onChange={(event) => setAnalysisFilter({ ...analysisFilter, port: event.target.value })} placeholder="端口，可留空" />
            <input value={analysisFilter.protocol} onChange={(event) => setAnalysisFilter({ ...analysisFilter, protocol: event.target.value })} placeholder="协议，可留空" />
            <button className="primary" onClick={analyzeCurrentFilter} disabled={!graph || !graph.captures.length} title={!graph ? "请先新建或加载会话。" : !graph.captures.length ? "请先上传 pcap。" : "按当前筛选条件创建 QueryRun"}>创建 QueryRun</button>
          </div>

          <h2>地址转换线索</h2>
          <div className="mappingActions">
            <button onClick={addMappingHint} disabled={!graph}>新增线索</button>
            <button className="primary" onClick={saveMappingHints} disabled={!graph}>保存线索</button>
          </div>
          {mappingHints.length ? (
            <div className="mappingTable">
              <div className="mappingHeader">
                <span>类型</span><span>起点</span><span>终点</span><span>原源</span><span>原目的</span><span>转换源</span><span>转换目的</span><span>备注</span><span>操作</span>
              </div>
              {mappingHints.map((hint, index) => (
                <div className="mappingRow" key={`${hint.hintId}-${index}`}>
                  <select value={hint.kind} onChange={(event) => updateMappingHint(index, { kind: event.target.value as MappingHint["kind"] })}>
                    <option value="nat">NAT</option>
                    <option value="slb">SLB</option>
                    <option value="proxy">代理</option>
                    <option value="gateway">网关</option>
                    <option value="tunnel">隧道</option>
                  </select>
                  <select value={hint.fromNodeId || ""} onChange={(event) => updateMappingHint(index, { fromNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <select value={hint.toNodeId || ""} onChange={(event) => updateMappingHint(index, { toNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <input value={`${hint.originalSrcIp || ""}${hint.originalSrcPort ? `:${hint.originalSrcPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { originalSrcIp: ip || undefined, originalSrcPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={`${hint.originalDstIp || ""}${hint.originalDstPort ? `:${hint.originalDstPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { originalDstIp: ip || undefined, originalDstPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={`${hint.translatedSrcIp || ""}${hint.translatedSrcPort ? `:${hint.translatedSrcPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { translatedSrcIp: ip || undefined, translatedSrcPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={`${hint.translatedDstIp || ""}${hint.translatedDstPort ? `:${hint.translatedDstPort}` : ""}`} onChange={(event) => {
                    const [ip, port] = event.target.value.split(":");
                    updateMappingHint(index, { translatedDstIp: ip || undefined, translatedDstPort: numberOrUndefined(port || "") });
                  }} placeholder="IP[:端口]" />
                  <input value={hint.note} onChange={(event) => updateMappingHint(index, { note: event.target.value })} placeholder="备注" />
                  <button onClick={() => removeMappingHint(index)}>删除</button>
                </div>
              ))}
            </div>
          ) : <div className="empty">暂无地址转换线索。</div>}

          <h2>时间偏移线索</h2>
          <div className="mappingActions">
            <button onClick={addTimeOffsetHint} disabled={!graph}>新增偏移</button>
            <button className="primary" onClick={saveTimeOffsetHints} disabled={!graph}>保存偏移</button>
          </div>
          {timeOffsetHints.length ? (
            <div className="timeOffsetTable">
              <div className="timeOffsetHeader">
                <span>起点</span><span>终点</span><span>终点偏移秒</span><span>备注</span><span>操作</span>
              </div>
              {timeOffsetHints.map((hint, index) => (
                <div className="timeOffsetRow" key={`${hint.hintId}-${index}`}>
                  <select value={hint.fromNodeId || ""} onChange={(event) => updateTimeOffsetHint(index, { fromNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <select value={hint.toNodeId || ""} onChange={(event) => updateTimeOffsetHint(index, { toNodeId: event.target.value || undefined })}>
                    <option value="">任意</option>
                    {(graph?.captures || []).map((node) => <option value={node.nodeId} key={node.nodeId}>{node.name}</option>)}
                  </select>
                  <input type="number" value={hint.offsetSeconds} onChange={(event) => updateTimeOffsetHint(index, { offsetSeconds: Number(event.target.value) })} placeholder="可为负数" />
                  <input value={hint.note} onChange={(event) => updateTimeOffsetHint(index, { note: event.target.value })} placeholder="备注" />
                  <button onClick={() => removeTimeOffsetHint(index)}>删除</button>
                </div>
              ))}
            </div>
          ) : <div className="empty">暂无时间偏移线索。</div>}

          {(graph?.captures || []).map((node) => (
            <article className="node" key={node.nodeId}>
              <strong>{node.name}</strong>
              <span>{node.capturePosition || node.role}</span>
            </article>
          ))}
        </aside>

        <section className="mainDesk">
          <section className="chatPanel panel">
            <div className="chatTopbar">
              <div>
                <h2>Leader Agent</h2>
                <span>{llmRuntime?.agent.lastStatus || "not_run"}{llmRuntime?.agent.lastRunAt ? ` / ${new Date(llmRuntime.agent.lastRunAt).toLocaleString()}` : ""}</span>
              </div>
            </div>

            <section className="queryPathPanel">
              <div>
                <h3>当前访问路径</h3>
                <span>{activeQueryRun?.path?.summary || "向 Agent 提出访问查询后生成路径图。"}</span>
              </div>
              {activeQueryRun?.path?.hops?.length ? (
                <div className="queryPath">
                  {activeQueryRun.path.hops.map((hop, index) => (
                    <React.Fragment key={hop.hopId}>
                      <article className={`queryHop ${hop.status}`}>
                        <strong>{graph?.captures.find((capture) => capture.nodeId === hop.nodeId)?.name || hop.nodeId}</strong>
                        <span>{hop.observedTuple}</span>
                        <small>{hop.packetCount} 包{hop.anomalies.length ? ` / ${hop.anomalies.join("，")}` : ""}</small>
                        {hop.correlation ? <small>{hop.correlation}{hop.correlationReasons?.length ? `：${hop.correlationReasons.join("；")}` : ""}</small> : null}
                      </article>
                      {index < (activeQueryRun.path?.edges.length || 0) && (
                        <span className={`queryEdge ${activeQueryRun.path!.edges[index].status}`} title={activeQueryRun.path!.edges[index].reasons?.join("；") || activeQueryRun.path!.edges[index].diagnosis}>
                          <strong>{activeQueryRun.path!.edges[index].label}</strong>
                          {activeQueryRun.path!.edges[index].diagnosis ? <small>{activeQueryRun.path!.edges[index].diagnosis}</small> : null}
                        </span>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              ) : null}
            </section>

            <MessageList
              messages={chatMessages}
              copiedMessageId={copiedMessageId}
              llmRuntime={llmRuntime}
              containerRef={chatMessagesRef}
              onCopy={(message) => void copyMessage(message)}
              onOpenEvidence={(message, stepIndex) => openEvidenceDetail(message, graph?.spec.caseId || "", stepIndex)}
              onSelectQuestion={(q) => setQuestion(q)}
            />

            <div
              className={`chatComposer ${dragActive ? "dragActive" : ""} ${composerExpanded ? "expanded" : ""}`}
              onDragOver={(event) => {
                event.preventDefault();
                setDragActive(true);
              }}
              onDragLeave={() => setDragActive(false)}
              onDrop={(event) => {
                event.preventDefault();
                setDragActive(false);
                addComposerFiles(Array.from(event.dataTransfer.files || []));
              }}
              onPaste={(event) => {
                const files = Array.from(event.clipboardData.files || []);
                if (files.length) addComposerFiles(files);
              }}
            >
              {composerFiles.length ? (
                <div className="attachmentTray">
                  {composerFiles.map((file, index) => (
                    <span key={`${file.name}-${index}`}>
                      {file.name}
                      <button type="button" onClick={() => setComposerFiles((files) => files.filter((_, fileIndex) => fileIndex !== index))}>×</button>
                    </span>
                  ))}
                </div>
              ) : null}
              <textarea
                rows={composerExpanded ? 6 : 1}
                name="pcapai-message-body"
                autoComplete="new-password"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void ask();
                  }
                }}
                placeholder="描述故障时间、源 IP、目标 IP、端口，或直接拖入 pcap"
              />
              <button
                className="composerExpandButton"
                type="button"
                onClick={() => setComposerExpanded((expanded) => !expanded)}
                title={composerExpanded ? "收起输入框" : "展开输入框"}
              >
                {composerExpanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
              </button>
              <input
                ref={composerFileInputRef}
                type="file"
                accept=".pcap,.pcapng,.cap"
                multiple
                hidden
                onChange={(event) => addComposerFiles(Array.from(event.target.files || []))}
              />
              <div className="composerToolbar">
                <div className="composerTools">
                  <button className="composerIconButton" type="button" onClick={() => composerFileInputRef.current?.click()} title="上传 pcap / pcapng / cap">
                    <Paperclip size={18} />
                  </button>
                  <select className="composerSelect modelSelect" value={chatProfileId} onChange={(event) => setChatProfileId(event.target.value)} title="选择 LLM">
                    {manualModelOption ? <option value="">{manualModelOption}</option> : null}
                    {!manualModelOption && llmProfiles.length ? <option value="" disabled hidden>选择模型</option> : null}
                    {llmProfiles.map((profile) => (
                      <option value={profile.profileId} key={profile.profileId}>{profile.name} / {profile.model}</option>
                    ))}
                    {!manualModelOption && !llmProfiles.length ? <option value="">未配置模型</option> : null}
                  </select>
                  <select className="composerSelect" value={thinkingDepth} onChange={(event) => setThinkingDepth(event.target.value)} title="思考深度">
                    <option value="快速">思考：快速</option>
                    <option value="标准">思考：标准</option>
                    <option value="深入">思考：深入</option>
                  </select>
                  <select className="composerSelect" value={reasoningDepth} onChange={(event) => setReasoningDepth(event.target.value)} title="推理深度">
                    <option value="低">推理：低</option>
                    <option value="标准">推理：标准</option>
                    <option value="高">推理：高</option>
                  </select>
                </div>
                <button
                  className={`composerSendButton ${isAsking ? "stopButton" : ""}`}
                  onClick={() => {
                    if (isAsking) {
                      abortControllerRef.current?.abort();
                    } else {
                      void ask();
                    }
                  }}
                  disabled={!isAsking && !question.trim() && !composerFiles.length}
                  title={isAsking ? "停止" : "发送"}
                >
                  {isAsking ? <Square size={16} /> : <ArrowUp size={22} />}
                </button>
              </div>
            </div>
          </section>
        </section>

      </section>
      )}
        </section>
      </AppShell>
      {createFlowOpen && (
        <section className="detailOverlay" role="dialog" aria-modal="true">
          <div className="createDialog">
            <header className="detailHeader">
              <div>
                <h2>新建案例</h2>
                <p>按流程创建案例、上传 pcap，并可选填写初始筛选条件。</p>
              </div>
              <button className="themeToggle" onClick={() => setCreateFlowOpen(false)} aria-label="关闭新建案例">
                <X size={18} />
              </button>
            </header>
            <div className="wizardSteps">
              {["基本信息", "上传数据包", "可选筛选"].map((label, index) => (
                <button className={createStep === index + 1 ? "active" : ""} key={label} onClick={() => setCreateStep(index + 1)}>
                  {index + 1}. {label}
                </button>
              ))}
            </div>
            <div className="createBody">
              {createStep === 1 && (
                <div className="form">
                  <label>
                    <span>案例名称</span>
                    <input value={caseForm.title} onChange={(event) => setCaseForm({ title: event.target.value })} placeholder="例如：客户端访问服务端 443 失败" />
                  </label>
                </div>
              )}
              {createStep === 2 && (
                <div className="form">
                  <label>
                    <span>pcap / pcapng 文件</span>
                    <input type="file" accept=".pcap,.pcapng,.cap" multiple onChange={(event) => setSelectedFiles(Array.from(event.target.files || []))} />
                  </label>
                  {captureDrafts.length ? (
                    <div className="captureTable">
                      <div className="captureHeader">
                        <span>文件名</span>
                        <span>节点名</span>
                        <span>节点角色</span>
                        <span>入/出方向</span>
                        <span>抓包位置</span>
                      </div>
                      {captureDrafts.map((draft, index) => (
                        <div className="captureRow" key={`${draft.file.name}-${index}`}>
                          <span title={draft.file.name}>{draft.file.name}</span>
                          <input value={draft.name} onChange={(event) => updateCaptureDraft(index, { name: event.target.value })} placeholder="节点名" />
                          <input value={draft.role} onChange={(event) => updateCaptureDraft(index, { role: event.target.value })} placeholder="节点角色" />
                          <select value={draft.interfaceDirection} onChange={(event) => updateCaptureDraft(index, { interfaceDirection: event.target.value as CaptureDraft["interfaceDirection"] })}>
                            <option value="unknown">未知方向</option>
                            <option value="ingress">入方向</option>
                            <option value="egress">出方向</option>
                            <option value="bidirectional">双向</option>
                          </select>
                          <input value={draft.capturePosition} onChange={(event) => updateCaptureDraft(index, { capturePosition: event.target.value })} placeholder="抓包位置" />
                        </div>
                      ))}
                    </div>
                  ) : <div className="empty">可以先不上传，创建后再补数据包。</div>}
                </div>
              )}
              {createStep === 3 && (
                <div className="form">
                  <label>
                    <span>客户端地址</span>
                    <input value={createAnalysisFilter.client} onChange={(event) => setCreateAnalysisFilter({ ...createAnalysisFilter, client: event.target.value })} placeholder="可留空" />
                  </label>
                  <label>
                    <span>服务端地址</span>
                    <input value={createAnalysisFilter.server} onChange={(event) => setCreateAnalysisFilter({ ...createAnalysisFilter, server: event.target.value })} placeholder="可留空" />
                  </label>
                  <label>
                    <span>端口</span>
                    <input value={createAnalysisFilter.port} onChange={(event) => setCreateAnalysisFilter({ ...createAnalysisFilter, port: event.target.value })} placeholder="可留空" />
                  </label>
                  <label>
                    <span>协议</span>
                    <input value={createAnalysisFilter.protocol} onChange={(event) => setCreateAnalysisFilter({ ...createAnalysisFilter, protocol: event.target.value })} placeholder="可留空，例如 tcp / tls / http" />
                  </label>
                </div>
              )}
            </div>
            <footer className="wizardActions">
              <button onClick={() => setCreateFlowOpen(false)}>取消</button>
              <button onClick={() => setCreateStep((step) => Math.max(1, step - 1))} disabled={createStep === 1}>上一步</button>
              {createStep < 3 ? (
                <button className="primary" onClick={() => setCreateStep((step) => Math.min(3, step + 1))} disabled={!caseForm.title.trim()}>下一步</button>
              ) : (
                <button className="primary" onClick={createCaseFromFlow} disabled={!caseForm.title.trim()}>创建并进入工作台</button>
              )}
            </footer>
          </div>
        </section>
      )}
      {detailView && (
        <section className="detailOverlay" role="dialog" aria-modal="true">
          <div className="detailPage">
            <header className="detailHeader">
              <div>
                <h2>{detailTitle(detailView)}</h2>
                <p>{graph ? graph.spec.title : "尚未加载案例"}</p>
              </div>
              <button className="themeToggle" onClick={() => setDetailView(null)} aria-label="关闭详情">
                <X size={18} />
              </button>
            </header>

            <div className="detailBody">
              {detailView === "path" && (
                <>
                  {activeQueryRun?.path?.hops.length ? (
                    <div className="path detailPath">
                      {activeQueryRun.path.hops.map((hop, index) => (
                        <React.Fragment key={hop.hopId}>
                          <article className={`pathNode ${hop.status}`}>
                            <strong>{graph?.captures.find((capture) => capture.nodeId === hop.nodeId)?.name || hop.nodeId}</strong>
                            <span>{hop.observedTuple}</span>
                            {hop.correlation ? <small>{hop.correlation}{hop.correlationReasons?.length ? `：${hop.correlationReasons.join("；")}` : ""}</small> : null}
                          </article>
                          {index < activeQueryRun.path!.edges.length && (
                            <span className={`edge ${activeQueryRun.path!.edges[index].status}`} title={activeQueryRun.path!.edges[index].reasons?.join("；") || activeQueryRun.path!.edges[index].diagnosis}>
                              <strong>{activeQueryRun.path!.edges[index].label}</strong>
                              {activeQueryRun.path!.edges[index].diagnosis ? <small>{activeQueryRun.path!.edges[index].diagnosis}</small> : null}
                            </span>
                          )}
                        </React.Fragment>
                      ))}
                    </div>
                  ) : <div className="empty">尚未创建 QueryRun 路径。</div>}
                </>
              )}

              {detailView === "sessions" && (
                <>
                  {graph?.sessions?.length ? (
                    <>
                      <div className="sessionHeader">
                        <span>节点</span><span>协议</span><span>访问方向</span><span>事件</span><span>包数</span><span>置信度</span>
                      </div>
                      <div className="sessionTable">
                        {graph.sessions.map((session) => (
                          <article className="session" key={session.segmentId} title={session.summary}>
                            <strong>{session.nodeId}</strong>
                            <span>{session.protocol.toUpperCase()}</span>
                            <span>{`${session.clientIp || "*"}:${session.clientPort ?? "*"} -> ${session.serverIp || "*"}:${session.serverPort ?? "*"}`}</span>
                            <span>{session.eventKinds.join(", ") || "-"}</span>
                            <span>{session.packetIds.length}</span>
                            <span>{session.confidence}</span>
                          </article>
                        ))}
                      </div>
                    </>
                  ) : <div className="empty">尚未生成会话片段。</div>}
                </>
              )}

              {detailView === "links" && (
                <>
                  {graph?.sessionLinks?.length ? (
                    <>
                      <div className="linkHeader">
                        <span>节点</span><span>会话</span><span>依据</span><span>反证</span><span>分数</span><span>置信度</span>
                      </div>
                      <div className="linkTable">
                        {graph.sessionLinks.map((link) => (
                          <article className="linkRow" key={link.linkId} title={[...link.matchReasons, ...link.counterEvidence].join("；")}>
                            <strong>{`${link.fromNodeId} -> ${link.toNodeId}`}</strong>
                            <span>{`${link.fromSegmentId} -> ${link.toSegmentId}`}</span>
                            <span>{link.matchReasons.join("，") || "-"}</span>
                            <span>{link.counterEvidence.join("，") || "-"}</span>
                            <span>{link.score}</span>
                            <span>{link.confidence}</span>
                          </article>
                        ))}
                      </div>
                    </>
                  ) : <div className="empty">尚未生成跨节点关联。</div>}
                </>
              )}

              {detailView === "packets" && (
                <>
                  {graph?.packets.length ? (
                    <>
                      <div className="packetHeader">
                        <span>帧</span><span>协议</span><span>源</span><span>目的</span><span>标记</span><span>长度</span>
                      </div>
                      <div className="packetTable">
                        {graph.packets.map((packet) => (
                          <article className="packet" key={packet.packetId} title={packet.summary}>
                            <strong>#{packet.frameNumber}</strong>
                            <span>{packet.protocol.toUpperCase()}</span>
                            <span>{packet.srcIp || "*"}:{packet.srcPort ?? "*"}</span>
                            <span>{packet.dstIp || "*"}:{packet.dstPort ?? "*"}</span>
                            <span>{packet.tcpFlags.join(",") || "-"}</span>
                            <span>{packet.length ?? "-"}</span>
                          </article>
                        ))}
                      </div>
                    </>
                  ) : <div className="empty">尚未解析数据包。</div>}
                </>
              )}

              {detailView === "findings" && (
                <>
                  {(graph?.findings || []).map((finding) => (
                    <article className="finding" key={finding.findingId}>
                      <strong>{finding.title}</strong>
                      <p>{finding.summary}</p>
                      <span>置信度：{finding.confidence}</span>
                      <span>标签：{finding.tagIds?.join("，") || "-"}</span>
                      <span>证据：{finding.evidenceIds.join("，") || "-"}</span>
                      {finding.nextSteps.length ? <ul>{finding.nextSteps.map((step) => <li key={step}>{step}</li>)}</ul> : null}
                    </article>
                  ))}
                  {!graph?.findings.length && <div className="empty">尚未生成 finding。</div>}
                </>
              )}

              {detailView === "events" && (
                <>
                  {(graph?.evidence || []).map((event) => (
                    <article className="event" key={event.evidenceId}>
                      <strong>{event.title}</strong>
                      <p>{event.detail}</p>
                      <span>{event.evidenceId}</span>
                    </article>
                  ))}
                  {!graph?.evidence.length && <div className="empty">尚未生成证据事件。</div>}
                </>
              )}

              {detailView === "tcp_stream" && (
                <>
                  <div className="tcpStreamPanel">
                    {!tcpStreams.length && !tcpStreamLoading && (
                      <button className="primary" onClick={async () => {
                        if (!graph) return;
                        setTcpStreamLoading(true);
                        setTcpStreams(await loadTcpStreams(graph.spec.caseId));
                        setTcpStreamLoading(false);
                      }}>加载 TCP 流列表</button>
                    )}
                    {tcpStreamLoading && <div className="empty">加载中...</div>}
                    {tcpStreams.length > 0 && !tcpStreamContent && (
                      <div className="tcpStreamList">
                        {tcpStreams.map((s) => (
                          <button key={s.streamIndex} onClick={async () => {
                            if (!graph) return;
                            setTcpStreamLoading(true);
                            const content = await loadTcpStreamContent(graph.spec.caseId, s.streamIndex);
                            setTcpStreamContent(content);
                            setTcpStreamLoading(false);
                          }}>
                            <span>Stream {s.streamIndex}: {s.srcIp}:{s.srcPort} ↔ {s.dstIp}:{s.dstPort}</span>
                            <small>{s.packetCount} pkts / {s.byteCount} bytes</small>
                          </button>
                        ))}
                      </div>
                    )}
                    {tcpStreamContent && (
                      <div className="tcpStreamViewer">
                        <div className="tcpStreamHeader">
                          <strong>Stream {tcpStreamContent.streamIndex}</strong>
                          <span>{tcpStreamContent.totalBytes} bytes{tcpStreamContent.truncated ? " (已截断)" : ""}</span>
                          <button onClick={() => setTcpStreamContent(null)}>← 返回列表</button>
                        </div>
                        <div className="tcpStreamData">
                          <div className="tcpStreamCol">
                            <h4>客户端 → 服务端</h4>
                            <pre className="clientData">{tcpStreamContent.clientData || "(空)"}</pre>
                          </div>
                          <div className="tcpStreamCol">
                            <h4>服务端 → 客户端</h4>
                            <pre className="serverData">{tcpStreamContent.serverData || "(空)"}</pre>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </>
              )}

              {detailView === "topology" && (
                <>
                  {graph?.networkTopology?.devices?.length ? (
                    <TopologyDiagram
                      devices={graph.networkTopology.devices}
                      dataPath={graph.networkTopology.dataPath || []}
                      captures={graph.captures}
                    />
                  ) : (
                    <div className="empty">尚未收集网络拓扑信息。在 Agent 对话中描述网络路径和设备，或手动输入 Mapping Hints。</div>
                  )}
                </>
              )}
            </div>
          </div>
        </section>
      )}
    </main>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(<App />);
