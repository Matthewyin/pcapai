import React from "react";
import ReactDOM from "react-dom/client";
import { ArrowUp, BookOpen, CheckCircle, ChevronDown, Copy, Cpu, Eye, EyeOff, History, Maximize2, Minimize2, Moon, MoreHorizontal, Paperclip, Pencil, Pin, PinOff, Plus, Save, Settings, Sun, Trash2, X } from "lucide-react";
import { marked } from "marked";
import DOMPurify from "dompurify";
import { webConfig } from "./config";
import "./styles.css";

marked.setOptions({ breaks: true, gfm: true });

function renderMarkdown(text: string): string {
  const html = marked.parse(text) as string;
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ["h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr", "strong", "em", "del", "ul", "ol", "li", "a", "code", "pre", "blockquote"],
    ALLOWED_ATTR: ["href", "target", "rel"]
  });
}

type PacketSummary = {
  packetId: string;
  nodeId?: string;
  pcapFilename?: string;
  frameNumber: number;
  timestamp: number;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol: string;
  tcpFlags: string[];
  tcpAnalysis?: {
    retransmission?: boolean;
    fastRetransmission?: boolean;
    duplicateAck?: boolean;
    zeroWindow?: boolean;
    lostSegment?: boolean;
  };
  length?: number;
  summary: string;
};

type CaseGraph = {
  spec: { caseId: string; title: string; client?: string; server?: string; port?: number; protocol: string };
  captures: { nodeId: string; name: string; role: string; pcapFilename?: string; capturePosition: string; packetCount?: number; firstPacketTime?: number; lastPacketTime?: number }[];
  mappingHints: MappingHint[];
  timeOffsetHints: TimeOffsetHint[];
  rawPackets: {
    packetId: string;
  }[];
  analysisFilter: { client?: string; server?: string; protocol?: string; port?: number };
  packets: PacketSummary[];
  sessions: {
    segmentId: string;
    nodeId: string;
    protocol: string;
    clientIp?: string;
    clientPort?: number;
    serverIp?: string;
    serverPort?: number;
    startTime: number;
    endTime: number;
    packetIds: string[];
    eventKinds: string[];
    summary: string;
    confidence: string;
  }[];
  sessionLinks: {
    linkId: string;
    fromSegmentId: string;
    toSegmentId: string;
    fromNodeId: string;
    toNodeId: string;
    matchReasons: string[];
    counterEvidence: string[];
    confidence: string;
    score: number;
  }[];
  diagnosticTags: DiagnosticTag[];
  findings: { findingId: string; title: string; summary: string; confidence: string; tagIds?: string[]; evidenceIds: string[]; packetIds?: string[]; nextSteps: string[] }[];
  evidence: { evidenceId: string; title: string; detail: string; packetIds: string[] }[];
  path: { nodes: { nodeId: string; label: string; role: string; status: string }[]; edges: { edgeId: string; label: string; status: string }[] };
  queryRuns: QueryRun[];
  activeQueryRunId?: string;
  analysisRuns: AnalysisRun[];
  activeRunId?: string;
  toolRuns: ToolRun[];
  insights?: PacketInsight[];
  networkTopology?: {
    devices: { deviceId: string; name: string; type: string; description?: string }[];
    dataPath: { hopIndex: number; deviceName: string }[];
  };
};

type PacketInsight = {
  insightId: string;
  type: "connection_lifecycle" | "ack_gap" | "tcp_timing" | "tcp_window_trend" | "tcp_rst_direction" | "tcp_handshake_retry" | "tcp_delayed_ack" | "tcp_connection_flood" | "tcp_segment_anomaly" | "tcp_keepalive" | "tcp_throughput" | "tcp_options" | "http_status_chain" | "http_header_anomaly" | "http_timing" | "icmp_echo_pair" | "icmp_unreachable" | "icmp_mtu" | "icmp_redirect" | "cross_protocol_chain" | "tls_handshake" | "dns_anomaly" | "udp_anomaly" | "udp_flow" | "quic_anomaly" | "ntp_anomaly" | "ssh_anomaly";
  severity: "info" | "warning" | "critical";
  packetIds: string[];
  description: string;
  detail: Record<string, unknown>;
  scenario?: string;
};

type Conversation = {
  conversationId: string;
  nodeId: string;
  pcapFilename: string;
  protocol: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  startTime: number;
  endTime: number;
  packetCount: number;
  byteCount: number;
  tcpFlags: string[];
  rstCount: number;
  retransmissionCount: number;
  zeroWindowCount: number;
  rankScore?: number;
  rankReasons?: string[];
  displayFilter: string;
};

type QueryDiagnosis = {
  conversationId: string;
  summary: string;
  confidence: string;
  checks: {
    key: "handshake" | "rst" | "traffic_direction" | "retransmission" | "zero_window" | "close_state" | "path" | "protocol" | "icmp" | "dns" | "udp" | "tls" | "http";
    label: string;
    status: "ok" | "warn" | "problem" | "unknown";
    summary: string;
    packetIds: string[];
    nextSteps: string[];
  }[];
  diagnosticTags: DiagnosticTag[];
  findings: { findingId: string; title: string; summary: string; confidence: string; tagIds?: string[]; evidenceIds: string[]; packetIds?: string[]; nextSteps: string[] }[];
  nextSteps: string[];
};

type EvidenceCard = {
  cardId: string;
  kind: "capture" | "time_range" | "conversation" | "packet" | "protocol_event" | "transaction" | "filter" | "statistic" | "missing_context";
  title: string;
  summary: string;
  pcapFilename?: string;
  frameNumber?: number;
  displayFilter?: string;
  packetDisplayFilter?: string;
  conversationId?: string;
  queryRunId?: string;
  actions: Array<"open_wireshark" | "select_conversation" | "query_packets" | "request_upload" | "copy_filter">;
};

type ProtocolCorrelation = {
  correlationId: string;
  kind: "dns_to_tcp" | "tls_sni_to_tcp" | "http_host_to_tcp";
  sourcePacketId: string;
  sourceEvidenceCardId?: string;
  targetConversationId?: string;
  targetDisplayFilter: string;
  relation: string;
  confidence: string;
  summary: string;
  reasons: string[];
  nextSteps: string[];
};

type AccessCandidateGroup = {
  groupId: string;
  protocol: string;
  srcIp?: string;
  dstIp?: string;
  dstPort?: number;
  conversationIds: string[];
  selectedConversationId?: string;
  conversationCount: number;
  successCount: number;
  failureCount: number;
  rstCount: number;
  retransmissionCount: number;
  zeroWindowCount: number;
  failureModes: { kind: string; label: string; count: number; conversationIds: string[] }[];
  firstSeen?: number;
  lastSeen?: number;
  rankScore: number;
  rankReasons: string[];
  summary: string;
};

type QueryPath = {
  queryRunId: string;
  conversationId: string;
  hops: {
    hopId: string;
    nodeId: string;
    conversationId: string;
    observedTuple: string;
    status: string;
    startTime?: number;
    endTime?: number;
    packetCount: number;
    anomalies: string[];
    wiresharkFilter: string;
    correlation?: string;
    correlationReasons?: string[];
  }[];
  edges: {
    edgeId: string;
    fromNodeId: string;
    toNodeId: string;
    status: string;
    label: string;
    diagnosis?: string;
    reasons?: string[];
    nextSteps?: string[];
    timeDeltaSeconds?: number;
  }[];
  missingHops: string[];
  confidence: string;
  summary: string;
};

type QueryRun = {
  queryRunId: string;
  caseId: string;
  question: string;
  timeRange: { start?: number; end?: number };
  srcIp?: string;
  dstIp?: string;
  port?: number;
  protocol?: string;
  displayFilter: string;
  totalConversationCount?: number;
  candidateGroups: AccessCandidateGroup[];
  selectedCandidateGroupId?: string;
  conversationIds: string[];
  conversations: Conversation[];
  selectedConversationId?: string;
  path?: QueryPath;
  selectedDiagnosis?: QueryDiagnosis;
  evidenceCards: EvidenceCard[];
  protocolCorrelations: ProtocolCorrelation[];
  selectedEvidenceCardId?: string;
  createdAt: string;
};

type AnalysisRun = {
  runId: string;
  createdAt: string;
  kind: "capture_update" | "parse" | "analysis";
  summary: string;
  captureCount: number;
  rawPacketCount: number;
  packetCount: number;
  findingCount: number;
};

type ToolRun = {
  toolRunId: string;
  createdAt: string;
  kind: "planner" | "tool" | "mcp" | "agent";
  status: "success" | "error" | "skipped";
  target: string;
  question?: string;
  intent?: string;
  summary: string;
  inputSummary?: string;
  outputSummary?: string;
  queryRunId?: string;
  evidenceCardIds?: string[];
  pcapFilename?: string;
  frameNumber?: number;
  displayFilter?: string;
  packetDisplayFilter?: string;
  durationMs?: number;
  error?: string;
};

type MappingHint = {
  hintId: string;
  kind: "nat" | "slb" | "proxy" | "gateway" | "tunnel";
  fromNodeId?: string;
  toNodeId?: string;
  originalSrcIp?: string;
  originalSrcPort?: number;
  originalDstIp?: string;
  originalDstPort?: number;
  translatedSrcIp?: string;
  translatedSrcPort?: number;
  translatedDstIp?: string;
  translatedDstPort?: number;
  note: string;
};

type TimeOffsetHint = {
  hintId: string;
  fromNodeId?: string;
  toNodeId?: string;
  offsetSeconds: number;
  note: string;
};

type DiagnosticTag = {
  tagId: string;
  kind: string;
  nodeIds: string[];
  segmentIds: string[];
  packetIds: string[];
  evidenceIds: string[];
  confidence: string;
  summary: string;
  nextSteps: string[];
};

type CaseSummary = {
  caseId: string;
  title: string;
  updatedAt: number;
  captureCount: number;
  rawPacketCount: number;
  packetCount: number;
  findingCount: number;
  runCount: number;
  activeRunId: string;
};

type LlmProfile = {
  profileId: string;
  name: string;
  baseURL: string;
  model: string;
  providerData: string;
  hasKey: boolean;
  active: boolean;
};

type LlmRuntimeStatus = {
  settings: {
    baseURL: string;
    model: string;
    providerData: string;
    hasKey: boolean;
    activeProfileId: string;
  };
  useResponses: boolean;
  agent: {
    lastRunAt: string;
    lastStatus: string;
    lastError: string;
    lastCaseId: string;
    lastModel: string;
    lastBaseURL: string;
  };
};

type CaptureDraft = {
  file: File;
  nodeId: string;
  name: string;
  role: string;
  interfaceDirection: "unknown" | "ingress" | "egress" | "bidirectional";
  capturePosition: string;
};

type DetailView = "path" | "findings" | "sessions" | "links" | "packets" | "events" | "topology" | "tcp_stream";
type DiagnosticHypothesis = {
  id: string;
  description: string;
  status: "pending" | "testing" | "confirmed" | "ruled_out";
  evidenceFor: string[];
  evidenceAgainst: string[];
};

type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  thoughts?: string[];
  evidenceCards?: EvidenceCard[];
  suggestedQueries?: Array<{ question: string; reason: string; intent: string }>;
  streaming?: boolean;
  evidenceIds?: string[];
  packetIds?: string[];
  findingIds?: string[];
  sessionLinkIds?: string[];
  handoffAgent?: string;
  confidence?: string;
  missingContext?: string[];
  suggestedActions?: string[];
  protocolCorrelations?: ProtocolCorrelation[];
  followUpQuestions?: string[];
  diagnosticPhase?: "interview" | "hypothesis" | "testing" | "conclusion";
  hypotheses?: DiagnosticHypothesis[];
  stepEvidence?: Record<number, { purpose: string; evidenceCards: EvidenceCard[] }>;
};

function fileStem(filename: string) {
  return filename.replace(/\.[^.]+$/, "");
}

function capturePacketTotal(graph?: CaseGraph | null) {
  return graph?.captures.reduce((sum, capture) => sum + (capture.packetCount || 0), 0) || 0;
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

function formatPacketTime(timestamp?: number) {
  if (!Number.isFinite(timestamp)) return "-";
  const milliseconds = timestamp! > 1_000_000_000_000 ? timestamp! : timestamp! * 1000;
  return new Date(milliseconds).toLocaleString();
}

function formatShortPacketTime(timestamp?: number) {
  if (!Number.isFinite(timestamp)) return "-";
  const milliseconds = timestamp! > 1_000_000_000_000 ? timestamp! : timestamp! * 1000;
  return new Date(milliseconds).toLocaleTimeString();
}

function formatDuration(start?: number, end?: number) {
  if (!Number.isFinite(start) || !Number.isFinite(end)) return "-";
  const duration = Math.max(0, end! - start!);
  if (duration < 1) return `${Math.round(duration * 1000)}ms`;
  return `${duration.toFixed(1)}s`;
}

function formatEndpoint(ip?: string, port?: number) {
  return `${ip || "*"}:${port ?? "*"}`;
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

// 瀑布图组件
function WaterfallChart({ stages }: { stages: Array<{ stage: string; timestamp: number; deltaMs: number; summary: string }> }) {
  if (!stages.length) return null;
  const protocolColors: Record<string, string> = { DNS: "#4A90D9", TCP: "#7BC67E", TLS: "#E8913A", HTTP: "#9B59B6", ICMP: "#E74C3C" };
  const getColor = (stage: string) => {
    const upper = stage.toUpperCase();
    for (const [proto, color] of Object.entries(protocolColors)) {
      if (upper.includes(proto)) return color;
    }
    return "#95A5A6";
  };
  const rowH = 32, padL = 120, padR = 20, padT = 10;
  const maxDelta = Math.max(...stages.map(s => s.deltaMs), 1);
  const chartW = 500, barMaxW = chartW - padL - padR;
  const scaleX = (ms: number) => padL + (ms / maxDelta) * barMaxW;
  const totalH = padT + stages.length * rowH;
  return (
    <svg className="waterfallChart" viewBox={`0 0 ${chartW} ${totalH}`} preserveAspectRatio="xMidYMid meet">
      {stages.map((s, i) => {
        const x = scaleX(s.deltaMs);
        const color = getColor(s.stage);
        return (
          <g key={i}>
            <text x={padL - 8} y={padT + i * rowH + 16} textAnchor="end" fontSize={11} fill="var(--text-secondary)">{s.stage}</text>
            <rect x={x} y={padT + i * rowH + 2} width={Math.max(barMaxW * 0.15, 60)} height={22} fill={color} rx={3} opacity={0.85} />
            <text x={x + 6} y={padT + i * rowH + 17} fontSize={10} fill="white">{s.deltaMs.toFixed(0)}ms</text>
            {i > 0 && <line x1={scaleX(stages[i - 1].deltaMs)} y1={padT + i * rowH - 4} x2={x} y2={padT + i * rowH + 4} stroke="var(--border)" strokeDasharray="3,2" />}
          </g>
        );
      })}
    </svg>
  );
}

// 拓扑图组件
function TopologyDiagram({ devices, dataPath, captures }: { devices: Array<{ deviceId: string; name: string; type: string; description?: string }>; dataPath: Array<{ hopIndex: number; deviceName: string }>; captures: Array<{ nodeId: string; pcapFilename?: string }> }) {
  const nodeW = 130, nodeH = 44, gapX = 180, padX = 40, padY = 30;
  const typeColors: Record<string, string> = { client: "#4A90D9", server: "#7BC67E", firewall: "#E74C3C", load_balancer: "#E8913A", switch_: "#9B59B6", router: "#1ABC9C", unknown: "#95A5A6" };
  const nodes = devices.map((d, i) => ({
    id: d.deviceId, label: d.name, type: d.type,
    x: padX + i * gapX, y: padY, color: typeColors[d.type] || typeColors.unknown,
    isCapture: captures.some(c => c.nodeId === d.deviceId)
  }));
  const edges = nodes.length > 1 ? nodes.slice(0, -1).map((n, i) => ({ from: n, to: nodes[i + 1] })) : [];
  const totalW = padX * 2 + Math.max(devices.length - 1, 0) * gapX + nodeW;
  const totalH = padY * 2 + nodeH + (nodes.some(n => n.isCapture) ? 40 : 0);
  return (
    <svg className="topologySvg" viewBox={`0 0 ${totalW} ${totalH}`} preserveAspectRatio="xMidYMid meet">
      {edges.map((e, i) => (
        <line key={i} x1={e.from.x + nodeW} y1={e.from.y + nodeH / 2} x2={e.to.x} y2={e.to.y + nodeH / 2} stroke="var(--border)" strokeWidth={2} />
      ))}
      {nodes.map((n) => (
        <g key={n.id} transform={`translate(${n.x},${n.y})`}>
          <rect width={nodeW} height={nodeH} rx={6} fill={n.color} opacity={0.9} />
          <text x={nodeW / 2} y={20} textAnchor="middle" fontSize={12} fill="white" fontWeight="bold">{n.label}</text>
          <text x={nodeW / 2} y={35} textAnchor="middle" fontSize={9} fill="rgba(255,255,255,0.8)">{n.type}</text>
          {n.isCapture && <circle cx={nodeW - 10} cy={10} r={6} fill="#FFD700" stroke="white" strokeWidth={1.5} />}
        </g>
      ))}
    </svg>
  );
}

function App() {
  const [page, setPage] = React.useState<"workbench" | "history" | "settings" | "help">("workbench");
  const [theme, setTheme] = React.useState<"dark" | "light">(() => {
    return localStorage.getItem("pcapai-theme") === "dark" ? "dark" : "light";
  });
  const [detailView, setDetailView] = React.useState<DetailView | null>(null);
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
  const [settingsMenuOpen, setSettingsMenuOpen] = React.useState(false);
  const [toolTraceOpen, setToolTraceOpen] = React.useState(false);
  const [insightsOpen, setInsightsOpen] = React.useState(false);
  const [caseMenuId, setCaseMenuId] = React.useState("");
  const [renamingCaseId, setRenamingCaseId] = React.useState("");
  const [renameDraft, setRenameDraft] = React.useState("");
  const [pinnedCaseIds, setPinnedCaseIds] = React.useState<string[]>(() => loadPinnedCaseIds());
  const chatMessagesRef = React.useRef<HTMLDivElement | null>(null);
  const chatSaveTimerRef = React.useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const composerFileInputRef = React.useRef<HTMLInputElement | null>(null);
  const uploadDisabledReason = !graph ? "请先新建案例。" : !captureDrafts.length ? "请选择一个或多个 pcap/pcapng 文件。" : "";

  function resetCreateFlow() {
    setCreateStep(1);
    setCaseForm({ title: "新建离线排障案例" });
    setCaptureDrafts([]);
    setCreateAnalysisFilter({ client: "", server: "", protocol: "", port: "" });
  }

  async function loadCaseHistory() {
    const response = await fetch("/api/cases");
    const data = await response.json();
    if (response.ok) {
      const cases = data.cases || [];
      setCaseHistory(cases);
      setSelectedCaseIds((ids) => ids.filter((id) => cases.some((item: CaseSummary) => item.caseId === id)));
    }
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
    setCaseMenuId("");
  }

  async function renameCase(caseId: string) {
    const title = renameDraft.trim();
    if (!title) return;
    const response = await fetch(`/api/cases/${caseId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title })
    });
    const data = await response.json();
    if (response.ok) {
      if (graph?.spec.caseId === caseId) setGraph(data);
      await loadCaseHistory();
      setRenamingCaseId("");
      setCaseMenuId("");
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
      setCaseMenuId("");
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
    } else {
      localStorage.removeItem(LAST_CASE_ID_KEY);
      localStorage.removeItem(LAST_RUN_ID_KEY);
    }
    setStatus(response.ok ? "历史案例已加载。" : formatApiError(data));
  }

  function openSettingsMenuPage(nextPage: "history" | "settings" | "help") {
    setPage(nextPage);
    setSettingsMenuOpen(false);
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
    if (response.ok && data.graph) setGraph(data.graph);
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
    } else {
      setStatus(formatApiError(data));
    }
  }

  async function openToolRun(run: ToolRun) {
    if (!graph) return;
    const card = evidenceCardFromToolRun(run);
    if (run.pcapFilename && run.displayFilter) {
      const response = await fetch(`/api/cases/${graph.spec.caseId}/evidence/open`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pcapFilename: run.pcapFilename,
          displayFilter: run.displayFilter,
          frameNumber: run.frameNumber,
          queryRunId: run.queryRunId,
          cardId: card?.cardId
        })
      });
      const data = await response.json();
      if (response.ok && data.graph) setGraph(data.graph);
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
    return run.intent || run.target;
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
    if (response.ok && data.graph) setGraph(data.graph);
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
    const targetGraph = graph || await createNewChat();
    if (!targetGraph) return;
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
        if (uploadResult?.agentAnswer && !prompt) {
          setAnswer(uploadResult.agentAnswer.answer);
          setChatMessages((messages) => messages.map((message) => message.id === assistantId ? {
            ...message,
            content: uploadResult.agentAnswer?.answer || "",
            thoughts: uploadResult.agentAnswer?.thoughts || [],
            evidenceCards: uploadResult.agentAnswer?.evidenceCards || [],
            protocolCorrelations: uploadResult.agentAnswer?.protocolCorrelations || [],
            streaming: false
          } : message));
          await loadLlmRuntime();
          return;
        }
      } catch (error) {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: error instanceof Error ? error.message : String(error), streaming: false } : message));
        return;
      }
    }

    if (!prompt) return;

    const currentCaseId = (graph || targetGraph).spec.caseId;
    const response = await fetch(`/api/cases/${currentCaseId}/agent/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: prompt, chatHistory, profileId: chatProfileId || undefined, thinkingDepth, reasoningDepth })
    });
    if (!response.ok || !response.body) {
      const data = await response.json();
      const error = formatApiError(data);
      setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: error, streaming: false } : message));
      await loadLlmRuntime();
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
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, thoughts: [...(message.thoughts || []), data.text] } : message));
      } else if (event === "chain_start") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, thoughts: [...(message.thoughts || []), `开始分析链（共 ${data.stepCount} 步）`] } : message));
      } else if (event === "step_start") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, thoughts: [...(message.thoughts || []), `▸ 步骤 ${data.index + 1}/${data.total}：${data.purpose}`] } : message));
      } else if (event === "step_done") {
        const stepCards = Array.isArray(data.evidenceCards) ? data.evidenceCards : [];
        setChatMessages((messages) => messages.map((message) => {
          if (message.id !== assistantId) return message;
          const updated = { ...message };
          if (data.status === "error") {
            updated.thoughts = [...(updated.thoughts || []), `  ✗ 步骤 ${data.index + 1} 失败：${data.summary}`];
          }
          if (stepCards.length) {
            const se = { ...(updated.stepEvidence || {}) };
            se[data.index] = { purpose: data.purpose || `步骤 ${data.index + 1}`, evidenceCards: stepCards };
            updated.stepEvidence = se;
          }
          return updated;
        }));
      } else if (event === "chain_done") {
        const summaries = (data.summaries || []).map((s: { stepId: string; status: string }, i: number) => `${i + 1}. ${s.status}`).join("；");
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, thoughts: [...(message.thoughts || []), `分析链完成：${summaries}`] } : message));
      } else if (event === "delta") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: message.content + data.text } : message));
      } else if (event === "done") {
        setAnswer(data.answer || "");
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: data.answer || message.content, evidenceCards: data.evidenceCards || [], suggestedQueries: data.suggestedQueries || [], evidenceIds: data.evidenceIds || [], packetIds: data.packetIds || [], findingIds: data.findingIds || [], sessionLinkIds: data.sessionLinkIds || [], handoffAgent: data.handoffAgent || undefined, confidence: data.confidence || undefined, missingContext: data.missingContext || [], suggestedActions: data.suggestedActions || [], protocolCorrelations: data.protocolCorrelations || [], followUpQuestions: data.followUpQuestions || [], diagnosticPhase: data.diagnosticPhase || undefined, hypotheses: data.hypotheses || [], streaming: false } : message));
        void refreshGraph(currentCaseId);
      } else if (event === "error") {
        setChatMessages((messages) => messages.map((message) => message.id === assistantId ? { ...message, content: data.error, streaming: false } : message));
      }
    };

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() || "";
      events.forEach(applyEvent);
    }
    if (buffer.trim()) applyEvent(buffer);
    setChatMessages((messages) => {
      const updated = messages.map((message) => message.id === assistantId ? { ...message, streaming: false } : message);
      saveChatMessages(currentCaseId, updated);
      return updated;
    });
    await loadLlmRuntime();
  }

  function openEvidenceDetail(message: ChatMessage, caseId: string, stepIndex?: number) {
    const allCards = message.evidenceCards || [];
    const correlations = message.protocolCorrelations || [];
    const stepEvidence = message.stepEvidence;
    const cards = stepIndex !== undefined && stepEvidence?.[stepIndex] ? stepEvidence[stepIndex].evidenceCards : allCards;
    const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    const cardSections = cards.map((card) => `
      <div class="ev-card">
        <div class="ev-card-title">${esc(card.title)}</div>
        <div class="ev-card-summary">${esc(card.summary)}</div>
        ${card.pcapFilename ? `<div class="ev-meta">文件：${esc(card.pcapFilename)}${card.frameNumber ? ` / Frame ${card.frameNumber}` : ""}</div>` : ""}
        ${card.displayFilter ? `<div class="ev-filter"><code>${esc(card.displayFilter)}</code><button onclick="copyFilter(this)" title="复制过滤器">复制</button>${card.pcapFilename ? `<button onclick="openWireshark('${esc(card.pcapFilename)}','${esc(card.displayFilter)}')" title="在 Wireshark 中打开">Wireshark</button>` : ""}</div>` : ""}
        ${card.packetDisplayFilter && card.packetDisplayFilter !== card.displayFilter ? `<div class="ev-filter"><span>包级过滤器：</span><code>${esc(card.packetDisplayFilter)}</code><button onclick="copyFilter(this)">复制</button></div>` : ""}
      </div>`).join("");
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
    if (message.handoffAgent) diagSections.push(`<div class="diag-item"><strong>Agent</strong><span>${esc(message.handoffAgent)}</span></div>`);
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
    const text = [
      `${message.role === "user" ? "你" : "Agent"}：`,
      message.thoughts?.length ? `执行轨迹：\n${message.thoughts.map((thought, index) => `${index + 1}. ${thought}`).join("\n")}` : "",
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

  React.useEffect(() => {
    localStorage.setItem("pcapai-theme", theme);
  }, [theme]);

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

  React.useEffect(() => {
    void loadLlmSettings();
    void loadLlmProfiles();
    void loadLlmRuntime();
    void loadCaseHistory();
    const lastCaseId = localStorage.getItem(LAST_CASE_ID_KEY);
    if (lastCaseId) void openCase(lastCaseId, localStorage.getItem(LAST_RUN_ID_KEY));
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

  const tcpConnectionCount = graph?.sessions.filter((session) => session.protocol.toLowerCase() === "tcp").length || 0;
  const tcpCommunicationPairCount = (() => {
    if (!graph) return 0;
    const sessionPairs = new Set(graph.sessions
      .filter((session) => session.protocol.toLowerCase() === "tcp" && session.clientIp && session.serverIp && session.clientPort !== undefined && session.serverPort !== undefined)
      .map((session) => [`${session.clientIp}:${session.clientPort}`, `${session.serverIp}:${session.serverPort}`].sort().join(" <-> ")));
    if (sessionPairs.size) return sessionPairs.size;
    return new Set(graph.packets
      .filter((packet) => packet.protocol.toLowerCase() === "tcp" && packet.srcIp && packet.dstIp && packet.srcPort !== undefined && packet.dstPort !== undefined)
      .map((packet) => [`${packet.srcIp}:${packet.srcPort}`, `${packet.dstIp}:${packet.dstPort}`].sort().join(" <-> "))).size;
  })();
  const packetTimes = (graph?.packets || []).map((packet) => packet.timestamp).filter(Number.isFinite);
  const timeRange = packetTimes.length
    ? `${formatPacketTime(Math.min(...packetTimes))} - ${formatPacketTime(Math.max(...packetTimes))}`
    : "-";
  const tcpPackets = (graph?.packets || []).filter((packet) => packet.protocol.toLowerCase() === "tcp");
  const packetCountByFlag = (flag: string) => tcpPackets.filter((packet) => packet.tcpFlags.includes(flag)).length;
  const retransmissionPacketCount = tcpPackets.filter((packet) => packet.tcpAnalysis?.retransmission || packet.tcpAnalysis?.fastRetransmission).length;
  const duplicateAckPacketCount = tcpPackets.filter((packet) => packet.tcpAnalysis?.duplicateAck).length;
  const zeroWindowPacketCount = tcpPackets.filter((packet) => packet.tcpAnalysis?.zeroWindow).length;
  const activeQueryRun = graph?.queryRuns?.find((run) => run.queryRunId === graph.activeQueryRunId) || graph?.queryRuns?.[0];
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

  return (
    <main className="app" data-theme={theme}>
      <section className="appShell">
        <aside className="appSidebar panel">
          <div className="sidebarBrand">
            <div>
              <strong>PcapAI</strong>
              <span>packet agent</span>
            </div>
            <button className="newCaseButton" onClick={() => void createNewChat()}>
              <Plus size={18} /> 新建会话
            </button>
          </div>

          <section className="currentSession">
            <span>当前会话</span>
            <strong>{graph ? graph.spec.title : "尚未选择会话"}</strong>
            <small>{graph ? `${graph.captures.length} 文件 · ${graph.rawPackets.length || graph.packets.length} 包${activeQueryRun ? ` · ${activeQueryRun.protocol || "query"}` : ""}` : "新建会话后上传 pcap 开始分析"}</small>
          </section>

          <section className="sidebarCases">
            <div className="sidebarSectionTitle">
              <h2>最近会话</h2>
            </div>
            {displayedCaseHistory.map((item) => (
              <article className={`sidebarCase ${graph?.spec.caseId === item.caseId ? "active" : ""}`} key={item.caseId} onContextMenu={(event) => {
                event.preventDefault();
                setCaseMenuId(item.caseId);
              }}>
                {renamingCaseId === item.caseId ? (
                  <form className="caseRenameForm" onSubmit={(event) => {
                    event.preventDefault();
                    void renameCase(item.caseId);
                  }}>
                    <input value={renameDraft} autoFocus onChange={(event) => setRenameDraft(event.target.value)} onKeyDown={(event) => {
                      if (event.key === "Escape") setRenamingCaseId("");
                    }} />
                    <button type="submit">保存</button>
                  </form>
                ) : (
                  <>
                    <button className="sessionOpenButton" onClick={() => openCase(item.caseId)}>
                      <span className="caseTitle">{pinnedCaseIds.includes(item.caseId) ? "置顶 · " : ""}{item.title}</span>
                      <span className="caseMeta">{item.captureCount} 文件 · {item.rawPacketCount || item.packetCount} 包 · {item.runCount} 查询</span>
                      <span className="caseTime">{formatPacketTime(item.updatedAt)}</span>
                    </button>
                    <button className="caseMoreButton" onClick={(event) => {
                      event.stopPropagation();
                      setCaseMenuId((id) => id === item.caseId ? "" : item.caseId);
                    }} aria-label="会话操作">
                      <MoreHorizontal size={16} />
                    </button>
                    {caseMenuId === item.caseId && (
                      <div className="caseActionMenu">
                        <button onClick={() => {
                          setRenameDraft(item.title);
                          setRenamingCaseId(item.caseId);
                          setCaseMenuId("");
                        }}><Pencil size={14} /> 重命名</button>
                        <button onClick={() => togglePinnedCase(item.caseId)}>
                          {pinnedCaseIds.includes(item.caseId) ? <PinOff size={14} /> : <Pin size={14} />}
                          {pinnedCaseIds.includes(item.caseId) ? "取消置顶" : "置顶"}
                        </button>
                        <button className="dangerAction" onClick={() => void deleteCaseFromSidebar(item.caseId)}><Trash2 size={14} /> 删除</button>
                      </div>
                    )}
                  </>
                )}
              </article>
            ))}
            {!displayedCaseHistory.length && <div className="empty">暂无历史案例。</div>}
          </section>

          <div className="sidebarFooter">
            <button className={`settingsMenuButton ${page !== "workbench" || settingsMenuOpen ? "active" : ""}`} onClick={() => setSettingsMenuOpen((open) => !open)}><Settings size={16} /> 设置</button>
            {settingsMenuOpen && (
              <div className="settingsMenu">
                <button onClick={() => openSettingsMenuPage("history")}><History size={15} /> 历史案例</button>
                <button onClick={() => openSettingsMenuPage("settings")}><Cpu size={15} /> 模型配置</button>
                <button onClick={() => openSettingsMenuPage("help")}><BookOpen size={15} /> 帮助</button>
                <button onClick={() => {
                  setTheme(theme === "dark" ? "light" : "dark");
                  setSettingsMenuOpen(false);
                }}>
                  {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />} {theme === "dark" ? "亮色主题" : "暗色主题"}
                </button>
              </div>
            )}
          </div>
        </aside>

        <section className={`appContent ${page === "workbench" ? "workbenchContent" : "pageContent"}`}>
      {page === "help" ? (
        <section className="helpPage">
          <section className="helpHero">
            <span>Agent-first pcap 排障工作流</span>
            <h2>从聊天上传数据包，到查询通信，再点证据进 Wireshark。</h2>
            <p>PcapAI 适合围绕一次访问链路排障。用户在聊天里上传 pcap 并提出问题，Agent 通过 tshark-query 获取事实，再用证据卡片把通信、包和过滤器返回给你。</p>
          </section>

          <section className="helpGrid">
            <article>
              <strong>1. 新建会话</strong>
              <p>点击左侧新建会话会立即创建一个空 case，后续所有上传、查询和证据都围绕这个会话展开。</p>
            </article>
            <article>
              <strong>2. 在聊天中上传 pcap</strong>
              <p>可以选择、拖拽或粘贴 pcap、pcapng、cap 文件。上传后系统裁剪 payload，并自动生成最小节点信息。</p>
            </article>
            <article>
              <strong>3. Agent 追问上下文</strong>
              <p>只上传文件时，Agent 会返回抓包时间范围，并追问节点角色、抓包位置、方向、故障时间、源、目的和端口。</p>
            </article>
            <article>
              <strong>4. 创建 QueryRun</strong>
              <p>条件足够时，Agent 调用 tshark-query 构造 display filter，列出候选访问链路和关键包证据。</p>
            </article>
            <article>
              <strong>5. 打开证据</strong>
              <p>点击 conversation、packet 或 time range 证据卡片，会通过 evidence-opener 用对应过滤器打开本地 Wireshark。</p>
            </article>
            <article>
              <strong>6. 多节点链路</strong>
              <p>首版按同一五元组和时间重叠做确定性关联；遇到 NAT、F5、SSL 卸载或代理时，Agent 会追问映射线索。</p>
            </article>
            <article>
              <strong>7. 配置大模型</strong>
              <p>在配置页填写 OpenAI 兼容 Base URL、API Key 和模型名。可以保存多个配置档案并测试连通性。</p>
            </article>
            <article>
              <strong>8. 询问 Agent</strong>
              <p>Leader Agent 只解释 case graph、QueryRun 和 evidence card，不直接读取原始 pcap，也不绕过 MCP 自行判断包级事实。</p>
            </article>
          </section>

          <section className="helpPanel">
            <h2>推荐排障顺序</h2>
            <ol>
              <li>先确认每个抓包节点的角色和位置是否正确。</li>
              <li>再确认筛选条件是否命中目标访问流量。</li>
              <li>如果路径断裂，优先补 NAT/SLB/代理线索和时间偏移。</li>
              <li>最后再让 Agent 解释 finding，避免让模型替代证据判断。</li>
            </ol>
          </section>
        </section>
      ) : page === "history" ? (
        <section className="historyPage">
          <section className="historyToolbar">
            <div>
              <h2>历史案例管理</h2>
              <p>这里集中处理历史案例的批量选择和删除。左侧边栏只用于快速进入案例。</p>
            </div>
            <div className="bulkActions">
              <button onClick={() => setSelectedCaseIds(caseHistory.map((item) => item.caseId))} disabled={!caseHistory.length}>全选</button>
              <button onClick={() => setSelectedCaseIds([])} disabled={!selectedCaseIds.length}>清空</button>
              <button className="danger" onClick={deleteSelectedCases} disabled={!selectedCaseIds.length}>
                <Trash2 size={16} /> 删除
              </button>
            </div>
          </section>
          <section className="historyGrid">
            {caseHistory.map((item) => (
              <article className="historyCard" key={item.caseId}>
                <input type="checkbox" checked={selectedCaseIds.includes(item.caseId)} onChange={() => toggleCaseSelection(item.caseId)} aria-label={`选择 ${item.title}`} />
                <button onClick={() => openCase(item.caseId)}>
                  <strong>{item.title}</strong>
                  <span>{item.captureCount} 节点 / {item.rawPacketCount} 捕获包 / {item.packetCount} 样本包</span>
                  <small>{item.runCount} 个分析版本 / {item.findingCount} 条判断</small>
                </button>
              </article>
            ))}
            {!caseHistory.length && <div className="empty">暂无历史案例。</div>}
          </section>
        </section>
      ) : page === "settings" ? (
        <section className="settingsPage">
          <section className="settingsPanel">
            <h2>添加 LLM</h2>
            {llmRuntime && (
              <dl className="runtimeSummary">
                <dt>当前模型</dt>
                <dd>{llmRuntime.settings.model || "-"}</dd>
                <dt>配置档案</dt>
                <dd>{llmRuntime.settings.activeProfileId || "手工配置"}</dd>
                <dt>Key 状态</dt>
                <dd>{llmRuntime.settings.hasKey ? "已配置" : "未配置"}</dd>
                <dt>调用模式</dt>
                <dd>{llmRuntime.useResponses ? "Responses API" : "Chat Completions"}</dd>
              </dl>
            )}
            <div className="savedConfigCard">
              <div>
                <strong>当前已保存配置</strong>
                <span>{llmForm.baseURL || "-"} / {llmForm.model || "-"} / {llmRuntime?.settings.hasKey ? "已保存 Key" : "未保存 Key"}</span>
              </div>
              <button onClick={() => { void loadLlmSettings(); void loadLlmProfiles(); void loadLlmRuntime(); }}>
                查询配置
              </button>
            </div>
            <div className="form">
              <label>
                <span>Base URL</span>
                <input value={llmForm.baseURL} onChange={(event) => setLlmForm({ ...llmForm, baseURL: event.target.value })} placeholder="OpenAI 兼容 Base URL" />
              </label>
              <label>
                <span>模型名称</span>
                <input value={llmForm.model} onChange={(event) => setLlmForm({ ...llmForm, model: event.target.value })} placeholder="模型名称" />
              </label>
              <label>
                <span>兼容参数 JSON</span>
                <textarea
                  rows={3}
                  value={llmForm.providerData}
                  onChange={(event) => setLlmForm({ ...llmForm, providerData: event.target.value })}
                  placeholder='例如 DeepSeek V4 Flash: {"thinking":{"type":"disabled"}}'
                />
              </label>
              <label>
                <span>API Key</span>
                <div className="secretInput">
                  <input type={showLlmApiKey ? "text" : "password"} value={llmForm.apiKey} onChange={(event) => setLlmForm({ ...llmForm, apiKey: event.target.value })} placeholder="已有同名档案可留空；新增配置请填写 Key" />
                  <button type="button" onClick={() => setShowLlmApiKey((visible) => !visible)} title={showLlmApiKey ? "隐藏 API Key" : "显示 API Key"} aria-label={showLlmApiKey ? "隐藏 API Key" : "显示 API Key"}>
                    {showLlmApiKey ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
              </label>
              <button className="primary" onClick={saveLlmSettings} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
                <Save size={16} /> 保存配置
              </button>
              <button onClick={testLlmSettings} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
                测试配置
              </button>
              <button onClick={testAgentCompatibility} disabled={!llmForm.baseURL.trim() || !llmForm.model.trim()}>
                Agent 兼容测试
              </button>
              <span className="status">{llmStatus}</span>
              <p className="formHint">本地 Ollama 作为普通 OpenAI 兼容配置添加：Base URL 填本地 /v1 地址，模型名填已安装模型，API Key 按你的服务配置填写；常见本地默认可填 ollama。</p>
            </div>
          </section>

          <section className="settingsPanel llmListPanel">
            <h2>LLM 列表</h2>
            <div className="bulkActions">
              <button onClick={() => setSelectedProfileIds(llmProfiles.map((profile) => profile.profileId))} disabled={!llmProfiles.length}>全选</button>
              <button onClick={() => setSelectedProfileIds([])} disabled={!selectedProfileIds.length}>清空</button>
              <button className="danger" onClick={deleteSelectedProfiles} disabled={!selectedProfileIds.length}>
                <Trash2 size={16} /> 删除
              </button>
            </div>

            <div className="profileList">
              {llmProfiles.map((profile) => (
                <article className="profileItem" key={profile.profileId}>
                  <input type="checkbox" checked={selectedProfileIds.includes(profile.profileId)} onChange={() => toggleProfileSelection(profile.profileId)} aria-label={`选择 ${profile.name}`} />
                  <div>
                    <strong>{profile.name}</strong>
                    <span>{profile.baseURL} / {profile.model} / {profile.hasKey ? "已保存 Key" : "未保存 Key"}{profile.providerData ? " / 有兼容参数" : ""}{profile.active ? " / 当前启用" : ""}</span>
                  </div>
                  <button onClick={() => editLlmProfile(profile)} title="编辑配置档案"><Pencil size={16} /></button>
                  <button onClick={() => activateProfile(profile.profileId)} disabled={profile.active} title="启用配置档案"><CheckCircle size={16} /></button>
                </article>
              ))}
              {!llmProfiles.length && <div className="empty">暂无模型配置档案。</div>}
            </div>
          </section>
        </section>
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

            <div className="chatMessages" ref={chatMessagesRef}>
              {chatMessages.length ? chatMessages.map((message) => (
                <article className={`chatBubble ${message.role === "user" ? "userBubble" : "assistantBubble"}`} key={message.id}>
                  <div className="chatBubbleHeader">
                    <strong>{message.role === "user" ? "你" : "Agent"}{message.streaming ? " 正在输出..." : ""}</strong>
                    <button className="copyButton" onClick={() => copyMessage(message)} type="button">
                      <Copy size={14} />
                      {copiedMessageId === message.id ? "已复制" : "复制"}
                    </button>
                  </div>
                  {message.thoughts?.length ? (
                    <details className="thoughtBox" open>
                      <summary>执行轨迹</summary>
                      <ol>{message.thoughts.map((thought, index) => <li key={`${message.id}-thought-${index}`}>{thought}</li>)}</ol>
                    </details>
                  ) : null}
                  {message.role === "assistant" && message.stepEvidence && Object.keys(message.stepEvidence).length ? (
                    <div className="stepEvidenceLinks">
                      {Object.entries(message.stepEvidence).map(([idx, step]) => step.evidenceCards.length ? (
                        <div key={`${message.id}-se-${idx}`} className="stepEvidenceLink">
                          <span className="stepEvidenceLabel">步骤 {Number(idx) + 1}：{step.purpose}</span>
                          <button type="button" onClick={() => openEvidenceDetail(message, graph?.spec.caseId || "", Number(idx))}>
                            {step.evidenceCards.length} 张卡片
                          </button>
                        </div>
                      ) : null)}
                    </div>
                  ) : null}
                  {message.role === "assistant" && !message.streaming && message.content ? (
                    <div className="markdownBody" dangerouslySetInnerHTML={{ __html: renderMarkdown(message.content) }} />
                  ) : (
                    <p>{message.content || (message.streaming ? "等待模型返回..." : "")}</p>
                  )}
	                  {message.role === "assistant" && !message.streaming && message.evidenceCards?.length ? (
	                    <div className="evidenceRefLink">
	                      <button type="button" onClick={() => openEvidenceDetail(message, graph?.spec.caseId || "")}>
	                        查看证据详情（{message.evidenceCards.length} 张卡片）
	                      </button>
	                    </div>
	                  ) : null}
	                  {message.role === "assistant" && !message.streaming && message.hypotheses?.length ? (
	                    <div className="hypothesesPanel">
	                      <div className="hypothesesTitle">假设验证进度</div>
	                      {message.hypotheses.map((h, index) => (
	                        <div key={`${message.id}-h-${index}`} className={`hypothesisItem hypothesis-${h.status}`}>
	                          <span className="hypothesisStatus">{h.status === "confirmed" ? "✓" : h.status === "ruled_out" ? "✗" : h.status === "testing" ? "◎" : "○"}</span>
	                          <span className="hypothesisDesc">{h.description}</span>
	                        </div>
	                      ))}
	                    </div>
	                  ) : null}
	                  {message.role === "assistant" && !message.streaming && message.followUpQuestions?.length ? (
	                    <div className="followUpQuestions">
	                      <div className="followUpTitle">你可以回答：</div>
	                      {message.followUpQuestions.map((q, index) => (
	                        <button type="button" className="followUpButton" key={`${message.id}-fq-${index}`} onClick={() => { setQuestion(q); }}>{q}</button>
	                      ))}
	                    </div>
	                  ) : null}
                  {message.suggestedQueries?.length ? (
                    <div className="suggestedQueries">
                      {message.suggestedQueries.map((sq, index) => (
                        <button type="button" className="suggestedQuery" key={`${message.id}-sq-${index}`} title={sq.reason} onClick={() => { setQuestion(sq.question); }}>{sq.question}</button>
                      ))}
                    </div>
                  ) : null}
                </article>
              )) : (
                <article className="chatBubble assistantBubble">
                  <strong>Agent</strong>
                  <p>Agent 只读取当前 case graph，不直接解析 pcap。选择模型和深度后，可以直接询问当前访问链路的问题。</p>
                </article>
              )}
              {llmRuntime?.agent.lastError ? (
                <article className="chatBubble errorBubble">
                  <strong>最近错误</strong>
                  <p>{llmRuntime.agent.lastError}</p>
                </article>
              ) : null}
            </div>

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
                value={question}
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" && !event.shiftKey) {
                    event.preventDefault();
                    void ask();
                  }
                }}
                placeholder="描述故障时间、源地址、目的地址、端口，或直接拖入 pcap"
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
                <button className="composerSendButton" onClick={ask} disabled={!question.trim() && !composerFiles.length} title="发送">
                  <ArrowUp size={22} />
                </button>
              </div>
            </div>
          </section>
        </section>

        <aside className="insightDock panel">
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

          <section className="toolTracePanel">
            <button
              type="button"
              className="toolTraceToggle"
              onClick={() => setToolTraceOpen((value) => !value)}
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
                    onClick={() => void openToolRun(run)}
                    title={toolRunDetail(run) || run.summary}
                  >
                    <div className="toolTraceRowMain">
                      <strong>{toolRunTitle(run)}</strong>
                      <p>{run.summary}</p>
                    </div>
                    <span className={`toolTraceStatus ${run.status}`}>{toolRunStatusLabel(run.status)}</span>
                  </button>
                ))}
              </div>
            ) : toolTraceOpen ? <div className="empty">尚无持久化执行轨迹。</div> : null}
          </section>

          <section className="insightsPanel">
            <button
              type="button"
              className="toolTraceToggle"
              onClick={() => setInsightsOpen((value) => !value)}
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
                  return <>
                    {critical ? <span className="statusBadge error">{critical}</span> : null}
                    {warning ? <span className="statusBadge warn">{warning}</span> : null}
                    {!critical && !warning ? <span className="statusBadge neutral">{graph?.insights?.length || 0}</span> : null}
                  </>;
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

          {selectedEvidenceCard ? (
            <section className="evidenceContextPanel">
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
                    <span>{packetMarkers(selectedEvidencePacket).join("，") || selectedEvidencePacket.protocol.toUpperCase()}</span>
                  </div>
                ) : null}
                <div className="evidenceContextActions">
                  {selectedEvidenceCard.pcapFilename && (selectedEvidenceCard.displayFilter || selectedEvidenceCard.frameNumber) ? <button type="button" onClick={() => void openEvidenceCard(selectedEvidenceCard)}>Wireshark</button> : null}
                  {selectedEvidenceCard.displayFilter || selectedEvidenceCard.packetDisplayFilter ? <button type="button" onClick={() => void copyEvidenceFilter(selectedEvidenceCard)}>复制过滤器</button> : null}
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
                      <button type="button" onClick={() => void openProtocolCorrelation(correlation)}>Wireshark</button>
                      <button type="button" onClick={() => void copyProtocolCorrelationFilter(correlation)}>复制过滤器</button>
                    </div>
                  </article>
                ))}
              </div>
            </section>
          ) : null}

          <section className="conversationPanel">
            <div className="panelTitleRow">
              <h2>候选访问链路</h2>
              <button onClick={openSelectedInWireshark} disabled={!selectedConversation}>打开 Wireshark</button>
            </div>
            {activeCandidateGroups.length ? (
              <div className="accessGroupList">
                {activeCandidateGroups.map((group) => (
                  <button
                    className={group.groupId === selectedCandidateGroup?.groupId ? "active" : ""}
                    key={group.groupId}
                    onClick={() => setSelectedCandidateGroupId(group.groupId)}
                  >
                    <div className="accessGroupHeader">
                      <strong>{group.srcIp || "*"}{" -> "}{group.dstIp || "*"}:{group.dstPort ?? "*"}</strong>
                      <span className={`statusBadge ${groupState(group).className}`}>{groupState(group).label}</span>
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
                onChange={(event) => setConversationSearch(event.target.value)}
                placeholder="搜索 IP、端口、节点"
              />
              <select value={conversationSort} onChange={(event) => setConversationSort(event.target.value as typeof conversationSort)}>
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
                  const state = conversationState(conversation);
                  return (
                    <button
                      className={conversation.conversationId === activeQueryRun.selectedConversationId ? "active" : ""}
                      onClick={() => selectConversation(activeQueryRun.queryRunId, conversation.conversationId)}
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
            <section className="selectedConversationPanel">
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
                        const state = diagnosisCheckState(check.status);
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
                                    <button key={packetId} type="button" onClick={() => void openDiagnosisPacket(packetId)}>
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
                      {selectedDiagnosis.diagnosticTags.map((tag) => (
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
                        <span>{packetMarkers(packet).join("，") || packet.protocol.toUpperCase()}</span>
                        <small>{formatPacketTime(packet.timestamp)}</small>
                      </article>
                    ))}
                  </div>
                ) : conversationPacketsStatus ? null : <div className="empty">暂无关键包。</div>}
              </div>
            </section>
          )}

          <section className="caseStatusBar">
            <h3 className="metricGroupTitle">基础统计</h3>
            <article>
              <span>抓包节点</span>
              <strong>{graph?.captures.length || 0}</strong>
            </article>
            <article>
              <span>捕获包</span>
              <strong>{capturePacketTotal(graph)}</strong>
            </article>
            <article>
              <span>筛选包</span>
              <strong>{graph?.packets.length || 0}</strong>
            </article>
            <article>
              <span>TCP 通信对</span>
              <strong>{tcpCommunicationPairCount}</strong>
            </article>
            <article>
              <span>TCP 会话片段</span>
              <strong>{tcpConnectionCount}</strong>
            </article>
            <article>
              <span>TCP 包</span>
              <strong>{tcpPackets.length}</strong>
            </article>
            <article>
              <span>跨节点关联</span>
              <strong>{graph?.sessionLinks.length || 0}</strong>
            </article>
            <article>
              <span>判断</span>
              <strong>{graph?.findings.length || 0}</strong>
            </article>
            <article className="metricWide">
              <span>当前筛选时间区间</span>
              <b>{timeRange}</b>
            </article>
            <h3 className="metricGroupTitle">包级统计</h3>
            <article>
              <span>RST 包</span>
              <strong>{packetCountByFlag("RST")}</strong>
            </article>
            <article>
              <span>重传包</span>
              <strong>{retransmissionPacketCount}</strong>
            </article>
            <article>
              <span>Dup ACK 包</span>
              <strong>{duplicateAckPacketCount}</strong>
            </article>
            <article>
              <span>Zero Window 包</span>
              <strong>{zeroWindowPacketCount}</strong>
            </article>
          </section>

          <section className="evidenceDeck">
            <h2>明细数据</h2>
            <div className="detailLaunchGrid">
              <button onClick={() => setDetailView("path")}>
                <strong>访问路径</strong>
                <span>{graph?.path.nodes.length || 0} 个节点</span>
              </button>
              <button onClick={() => setDetailView("findings")}>
                <strong>判断结果</strong>
                <span>{graph?.findings.length || 0} 条 finding</span>
              </button>
              <button onClick={() => setDetailView("sessions")}>
                <strong>会话片段</strong>
                <span>{graph?.sessions.length || 0} 个片段</span>
              </button>
              <button onClick={() => setDetailView("links")}>
                <strong>跨节点关联</strong>
                <span>{graph?.sessionLinks.length || 0} 条关联</span>
              </button>
              <button onClick={() => setDetailView("packets")}>
                <strong>数据包</strong>
                <span>{graph?.packets.length || 0} 个包</span>
              </button>
              <button onClick={() => setDetailView("events")}>
                <strong>关键事件</strong>
                <span>{graph?.evidence.length || 0} 条证据</span>
              </button>
              <button onClick={() => setDetailView("tcp_stream")}>
                <strong>TCP 流</strong>
                <span>查看完整 TCP 会话</span>
              </button>
              <button onClick={() => setDetailView("topology")}>
                <strong>网络拓扑</strong>
                <span>{graph?.networkTopology?.devices?.length || 0} 个设备</span>
              </button>
            </div>
          </section>

          <section className="reportPanel">
            <h2>报告</h2>
            <div className="mappingActions">
              <button className="primary" onClick={exportReport} disabled={!graph}>生成报告</button>
              <button onClick={copyReport} disabled={!report}>复制报告</button>
            </div>
            <pre>{report || "报告基于当前 QueryRun、当前证据卡、选中 session 和 checks 生成，不调用大模型。"}</pre>
          </section>
        </aside>
      </section>
      )}
        </section>
      </section>
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
