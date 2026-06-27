// 领域模型类型（从 main.tsx 抽离，定义保持不变）

export type PacketSummary = {
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

export type CaseGraph = {
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

export type PacketInsight = {
  insightId: string;
  type: "connection_lifecycle" | "ack_gap" | "tcp_timing" | "tcp_window_trend" | "tcp_rst_direction" | "tcp_handshake_retry" | "tcp_delayed_ack" | "tcp_connection_flood" | "tcp_segment_anomaly" | "tcp_keepalive" | "tcp_throughput" | "tcp_options" | "http_status_chain" | "http_header_anomaly" | "http_timing" | "icmp_echo_pair" | "icmp_unreachable" | "icmp_mtu" | "icmp_redirect" | "cross_protocol_chain" | "tls_handshake" | "dns_anomaly" | "udp_anomaly" | "udp_flow" | "quic_anomaly" | "ntp_anomaly" | "ssh_anomaly";
  severity: "info" | "warning" | "critical";
  packetIds: string[];
  description: string;
  detail: Record<string, unknown>;
  scenario?: string;
};

export type Conversation = {
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

export type QueryDiagnosis = {
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

export type EvidenceCard = {
  cardId: string;
  kind: "capture" | "time_range" | "conversation" | "packet" | "protocol_event" | "transaction" | "filter" | "statistic" | "missing_context";
  title: string;
  summary: string;
  pcapFilename?: string;
  frameNumber?: number;
  displayFilter?: string;
  packetDisplayFilter?: string;
  coverage?: string;
  reviewQuery?: string;
  reviewNotes?: string[];
  conversationId?: string;
  queryRunId?: string;
  actions: Array<"open_wireshark" | "select_conversation" | "query_packets" | "request_upload" | "copy_filter">;
};

export type ProtocolCorrelation = {
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

export type AccessCandidateGroup = {
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

export type QueryPath = {
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

export type QueryRun = {
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

export type AnalysisRun = {
  runId: string;
  createdAt: string;
  kind: "capture_update" | "parse" | "analysis";
  summary: string;
  captureCount: number;
  rawPacketCount: number;
  packetCount: number;
  findingCount: number;
};

export type ToolRun = {
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

export type MappingHint = {
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

export type TimeOffsetHint = {
  hintId: string;
  fromNodeId?: string;
  toNodeId?: string;
  offsetSeconds: number;
  note: string;
};

export type DiagnosticTag = {
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

export type CaseSummary = {
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

export type LlmProfile = {
  profileId: string;
  name: string;
  baseURL: string;
  model: string;
  thinkingDepth: string;
  reasoningDepth: string;
  temperature: string;
  maxTokens: string;
  hasKey: boolean;
  active: boolean;
};

export type LlmRuntimeStatus = {
  settings: {
    baseURL: string;
    model: string;
    thinkingDepth: string;
    reasoningDepth: string;
    temperature: string;
    maxTokens: string;
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

export type McpServerInfo = {
  id: string;
  name: string;
  description: string;
  toolCount: number;
  kind: string;
};

export type CaptureDraft = {
  file: File;
  nodeId: string;
  name: string;
  role: string;
  interfaceDirection: "unknown" | "ingress" | "egress" | "bidirectional";
  capturePosition: string;
};

export type DetailView = "path" | "findings" | "sessions" | "links" | "packets" | "events" | "topology" | "tcp_stream";
export type DiagnosticHypothesis = {
  id: string;
  description: string;
  status: "pending" | "testing" | "confirmed" | "ruled_out";
  evidenceFor: string[];
  evidenceAgainst: string[];
};

/**
 * 根因条目（阶段 2 数据契约补全）。区分"RFC 验证结论"与"经验推测"，
 * 右栏诊断档案 Tab 据此用 verified / speculative 颜色分层（防幻觉边界）。
 */
export type RootCauseEntry = {
  id: string;
  description: string;
  confidence: "certain" | "high" | "low" | "needs_context";
  /** 是否经 RFC 章节验证（false = 推测，需在卡片上明确标注） */
  rfcVerified: boolean;
  rfcSection?: string;
  evidenceCardIds: string[];
  packetIds: string[];
};

export type ChatMessage = {
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
  /**
   * 根因列表（阶段 2 数据契约补全）。每条带 rfcVerified 区分"RFC 验证结论"与"经验推测"，
   * 右栏诊断档案 Tab 据此用 verified / speculative 颜色分层（防幻觉边界）。
   */
  rootCauses?: RootCauseEntry[];
  /** 本轮 Agent 运行的 token 消耗（运行结束后聚合）。确定性 adapter 无此字段。 */
  usage?: { inputTokens: number; outputTokens: number; totalTokens: number; model?: string };
};
