import { z } from "zod";

export const ConfidenceSchema = z.enum(["certain", "high", "low", "needs_context"]);
export type Confidence = z.infer<typeof ConfidenceSchema>;

export const CaseSpecSchema = z.object({
  caseId: z.string(),
  title: z.string(),
  client: z.string().optional(),
  server: z.string().optional(),
  protocol: z.string().default("tcp"),
  port: z.number().int().optional()
});
export type CaseSpec = z.infer<typeof CaseSpecSchema>;

export const AnalysisFilterSchema = z.object({
  client: z.string().optional(),
  server: z.string().optional(),
  protocol: z.string().optional(),
  port: z.number().int().optional()
});
export type AnalysisFilter = z.infer<typeof AnalysisFilterSchema>;

export const CaptureNodeSchema = z.object({
  nodeId: z.string(),
  name: z.string(),
  role: z.string(),
  pcapFilename: z.string().optional(),
  interfaceDirection: z.enum(["ingress", "egress", "bidirectional", "unknown"]).default("unknown"),
  capturePosition: z.string().default(""),
  packetCount: z.number().int().optional(),
  firstPacketTime: z.number().optional(),
  lastPacketTime: z.number().optional()
});
export type CaptureNode = z.infer<typeof CaptureNodeSchema>;

export const MappingHintSchema = z.object({
  hintId: z.string(),
  kind: z.enum(["nat", "slb", "proxy", "gateway", "tunnel"]),
  fromNodeId: z.string().optional(),
  toNodeId: z.string().optional(),
  originalSrcIp: z.string().optional(),
  originalSrcPort: z.number().int().optional(),
  originalDstIp: z.string().optional(),
  originalDstPort: z.number().int().optional(),
  translatedSrcIp: z.string().optional(),
  translatedSrcPort: z.number().int().optional(),
  translatedDstIp: z.string().optional(),
  translatedDstPort: z.number().int().optional(),
  note: z.string().default("")
});
export type MappingHint = z.infer<typeof MappingHintSchema>;

export const TimeOffsetHintSchema = z.object({
  hintId: z.string(),
  fromNodeId: z.string().optional(),
  toNodeId: z.string().optional(),
  offsetSeconds: z.number(),
  note: z.string().default("")
});
export type TimeOffsetHint = z.infer<typeof TimeOffsetHintSchema>;

export const PacketSummarySchema = z.object({
  packetId: z.string(),
  nodeId: z.string(),
  pcapFilename: z.string(),
  frameNumber: z.number().int(),
  timestamp: z.number(),
  srcIp: z.string().optional(),
  srcPort: z.number().int().optional(),
  dstIp: z.string().optional(),
  dstPort: z.number().int().optional(),
  protocol: z.string(),
  tcpFlags: z.array(z.string()).default([]),
  tcpSeq: z.number().int().optional(),
  tcpAck: z.number().int().optional(),
  tcpPayloadLength: z.number().int().optional(),
  tcpWindowSize: z.number().int().optional(),
  tcpAnalysis: z.object({
    retransmission: z.boolean().default(false),
    fastRetransmission: z.boolean().default(false),
    duplicateAck: z.boolean().default(false),
    zeroWindow: z.boolean().default(false),
    lostSegment: z.boolean().default(false)
  }).default({
    retransmission: false,
    fastRetransmission: false,
    duplicateAck: false,
    zeroWindow: false,
    lostSegment: false
  }),
  icmpType: z.number().int().optional(),
  icmpCode: z.number().int().optional(),
  dnsId: z.string().optional(),
  dnsQueryName: z.string().optional(),
  dnsIsResponse: z.boolean().optional(),
  dnsRcode: z.number().int().optional(),
  dnsResponseAddress: z.string().optional(),
  tlsHandshakeType: z.number().int().optional(),
  tlsSni: z.string().optional(),
  tlsRecordVersion: z.string().optional(),
  tlsHandshakeVersion: z.string().optional(),
  tlsAlertLevel: z.number().int().optional(),
  tlsAlertDescription: z.number().int().optional(),
  httpRequestMethod: z.string().optional(),
  httpHost: z.string().optional(),
  httpRequestUri: z.string().optional(),
  httpResponseCode: z.number().int().optional(),
  httpResponseCodeDescription: z.string().optional(),
  httpRequestIn: z.number().int().optional(),
  httpResponseIn: z.number().int().optional(),
  httpTime: z.number().optional(),
  httpCookie: z.string().optional(),
  httpSetCookie: z.string().optional(),
  httpXForwardedFor: z.string().optional(),
  httpContentType: z.string().optional(),
  httpContentLength: z.number().int().optional(),
  httpConnection: z.string().optional(),
  httpTransferEncoding: z.string().optional(),
  httpAuthorization: z.boolean().optional(),
  httpWwwAuthenticate: z.boolean().optional(),
  httpVia: z.string().optional(),
  httpUpgrade: z.string().optional(),
  httpAcceptEncoding: z.string().optional(),
  httpContentEncoding: z.string().optional(),
  httpCacheControl: z.string().optional(),
  tlsCipherSuite: z.string().optional(),
  tlsCertDnsName: z.string().optional(),
  tlsSessionId: z.string().optional(),
  tlsAlpnProtocol: z.string().optional(),
  tlsSessionTicket: z.string().optional(),
  dnsQueryType: z.number().int().optional(),
  dnsTtl: z.number().int().optional(),
  dnsCname: z.string().optional(),
  dnsTruncated: z.boolean().optional(),
  dnsAnswerCount: z.number().int().optional(),
  icmpIdent: z.number().int().optional(),
  icmpSeq: z.number().int().optional(),
  icmpMtuNextHop: z.number().int().optional(),
  ipDf: z.boolean().optional(),
  udpLength: z.number().int().optional(),
  quicVersion: z.string().optional(),
  quicConnectionId: z.string().optional(),
  quicPacketType: z.string().optional(),
  quicFrameType: z.string().optional(),
  ntpRefid: z.string().optional(),
  ntpStratum: z.number().int().optional(),
  ntpRootdelay: z.number().optional(),
  ntpXmt: z.number().optional(),
  ntpOrg: z.number().optional(),
  sshMessage: z.string().optional(),
  sshDirection: z.string().optional(),
  sshProtocol: z.string().optional(),
  length: z.number().int().optional(),
  summary: z.string(),
  raw: z.record(z.string(), z.unknown()).default({})
});
export type PacketSummary = z.infer<typeof PacketSummarySchema>;

export const EvidenceEventSchema = z.object({
  evidenceId: z.string(),
  kind: z.string(),
  title: z.string(),
  nodeId: z.string().optional(),
  packetIds: z.array(z.string()).default([]),
  detail: z.string(),
  confidence: ConfidenceSchema
});
export type EvidenceEvent = z.infer<typeof EvidenceEventSchema>;

export const SessionSegmentSchema = z.object({
  segmentId: z.string(),
  nodeId: z.string(),
  pcapFilename: z.string().optional(),
  protocol: z.string(),
  clientIp: z.string().optional(),
  clientPort: z.number().int().optional(),
  serverIp: z.string().optional(),
  serverPort: z.number().int().optional(),
  startTime: z.number(),
  endTime: z.number(),
  packetIds: z.array(z.string()).default([]),
  eventKinds: z.array(z.string()).default([]),
  summary: z.string(),
  confidence: ConfidenceSchema
});
export type SessionSegment = z.infer<typeof SessionSegmentSchema>;

export const SessionLinkSchema = z.object({
  linkId: z.string(),
  fromSegmentId: z.string(),
  toSegmentId: z.string(),
  fromNodeId: z.string(),
  toNodeId: z.string(),
  matchReasons: z.array(z.string()).default([]),
  counterEvidence: z.array(z.string()).default([]),
  confidence: ConfidenceSchema,
  score: z.number()
});
export type SessionLink = z.infer<typeof SessionLinkSchema>;

export const FindingSchema = z.object({
  findingId: z.string(),
  title: z.string(),
  summary: z.string(),
  tagIds: z.array(z.string()).default([]),
  evidenceIds: z.array(z.string()).default([]),
  packetIds: z.array(z.string()).default([]),
  confidence: ConfidenceSchema,
  nextSteps: z.array(z.string()).default([])
});
export type Finding = z.infer<typeof FindingSchema>;

export const DiagnosticTagKindSchema = z.enum([
  "syn_sent_no_synack",
  "syn_seen_at_a_missing_at_b",
  "synack_seen_at_server_missing_on_return_path",
  "rst_first_seen_at_node",
  "one_way_traffic",
  "retransmission_burst",
  "dup_ack_burst",
  "zero_window",
  "fin_without_peer_fin_ack",
  "session_seen_on_one_node_only",
  "nat_mapping_required_but_missing",
  "time_window_not_overlapped"
]);
export type DiagnosticTagKind = z.infer<typeof DiagnosticTagKindSchema>;

export const DiagnosticTagSchema = z.object({
  tagId: z.string(),
  kind: DiagnosticTagKindSchema,
  nodeIds: z.array(z.string()).default([]),
  segmentIds: z.array(z.string()).default([]),
  packetIds: z.array(z.string()).default([]),
  evidenceIds: z.array(z.string()).default([]),
  confidence: ConfidenceSchema,
  summary: z.string(),
  nextSteps: z.array(z.string()).default([])
});
export type DiagnosticTag = z.infer<typeof DiagnosticTagSchema>;

export const PathGraphSchema = z.object({
  nodes: z.array(z.object({
    nodeId: z.string(),
    label: z.string(),
    role: z.string(),
    status: z.enum(["observed", "missing", "unknown"])
  })).default([]),
  edges: z.array(z.object({
    edgeId: z.string(),
    fromNodeId: z.string(),
    toNodeId: z.string(),
    status: z.enum(["observed", "suspect", "unknown"]),
    label: z.string()
  })).default([])
});
export type PathGraph = z.infer<typeof PathGraphSchema>;

export const QueryRunInputSchema = z.object({
  question: z.string().default(""),
  timeRange: z.object({
    start: z.number().optional(),
    end: z.number().optional()
  }).default({}),
  srcIp: z.string().optional(),
  dstIp: z.string().optional(),
  port: z.number().int().optional(),
  protocol: z.string().optional()
});
export type QueryRunInput = z.infer<typeof QueryRunInputSchema>;

export const ConversationSchema = z.object({
  conversationId: z.string(),
  nodeId: z.string(),
  pcapFilename: z.string(),
  protocol: z.string(),
  srcIp: z.string().optional(),
  srcPort: z.number().int().optional(),
  dstIp: z.string().optional(),
  dstPort: z.number().int().optional(),
  startTime: z.number(),
  endTime: z.number(),
  packetCount: z.number().int(),
  byteCount: z.number().int(),
  tcpFlags: z.array(z.string()).default([]),
  rstCount: z.number().int().default(0),
  retransmissionCount: z.number().int().default(0),
  zeroWindowCount: z.number().int().default(0),
  rankScore: z.number().default(0),
  rankReasons: z.array(z.string()).default([]),
  displayFilter: z.string()
});
export type Conversation = z.infer<typeof ConversationSchema>;

export const AccessCandidateGroupSchema = z.object({
  groupId: z.string(),
  protocol: z.string(),
  srcIp: z.string().optional(),
  dstIp: z.string().optional(),
  dstPort: z.number().int().optional(),
  conversationIds: z.array(z.string()).default([]),
  selectedConversationId: z.string().optional(),
  conversationCount: z.number().int().default(0),
  successCount: z.number().int().default(0),
  failureCount: z.number().int().default(0),
  rstCount: z.number().int().default(0),
  retransmissionCount: z.number().int().default(0),
  zeroWindowCount: z.number().int().default(0),
  failureModes: z.array(z.object({
    kind: z.string(),
    label: z.string(),
    count: z.number().int(),
    conversationIds: z.array(z.string()).default([])
  })).default([]),
  firstSeen: z.number().optional(),
  lastSeen: z.number().optional(),
  rankScore: z.number().default(0),
  rankReasons: z.array(z.string()).default([]),
  summary: z.string()
});
export type AccessCandidateGroup = z.infer<typeof AccessCandidateGroupSchema>;

export const PathHopSchema = z.object({
  hopId: z.string(),
  nodeId: z.string(),
  conversationId: z.string(),
  observedTuple: z.string(),
  status: z.enum(["observed", "missing", "unknown"]),
  startTime: z.number().optional(),
  endTime: z.number().optional(),
  packetCount: z.number().int().default(0),
  anomalies: z.array(z.string()).default([]),
  wiresharkFilter: z.string(),
  correlation: z.enum(["exact_tuple", "mapping_hint", "missing", "needs_context"]).default("missing"),
  correlationReasons: z.array(z.string()).default([]),
  protocolStatus: z.record(z.string(), z.unknown()).optional()
});
export type PathHop = z.infer<typeof PathHopSchema>;

export const QueryPathSchema = z.object({
  queryRunId: z.string(),
  conversationId: z.string(),
  hops: z.array(PathHopSchema).default([]),
  edges: z.array(z.object({
    edgeId: z.string(),
    fromNodeId: z.string(),
    toNodeId: z.string(),
    status: z.enum(["observed", "suspect", "needs_context", "unknown"]),
    label: z.string(),
    diagnosis: z.string().default(""),
    reasons: z.array(z.string()).default([]),
    nextSteps: z.array(z.string()).default([]),
    timeDeltaSeconds: z.number().optional()
  })).default([]),
  missingHops: z.array(z.string()).default([]),
  confidence: ConfidenceSchema,
  summary: z.string()
});
export type QueryPath = z.infer<typeof QueryPathSchema>;

export const ProtocolCorrelationSchema = z.object({
  correlationId: z.string(),
  kind: z.enum(["dns_to_tcp", "tls_sni_to_tcp", "http_host_to_tcp", "icmp_to_tcp"]),
  sourcePacketId: z.string(),
  sourceEvidenceCardId: z.string().optional(),
  targetConversationId: z.string().optional(),
  targetDisplayFilter: z.string(),
  relation: z.string(),
  confidence: ConfidenceSchema,
  summary: z.string(),
  reasons: z.array(z.string()).default([]),
  nextSteps: z.array(z.string()).default([])
});
export type ProtocolCorrelation = z.infer<typeof ProtocolCorrelationSchema>;

export const QueryDiagnosisCheckSchema = z.object({
  key: z.enum(["handshake", "rst", "traffic_direction", "retransmission", "zero_window", "close_state", "path", "protocol", "icmp", "dns", "udp", "tls", "http"]),
  label: z.string(),
  status: z.enum(["ok", "warn", "problem", "unknown"]),
  summary: z.string(),
  packetIds: z.array(z.string()).default([]),
  nextSteps: z.array(z.string()).default([])
});
export type QueryDiagnosisCheck = z.infer<typeof QueryDiagnosisCheckSchema>;

export const QueryDiagnosisSchema = z.object({
  conversationId: z.string(),
  summary: z.string(),
  confidence: ConfidenceSchema,
  checks: z.array(QueryDiagnosisCheckSchema).default([]),
  diagnosticTags: z.array(DiagnosticTagSchema).default([]),
  evidence: z.array(EvidenceEventSchema).default([]),
  findings: z.array(FindingSchema).default([]),
  nextSteps: z.array(z.string()).default([])
});
export type QueryDiagnosis = z.infer<typeof QueryDiagnosisSchema>;

export const EvidenceCardSchema = z.object({
  cardId: z.string(),
  kind: z.enum(["capture", "time_range", "conversation", "packet", "protocol_event", "transaction", "filter", "statistic", "missing_context"]),
  title: z.string(),
  summary: z.string(),
  pcapFilename: z.string().optional(),
  frameNumber: z.number().int().optional(),
  displayFilter: z.string().optional(),
  packetDisplayFilter: z.string().optional(),
  conversationId: z.string().optional(),
  queryRunId: z.string().optional(),
  actions: z.array(z.enum(["open_wireshark", "select_conversation", "query_packets", "request_upload", "copy_filter"])).default([])
});
export type EvidenceCard = z.infer<typeof EvidenceCardSchema>;

export const QueryRunSchema = z.object({
  queryRunId: z.string(),
  caseId: z.string(),
  question: z.string(),
  timeRange: z.object({
    start: z.number().optional(),
    end: z.number().optional()
  }).default({}),
  srcIp: z.string().optional(),
  dstIp: z.string().optional(),
  port: z.number().int().optional(),
  protocol: z.string().optional(),
  displayFilter: z.string(),
  totalConversationCount: z.number().int().default(0),
  candidateGroups: z.array(AccessCandidateGroupSchema).default([]),
  selectedCandidateGroupId: z.string().optional(),
  conversationIds: z.array(z.string()).default([]),
  conversations: z.array(ConversationSchema).default([]),
  selectedConversationId: z.string().optional(),
  path: QueryPathSchema.optional(),
  selectedDiagnosis: QueryDiagnosisSchema.optional(),
  evidenceCards: z.array(EvidenceCardSchema).default([]),
  protocolCorrelations: z.array(ProtocolCorrelationSchema).default([]),
  selectedEvidenceCardId: z.string().optional(),
  createdAt: z.string()
});
export type QueryRun = z.infer<typeof QueryRunSchema>;

export const AnalysisRunSchema = z.object({
  runId: z.string(),
  createdAt: z.string(),
  kind: z.enum(["capture_update", "parse", "analysis"]),
  summary: z.string(),
  captureCount: z.number().int(),
  rawPacketCount: z.number().int(),
  packetCount: z.number().int(),
  findingCount: z.number().int(),
  analysisFilter: AnalysisFilterSchema.default({}),
  snapshotFilename: z.string().optional()
});
export type AnalysisRun = z.infer<typeof AnalysisRunSchema>;

export const ToolRunSchema = z.object({
  toolRunId: z.string(),
  createdAt: z.string(),
  kind: z.enum(["planner", "tool", "mcp", "agent"]),
  status: z.enum(["success", "error", "skipped"]),
  target: z.string(),
  question: z.string().optional(),
  intent: z.string().optional(),
  summary: z.string(),
  inputSummary: z.string().optional(),
  outputSummary: z.string().optional(),
  queryRunId: z.string().optional(),
  evidenceCardIds: z.array(z.string()).default([]),
  pcapFilename: z.string().optional(),
  frameNumber: z.number().int().optional(),
  displayFilter: z.string().optional(),
  packetDisplayFilter: z.string().optional(),
  durationMs: z.number().optional(),
  error: z.string().optional()
});
export type ToolRun = z.infer<typeof ToolRunSchema>;

export const NetworkDeviceSchema = z.object({
  deviceId: z.string(),
  name: z.string(),
  type: z.enum(["firewall", "switch", "load_balancer", "ssl_terminator", "waf", "router", "proxy", "cdn", "nat_gateway", "other"]),
  description: z.string().optional(),
  configurations: z.array(z.string()).optional()
});
export type NetworkDevice = z.infer<typeof NetworkDeviceSchema>;

export const DataPathHopSchema = z.object({
  hopIndex: z.number(),
  deviceName: z.string().optional(),
  clientSideCapture: z.string().optional(),
  serverSideCapture: z.string().optional(),
  description: z.string().optional()
});
export type DataPathHop = z.infer<typeof DataPathHopSchema>;

export const NetworkTopologySchema = z.object({
  devices: z.array(NetworkDeviceSchema).default([]),
  dataPath: z.array(DataPathHopSchema).optional(),
  notes: z.string().optional()
});
export type NetworkTopology = z.infer<typeof NetworkTopologySchema>;

export const PacketInsightSchema = z.object({
  insightId: z.string(),
  type: z.enum([
    "connection_lifecycle",
    "ack_gap",
    "tcp_timing",
    "tcp_window_trend",
    "tcp_rst_direction",
    "tcp_handshake_retry",
    "tcp_delayed_ack",
    "tcp_connection_flood",
    "tcp_segment_anomaly",
    "tcp_keepalive",
    "tcp_throughput",
    "tcp_options",
    "http_status_chain",
    "http_header_anomaly",
    "http_timing",
    "icmp_echo_pair",
    "cross_protocol_chain",
    "tls_handshake",
    "dns_anomaly",
    "udp_anomaly",
    "udp_flow",
    "icmp_unreachable",
    "icmp_mtu",
    "icmp_redirect",
    "quic_anomaly",
    "ntp_anomaly",
    "ssh_anomaly"
  ]),
  severity: z.enum(["info", "warning", "critical"]),
  packetIds: z.array(z.string()),
  description: z.string(),
  detail: z.record(z.string(), z.unknown()).default({}),
  scenario: z.string().optional()
});
export type PacketInsight = z.infer<typeof PacketInsightSchema>;

export const TcpStreamSummarySchema = z.object({
  streamIndex: z.number().int(),
  srcIp: z.string().optional(),
  srcPort: z.number().int().optional(),
  dstIp: z.string().optional(),
  dstPort: z.number().int().optional(),
  packetCount: z.number().int(),
  byteCount: z.number().int(),
  displayFilter: z.string()
});
export type TcpStreamSummary = z.infer<typeof TcpStreamSummarySchema>;

export const TcpStreamContentSchema = z.object({
  streamIndex: z.number().int(),
  format: z.enum(["ascii", "raw"]),
  clientData: z.string(),
  serverData: z.string(),
  totalBytes: z.number().int(),
  truncated: z.boolean(),
  displayFilter: z.string()
});
export type TcpStreamContent = z.infer<typeof TcpStreamContentSchema>;

export const CaseGraphSchema = z.object({
  spec: CaseSpecSchema,
  captures: z.array(CaptureNodeSchema),
  mappingHints: z.array(MappingHintSchema).default([]),
  timeOffsetHints: z.array(TimeOffsetHintSchema).default([]),
  rawPackets: z.array(PacketSummarySchema).default([]),
  analysisFilter: AnalysisFilterSchema.default({}),
  packets: z.array(PacketSummarySchema).default([]),
  sessions: z.array(SessionSegmentSchema).default([]),
  sessionLinks: z.array(SessionLinkSchema).default([]),
  diagnosticTags: z.array(DiagnosticTagSchema).default([]),
  evidence: z.array(EvidenceEventSchema).default([]),
  findings: z.array(FindingSchema).default([]),
  path: PathGraphSchema,
  queryRuns: z.array(QueryRunSchema).default([]),
  activeQueryRunId: z.string().optional(),
  analysisRuns: z.array(AnalysisRunSchema).default([]),
  activeRunId: z.string().optional(),
  toolRuns: z.array(ToolRunSchema).default([]),
  networkTopology: NetworkTopologySchema.optional(),
  insights: z.array(PacketInsightSchema).default([])
});
export type CaseGraph = z.infer<typeof CaseGraphSchema>;

export const SuggestedQuerySchema = z.object({
  question: z.string(),
  reason: z.string(),
  intent: z.string()
});
export type SuggestedQuery = z.infer<typeof SuggestedQuerySchema>;

export const DiagnosticHypothesisSchema = z.object({
  id: z.string(),
  description: z.string(),
  status: z.enum(["pending", "testing", "confirmed", "ruled_out"]),
  evidenceFor: z.array(z.string()).default([]),
  evidenceAgainst: z.array(z.string()).default([])
});
export type DiagnosticHypothesis = z.infer<typeof DiagnosticHypothesisSchema>;

export const AgentAnswerSchema = z.object({
  answer: z.string(),
  thoughts: z.array(z.string()).optional(),
  evidenceCards: z.array(EvidenceCardSchema).optional(),
  actions: z.array(z.string()).optional(),
  evidenceIds: z.array(z.string()).default([]),
  packetIds: z.array(z.string()).default([]),
  sessionLinkIds: z.array(z.string()).default([]),
  findingIds: z.array(z.string()).default([]),
  missingContext: z.array(z.string()).default([]),
  confidence: ConfidenceSchema.optional(),
  suggestedActions: z.array(z.string()).default([]),
  suggestedQueries: z.array(SuggestedQuerySchema).optional(),
  handoffAgent: z.string().optional(),
  protocolCorrelations: z.array(ProtocolCorrelationSchema).optional(),
  followUpQuestions: z.array(z.string()).optional(),
  diagnosticPhase: z.enum(["interview", "hypothesis", "testing", "conclusion"]).optional(),
  hypotheses: z.array(DiagnosticHypothesisSchema).optional()
});
export type AgentAnswer = z.infer<typeof AgentAnswerSchema>;

export const AgentIntentEnum = z.enum([
  "usage_help",
  "protocol_statistics",
  "network_statistics",
  "tcp_session_query",
  "protocol_event_query",
  "capture_correlation",
  "mapping_hint_update",
  "active_query_explain",
  "selected_session_diagnosis",
  "report_request",
  "needs_clarification",
  "llm_explain"
]);
export type AgentIntent = z.infer<typeof AgentIntentEnum>;

export const AnalysisChainStepSchema = z.object({
  stepId: z.string(),
  intent: AgentIntentEnum,
  purpose: z.string(),
  params: QueryRunInputSchema.partial().optional(),
  paramsFrom: z.record(z.string(), z.string()).optional()
});
export type AnalysisChainStep = z.infer<typeof AnalysisChainStepSchema>;

export const AnalysisChainPlanSchema = z.object({
  chainId: z.string(),
  planKind: z.enum(["single", "chain"]),
  question: z.string(),
  steps: z.array(AnalysisChainStepSchema),
  confidence: z.enum(["high", "medium", "low"]).default("medium"),
  reason: z.string().default(""),
  missingContext: z.array(z.string()).default([])
});
export type AnalysisChainPlan = z.infer<typeof AnalysisChainPlanSchema>;

export const ChainStepResultSchema = z.object({
  stepId: z.string(),
  intent: AgentIntentEnum,
  status: z.string(),
  answer: AgentAnswerSchema,
  durationMs: z.number().optional()
});
export type ChainStepResult = z.infer<typeof ChainStepResultSchema>;
