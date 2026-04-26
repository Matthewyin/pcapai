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
  capturePosition: z.string().default("")
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
  evidenceIds: z.array(z.string()).default([]),
  packetIds: z.array(z.string()).default([]),
  confidence: ConfidenceSchema,
  nextSteps: z.array(z.string()).default([])
});
export type Finding = z.infer<typeof FindingSchema>;

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
  evidence: z.array(EvidenceEventSchema).default([]),
  findings: z.array(FindingSchema).default([]),
  path: PathGraphSchema,
  analysisRuns: z.array(AnalysisRunSchema).default([]),
  activeRunId: z.string().optional()
});
export type CaseGraph = z.infer<typeof CaseGraphSchema>;

export const AgentAnswerSchema = z.object({
  answer: z.string(),
  evidenceIds: z.array(z.string()).default([]),
  packetIds: z.array(z.string()).default([]),
  sessionLinkIds: z.array(z.string()).default([]),
  findingIds: z.array(z.string()).default([]),
  missingContext: z.array(z.string()).default([]),
  confidence: ConfidenceSchema.optional(),
  suggestedActions: z.array(z.string()).default([]),
  handoffAgent: z.string().optional()
});
export type AgentAnswer = z.infer<typeof AgentAnswerSchema>;
