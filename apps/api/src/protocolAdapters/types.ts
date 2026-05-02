import type { z } from "zod";
import { QueryRunInputSchema, type AgentAnswer, type CaseGraph, type EvidenceCard, type PacketSummary, type ProtocolCorrelation, type QueryDiagnosis } from "../../../../packages/shared/src/index.js";
import type { CaptureQueryInput } from "../mcp/tsharkQueryClient.js";

export type ProtocolAdapter = {
  id: string;
  protocol: "tcp" | "icmp" | "dns" | "udp" | "tls" | "http";
  status: string;
  errorPrefix: string;
  match: (question: string) => boolean;
  run: (graph: CaseGraph, question: string) => Promise<AgentAnswer>;
};

export type ProtocolQueryInput = z.infer<typeof QueryRunInputSchema>;

export type ProtocolPairGroup = {
  src: string;
  dst: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  nodeId?: string;
  protocol?: string;
  count: number;
  firstSeen: number;
  lastSeen: number;
  packetIds: string[];
  pcapFilename?: string;
  frameNumber?: number;
  displayFilter?: string;
  packetDisplayFilter?: string;
};

export type ProtocolPacket = {
  packetId: string;
  nodeId: string;
  pcapFilename: string;
  frameNumber: number;
  timestamp: number;
  protocol?: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  tcpFlags: string[];
  summary: string;
};

export type DeterministicMetricKind = "rst" | "retransmission" | "zero_window" | "syn_no_synack" | "one_way";

export type PacketPairAnswerInput = {
  graph: CaseGraph;
  queryInput: ProtocolQueryInput;
  displayFilter: string;
  pairs: ProtocolPairGroup[];
  limit: number;
  title: string;
  metricLabel: string;
  metricKind: DeterministicMetricKind;
  noResult: string;
  thoughts: string[];
  cardPrefix: string;
  suggestedAction: string;
};

export type ProtocolQueryResult = {
  graph: CaseGraph;
  queryRunId: string;
  queryInput: ProtocolQueryInput;
  displayFilter: string;
  protocol: string;
  title: string;
  packets: PacketSummary[];
  noResult: string;
  thoughts: string[];
  evidenceCards: EvidenceCard[];
  protocolCorrelations?: ProtocolCorrelation[];
  checks: QueryDiagnosis["checks"];
  suggestedActions: string[];
  handoffAgent: string;
};

export type ProtocolAdapterContext = {
  queryPacketLimit: number;
  captureQueryInputs: (graph: CaseGraph) => CaptureQueryInput[];
  requestedLimit: (question: string, fallback?: number) => number;
  displayFilterFromQuestion: (graph: CaseGraph, question: string, fallbackProtocol?: string) => Promise<{ input: ProtocolQueryInput; displayFilter: string }>;
  noCaptureAnswer: () => AgentAnswer;
  packetPairAnswer: (input: PacketPairAnswerInput) => Promise<AgentAnswer>;
  protocolPacketCard: (packet: PacketSummary, queryRunId: string, title: string, summary: string, kind?: "protocol_event" | "transaction") => EvidenceCard;
  protocolQueryAnswer: (input: ProtocolQueryResult) => AgentAnswer;
  groupPacketPairs: (packets: ProtocolPacket[], baseFilter?: string) => ProtocolPairGroup[];
  pairKey: (packet: ProtocolPacket) => string;
  pairGroupFromPackets: (packets: ProtocolPacket[], count: number, baseFilter?: string) => ProtocolPairGroup;
  formatBeijingTime: (timestamp: number) => string;
  queryPackets: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: PacketSummary[] }>;
  listTcpResets: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: ProtocolPacket[] }>;
  listTcpRetransmissions: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: ProtocolPacket[] }>;
  listTcpZeroWindow: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: ProtocolPacket[] }>;
  listIcmpEvents: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: PacketSummary[] }>;
  listDnsPackets: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: PacketSummary[] }>;
  listUdpPackets: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: PacketSummary[] }>;
  listTlsPackets: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: PacketSummary[] }>;
  listHttpPackets: (input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) => Promise<{ packets: PacketSummary[] }>;
};

export async function runProtocolAdapter(adapters: ProtocolAdapter[], graph: CaseGraph, question: string): Promise<{ adapter: ProtocolAdapter; answer: AgentAnswer } | null> {
  const adapter = adapters.find((candidate) => candidate.match(question));
  if (!adapter) return null;
  return { adapter, answer: await adapter.run(graph, question) };
}

export function protocolAdapterErrorStatus(adapter?: ProtocolAdapter) {
  return adapter ? `${adapter.status}_error` : "protocol_adapter_error";
}

export function protocolAdapterErrorMessage(error: unknown, adapter?: ProtocolAdapter) {
  const prefix = adapter?.errorPrefix || "协议查询失败";
  return `${prefix}：${error instanceof Error ? error.message : String(error)}`;
}
