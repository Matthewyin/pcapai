import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "packet-normalizer-mcp", version: "0.1.0" });

type Confidence = "certain" | "high" | "low" | "needs_context";
type PacketSummary = {
  packetId: string;
  nodeId: string;
  pcapFilename: string;
  frameNumber: number;
  timestamp: number;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol: string;
  tcpFlags: string[];
  length?: number;
  summary: string;
};
type CaptureNode = {
  nodeId: string;
  name: string;
  role: string;
  pcapFilename?: string;
  interfaceDirection?: "ingress" | "egress" | "bidirectional" | "unknown";
  capturePosition?: string;
};
type CaseGraphInput = {
  spec: { caseId: string; client?: string; server?: string; port?: number; protocol: string };
  analysisFilter?: { client?: string; server?: string; protocol?: string; port?: number };
  captures: CaptureNode[];
  packets: PacketSummary[];
};
type SessionSegment = {
  segmentId: string;
  nodeId: string;
  pcapFilename?: string;
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
  confidence: Confidence;
};
type EvidenceEvent = {
  evidenceId: string;
  kind: string;
  title: string;
  nodeId?: string;
  packetIds: string[];
  detail: string;
  confidence: Confidence;
};

function endpoint(ip?: string, port?: number) {
  return `${ip || "*"}:${port ?? "*"}`;
}

function sessionKey(packet: PacketSummary) {
  const endpoints = [endpoint(packet.srcIp, packet.srcPort), endpoint(packet.dstIp, packet.dstPort)].sort();
  return [packet.nodeId, packet.protocol, ...endpoints].join("|");
}

function chooseOrientation(packets: PacketSummary[], graph: CaseGraphInput) {
  const syn = packets.find((packet) => packet.tcpFlags.includes("SYN") && !packet.tcpFlags.includes("ACK"));
  const client = graph.analysisFilter?.client || graph.spec.client;
  const server = graph.analysisFilter?.server || graph.spec.server;
  const matched = packets.find((packet) => packet.srcIp === client || packet.dstIp === server);
  const first = syn || matched || packets[0];
  return {
    clientIp: first.srcIp,
    clientPort: first.srcPort,
    serverIp: first.dstIp,
    serverPort: first.dstPort
  };
}

function eventKindsFor(packets: PacketSummary[]) {
  const kinds = new Set<string>();
  if (packets.some((packet) => packet.tcpFlags.includes("SYN") && !packet.tcpFlags.includes("ACK"))) kinds.add("tcp_syn");
  if (packets.some((packet) => packet.tcpFlags.includes("SYN") && packet.tcpFlags.includes("ACK"))) kinds.add("tcp_syn_ack");
  if (packets.some((packet) => packet.tcpFlags.includes("RST"))) kinds.add("tcp_rst");
  if (packets.some((packet) => packet.tcpFlags.includes("FIN"))) kinds.add("tcp_fin");
  if (packets.some((packet) => packet.protocol.includes("icmp") && packet.summary.toLowerCase().includes("unreachable"))) kinds.add("icmp_unreachable");
  return [...kinds];
}

function firstPacketForKind(packets: PacketSummary[], kind: string) {
  if (kind === "tcp_syn") return packets.find((packet) => packet.tcpFlags.includes("SYN") && !packet.tcpFlags.includes("ACK"));
  if (kind === "tcp_syn_ack") return packets.find((packet) => packet.tcpFlags.includes("SYN") && packet.tcpFlags.includes("ACK"));
  if (kind === "tcp_rst") return packets.find((packet) => packet.tcpFlags.includes("RST"));
  if (kind === "icmp_unreachable") return packets.find((packet) => packet.protocol.includes("icmp") && packet.summary.toLowerCase().includes("unreachable"));
  return undefined;
}

function eventTitle(kind: string) {
  if (kind === "tcp_syn") return "观察到 TCP SYN";
  if (kind === "tcp_syn_ack") return "观察到 TCP SYN-ACK";
  if (kind === "tcp_rst") return "观察到 TCP RST";
  if (kind === "icmp_unreachable") return "观察到 ICMP unreachable";
  return kind;
}

function normalizeCaseGraph(graph: CaseGraphInput) {
  const sortedPackets = [...graph.packets].sort((left, right) => left.timestamp - right.timestamp || left.frameNumber - right.frameNumber);
  const groups = new Map<string, PacketSummary[]>();
  for (const packet of sortedPackets) {
    const key = sessionKey(packet);
    groups.set(key, [...(groups.get(key) || []), packet]);
  }

  const sessions: SessionSegment[] = [...groups.values()].map((packets, index) => {
    const first = packets[0];
    const last = packets[packets.length - 1];
    const orientation = chooseOrientation(packets, graph);
    const eventKinds = eventKindsFor(packets);
    return {
      segmentId: `seg-${index + 1}`,
      nodeId: first.nodeId,
      pcapFilename: first.pcapFilename,
      protocol: first.protocol,
      ...orientation,
      startTime: first.timestamp,
      endTime: last.timestamp,
      packetIds: packets.map((packet) => packet.packetId),
      eventKinds,
      summary: `${endpoint(orientation.clientIp, orientation.clientPort)} -> ${endpoint(orientation.serverIp, orientation.serverPort)}，${packets.length} 个包`,
      confidence: eventKinds.length ? "high" : "low"
    };
  });

  const evidence: EvidenceEvent[] = [];
  for (const session of sessions) {
    const packets = sortedPackets.filter((packet) => session.packetIds.includes(packet.packetId));
    for (const kind of session.eventKinds.filter((item) => ["tcp_syn", "tcp_syn_ack", "tcp_rst", "icmp_unreachable"].includes(item))) {
      const packet = firstPacketForKind(packets, kind);
      if (!packet) continue;
      evidence.push({
        evidenceId: `evt-${evidence.length + 1}`,
        kind,
        title: eventTitle(kind),
        nodeId: packet.nodeId,
        packetIds: [packet.packetId],
        detail: `${eventTitle(kind)}，节点 ${packet.nodeId}，帧 ${packet.frameNumber}，${endpoint(packet.srcIp, packet.srcPort)} -> ${endpoint(packet.dstIp, packet.dstPort)}`,
        confidence: "high"
      });
    }
  }

  const synNodeIds = new Set(evidence.filter((event) => event.kind === "tcp_syn").map((event) => event.nodeId).filter(Boolean));
  for (let index = 0; index < graph.captures.length - 1; index += 1) {
    const current = graph.captures[index];
    const next = graph.captures[index + 1];
    if (synNodeIds.has(current.nodeId) && !synNodeIds.has(next.nodeId)) {
      evidence.push({
        evidenceId: `evt-${evidence.length + 1}`,
        kind: "missing_observation",
        title: "后一节点未观察到对应 SYN",
        nodeId: next.nodeId,
        packetIds: [],
        detail: `${current.name} 已观察到 SYN，但 ${next.name} 暂未观察到 SYN。首版按节点顺序判断疑似断点。`,
        confidence: "low"
      });
    }
  }

  const path = {
    nodes: graph.captures.map((capture) => ({
      nodeId: capture.nodeId,
      label: capture.name,
      role: capture.role,
      status: sessions.some((session) => session.nodeId === capture.nodeId) ? "observed" as const : "missing" as const
    })),
    edges: graph.captures.slice(0, -1).map((capture, index) => {
      const next = graph.captures[index + 1];
      const status = synNodeIds.has(capture.nodeId) && !synNodeIds.has(next.nodeId) ? "suspect" as const : sessions.some((session) => session.nodeId === capture.nodeId) && sessions.some((session) => session.nodeId === next.nodeId) ? "observed" as const : "unknown" as const;
      return {
        edgeId: `edge-${index + 1}`,
        fromNodeId: capture.nodeId,
        toNodeId: next.nodeId,
        status,
        label: status === "suspect" ? "疑似断点" : status === "observed" ? "已观察" : "待确认"
      };
    })
  };

  const findings = path.edges.filter((edge) => edge.status === "suspect").map((edge, index) => {
    const fromNode = graph.captures.find((capture) => capture.nodeId === edge.fromNodeId);
    const toNode = graph.captures.find((capture) => capture.nodeId === edge.toNodeId);
    const edgeEvidence = evidence.filter((event) => event.nodeId === edge.fromNodeId || event.nodeId === edge.toNodeId);
    return {
      findingId: `finding-${index + 1}`,
      title: `疑似断点：${fromNode?.name || edge.fromNodeId} -> ${toNode?.name || edge.toNodeId}`,
      summary: `前一节点观察到访问 SYN，后一节点在当前抓包中未观察到对应 SYN。首版尚未应用 NAT/SLB 映射和时间偏移校准，因此置信度保持为 low。`,
      evidenceIds: edgeEvidence.map((event) => event.evidenceId),
      packetIds: edgeEvidence.flatMap((event) => event.packetIds),
      confidence: "low" as const,
      nextSteps: ["确认两个节点的抓包时间窗口是否重叠", "补充 NAT/SLB/网关映射信息", "确认节点顺序和入/出方向是否正确"]
    };
  });

  return { caseId: graph.spec.caseId, sessions, evidence, path, findings };
}

server.registerTool(
  "normalize_packets",
  {
    title: "Normalize packets",
    description: "Convert packet summaries into normalized evidence events and session segments.",
    inputSchema: {
      caseGraphJson: z.string()
    }
  },
  async ({ caseGraphJson }) => ({
    content: [{ type: "text", text: JSON.stringify(normalizeCaseGraph(JSON.parse(caseGraphJson))) }]
  })
);

server.registerTool(
  "validate_capture_context",
  {
    title: "Validate capture context",
    description: "Detect missing node roles, directions, and mapping hints.",
    inputSchema: {
      caseGraphJson: z.string()
    }
  },
  async ({ caseGraphJson }) => {
    const graph = JSON.parse(caseGraphJson) as CaseGraphInput;
    const missingContext = graph.captures.flatMap((capture) => {
      const missing = [];
      if (!capture.role || capture.role === "未知节点") missing.push(`${capture.name} 缺少节点角色`);
      if (!capture.interfaceDirection || capture.interfaceDirection === "unknown") missing.push(`${capture.name} 缺少入/出方向`);
      if (!capture.capturePosition) missing.push(`${capture.name} 缺少抓包位置`);
      return missing;
    });
    return { content: [{ type: "text", text: JSON.stringify({ missingContext }) }] };
  }
);

await server.connect(new StdioServerTransport());
