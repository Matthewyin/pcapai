import { z } from "zod";
import {
  AnalysisFilterSchema,
  QueryDiagnosisSchema,
  QueryRunInputSchema,
  QueryRunSchema,
  type AccessCandidateGroup,
  type AgentAnswer,
  type CaseGraph,
  type Conversation,
  type EvidenceCard,
  type PacketSummary,
  type ProtocolCorrelation,
  type QueryDiagnosis,
  type QueryPath
} from "../../../../packages/shared/src/index.js";
import type { CaptureQueryInput } from "../mcp/tsharkQueryClient.js";
import type { DeterministicMetricKind, PacketPairAnswerInput, ProtocolPacket, ProtocolPairGroup, ProtocolQueryResult } from "./types.js";

type BuilderDependencies = {
  conversationPacketLimit: number;
  retainedQueryRunLimit: number;
  captureQueryInputs: (graph: CaseGraph) => CaptureQueryInput[];
  getConversationPackets: (input: { capture: CaptureQueryInput; displayFilter: string; limit?: number }) => Promise<{ packets: PacketSummary[] }>;
  buildAccessCandidateGroups: (conversations: Conversation[], query: z.infer<typeof QueryRunInputSchema>) => AccessCandidateGroup[];
  buildQueryPath: (graph: CaseGraph, queryRunId: string, conversationId: string, conversations: Conversation[]) => QueryPath;
  buildQueryDiagnosis: (graph: CaseGraph, queryRunId: string, conversation: Conversation, packets: PacketSummary[], pathResult: QueryPath) => QueryDiagnosis;
  writeCaseGraph: (graph: CaseGraph) => void;
  setCaseGraph: (caseId: string, graph: CaseGraph) => void;
  formatBeijingTime: (epochSeconds: number) => string;
};

export function endpointText(ip?: string, port?: number) {
  return `${ip || "*"}:${port ?? "*"}`;
}

export function pairKey(packet: ProtocolPacket) {
  return [endpointText(packet.srcIp, packet.srcPort), endpointText(packet.dstIp, packet.dstPort)].sort().join(" <-> ");
}

function packetFlowDisplayFilter(packet: PacketSummary) {
  const parts: string[] = [];
  if (packet.srcIp && packet.dstIp) parts.push(`ip.addr == ${packet.srcIp} && ip.addr == ${packet.dstIp}`);
  if (packet.srcPort !== undefined && packet.dstPort !== undefined) {
    const protocol = packet.protocol.toLowerCase();
    const field = protocol === "udp" || protocol === "dns" ? "udp.port" : "tcp.port";
    parts.push(`${field} == ${packet.srcPort} && ${field} == ${packet.dstPort}`);
  }
  return parts.join(" && ") || `frame.number == ${packet.frameNumber}`;
}

function pairDisplayFilter(packet: ProtocolPacket, baseFilter = "tcp") {
  const parts = [baseFilter];
  if (packet.srcIp && packet.dstIp) parts.push(`ip.addr == ${packet.srcIp} && ip.addr == ${packet.dstIp}`);
  if (packet.srcPort !== undefined && packet.dstPort !== undefined) {
    const field = (packet.protocol || "").toLowerCase() === "udp" ? "udp.port" : "tcp.port";
    parts.push(`${field} == ${packet.srcPort} && ${field} == ${packet.dstPort}`);
  }
  return parts.filter(Boolean).join(" && ");
}

export function groupPacketPairs(packets: ProtocolPacket[], baseFilter = "tcp") {
  const grouped = new Map<string, ProtocolPairGroup>();
  for (const packet of packets) {
    const src = endpointText(packet.srcIp, packet.srcPort);
    const dst = endpointText(packet.dstIp, packet.dstPort);
    const key = [src, dst].sort().join(" <-> ");
    const current = grouped.get(key);
    if (current) {
      current.count += 1;
      current.firstSeen = Math.min(current.firstSeen, packet.timestamp);
      current.lastSeen = Math.max(current.lastSeen, packet.timestamp);
      current.packetIds.push(packet.packetId);
    } else {
      grouped.set(key, {
        src,
        dst,
        srcIp: packet.srcIp,
        srcPort: packet.srcPort,
        dstIp: packet.dstIp,
        dstPort: packet.dstPort,
        nodeId: packet.nodeId,
        protocol: packet.protocol,
        count: 1,
        firstSeen: packet.timestamp,
        lastSeen: packet.timestamp,
        packetIds: [packet.packetId],
        pcapFilename: packet.pcapFilename,
        frameNumber: packet.frameNumber,
        displayFilter: pairDisplayFilter(packet, baseFilter),
        packetDisplayFilter: `frame.number == ${packet.frameNumber}`
      });
    }
  }
  return [...grouped.values()].sort((left, right) => right.count - left.count || left.firstSeen - right.firstSeen);
}

export function pairGroupFromPackets(packets: ProtocolPacket[], count: number, baseFilter = "tcp"): ProtocolPairGroup {
  const first = packets[0];
  const timestamps = packets.map((packet) => packet.timestamp);
  return {
    src: endpointText(first.srcIp, first.srcPort),
    dst: endpointText(first.dstIp, first.dstPort),
    srcIp: first.srcIp,
    srcPort: first.srcPort,
    dstIp: first.dstIp,
    dstPort: first.dstPort,
    nodeId: first.nodeId,
    protocol: first.protocol,
    count,
    firstSeen: Math.min(...timestamps),
    lastSeen: Math.max(...timestamps),
    packetIds: packets.map((packet) => packet.packetId),
    pcapFilename: first.pcapFilename,
    frameNumber: first.frameNumber,
    displayFilter: pairDisplayFilter(first, baseFilter),
    packetDisplayFilter: `frame.number == ${first.frameNumber}`
  };
}

export function noCaptureAnswer(): AgentAnswer {
  return {
    answer: "当前会话还没有可查询的 pcap 文件。请先上传抓包文件。",
    evidenceIds: [],
    packetIds: [],
    sessionLinkIds: [],
    findingIds: [],
    missingContext: ["缺少 pcap capture"],
    confidence: "needs_context",
    suggestedActions: ["先在聊天输入框上传 pcap/pcapng/cap 文件。"],
    handoffAgent: "DiagnosticInterviewAgent"
  };
}

export function protocolPacketCard(packet: PacketSummary, queryRunId: string, title: string, summary: string, kind: "protocol_event" | "transaction" = "protocol_event"): EvidenceCard {
  return {
    cardId: `${kind}-${queryRunId}-${packet.packetId}`,
    kind,
    title,
    summary,
    pcapFilename: packet.pcapFilename,
    frameNumber: packet.frameNumber,
    displayFilter: packetFlowDisplayFilter(packet),
    packetDisplayFilter: `frame.number == ${packet.frameNumber}`,
    queryRunId,
    actions: ["open_wireshark", "copy_filter"]
  };
}

function pairConversation(pair: ProtocolPairGroup, queryRunId: string, index: number, metricKind: DeterministicMetricKind): Conversation {
  const rstCount = metricKind === "rst" ? pair.count : 0;
  const retransmissionCount = metricKind === "retransmission" ? pair.count : 0;
  const zeroWindowCount = metricKind === "zero_window" ? pair.count : 0;
  return {
    conversationId: `${queryRunId}-conversation-${index + 1}`,
    nodeId: pair.nodeId || "unknown",
    pcapFilename: pair.pcapFilename || "",
    protocol: (pair.protocol || "tcp").toUpperCase(),
    srcIp: pair.srcIp,
    srcPort: pair.srcPort,
    dstIp: pair.dstIp,
    dstPort: pair.dstPort,
    startTime: pair.firstSeen,
    endTime: pair.lastSeen,
    packetCount: pair.count,
    byteCount: 0,
    tcpFlags: metricKind === "rst" ? ["RST"] : metricKind === "syn_no_synack" ? ["SYN"] : [],
    rstCount,
    retransmissionCount,
    zeroWindowCount,
    rankScore: pair.count,
    rankReasons: [`命中 ${pair.count} 个${metricKind === "rst" ? " RST" : metricKind === "retransmission" ? "重传" : metricKind === "zero_window" ? " Zero Window" : metricKind === "syn_no_synack" ? "未应答 SYN" : "单向流量"}包`],
    displayFilter: pair.displayFilter || "tcp"
  };
}

function pairEvidenceCards(conversations: Conversation[], cardPrefix: string, metricLabel: string, formatBeijingTime: (epochSeconds: number) => string): EvidenceCard[] {
  const now = Date.now();
  return conversations.map((conversation, index) => ({
    cardId: `${cardPrefix}-${now}-${index + 1}`,
    kind: "conversation" as const,
    title: `${index + 1}. ${endpointText(conversation.srcIp, conversation.srcPort)} <-> ${endpointText(conversation.dstIp, conversation.dstPort)}`,
    summary: `${metricLabel} ${metricLabel === "RST" ? conversation.rstCount : metricLabel === "重传" ? conversation.retransmissionCount : metricLabel === "Zero Window" ? conversation.zeroWindowCount : conversation.packetCount} 个，时间 ${formatBeijingTime(conversation.startTime)} - ${formatBeijingTime(conversation.endTime)}。`,
    pcapFilename: conversation.pcapFilename,
    displayFilter: conversation.displayFilter,
    conversationId: conversation.conversationId,
    actions: ["select_conversation" as const, "open_wireshark" as const, "copy_filter" as const]
  }));
}

export function createPacketPairAnswer(deps: BuilderDependencies) {
  return async function packetPairAnswer(input: PacketPairAnswerInput): Promise<AgentAnswer> {
    const pairs = input.pairs.slice(0, input.limit);
    const queryRunId = `query-${Date.now()}`;
    const conversations = pairs.map((pair, index) => pairConversation(pair, queryRunId, index, input.metricKind));
    const initialCandidateGroups = deps.buildAccessCandidateGroups(conversations, input.queryInput);
    const selectedConversationId = initialCandidateGroups[0]?.selectedConversationId || conversations[0]?.conversationId;
    const selectedConversation = conversations.find((conversation) => conversation.conversationId === selectedConversationId);
    const selectedCapture = selectedConversation ? deps.captureQueryInputs(input.graph).find((capture) => capture.nodeId === selectedConversation.nodeId && capture.pcapFilename === selectedConversation.pcapFilename) : undefined;
    const selectedPackets = selectedCapture && selectedConversation
      ? (await deps.getConversationPackets({ capture: selectedCapture, displayFilter: selectedConversation.displayFilter, limit: deps.conversationPacketLimit })).packets
      : [];
    const conversationsWithSelectedPackets = conversations.map((conversation) => conversation.conversationId === selectedConversationId
      ? {
        ...conversation,
        packetCount: selectedPackets.length || conversation.packetCount,
        byteCount: selectedPackets.reduce((sum, packet) => sum + (packet.length || 0), 0),
        tcpFlags: [...new Set(selectedPackets.flatMap((packet) => packet.tcpFlags))]
      }
      : conversation);
    const candidateGroups = deps.buildAccessCandidateGroups(conversationsWithSelectedPackets, input.queryInput);
    const selectedCandidateGroupId = candidateGroups.find((group) => selectedConversationId && group.conversationIds.includes(selectedConversationId))?.groupId || candidateGroups[0]?.groupId;
    const pathResult = selectedConversationId ? deps.buildQueryPath(input.graph, queryRunId, selectedConversationId, conversationsWithSelectedPackets) : undefined;
    const selectedConversationWithPackets = conversationsWithSelectedPackets.find((conversation) => conversation.conversationId === selectedConversationId);
    const selectedDiagnosis = selectedConversationWithPackets && pathResult
      ? deps.buildQueryDiagnosis(input.graph, queryRunId, selectedConversationWithPackets, selectedPackets, pathResult)
      : undefined;
    const evidenceCards = pairEvidenceCards(conversations, input.cardPrefix, input.metricLabel, deps.formatBeijingTime);
    const queryRun = QueryRunSchema.parse({
      queryRunId,
      caseId: input.graph.spec.caseId,
      question: input.queryInput.question,
      timeRange: input.queryInput.timeRange,
      srcIp: input.queryInput.srcIp,
      dstIp: input.queryInput.dstIp,
      port: input.queryInput.port,
      protocol: input.queryInput.protocol || "tcp",
      displayFilter: input.displayFilter,
      totalConversationCount: conversations.length,
      candidateGroups,
      selectedCandidateGroupId,
      conversations: conversationsWithSelectedPackets,
      conversationIds: conversationsWithSelectedPackets.map((conversation) => conversation.conversationId),
      selectedConversationId,
      path: pathResult,
      selectedDiagnosis,
      evidenceCards,
      createdAt: new Date().toISOString()
    });
    const nextGraph: CaseGraph = {
      ...input.graph,
      queryRuns: [queryRun, ...(input.graph.queryRuns || [])].slice(0, deps.retainedQueryRunLimit),
      activeQueryRunId: queryRunId,
      packets: selectedPackets,
      analysisFilter: AnalysisFilterSchema.parse({
        client: input.queryInput.srcIp,
        server: input.queryInput.dstIp,
        protocol: input.queryInput.protocol,
        port: input.queryInput.port
      })
    };
    deps.writeCaseGraph(nextGraph);
    deps.setCaseGraph(input.graph.spec.caseId, nextGraph);
    const lines = pairs.length
      ? [
        `${input.title}：命中 ${pairs.length} 个候选 TCP session。`,
        "明细已生成证据卡片；点击卡片的 Wireshark 按钮打开对应 TCP session。",
        selectedDiagnosis ? `当前选中诊断：${selectedDiagnosis.summary}` : "",
        selectedDiagnosis?.checks.length ? `诊断项：${selectedDiagnosis.checks.map((check) => `${check.label}=${check.status}`).join("；")}` : ""
      ]
      : [input.noResult];
    return {
      answer: lines.join("\n"),
      thoughts: input.thoughts,
      evidenceCards,
      actions: evidenceCards.flatMap((card) => card.actions),
      evidenceIds: selectedDiagnosis?.evidence.map((event) => event.evidenceId) || [],
      packetIds: selectedDiagnosis?.diagnosticTags.flatMap((tag) => tag.packetIds) || pairs.flatMap((pair) => pair.packetIds.slice(0, 1)),
      sessionLinkIds: [],
      findingIds: selectedDiagnosis?.findings.map((finding) => finding.findingId) || [],
      missingContext: [],
      confidence: selectedDiagnosis?.confidence || (pairs.length ? "high" : "low"),
      suggestedActions: pairs.length ? [input.suggestedAction] : ["确认时间范围、抓包方向和是否包含故障时段。"],
      handoffAgent: "HypothesisAgent"
    };
  };
}

export function createProtocolQueryAnswer(deps: Pick<BuilderDependencies, "retainedQueryRunLimit" | "writeCaseGraph" | "setCaseGraph">) {
  return function protocolQueryAnswer(input: ProtocolQueryResult): AgentAnswer {
    const lines = input.packets.length
      ? [
        `${input.title}：命中 ${input.packets.length} 个证据包。`,
        "明细已生成证据卡片；点击 Wireshark 可定位到对应 frame。",
        input.protocolCorrelations?.length ? `已生成 ${input.protocolCorrelations.length} 条 L7-to-TCP 确定性关联。` : ""
      ]
        .filter(Boolean)
      : [input.noResult];
    const confidence = input.packets.length ? "high" : "low";
    const selectedDiagnosis = QueryDiagnosisSchema.parse({
      conversationId: input.queryRunId,
      summary: lines[0],
      confidence,
      checks: input.checks,
      diagnosticTags: [],
      evidence: [],
      findings: [],
      nextSteps: input.packets.length ? input.suggestedActions : ["确认协议、时间范围、源目的地址是否正确。"]
    });
    const queryRun = QueryRunSchema.parse({
      queryRunId: input.queryRunId,
      caseId: input.graph.spec.caseId,
      question: input.queryInput.question,
      timeRange: input.queryInput.timeRange,
      srcIp: input.queryInput.srcIp,
      dstIp: input.queryInput.dstIp,
      port: input.queryInput.port,
      protocol: input.protocol,
      displayFilter: input.displayFilter,
      totalConversationCount: input.evidenceCards.length,
      evidenceCards: input.evidenceCards,
      protocolCorrelations: input.protocolCorrelations || [],
      selectedEvidenceCardId: input.evidenceCards[0]?.cardId,
      selectedDiagnosis,
      createdAt: new Date().toISOString()
    });
    const nextGraph: CaseGraph = {
      ...input.graph,
      queryRuns: [queryRun, ...(input.graph.queryRuns || [])].slice(0, deps.retainedQueryRunLimit),
      activeQueryRunId: input.queryRunId,
      packets: input.packets,
      analysisFilter: AnalysisFilterSchema.parse({
        client: input.queryInput.srcIp,
        server: input.queryInput.dstIp,
        protocol: input.protocol,
        port: input.queryInput.port
      })
    };
    deps.writeCaseGraph(nextGraph);
    deps.setCaseGraph(input.graph.spec.caseId, nextGraph);
    return {
      answer: lines.join("\n"),
      thoughts: input.thoughts,
      evidenceCards: input.evidenceCards,
      actions: input.evidenceCards.flatMap((card) => card.actions),
      evidenceIds: [],
      packetIds: input.packets.map((packet) => packet.packetId),
      sessionLinkIds: [],
      findingIds: [],
      missingContext: [],
      confidence,
      suggestedActions: input.packets.length ? input.suggestedActions : ["确认协议、时间范围、源目的地址是否正确。"],
      handoffAgent: input.handoffAgent,
      protocolCorrelations: input.protocolCorrelations || []
    };
  };
}

function tcpFlowFilter(packet: PacketSummary) {
  const parts = ["tcp"];
  if (packet.srcIp && packet.dstIp) parts.push(`ip.addr == ${packet.srcIp} && ip.addr == ${packet.dstIp}`);
  if (packet.srcPort !== undefined) parts.push(`tcp.port == ${packet.srcPort}`);
  if (packet.dstPort !== undefined) parts.push(`tcp.port == ${packet.dstPort}`);
  return parts.join(" && ");
}

function dnsTargetFilter(address: string) {
  return `tcp && ip.addr == ${address}`;
}

function evidenceCardForPacket(cards: EvidenceCard[], packet: PacketSummary) {
  return cards.find((card) => card.frameNumber === packet.frameNumber && card.pcapFilename === packet.pcapFilename);
}

export function buildProtocolCorrelations(queryRunId: string, protocol: string, packets: PacketSummary[], cards: EvidenceCard[]): ProtocolCorrelation[] {
  return packets.flatMap((packet, index): ProtocolCorrelation[] => {
    const sourceEvidenceCardId = evidenceCardForPacket(cards, packet)?.cardId;
    if (protocol === "dns" && packet.dnsIsResponse && packet.dnsQueryName && packet.dnsResponseAddress) {
      return [{
        correlationId: `corr-${queryRunId}-${index + 1}`,
        kind: "dns_to_tcp" as const,
        sourcePacketId: packet.packetId,
        sourceEvidenceCardId,
        targetDisplayFilter: dnsTargetFilter(packet.dnsResponseAddress),
        relation: "DNS 响应地址可用于继续追踪访问该解析 IP 的 TCP 会话。",
        confidence: "high" as const,
        summary: `域名 ${packet.dnsQueryName} 解析到 ${packet.dnsResponseAddress}，可继续查看访问该 IP 的 TCP 会话。`,
        reasons: [`DNS rcode=${packet.dnsRcode ?? "-"}`, `response address=${packet.dnsResponseAddress}`],
        nextSteps: [`用过滤器 ${dnsTargetFilter(packet.dnsResponseAddress)} 查看后续 TCP 访问。`]
      }];
    }
    if (protocol === "tls" && packet.tlsSni) {
      const filter = tcpFlowFilter(packet);
      return [{
        correlationId: `corr-${queryRunId}-${index + 1}`,
        kind: "tls_sni_to_tcp" as const,
        sourcePacketId: packet.packetId,
        sourceEvidenceCardId,
        targetDisplayFilter: filter,
        relation: "TLS SNI 绑定在承载 ClientHello 的同一个 TCP flow 上。",
        confidence: "high" as const,
        summary: `SNI ${packet.tlsSni} 出现在该 TCP flow，可结合底层 TCP 建连、重传和 RST 判断。`,
        reasons: [`SNI=${packet.tlsSni}`, `frame=${packet.frameNumber}`],
        nextSteps: [`用过滤器 ${filter} 查看该 TLS 所在 TCP session。`]
      }];
    }
    if (protocol === "http" && packet.httpHost) {
      const filter = tcpFlowFilter(packet);
      return [{
        correlationId: `corr-${queryRunId}-${index + 1}`,
        kind: "http_host_to_tcp" as const,
        sourcePacketId: packet.packetId,
        sourceEvidenceCardId,
        targetDisplayFilter: filter,
        relation: "HTTP Host/request 由同一个 TCP flow 承载。",
        confidence: "high" as const,
        summary: `HTTP Host ${packet.httpHost} 出现在该 TCP flow，可结合 TCP session 判断应用层还是传输层问题。`,
        reasons: [`Host=${packet.httpHost}`, packet.httpRequestUri ? `URI=${packet.httpRequestUri}` : "", `frame=${packet.frameNumber}`].filter(Boolean),
        nextSteps: [`用过滤器 ${filter} 查看该 HTTP 所在 TCP session。`]
      }];
    }
    // ICMP Unreachable / Fragmentation Needed → 对应 TCP 流
    if ((protocol === "icmp" || packet.protocol.toLowerCase() === "icmp") && packet.icmpType === 3 && packet.dstIp) {
      const filter = `ip.addr == ${packet.dstIp}`;
      const unreachableDesc: Record<number, string> = { 0: "Network Unreachable", 1: "Host Unreachable", 3: "Port Unreachable", 4: "Fragmentation Needed" };
      const desc = unreachableDesc[packet.icmpCode ?? -1] || `Code ${packet.icmpCode}`;
      return [{
        correlationId: `corr-${queryRunId}-${index + 1}`,
        kind: "icmp_to_tcp" as const,
        sourcePacketId: packet.packetId,
        sourceEvidenceCardId,
        targetDisplayFilter: filter,
        relation: `ICMP ${desc} 指向 ${packet.dstIp}，可能影响到达该地址的 TCP 连接。`,
        confidence: "high" as const,
        summary: `${packet.srcIp} 发送 ICMP ${desc} 给 ${packet.dstIp}，可能导致相关 TCP 连接中断。`,
        reasons: [`type=${packet.icmpType}/code=${packet.icmpCode}`, `src=${packet.srcIp}`, `dst=${packet.dstIp}`],
        nextSteps: [`用过滤器 ${filter} 查看受影响的 TCP 会话。`, packet.icmpCode === 4 ? "检查 Path MTU Discovery 设置，ICMP 被过滤可能导致 PMTU 黑洞。" : ""].filter(Boolean)
      }];
    }
    return [];
  });
}

// ── HTTP 跨连接关联（七层代理/SSL 卸载场景） ─────────────────────────

interface HttpTransaction {
  packetId: string;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  host?: string;
  uri?: string;
  method?: string;
  statusCode?: number;
  timestamp: number;
  xff?: string;
  via?: string;
  cookie?: string;
}

function httpTransactionsFromPackets(packets: PacketSummary[]): HttpTransaction[] {
  const result: HttpTransaction[] = [];
  for (const p of packets) {
    if (!p.srcIp || !p.dstIp || p.srcPort == null || p.dstPort == null) continue;
    if (p.httpRequestMethod) {
      result.push({
        packetId: p.packetId, srcIp: p.srcIp, srcPort: p.srcPort,
        dstIp: p.dstIp, dstPort: p.dstPort, host: p.httpHost,
        uri: p.httpRequestUri, method: p.httpRequestMethod, timestamp: p.timestamp,
        xff: p.httpXForwardedFor
      });
    }
    if (p.httpResponseCode != null) {
      result.push({
        packetId: p.packetId, srcIp: p.srcIp, srcPort: p.srcPort,
        dstIp: p.dstIp, dstPort: p.dstPort, host: p.httpHost,
        uri: p.httpRequestUri, statusCode: p.httpResponseCode, timestamp: p.timestamp,
        xff: p.httpXForwardedFor, via: p.httpVia, cookie: p.httpSetCookie
      });
    }
  }
  return result;
}

/**
 * 检测同一 Host/URI 在不同 TCP 连接（不同五元组）之间出现，
 * 关联客户端→代理和代理→后端两条独立连接。
 */
export function buildHttpCrossConnectionCorrelation(
  queryRunId: string,
  packets: PacketSummary[],
  cards: EvidenceCard[]
): ProtocolCorrelation[] {
  const txns = httpTransactionsFromPackets(packets);
  if (txns.length < 2) return [];

  // 按 Host+URI 分组
  const byResource = new Map<string, HttpTransaction[]>();
  for (const t of txns) {
    const key = `${t.host || ""}|${t.uri || ""}`;
    const group = byResource.get(key) || [];
    group.push(t);
    byResource.set(key, group);
  }

  const correlations: ProtocolCorrelation[] = [];
  let idx = 0;

  for (const [resource, group] of byResource) {
    if (group.length < 2) continue;

    // 找出不同的五元组方向
    const flowKeys = new Map<string, HttpTransaction[]>();
    for (const t of group) {
      const fk = `${t.srcIp}:${t.srcPort}->${t.dstIp}:${t.dstPort}`;
      const fGroup = flowKeys.get(fk) || [];
      fGroup.push(t);
      flowKeys.set(fk, fGroup);
    }

    if (flowKeys.size < 2) continue;

    const [host, uri] = resource.split("|");
    const flows = [...flowKeys.values()];

    // 找一对流：一个包含请求（method），一个包含请求且指向不同后端
    for (let i = 0; i < flows.length; i++) {
      for (let j = i + 1; j < flows.length; j++) {
        const flowA = flows[i];
        const flowB = flows[j];
        const aHasRequest = flowA.some(t => t.method);
        const bHasRequest = flowB.some(t => t.method);
        if (!aHasRequest && !bHasRequest) continue;

        // 两个流的 dstIp 或 dstPort 不同 → 不同的 TCP 连接
        const aDst = `${flowA[0].dstIp}:${flowA[0].dstPort}`;
        const bDst = `${flowB[0].dstIp}:${flowB[0].dstPort}`;
        if (aDst === bDst) continue;

        // 检查是否有一方包含 XFF/Via（更强的代理证据）
        const hasProxyHeaders = [...flowA, ...flowB].some(t => t.xff || t.via);
        const confidence: "high" | "low" = hasProxyHeaders ? "high" : "low";

        const sourceTxn = aHasRequest ? flowA[0] : flowB[0];
        const targetTxn = aHasRequest ? flowB[0] : flowA[0];
        const sourceCardId = cards.find(c => c.frameNumber === parseInt(sourceTxn.packetId.split("-").pop() || ""))?.cardId;

        idx++;
        correlations.push({
          correlationId: `corr-${queryRunId}-xc-${idx}`,
          kind: "http_to_http",
          sourcePacketId: sourceTxn.packetId,
          sourceEvidenceCardId: sourceCardId,
          targetDisplayFilter: `ip.addr == ${targetTxn.dstIp} && tcp.port == ${targetTxn.dstPort}`,
          relation: `Host ${host} 的同一请求 ${uri || "/"} 出现在两条不同 TCP 连接中，可能经过七层代理转发`,
          confidence,
          summary: `客户端→${aDst} 与 ${bDst} 两条连接包含同一 HTTP 请求（${host}${uri}），疑似代理/LB 转发${hasProxyHeaders ? "（存在 XFF/Via 头）" : ""}`,
          reasons: [
            `连接 A: ${flowA[0].srcIp}:${flowA[0].srcPort} → ${aDst}`,
            `连接 B: ${flowB[0].srcIp}:${flowB[0].srcPort} → ${bDst}`,
            hasProxyHeaders ? "存在 XFF 或 Via 代理头" : "无直接代理头，仅基于 URI 匹配"
          ],
          nextSteps: [
            `用 display filter 检查两条连接的完整会话`,
            "检查 mapping hint 是否记录了此代理关系"
          ]
        });

        break; // 每对资源只关联一次
      }
    }
  }

  return correlations;
}
