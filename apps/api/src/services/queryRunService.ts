import path from "node:path";
import { z } from "zod";
import {
  AnalysisFilterSchema,
  AccessCandidateGroupSchema,
  MappingHintSchema,
  QueryDiagnosisSchema,
  QueryRunInputSchema,
  QueryRunSchema,
  TimeOffsetHintSchema,
  type AgentAnswer,
  type CaseGraph,
  type Conversation,
  type EvidenceCard,
  type MappingHint,
  type PacketSummary,
  type QueryDiagnosis,
  type QueryPath,
  type QueryRun,
  type TimeOffsetHint
} from "../../../../packages/shared/src/index.js";
import {
  buildDisplayFilterWithMcp,
  getConversationPacketsWithMcp,
  listTcpConversationsWithMcp,
  queryPacketsWithMcp,
  type CaptureQueryInput
} from "../mcp/tsharkQueryClient.js";

type McpRunRecord = {
  target: string;
  summary: string;
  inputSummary: string;
  outputSummary: string;
  queryRunId?: string;
  evidenceCardIds?: string[];
  pcapFilename?: string;
  displayFilter?: string;
};

export function createQueryRunService(deps: {
  candidateGroupLimit: number;
  queryPacketLimit: number;
  conversationPacketLimit: number;
  retainedQueryRunLimit: number;
  shortConversationPacketThreshold: number;
  retransmissionBurstThreshold: number;
  duplicateAckBurstThreshold: number;
  evidencePacketSampleLimit: number;
  transportEvidencePacketSampleLimit: number;
  finEvidencePacketSampleLimit: number;
  timeOverlapToleranceSeconds: number;
  fallbackPatterns: {
    accessQueryIntent: string;
    accessQueryScope: string;
    captureCorrelation: string;
  };
  capturesDirectory: (caseId: string) => string;
  writeCaseGraph: (graph: CaseGraph) => void;
  setGraph: (caseId: string, graph: CaseGraph) => void;
  recordQueryRunMcp: (caseId: string, target: string, question: string, queryRun: QueryRun, summary: string, inputSummary: string, outputSummary: string) => unknown;
  recordMcpRun: (caseId: string, run: McpRunRecord) => unknown;
  formatBeijingTime: (epochSeconds: number) => string;
}) {
  function nodeName(graph: CaseGraph, nodeId: string) {
    return graph.captures.find((capture) => capture.nodeId === nodeId)?.name || nodeId;
  }
  
  function captureQueryInputs(graph: CaseGraph): CaptureQueryInput[] {
    return graph.captures
      .filter((capture) => capture.pcapFilename)
      .map((capture) => ({
        nodeId: capture.nodeId,
        name: capture.name,
        pcapFilename: capture.pcapFilename,
        pcapPath: path.join(deps.capturesDirectory(graph.spec.caseId), capture.pcapFilename!)
      }));
  }
  
  function sameConversationTuple(left: Conversation, right: Conversation) {
    const leftEndpoints = [`${left.srcIp || ""}:${left.srcPort ?? ""}`, `${left.dstIp || ""}:${left.dstPort ?? ""}`].sort().join("|");
    const rightEndpoints = [`${right.srcIp || ""}:${right.srcPort ?? ""}`, `${right.dstIp || ""}:${right.dstPort ?? ""}`].sort().join("|");
    return left.protocol === right.protocol && leftEndpoints === rightEndpoints;
  }
  
  function tupleHintHasValue(srcIp?: string, srcPort?: number, dstIp?: string, dstPort?: number) {
    return srcIp !== undefined || srcPort !== undefined || dstIp !== undefined || dstPort !== undefined;
  }
  
  function tupleFieldMatches<T>(actual: T | undefined, expected: T | undefined) {
    return expected === undefined || actual === expected;
  }
  
  function tupleMatchesEndpoint(conversation: Conversation, srcIp?: string, srcPort?: number, dstIp?: string, dstPort?: number) {
    if (!tupleHintHasValue(srcIp, srcPort, dstIp, dstPort)) return false;
    return tupleFieldMatches(conversation.srcIp, srcIp)
      && tupleFieldMatches(conversation.srcPort, srcPort)
      && tupleFieldMatches(conversation.dstIp, dstIp)
      && tupleFieldMatches(conversation.dstPort, dstPort);
  }
  
  function sameConversationByMapping(left: Conversation, right: Conversation, graph: CaseGraph) {
    return graph.mappingHints.some((hint) => {
      const nodeMatched = (!hint.fromNodeId || hint.fromNodeId === left.nodeId || hint.fromNodeId === right.nodeId)
        && (!hint.toNodeId || hint.toNodeId === left.nodeId || hint.toNodeId === right.nodeId);
      if (!nodeMatched) return false;
      const leftOriginal = tupleMatchesEndpoint(left, hint.originalSrcIp, hint.originalSrcPort, hint.originalDstIp, hint.originalDstPort)
        || tupleMatchesEndpoint(left, hint.originalDstIp, hint.originalDstPort, hint.originalSrcIp, hint.originalSrcPort);
      const rightTranslated = tupleMatchesEndpoint(right, hint.translatedSrcIp, hint.translatedSrcPort, hint.translatedDstIp, hint.translatedDstPort)
        || tupleMatchesEndpoint(right, hint.translatedDstIp, hint.translatedDstPort, hint.translatedSrcIp, hint.translatedSrcPort);
      const rightOriginal = tupleMatchesEndpoint(right, hint.originalSrcIp, hint.originalSrcPort, hint.originalDstIp, hint.originalDstPort)
        || tupleMatchesEndpoint(right, hint.originalDstIp, hint.originalDstPort, hint.originalSrcIp, hint.originalSrcPort);
      const leftTranslated = tupleMatchesEndpoint(left, hint.translatedSrcIp, hint.translatedSrcPort, hint.translatedDstIp, hint.translatedDstPort)
        || tupleMatchesEndpoint(left, hint.translatedDstIp, hint.translatedDstPort, hint.translatedSrcIp, hint.translatedSrcPort);
      return (leftOriginal && rightTranslated) || (rightOriginal && leftTranslated);
    });
  }
  
  function timeOffsetBetween(graph: CaseGraph, fromNodeId: string, toNodeId: string) {
    const direct = graph.timeOffsetHints.find((hint) => {
      if (!hint.fromNodeId && !hint.toNodeId) return false;
      return (!hint.fromNodeId || hint.fromNodeId === fromNodeId) && (!hint.toNodeId || hint.toNodeId === toNodeId);
    });
    if (direct) return direct.offsetSeconds;
  
    const reverse = graph.timeOffsetHints.find((hint) => {
      if (!hint.fromNodeId && !hint.toNodeId) return false;
      return (!hint.fromNodeId || hint.fromNodeId === toNodeId) && (!hint.toNodeId || hint.toNodeId === fromNodeId);
    });
    return reverse ? -reverse.offsetSeconds : 0;
  }
  
  function adjustedConversationWindow(conversation: Conversation, graph: CaseGraph, targetNodeId: string) {
    const offsetSeconds = timeOffsetBetween(graph, conversation.nodeId, targetNodeId);
    return {
      startTime: conversation.startTime + offsetSeconds,
      endTime: conversation.endTime + offsetSeconds,
      offsetSeconds
    };
  }
  
  function timeWindowsOverlap(left: { startTime: number; endTime: number }, right: { startTime: number; endTime: number }) {
    const tolerance = deps.timeOverlapToleranceSeconds;
    return left.startTime <= right.endTime + tolerance && right.startTime <= left.endTime + tolerance;
  }
  
  function conversationCorrelation(candidate: Conversation, selected: Conversation, graph: CaseGraph) {
    const type = sameConversationTuple(candidate, selected)
      ? "exact_tuple" as const
      : sameConversationByMapping(candidate, selected, graph)
        ? "mapping_hint" as const
        : "missing" as const;
    if (type === "missing") return { matched: false, type, reasons: [] };
  
    const adjusted = adjustedConversationWindow(candidate, graph, selected.nodeId);
    const overlaps = timeWindowsOverlap(adjusted, selected);
    const reasons = [
      type === "exact_tuple" ? "五元组 exact tuple 命中" : "通过 NAT/SLB/代理 mapping hint 关联",
      adjusted.offsetSeconds ? `按 time offset ${adjusted.offsetSeconds}s 对齐时间窗口` : "未配置 time offset，按原始时间比较",
      overlaps
        ? `时间窗口重叠：${deps.formatBeijingTime(adjusted.startTime)} - ${deps.formatBeijingTime(adjusted.endTime)}`
        : `时间窗口不重叠：${deps.formatBeijingTime(adjusted.startTime)} - ${deps.formatBeijingTime(adjusted.endTime)} vs ${deps.formatBeijingTime(selected.startTime)} - ${deps.formatBeijingTime(selected.endTime)}`
    ];
    if (!overlaps) return { matched: false, type: "needs_context" as const, reasons };
    return { matched: true, type, reasons };
  }
  
  function edgeTimeDeltaSeconds(left: { nodeId: string; startTime?: number }, right: { nodeId: string; startTime?: number }, graph: CaseGraph) {
    if (left.startTime === undefined || right.startTime === undefined) return undefined;
    return right.startTime + timeOffsetBetween(graph, right.nodeId, left.nodeId) - left.startTime;
  }
  
  function edgeDiagnosis(currentHop: QueryPath["hops"][number], nextHop: QueryPath["hops"][number], graph: CaseGraph) {
    const timeDeltaSeconds = edgeTimeDeltaSeconds(currentHop, nextHop, graph);
    if (currentHop.status === "observed" && nextHop.status === "observed") {
      const viaMapping = currentHop.correlation === "mapping_hint" || nextHop.correlation === "mapping_hint";
      return {
        status: "observed" as const,
        label: viaMapping ? "通过 mapping hint 关联" : "相邻节点 exact tuple 命中",
        diagnosis: viaMapping ? "上下游均观察到候选会话，并通过 mapping hint 串联。" : "上下游均观察到同一五元组候选会话，路径连续。",
        reasons: [
          ...currentHop.correlationReasons,
          ...nextHop.correlationReasons,
          timeDeltaSeconds !== undefined ? `下游首包相对上游首包 ${timeDeltaSeconds.toFixed(3)}s` : ""
        ].filter(Boolean),
        nextSteps: viaMapping ? ["确认 NAT/F5/LB/代理映射是否覆盖本次访问。"] : [],
        timeDeltaSeconds
      };
    }
    if (currentHop.status === "observed" && nextHop.correlation === "needs_context") {
      return {
        status: "needs_context" as const,
        label: "需要补充映射或时间偏移",
        diagnosis: "上游节点观察到该访问，但下游未形成可确认关联。",
        reasons: nextHop.correlationReasons,
        nextSteps: ["确认两个节点抓包时间是否对齐。", "补充或修正 NAT/F5/LB/代理 mapping hint。", "确认下游抓包方向和过滤条件。"],
        timeDeltaSeconds
      };
    }
    if (currentHop.correlation === "needs_context" && nextHop.status === "observed") {
      return {
        status: "needs_context" as const,
        label: "需要补充上游证据",
        diagnosis: "下游节点观察到候选访问，但上游未形成可确认关联。",
        reasons: currentHop.correlationReasons,
        nextSteps: ["确认上游抓包是否覆盖故障时间。", "确认是否存在 NAT/F5/LB/代理或时间偏移。"],
        timeDeltaSeconds
      };
    }
    if (currentHop.status === "observed" || nextHop.status === "observed") {
      return {
        status: "suspect" as const,
        label: "单侧命中",
        diagnosis: currentHop.status === "observed" ? "上游可见、下游缺失，断点更可能位于该边或下游抓包覆盖范围。" : "下游可见、上游缺失，需要先复核上游抓包覆盖和时间。",
        reasons: [...currentHop.correlationReasons, ...nextHop.correlationReasons],
        nextSteps: ["复核抓包方向、时间窗口和过滤条件。", "如存在地址转换，补充 mapping hint。"],
        timeDeltaSeconds
      };
    }
    return {
      status: "unknown" as const,
      label: "未形成路径",
      diagnosis: "相邻两个节点都没有形成可确认候选访问。",
      reasons: [...currentHop.correlationReasons, ...nextHop.correlationReasons],
      nextSteps: ["缩小查询时间、源、目的、端口，或补充节点上下文。"],
      timeDeltaSeconds
    };
  }
  
  function conversationGroupKey(conversation: Conversation) {
    return [
      conversation.protocol,
      `${conversation.srcIp || ""}:${conversation.srcPort ?? ""}`,
      `${conversation.dstIp || ""}:${conversation.dstPort ?? ""}`
    ].sort().join("|");
  }
  
  function accessGroupKey(conversation: Conversation, query: z.infer<typeof QueryRunInputSchema>) {
    const protocol = (query.protocol || conversation.protocol || "tcp").toLowerCase();
    const srcIp = query.srcIp || conversation.srcIp || conversation.dstIp || "";
    const dstIp = query.dstIp || (conversation.dstPort === query.port ? conversation.dstIp : conversation.dstIp || conversation.srcIp || "");
    const dstPort = query.port || (conversation.dstIp === dstIp ? conversation.dstPort : conversation.srcPort);
    return [protocol, srcIp, dstIp, dstPort ?? ""].join("|");
  }
  
  function rankedConversation(conversation: Conversation, query: z.infer<typeof QueryRunInputSchema>) {
    const reasons: string[] = [];
    let score = 0;
    if (query.srcIp && (conversation.srcIp === query.srcIp || conversation.dstIp === query.srcIp)) {
      score += 1200;
      reasons.push(`匹配源地址 ${query.srcIp}`);
    }
    if (query.dstIp && (conversation.srcIp === query.dstIp || conversation.dstIp === query.dstIp)) {
      score += 1200;
      reasons.push(`匹配目的地址 ${query.dstIp}`);
    }
    if (query.port && (conversation.srcPort === query.port || conversation.dstPort === query.port)) {
      score += 1000;
      reasons.push(`匹配端口 ${query.port}`);
    }
    if (conversation.rstCount) {
      score += conversation.rstCount * 900;
      reasons.push(`存在 RST ${conversation.rstCount} 个`);
    }
    if (conversation.zeroWindowCount) {
      score += conversation.zeroWindowCount * 700;
      reasons.push(`存在 Zero Window ${conversation.zeroWindowCount} 个`);
    }
    if (conversation.retransmissionCount) {
      score += conversation.retransmissionCount * 300;
      reasons.push(`存在重传 ${conversation.retransmissionCount} 个`);
    }
    if (conversation.packetCount <= deps.shortConversationPacketThreshold) {
      score += 180;
      reasons.push("包数很少，可能是短连接或异常流");
    }
    score += Math.min(conversation.packetCount, 200);
    return { ...conversation, rankScore: score, rankReasons: reasons.length ? reasons : ["符合当前查询条件"] };
  }
  
  function conversationFailed(conversation: Conversation) {
    return conversation.rstCount > 0 || conversation.packetCount <= deps.shortConversationPacketThreshold;
  }
  
  function conversationMode(conversation: Conversation) {
    if (conversation.rstCount > 0) return { kind: "rst_ended", label: "RST 结束" };
    if (conversation.zeroWindowCount > 0) return { kind: "zero_window", label: "Zero Window" };
    if (conversation.retransmissionCount > 0) return { kind: "retransmission_completed", label: "有重传但未见 RST" };
    if (conversation.packetCount <= deps.shortConversationPacketThreshold) return { kind: "short_or_incomplete", label: "短流/疑似未完成" };
    if (conversation.tcpFlags.includes("SYN") && conversation.tcpFlags.includes("ACK") && conversation.tcpFlags.includes("FIN")) return { kind: "handshake_and_close_seen", label: "建连并关闭" };
    return { kind: "observed_no_obvious_issue", label: "未见明显 TCP 异常" };
  }
  
  function conversationModeDistribution(conversations: Conversation[]) {
    const modes = new Map<string, { kind: string; label: string; conversationIds: string[] }>();
    for (const conversation of conversations) {
      const mode = conversationMode(conversation);
      const current = modes.get(mode.kind) || { ...mode, conversationIds: [] };
      current.conversationIds.push(conversation.conversationId);
      modes.set(mode.kind, current);
    }
    return [...modes.values()]
      .map((mode) => ({ ...mode, count: mode.conversationIds.length }))
      .sort((left, right) => right.count - left.count);
  }
  
  function buildAccessCandidateGroups(conversations: Conversation[], query: z.infer<typeof QueryRunInputSchema>) {
    const ranked = conversations.map((conversation) => conversation.rankReasons.length ? conversation : rankedConversation(conversation, query));
    const groups = new Map<string, Conversation[]>();
    for (const conversation of ranked) {
      const key = accessGroupKey(conversation, query);
      groups.set(key, [...(groups.get(key) || []), conversation]);
    }
    return [...groups.entries()].map(([key, group], index) => {
      const [protocol, srcIp, dstIp, dstPortValue] = key.split("|");
      const sorted = [...group].sort((left, right) => right.rankScore - left.rankScore);
      const failureCount = sorted.filter(conversationFailed).length;
      const successCount = sorted.length - failureCount;
      const rstCount = sorted.reduce((sum, conversation) => sum + conversation.rstCount, 0);
      const retransmissionCount = sorted.reduce((sum, conversation) => sum + conversation.retransmissionCount, 0);
      const zeroWindowCount = sorted.reduce((sum, conversation) => sum + conversation.zeroWindowCount, 0);
      const failureModes = conversationModeDistribution(sorted);
      const firstSeen = Math.min(...sorted.map((conversation) => conversation.startTime));
      const lastSeen = Math.max(...sorted.map((conversation) => conversation.endTime));
      const rankReasons = [
        query.srcIp ? `匹配源地址 ${query.srcIp}` : "",
        query.dstIp ? `匹配目的地址 ${query.dstIp}` : "",
        query.port ? `匹配服务端口 ${query.port}` : "",
        failureCount ? `失败/异常 ${failureCount} 条` : "",
        rstCount ? `RST ${rstCount} 个` : "",
        retransmissionCount ? `重传 ${retransmissionCount} 个` : "",
        zeroWindowCount ? `Zero Window ${zeroWindowCount} 个` : ""
      ].filter(Boolean);
      return AccessCandidateGroupSchema.parse({
        groupId: `access-${index + 1}`,
        protocol,
        srcIp: srcIp || undefined,
        dstIp: dstIp || undefined,
        dstPort: dstPortValue ? Number(dstPortValue) : undefined,
        conversationIds: sorted.map((conversation) => conversation.conversationId),
        selectedConversationId: sorted[0]?.conversationId,
        conversationCount: sorted.length,
        successCount,
        failureCount,
        rstCount,
        retransmissionCount,
        zeroWindowCount,
        failureModes,
        firstSeen: Number.isFinite(firstSeen) ? firstSeen : undefined,
        lastSeen: Number.isFinite(lastSeen) ? lastSeen : undefined,
        rankScore: Math.max(...sorted.map((conversation) => conversation.rankScore)) + failureCount * 100,
        rankReasons: rankReasons.length ? rankReasons : ["符合当前查询条件"],
        summary: `${srcIp || "*"} -> ${dstIp || "*"}:${dstPortValue || "*"}，${sorted.length} 条 TCP conversation。`
      });
    }).sort((left, right) => right.rankScore - left.rankScore).slice(0, deps.candidateGroupLimit);
  }
  
  function rankedCandidateConversations(conversations: Conversation[], query: z.infer<typeof QueryRunInputSchema>) {
    const ranked = conversations.map((conversation) => rankedConversation(conversation, query));
    const groupConversationIds = new Set(buildAccessCandidateGroups(ranked, query).flatMap((group) => group.conversationIds));
    return ranked
      .filter((conversation) => groupConversationIds.has(conversation.conversationId))
      .sort((left, right) => right.rankScore - left.rankScore);
  }
  
  function conversationIdentity(conversation: Conversation) {
    const endpoints = [`${conversation.srcIp || ""}:${conversation.srcPort ?? ""}`, `${conversation.dstIp || ""}:${conversation.dstPort ?? ""}`].sort().join("|");
    return [conversation.nodeId, conversation.pcapFilename, conversation.protocol, endpoints].join("|");
  }
  
  function normalizeConversations(conversations: Conversation[], queryRunId: string) {
    const unique = new Map<string, Conversation>();
    for (const conversation of conversations) {
      if (!unique.has(conversationIdentity(conversation))) unique.set(conversationIdentity(conversation), conversation);
    }
    return [...unique.values()].map((conversation, index) => ({
      ...conversation,
      conversationId: `${queryRunId}-conversation-${index + 1}`
    }));
  }
  
  function packetIdentity(packet: PacketSummary) {
    return `${packet.nodeId}:${packet.pcapFilename}:${packet.frameNumber}`;
  }
  
  function uniquePackets(packets: PacketSummary[]) {
    const unique = new Map<string, PacketSummary>();
    for (const packet of packets) {
      if (!unique.has(packetIdentity(packet))) unique.set(packetIdentity(packet), packet);
    }
    return [...unique.values()].sort((left, right) => left.timestamp - right.timestamp || left.frameNumber - right.frameNumber);
  }
  
  function queryMatchesTuple(input: z.infer<typeof QueryRunInputSchema>, srcIp?: string, srcPort?: number, dstIp?: string, dstPort?: number) {
    if (!tupleHintHasValue(srcIp, srcPort, dstIp, dstPort)) return false;
    const srcMatched = !input.srcIp || srcIp === undefined || input.srcIp === srcIp || input.srcIp === dstIp;
    const dstMatched = !input.dstIp || dstIp === undefined || input.dstIp === dstIp || input.dstIp === srcIp;
    const portMatched = input.port === undefined || (srcPort === undefined && dstPort === undefined) || input.port === srcPort || input.port === dstPort;
    return srcMatched && dstMatched && portMatched;
  }
  
  function mappedQueryInputs(input: z.infer<typeof QueryRunInputSchema>, graph: CaseGraph) {
    const variants: Array<z.infer<typeof QueryRunInputSchema>> = [];
    for (const hint of graph.mappingHints) {
      if (queryMatchesTuple(input, hint.originalSrcIp, hint.originalSrcPort, hint.originalDstIp, hint.originalDstPort)) {
        variants.push(QueryRunInputSchema.parse({
          ...input,
          srcIp: hint.translatedSrcIp || input.srcIp,
          dstIp: hint.translatedDstIp || input.dstIp,
          port: input.port === hint.originalSrcPort ? hint.translatedSrcPort : input.port === hint.originalDstPort ? hint.translatedDstPort : input.port
        }));
      }
      if (queryMatchesTuple(input, hint.translatedSrcIp, hint.translatedSrcPort, hint.translatedDstIp, hint.translatedDstPort)) {
        variants.push(QueryRunInputSchema.parse({
          ...input,
          srcIp: hint.originalSrcIp || input.srcIp,
          dstIp: hint.originalDstIp || input.dstIp,
          port: input.port === hint.translatedSrcPort ? hint.originalSrcPort : input.port === hint.translatedDstPort ? hint.originalDstPort : input.port
        }));
      }
    }
    return variants;
  }
  
  function timeShiftedQueryInputs(input: z.infer<typeof QueryRunInputSchema>, graph: CaseGraph) {
    if (input.timeRange.start === undefined && input.timeRange.end === undefined) return [];
    const offsets = [...new Set(graph.timeOffsetHints.flatMap((hint) => [hint.offsetSeconds, -hint.offsetSeconds]).filter((offset) => offset !== 0))];
    return offsets.map((offset) => QueryRunInputSchema.parse({
      ...input,
      timeRange: {
        start: input.timeRange.start === undefined ? undefined : input.timeRange.start + offset,
        end: input.timeRange.end === undefined ? undefined : input.timeRange.end + offset
      }
    }));
  }
  
  async function queryDisplayFilters(graph: CaseGraph, input: z.infer<typeof QueryRunInputSchema>) {
    const mappedInputs = [input, ...mappedQueryInputs(input, graph)];
    const inputs = [...mappedInputs, ...mappedInputs.flatMap((item) => timeShiftedQueryInputs(item, graph))];
    const filters = await Promise.all(inputs.map((item) => buildDisplayFilterWithMcp({
      start: item.timeRange.start,
      end: item.timeRange.end,
      srcIp: item.srcIp,
      dstIp: item.dstIp,
      port: item.port,
      protocol: item.protocol || "tcp"
    })));
    return [...new Set(filters.map((filter) => filter.displayFilter))];
  }
  
  function conversationAnomalies(conversation: Conversation) {
    return [
      conversation.rstCount ? `RST ${conversation.rstCount}` : "",
      conversation.retransmissionCount ? `重传 ${conversation.retransmissionCount}` : "",
      conversation.zeroWindowCount ? `Zero Window ${conversation.zeroWindowCount}` : ""
    ].filter(Boolean);
  }
  
  function buildQueryPath(graph: CaseGraph, queryRunId: string, conversationId: string, conversations: Conversation[]): QueryPath {
    const selected = conversations.find((conversation) => conversation.conversationId === conversationId);
    const correlated = selected
      ? conversations
        .map((conversation) => ({ conversation, correlation: conversationCorrelation(conversation, selected, graph) }))
      : [];
    const related = correlated.filter((item) => item.correlation.matched);
    const blocked = correlated.filter((item) => !item.correlation.matched && item.correlation.type === "needs_context");
    const hops = graph.captures.map((capture) => {
      const relatedItem = related.find((item) => item.conversation.nodeId === capture.nodeId && item.conversation.conversationId === conversationId)
        || related.find((item) => item.conversation.nodeId === capture.nodeId);
      const blockedItem = selected ? blocked.find((item) => item.conversation.nodeId === capture.nodeId) : undefined;
      const conversation = relatedItem?.conversation;
      if (!conversation || !relatedItem) {
        return {
          hopId: `hop-${queryRunId}-${capture.nodeId}`,
          nodeId: capture.nodeId,
          conversationId,
          observedTuple: "-",
          status: "missing" as const,
          packetCount: 0,
          anomalies: blockedItem ? ["存在候选通讯对，但时间窗口不重叠"] : graph.mappingHints.length ? ["当前节点未命中，可能需要补充或修正 mapping/time offset 线索"] : ["当前查询未在该节点命中通讯对"],
          wiresharkFilter: selected?.displayFilter || "tcp",
          correlation: blockedItem || graph.mappingHints.length || graph.timeOffsetHints.length ? "needs_context" as const : "missing" as const,
          correlationReasons: blockedItem?.correlation.reasons || (graph.mappingHints.length || graph.timeOffsetHints.length ? ["存在 mapping/time offset hint，但该节点未关联到候选 conversation"] : ["未找到 exact tuple 或 mapping hint 匹配"])
        };
      }
      return {
        hopId: `hop-${queryRunId}-${capture.nodeId}`,
        nodeId: capture.nodeId,
        conversationId: conversation.conversationId,
        observedTuple: `${conversation.srcIp || "*"}:${conversation.srcPort ?? "*"} -> ${conversation.dstIp || "*"}:${conversation.dstPort ?? "*"}`,
        status: "observed" as const,
        startTime: conversation.startTime,
        endTime: conversation.endTime,
        packetCount: conversation.packetCount,
        anomalies: conversationAnomalies(conversation),
        wiresharkFilter: conversation.displayFilter,
        correlation: relatedItem.correlation.type,
        correlationReasons: relatedItem.correlation.reasons
      };
    });
    const edges = graph.captures.slice(0, -1).map((capture, index) => {
      const next = graph.captures[index + 1];
      const currentHop = hops[index];
      const nextHop = hops[index + 1];
      const diagnosis = edgeDiagnosis(currentHop, nextHop, graph);
      return {
        edgeId: `edge-${queryRunId}-${capture.nodeId}-${next.nodeId}`,
        fromNodeId: capture.nodeId,
        toNodeId: next.nodeId,
        ...diagnosis
      };
    });
    const observedCount = hops.filter((hop) => hop.status === "observed").length;
    const missingHops = hops.filter((hop) => hop.status === "missing").map((hop) => hop.nodeId);
  
    return {
      queryRunId,
      conversationId,
      hops,
      edges,
      missingHops,
      confidence: observedCount && !missingHops.length ? "high" as const : observedCount ? "needs_context" as const : "low" as const,
      summary: observedCount
        ? `当前通讯对在 ${observedCount}/${graph.captures.length} 个抓包节点命中；${hops.filter((hop) => hop.correlation === "mapping_hint").length} 个节点通过 mapping hint 关联。`
        : "当前通讯对没有形成可观测路径。"
    };
  }
  
  function hasFlag(packet: PacketSummary, flag: string) {
    return packet.tcpFlags.includes(flag);
  }
  
  function sameEndpoint(packet: PacketSummary, srcIp?: string, srcPort?: number, dstIp?: string, dstPort?: number) {
    return packet.srcIp === srcIp && packet.srcPort === srcPort && packet.dstIp === dstIp && packet.dstPort === dstPort;
  }
  
  function packetDirection(packet: PacketSummary, conversation: Conversation) {
    if (sameEndpoint(packet, conversation.srcIp, conversation.srcPort, conversation.dstIp, conversation.dstPort)) return "forward";
    if (sameEndpoint(packet, conversation.dstIp, conversation.dstPort, conversation.srcIp, conversation.srcPort)) return "reverse";
    return "unknown";
  }
  
  function captureTimeRanges(graph: CaseGraph) {
    return graph.captures.map((capture) => {
      return {
        nodeId: capture.nodeId,
        start: capture.firstPacketTime,
        end: capture.lastPacketTime
      };
    });
  }
  
  function buildQueryDiagnosis(graph: CaseGraph, queryRunId: string, conversation: Conversation, packets: PacketSummary[], pathResult: QueryPath): QueryDiagnosis {
    const checks: QueryDiagnosis["checks"] = [];
    const tags: QueryDiagnosis["diagnosticTags"] = [];
    const evidence: QueryDiagnosis["evidence"] = [];
    const findings: QueryDiagnosis["findings"] = [];
    const nextSteps = new Set<string>();
    const firstPacketId = packets[0]?.packetId;
    const addCheck = (
      key: QueryDiagnosis["checks"][number]["key"],
      label: string,
      status: QueryDiagnosis["checks"][number]["status"],
      summary: string,
      packetIds: string[] = [],
      steps: string[] = []
    ) => {
      checks.push({ key, label, status, summary, packetIds, nextSteps: steps });
      if (status === "problem" || status === "warn") steps.forEach((step) => nextSteps.add(step));
    };
    const addTag = (kind: QueryDiagnosis["diagnosticTags"][number]["kind"], summary: string, packetIds: string[], confidence: QueryDiagnosis["confidence"], steps: string[]) => {
      const tagId = `query-tag-${queryRunId}-${tags.length + 1}`;
      const evidenceId = `query-evidence-${queryRunId}-${evidence.length + 1}`;
      tags.push({
        tagId,
        kind,
        nodeIds: [conversation.nodeId],
        segmentIds: [],
        packetIds,
        evidenceIds: [evidenceId],
        confidence,
        summary,
        nextSteps: steps
      });
      evidence.push({
        evidenceId,
        kind,
        title: summary,
        nodeId: conversation.nodeId,
        packetIds,
        detail: summary,
        confidence
      });
      steps.forEach((step) => nextSteps.add(step));
    };
  
    const forwardPackets = packets.filter((packet) => packetDirection(packet, conversation) === "forward");
    const reversePackets = packets.filter((packet) => packetDirection(packet, conversation) === "reverse");
    const synPackets = forwardPackets.filter((packet) => hasFlag(packet, "SYN") && !hasFlag(packet, "ACK"));
    const synAckPackets = reversePackets.filter((packet) => hasFlag(packet, "SYN") && hasFlag(packet, "ACK"));
    const rstPackets = packets.filter((packet) => hasFlag(packet, "RST"));
    const retransmissionPackets = packets.filter((packet) => packet.tcpAnalysis?.retransmission || packet.tcpAnalysis?.fastRetransmission);
    const duplicateAckPackets = packets.filter((packet) => packet.tcpAnalysis?.duplicateAck);
    const zeroWindowPackets = packets.filter((packet) => packet.tcpAnalysis?.zeroWindow);
    const forwardFinPackets = forwardPackets.filter((packet) => hasFlag(packet, "FIN"));
    const reverseFinPackets = reversePackets.filter((packet) => hasFlag(packet, "FIN"));
    const handshakeAckPackets = synAckPackets.length
      ? forwardPackets.filter((packet) => packet.timestamp >= synAckPackets[0].timestamp && hasFlag(packet, "ACK") && !hasFlag(packet, "SYN"))
      : [];
    const evidenceSampleLimit = deps.evidencePacketSampleLimit;
    const transportSampleLimit = deps.transportEvidencePacketSampleLimit;
    const finSampleLimit = deps.finEvidencePacketSampleLimit;
  
    if (synPackets.length && synAckPackets.length && handshakeAckPackets.length) {
      addCheck("handshake", "建连", "ok", `三次握手完整：SYN frame ${synPackets[0].frameNumber}，SYN-ACK frame ${synAckPackets[0].frameNumber}，ACK frame ${handshakeAckPackets[0].frameNumber}。`, [synPackets[0].packetId, synAckPackets[0].packetId, handshakeAckPackets[0].packetId]);
    } else if (synPackets.length && synAckPackets.length) {
      addCheck("handshake", "建连", "warn", `看到 SYN 和 SYN-ACK，但当前样本内未确认第三次 ACK。`, [synPackets[0].packetId, synAckPackets[0].packetId], ["在 Wireshark 中查看握手后续 ACK，确认抓包窗口和方向是否覆盖完整建连。"]);
    } else if (synPackets.length) {
      addCheck("handshake", "建连", "problem", "看到 SYN，但没有看到对应 SYN-ACK，建连可能未完成。", synPackets.slice(0, evidenceSampleLimit).map((packet) => packet.packetId), ["检查服务端回包路径、防火墙策略、服务监听状态和抓包方向。"]);
    } else {
      addCheck("handshake", "建连", "unknown", "当前样本没有看到完整建连起点，可能抓包开始时间晚于会话建立。");
    }
  
    if (rstPackets.length) {
      const firstRst = rstPackets.sort((left, right) => left.timestamp - right.timestamp)[0];
      const direction = packetDirection(firstRst, conversation) === "forward" ? "访问方向" : packetDirection(firstRst, conversation) === "reverse" ? "返回方向" : "未知方向";
      addCheck("rst", "RST", "problem", `RST 首次出现在 ${nodeName(graph, firstRst.nodeId)}，${direction}，frame ${firstRst.frameNumber}。`, [firstRst.packetId], ["在 Wireshark 中查看 RST 前序包、序列号和 ACK，判断是端侧主动复位还是中间设备注入。"]);
    } else {
      addCheck("rst", "RST", "ok", "当前 TCP session 未看到 RST。");
    }
  
    if (forwardPackets.length && reversePackets.length) {
      addCheck("traffic_direction", "双向流量", "ok", `双向均有流量：访问方向 ${forwardPackets.length} 个包，返回方向 ${reversePackets.length} 个包。`);
    } else if (forwardPackets.length || reversePackets.length) {
      addCheck("traffic_direction", "双向流量", "problem", `只看到${forwardPackets.length ? "访问方向" : "返回方向"}流量，未看到对端返回。`, (forwardPackets.length ? forwardPackets : reversePackets).slice(0, evidenceSampleLimit).map((packet) => packet.packetId), ["检查回程路由、ACL、防火墙会话表和抓包点方向。"]);
    } else {
      addCheck("traffic_direction", "双向流量", "unknown", "当前 session 没有可用于判断方向的包。");
    }
  
    if (retransmissionPackets.length >= deps.retransmissionBurstThreshold) {
      addCheck("retransmission", "重传", "problem", `发现 ${retransmissionPackets.length} 个重传包，达到集中重传阈值。`, retransmissionPackets.slice(0, transportSampleLimit).map((packet) => packet.packetId), ["检查链路丢包、拥塞、路径 MTU 和中间设备丢弃。"]);
    } else if (retransmissionPackets.length) {
      addCheck("retransmission", "重传", "warn", `发现 ${retransmissionPackets.length} 个重传包，暂未达到集中重传阈值。`, retransmissionPackets.slice(0, transportSampleLimit).map((packet) => packet.packetId), ["结合业务失败时间点确认这些重传是否集中出现。"]);
    } else {
      addCheck("retransmission", "重传", "ok", "当前 TCP session 未看到 tshark 标记的重传。");
    }
  
    if (zeroWindowPackets.length) {
      addCheck("zero_window", "窗口", "problem", `发现 ${zeroWindowPackets.length} 个 Zero Window。`, zeroWindowPackets.slice(0, transportSampleLimit).map((packet) => packet.packetId), ["检查接收端处理能力、应用读取速度和接收窗口恢复情况。"]);
    } else {
      addCheck("zero_window", "窗口", "ok", "当前 TCP session 未看到 Zero Window。");
    }
  
    if (rstPackets.length) {
      addCheck("close_state", "关闭", "warn", "连接以 RST 相关行为结束或被复位，不能视为正常 FIN 关闭。", rstPackets.slice(0, evidenceSampleLimit).map((packet) => packet.packetId), ["结合 RST 方向判断是客户端、服务端还是中间设备触发复位。"]);
    } else if (forwardFinPackets.length && reverseFinPackets.length) {
      addCheck("close_state", "关闭", "ok", `看到双侧 FIN：访问方向 ${forwardFinPackets.length} 个，返回方向 ${reverseFinPackets.length} 个。`, [forwardFinPackets[0].packetId, reverseFinPackets[0].packetId]);
    } else if (forwardFinPackets.length || reverseFinPackets.length) {
      addCheck("close_state", "关闭", "warn", "连接关闭阶段只看到单侧 FIN，未看到对端完整关闭。", [...forwardFinPackets, ...reverseFinPackets].slice(0, finSampleLimit).map((packet) => packet.packetId), ["确认抓包窗口是否覆盖完整关闭阶段，检查对端是否异常退出或路径丢包。"]);
    } else {
      addCheck("close_state", "关闭", "unknown", "当前样本未看到 FIN/RST，可能抓包窗口没有覆盖关闭阶段。");
    }
  
    const observedHopCount = pathResult.hops.filter((hop) => hop.status === "observed").length;
    if (graph.captures.length <= 1) {
      addCheck("path", "路径", "ok", "当前只有一个抓包节点，路径判断限定为单节点证据。");
    } else if (!pathResult.missingHops.length) {
      addCheck("path", "路径", "ok", `当前 TCP session 在 ${observedHopCount}/${graph.captures.length} 个抓包节点命中。`);
    } else if (observedHopCount) {
      addCheck("path", "路径", "warn", `当前 TCP session 只在 ${observedHopCount}/${graph.captures.length} 个抓包节点命中。`, firstPacketId ? [firstPacketId] : [], ["确认节点顺序、抓包位置、接口方向、NAT/SLB 映射线索和时间偏移。"]);
    } else {
      addCheck("path", "路径", "problem", "当前 TCP session 没有形成可观测路径。", firstPacketId ? [firstPacketId] : [], ["重新核对查询条件、抓包文件和时间范围。"]);
    }
  
    if (synPackets.length && !synAckPackets.length) {
      addTag("syn_sent_no_synack", "看到 SYN，但没有看到对应 SYN-ACK，建连可能未完成。", synPackets.slice(0, evidenceSampleLimit).map((packet) => packet.packetId), "high", ["检查服务端回包路径、防火墙策略、服务监听状态和抓包方向。"]);
    }
    if (rstPackets.length) {
      const firstRst = rstPackets.sort((left, right) => left.timestamp - right.timestamp)[0];
      addTag("rst_first_seen_at_node", `RST 首次出现在 ${nodeName(graph, firstRst.nodeId)}，帧号 ${firstRst.frameNumber}。`, [firstRst.packetId], "high", ["在 Wireshark 中查看 RST 的方向、序列号和前序包，确认是客户端、服务端还是中间设备触发。"]);
    }
    if (forwardPackets.length && !reversePackets.length) {
      addTag("one_way_traffic", "当前通讯对只有一个方向的流量，未看到对端返回。", forwardPackets.slice(0, evidenceSampleLimit).map((packet) => packet.packetId), "high", ["检查回程路由、ACL、防火墙会话表和抓包点方向。"]);
    }
    if (retransmissionPackets.length >= deps.retransmissionBurstThreshold) {
      addTag("retransmission_burst", `发现 ${retransmissionPackets.length} 个重传包。`, retransmissionPackets.slice(0, transportSampleLimit).map((packet) => packet.packetId), "high", ["检查链路丢包、拥塞、路径 MTU 和中间设备丢弃。"]);
    }
    if (duplicateAckPackets.length >= deps.duplicateAckBurstThreshold) {
      addTag("dup_ack_burst", `发现 ${duplicateAckPackets.length} 个 Dup ACK。`, duplicateAckPackets.slice(0, transportSampleLimit).map((packet) => packet.packetId), "high", ["结合重传包检查是否存在单段丢失或乱序。"]);
    }
    if (zeroWindowPackets.length) {
      addTag("zero_window", `发现 ${zeroWindowPackets.length} 个 Zero Window。`, zeroWindowPackets.slice(0, transportSampleLimit).map((packet) => packet.packetId), "high", ["检查接收端处理能力、应用读取速度和接收窗口恢复情况。"]);
    }
    if ((forwardFinPackets.length && !reverseFinPackets.length) || (reverseFinPackets.length && !forwardFinPackets.length)) {
      addTag("fin_without_peer_fin_ack", "连接关闭阶段只看到单侧 FIN，未看到对端完整关闭。", [...forwardFinPackets, ...reverseFinPackets].slice(0, finSampleLimit).map((packet) => packet.packetId), "low", ["确认抓包窗口是否覆盖完整关闭阶段，检查对端是否异常退出或路径丢包。"]);
    }
    if (graph.captures.length > 1 && pathResult.hops.filter((hop) => hop.status === "observed").length === 1) {
      addTag("session_seen_on_one_node_only", "当前通讯对只在一个抓包节点出现。", firstPacketId ? [firstPacketId] : [], "needs_context", ["确认节点顺序、抓包位置、接口方向和过滤条件是否正确。"]);
    }
    if (graph.captures.length > 1 && pathResult.missingHops.length && synPackets.length) {
      addTag("syn_seen_at_a_missing_at_b", "某一节点看到 SYN，但相邻节点未命中同一通讯对。", synPackets.slice(0, evidenceSampleLimit).map((packet) => packet.packetId), "needs_context", ["检查两个节点之间的路由、ACL、NAT/SLB 转换线索和时间偏移。"]);
    }
    if (graph.captures.length > 1 && pathResult.missingHops.length && !graph.mappingHints.length) {
      addTag("nat_mapping_required_but_missing", "多节点路径缺失，且没有 NAT/SLB/代理映射线索。", firstPacketId ? [firstPacketId] : [], "needs_context", ["补充 NAT、SLB、代理或网关地址转换关系后重新查询。"]);
    }
    const ranges = captureTimeRanges(graph).filter((range) => range.start !== undefined && range.end !== undefined);
    if (ranges.length > 1 && Math.max(...ranges.map((range) => range.start!)) > Math.min(...ranges.map((range) => range.end!))) {
      addTag("time_window_not_overlapped", "多个抓包节点的时间窗口不重叠。", [], "needs_context", ["补充时间偏移线索，或重新提供覆盖同一故障时间段的抓包。"]);
    }
  
    if (tags.length) {
      findings.push({
        findingId: `query-finding-${queryRunId}-1`,
        title: "当前通讯对存在需要优先核查的 TCP 行为",
        summary: tags.map((tag) => tag.summary).join("；"),
        tagIds: tags.map((tag) => tag.tagId),
        evidenceIds: evidence.map((event) => event.evidenceId),
        packetIds: [...new Set(tags.flatMap((tag) => tag.packetIds))],
        confidence: tags.some((tag) => tag.confidence === "high") ? "high" : "needs_context",
        nextSteps: [...nextSteps]
      });
    }
    const failedChecks = checks.filter((check) => check.status === "problem");
    const warningChecks = checks.filter((check) => check.status === "warn");
    const okChecks = checks.filter((check) => check.status === "ok");
    const summary = failedChecks.length
      ? `当前 TCP session 存在 ${failedChecks.length} 项明确异常：${failedChecks.map((check) => check.label).join("、")}。`
      : warningChecks.length
        ? `当前 TCP session 有 ${warningChecks.length} 项需要复核：${warningChecks.map((check) => check.label).join("、")}。`
        : okChecks.length
          ? "当前 TCP session 在首版规则下未发现明确异常。"
          : "当前 TCP session 证据不足，无法形成明确判断。";
  
    return QueryDiagnosisSchema.parse({
      conversationId: conversation.conversationId,
      summary,
      confidence: failedChecks.length || tags.some((tag) => tag.confidence === "high") ? "high" : warningChecks.length ? "needs_context" : "low",
      checks,
      diagnosticTags: tags,
      evidence,
      findings,
      nextSteps: [...nextSteps]
    });
  }
  
  function beijingDayFromEpoch(epochSeconds?: number) {
    if (!epochSeconds) return "";
    const parts = new Intl.DateTimeFormat("en-CA", {
      timeZone: "Asia/Shanghai",
      year: "numeric",
      month: "2-digit",
      day: "2-digit"
    }).formatToParts(new Date(epochSeconds * 1000));
    const value = (type: string) => parts.find((part) => part.type === type)?.value || "";
    return `${value("year")}-${value("month")}-${value("day")}`;
  }
  
  function parseQuestionTimeRange(question: string, graph: CaseGraph) {
    const matches = [...question.matchAll(/\b([01]?\d|2[0-3]):([0-5]\d)(?::([0-5]\d))?\b/g)].map((match) => match[0].split(":").length === 2 ? `${match[0]}:00` : match[0]);
    if (matches.length < 2) return {};
    const captureStart = graph.captures
      .map((capture) => capture.firstPacketTime)
      .filter((timestamp): timestamp is number => Number.isFinite(timestamp))
      .sort((left, right) => left - right)[0];
    const baseDay = beijingDayFromEpoch(captureStart ?? graph.rawPackets[0]?.timestamp);
    if (!baseDay) return {};
    const start = Date.parse(`${baseDay}T${matches[0]}+08:00`) / 1000;
    const end = Date.parse(`${baseDay}T${matches[1]}+08:00`) / 1000;
    return Number.isFinite(start) && Number.isFinite(end) ? { start, end } : {};
  }
  
  function inferQueryRunInput(question: string, graph: CaseGraph) {
    const ips = [...question.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map((match) => match[0]);
    const explicitPort = question.match(/(?:端口|port|端口号|的)\s*[:：]?\s*(\d{1,5})\b/i)?.[1];
    const protocol = question.match(/\b(tcp|tls|http|https)\b/i)?.[1]?.toLowerCase();
    return {
      question,
      timeRange: parseQuestionTimeRange(question, graph),
      srcIp: ips[0],
      dstIp: ips[1],
      port: explicitPort ? Number(explicitPort) : undefined,
      protocol: protocol === "https" ? "tls" : protocol
    };
  }
  
  function shouldCreateQueryRun(question: string) {
    return new RegExp(deps.fallbackPatterns.accessQueryIntent, "i").test(question)
      && new RegExp(deps.fallbackPatterns.accessQueryScope).test(question);
  }
  
  function shouldCorrelateCaptures(question: string) {
    return new RegExp(deps.fallbackPatterns.captureCorrelation, "i").test(question);
  }
  
  function activeCorrelationNeedsContext(graph: CaseGraph) {
    const queryRun = graph.queryRuns.find((run) => run.queryRunId === graph.activeQueryRunId) || graph.queryRuns[0];
    if (!queryRun || !shouldCorrelateCaptures(queryRun.question)) return false;
    return queryRun.path?.confidence === "needs_context" || Boolean(queryRun.path?.missingHops.length);
  }
  
  function endpointHints(text: string) {
    return [...text.matchAll(/\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b/g)].map((match) => ({
      ip: match[1],
      port: match[2] ? Number(match[2]) : undefined
    }));
  }
  
  function mappingKindFromText(text: string): MappingHint["kind"] | undefined {
    if (/f5|slb|lb|负载均衡/i.test(text)) return "slb";
    if (/nat|地址转换|转换/i.test(text)) return "nat";
    if (/代理|proxy/i.test(text)) return "proxy";
    if (/网关|gateway/i.test(text)) return "gateway";
    if (/隧道|tunnel/i.test(text)) return "tunnel";
    return undefined;
  }
  
  function parseMappingHintFromQuestion(graph: CaseGraph, question: string): MappingHint | null {
    const kind = mappingKindFromText(question);
    if (!kind) return null;
    const endpoints = endpointHints(question);
    if (endpoints.length < 2) return null;
    const [originalSrc, originalDst, translatedSrc, translatedDst] = endpoints;
    const twoCaptures = graph.captures.length === 2;
    return MappingHintSchema.parse({
      hintId: `hint-${Date.now()}`,
      kind,
      fromNodeId: twoCaptures ? graph.captures[0].nodeId : undefined,
      toNodeId: twoCaptures ? graph.captures[1].nodeId : undefined,
      originalSrcIp: originalSrc.ip,
      originalSrcPort: originalSrc.port,
      originalDstIp: endpoints.length >= 4 ? originalDst.ip : undefined,
      originalDstPort: endpoints.length >= 4 ? originalDst.port : undefined,
      translatedSrcIp: endpoints.length >= 4 ? translatedSrc.ip : originalDst.ip,
      translatedSrcPort: endpoints.length >= 4 ? translatedSrc.port : originalDst.port,
      translatedDstIp: endpoints.length >= 4 ? translatedDst.ip : undefined,
      translatedDstPort: endpoints.length >= 4 ? translatedDst.port : undefined,
      note: `Agent 从用户补充上下文提取：${question}`
    });
  }
  
  function parseTimeOffsetHintFromQuestion(graph: CaseGraph, question: string): TimeOffsetHint | null {
    const match = question.match(/(?:时间|时钟|offset|偏移|差|快|慢)[^\d+-]{0,12}([-+]?\d+(?:\.\d+)?)\s*(ms|毫秒|s|秒|m|分钟)?/i);
    if (!match) return null;
    const unit = (match[2] || "秒").toLowerCase();
    const value = Number(match[1]);
    if (!Number.isFinite(value)) return null;
    const offsetSeconds = unit === "ms" || unit === "毫秒" ? value / 1000 : unit === "m" || unit === "分钟" ? value * 60 : value;
    return TimeOffsetHintSchema.parse({
      hintId: `time-${Date.now()}`,
      fromNodeId: graph.captures.length === 2 ? graph.captures[0].nodeId : undefined,
      toNodeId: graph.captures.length === 2 ? graph.captures[1].nodeId : undefined,
      offsetSeconds,
      note: `Agent 从用户补充上下文提取：${question}`
    });
  }
  
  function shouldApplyCorrelationContext(question: string, graph: CaseGraph) {
    if (!activeCorrelationNeedsContext(graph)) return false;
    return Boolean(mappingKindFromText(question) || parseTimeOffsetHintFromQuestion(graph, question));
  }
  
  async function applyCorrelationContextAndRerun(graph: CaseGraph, question: string): Promise<AgentAnswer> {
    const mappingHint = parseMappingHintFromQuestion(graph, question);
    const timeOffsetHint = parseTimeOffsetHintFromQuestion(graph, question);
    if (!mappingHint && !timeOffsetHint) {
      return {
        answer: [
          "我还不能把这段补充信息写成可执行的关联线索。",
          "请按这个格式补充：",
          "- NAT/F5 映射：原始 10.0.0.1:12345 -> 20.0.0.1:443 转换为 172.16.0.10:54321 -> 20.0.0.1:443",
          "- 时间偏移：node-2 比 node-1 快 2 秒"
        ].join("\n"),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: ["缺少可解析的 mapping hint 或 time offset"],
        confidence: "needs_context",
        suggestedActions: ["补充转换前后 IP/端口，或明确两个抓包节点的时间偏移。"],
        handoffAgent: "PathAgent"
      };
    }
    const nextGraph: CaseGraph = {
      ...graph,
      mappingHints: mappingHint ? [...graph.mappingHints, mappingHint] : graph.mappingHints,
      timeOffsetHints: timeOffsetHint ? [...graph.timeOffsetHints, timeOffsetHint] : graph.timeOffsetHints
    };
    deps.writeCaseGraph(nextGraph);
    deps.setGraph(graph.spec.caseId, nextGraph);
    const rerun = await createCaptureCorrelationQueryRun(nextGraph, "根据补充上下文重新判断这些文件是否能串起来");
    return {
      ...rerun,
      answer: [
        mappingHint ? `已写入 ${mappingHint.kind.toUpperCase()} mapping hint。` : "",
        timeOffsetHint ? `已写入 time offset hint：${timeOffsetHint.offsetSeconds}s。` : "",
        "已基于新线索自动重跑多文件关联。",
        "",
        rerun.answer
      ].filter(Boolean).join("\n"),
      thoughts: [
        "识别为多文件关联后的上下文补充。",
        ...(mappingHint ? ["从用户文本提取并写入 mapping hint。"] : []),
        ...(timeOffsetHint ? ["从用户文本提取并写入 time offset hint。"] : []),
        "重新运行多文件/多节点链路关联 QueryRun。",
        ...(rerun.thoughts || [])
      ]
    };
  }
  
  function pathScore(pathResult: QueryPath) {
    const observed = pathResult.hops.filter((hop) => hop.status === "observed").length;
    const mapped = pathResult.hops.filter((hop) => hop.correlation === "mapping_hint").length;
    const suspect = pathResult.edges.filter((edge) => edge.status === "suspect").length;
    const needsContext = pathResult.edges.filter((edge) => edge.status === "needs_context").length;
    return observed * 1000 + mapped * 200 - suspect * 200 - needsContext * 100 - pathResult.missingHops.length * 150;
  }
  
  async function createCaptureCorrelationQueryRun(graph: CaseGraph, question: string) {
    const captures = captureQueryInputs(graph);
    if (captures.length < 2) {
      return {
        answer: "当前少于 2 个 pcap 文件，无法判断多文件是否能串起来。",
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: ["缺少第二个 pcap 文件"],
        confidence: "needs_context" as const,
        suggestedActions: ["再上传相邻节点或上下游节点的 pcap 文件。"],
        handoffAgent: "PathAgent"
      };
    }
    const queryRunId = `query-${Date.now()}`;
    const displayFilter = "tcp";
    const listed = await listTcpConversationsWithMcp({ captures, displayFilter });
    const conversations = normalizeConversations(listed.conversations, queryRunId);
    const rankedPaths = conversations
      .map((conversation) => ({
        conversation,
        pathResult: buildQueryPath(graph, queryRunId, conversation.conversationId, conversations)
      }))
      .sort((left, right) => pathScore(right.pathResult) - pathScore(left.pathResult) || right.conversation.packetCount - left.conversation.packetCount);
    const selected = rankedPaths[0];
    const selectedConversation = selected?.conversation;
    const pathResult = selected?.pathResult;
    const selectedCapture = selectedConversation ? captures.find((capture) => capture.nodeId === selectedConversation.nodeId && capture.pcapFilename === selectedConversation.pcapFilename) : undefined;
    const selectedPackets = selectedCapture && selectedConversation
      ? (await getConversationPacketsWithMcp({ capture: selectedCapture, displayFilter: selectedConversation.displayFilter, limit: deps.conversationPacketLimit })).packets
      : [];
    const selectedDiagnosis = selectedConversation && pathResult
      ? buildQueryDiagnosis(graph, queryRunId, selectedConversation, selectedPackets, pathResult)
      : undefined;
    const candidateGroups = buildAccessCandidateGroups(conversations, QueryRunInputSchema.parse({ question, protocol: "tcp" }));
    const linkedPaths = rankedPaths.filter((item) => item.pathResult.hops.filter((hop) => hop.status === "observed").length >= 2);
    const evidenceCards: EvidenceCard[] = [
      {
        cardId: `filter-${queryRunId}`,
        kind: "filter",
        title: "跨文件关联过滤器",
        summary: "首版按 TCP conversation 做 exact tuple / mapping hint / time offset 关联。",
        displayFilter,
        queryRunId,
        actions: ["copy_filter"]
      },
      ...(pathResult ? [{
        cardId: `path-${queryRunId}`,
        kind: "statistic" as const,
        title: linkedPaths.length ? "可串联候选" : "未形成跨文件串联",
        summary: `${pathResult.summary} 当前共发现 ${linkedPaths.length} 条至少跨 2 个节点命中的候选 TCP conversation。`,
        displayFilter,
        queryRunId,
        actions: ["copy_filter" as const]
      }] : []),
      ...linkedPaths.slice(0, 10).map((item, index) => ({
        cardId: `linked-${queryRunId}-${index + 1}`,
        kind: "conversation" as const,
        title: `${index + 1}. ${item.conversation.srcIp}:${item.conversation.srcPort} <-> ${item.conversation.dstIp}:${item.conversation.dstPort}`,
        summary: `${item.pathResult.hops.filter((hop) => hop.status === "observed").length}/${graph.captures.length} 个节点命中；${item.conversation.packetCount} 包；RST ${item.conversation.rstCount}，重传 ${item.conversation.retransmissionCount}。`,
        pcapFilename: item.conversation.pcapFilename,
        displayFilter: item.conversation.displayFilter,
        conversationId: item.conversation.conversationId,
        queryRunId,
        actions: ["select_conversation" as const, "open_wireshark" as const, "copy_filter" as const]
      }))
    ];
    const lines = linkedPaths.length
      ? [
        `这 ${captures.length} 个文件可以串起来：发现 ${linkedPaths.length} 条至少跨 2 个抓包节点命中的 TCP conversation。`,
        pathResult ? `当前选中候选：${pathResult.summary}` : "",
        pathResult?.edges.length ? `路径边判断：${pathResult.edges.map((edge) => `${nodeName(graph, edge.fromNodeId)} -> ${nodeName(graph, edge.toNodeId)}：${edge.label}`).join("；")}` : "",
        "明细已生成证据卡片，点击候选 conversation 可进入 Wireshark 查看对应 TCP session。"
      ]
      : [
        `这 ${captures.length} 个文件暂时没有形成可确认串联：未发现跨 2 个节点命中的同一 TCP conversation。`,
        "这不等于一定不能串，常见原因是存在 NAT/F5/LB/代理转换、SSL 卸载、时间偏移，或两个 pcap 没覆盖同一故障窗口。",
        "请补充这些上下文，我会写入 mapping/time hint 并自动重跑关联：",
        `1. ${captures.map((capture) => `${capture.name || capture.nodeId} 是在哪个节点/设备抓的`).join("；")}？`,
        "2. 每个抓包点是入口、出口还是双向？",
        "3. 中间是否有 NAT、F5/LB/SLB、代理、SSL 卸载或 Cookie 会话保持？",
        "4. 如果有地址转换，请给出转换前后 IP/端口。",
        "5. 两个抓包文件时间是否同步？如果不同步，偏移多少秒？"
      ];
    const queryRun = QueryRunSchema.parse({
      queryRunId,
      caseId: graph.spec.caseId,
      question,
      protocol: "tcp",
      displayFilter,
      totalConversationCount: conversations.length,
      candidateGroups,
      selectedCandidateGroupId: candidateGroups.find((group) => selectedConversation && group.conversationIds.includes(selectedConversation.conversationId))?.groupId || candidateGroups[0]?.groupId,
      conversations,
      conversationIds: conversations.map((conversation) => conversation.conversationId),
      selectedConversationId: selectedConversation?.conversationId,
      path: pathResult,
      selectedDiagnosis,
      evidenceCards,
      selectedEvidenceCardId: evidenceCards[0]?.cardId,
      createdAt: new Date().toISOString()
    });
    const nextGraph: CaseGraph = {
      ...graph,
      packets: selectedPackets,
      analysisFilter: AnalysisFilterSchema.parse({ protocol: "tcp" }),
      queryRuns: [queryRun, ...(graph.queryRuns || [])].slice(0, deps.retainedQueryRunLimit),
      activeQueryRunId: queryRunId
    };
    deps.writeCaseGraph(nextGraph);
    deps.setGraph(graph.spec.caseId, nextGraph);
    deps.recordQueryRunMcp(graph.spec.caseId, "list_tcp_conversations", question, queryRun, "跨文件列出 TCP conversations 并构建路径关联。", `captures=${captures.length}; displayFilter=${displayFilter}`, `conversations=${conversations.length}; linkedPaths=${linkedPaths.length}; selected=${selectedConversation?.conversationId || "-"}`);
    return {
      answer: lines.filter(Boolean).join("\n"),
      thoughts: [
        "识别为多文件/多节点链路关联问题。",
        "调用 tshark-query MCP 列出当前所有 capture 的 TCP conversations。",
        "按 exact tuple、mapping hint 和 time offset 构建 QueryPath。",
        `已保存 QueryRun：${queryRunId}。`
      ],
      evidenceCards,
      actions: evidenceCards.flatMap((card) => card.actions),
      evidenceIds: selectedDiagnosis?.evidence.map((event) => event.evidenceId) || [],
      packetIds: selectedDiagnosis?.diagnosticTags.flatMap((tag) => tag.packetIds) || [],
      sessionLinkIds: [],
      findingIds: selectedDiagnosis?.findings.map((finding) => finding.findingId) || [],
      missingContext: linkedPaths.length ? [] : ["缺少节点顺序/抓包方向", "可能缺少 NAT/F5/LB/代理 mapping hint", "可能缺少 time offset"],
      confidence: linkedPaths.length ? "high" as const : "needs_context" as const,
      suggestedActions: linkedPaths.length
        ? ["选择跨节点候选 conversation，查看路径图和 Wireshark filter。"]
        : ["补充节点顺序、抓包位置、方向和地址转换线索后重新关联。"],
      handoffAgent: "PathAgent"
    };
  }
  
  async function createQueryRun(graph: CaseGraph, input: z.infer<typeof QueryRunInputSchema>) {
    const queryRunId = `query-${Date.now()}`;
    const displayFilters = await queryDisplayFilters(graph, input);
    const displayFilter = displayFilters.join(" || ");
    const captures = captureQueryInputs(graph);
    const listedResults = await Promise.all(displayFilters.map((filter) => listTcpConversationsWithMcp({ captures, displayFilter: filter })));
    const listedConversations = normalizeConversations(listedResults.flatMap((result) => result.conversations), queryRunId);
    const conversations = rankedCandidateConversations(listedConversations, input);
    const candidateGroups = buildAccessCandidateGroups(conversations, input);
    const packetResults = await Promise.all(displayFilters.map((filter) => queryPacketsWithMcp({ captures, displayFilter: filter, limit: deps.queryPacketLimit || undefined })));
    const allPackets = uniquePackets(packetResults.flatMap((result) => result.packets));
    const packets = deps.queryPacketLimit ? allPackets.slice(0, deps.queryPacketLimit) : allPackets;
    const selectedCandidateGroupId = candidateGroups[0]?.groupId;
    const selectedConversationId = candidateGroups[0]?.selectedConversationId || conversations[0]?.conversationId;
    const pathResult = selectedConversationId ? buildQueryPath(graph, queryRunId, selectedConversationId, conversations) : undefined;
    const selectedConversation = conversations.find((conversation) => conversation.conversationId === selectedConversationId);
    const selectedCapture = selectedConversation ? captures.find((capture) => capture.nodeId === selectedConversation.nodeId && capture.pcapFilename === selectedConversation.pcapFilename) : undefined;
    const selectedPackets = selectedCapture && selectedConversation
      ? (await getConversationPacketsWithMcp({ capture: selectedCapture, displayFilter: selectedConversation.displayFilter, limit: deps.conversationPacketLimit })).packets
      : [];
    const selectedDiagnosis = selectedConversation && pathResult
      ? buildQueryDiagnosis(graph, queryRunId, selectedConversation, selectedPackets, pathResult)
      : undefined;
    const evidenceCards: EvidenceCard[] = [
      {
        cardId: `filter-${queryRunId}`,
        kind: "filter",
        title: "当前 tshark 过滤器",
        summary: displayFilter,
        displayFilter,
        queryRunId,
        actions: ["query_packets"]
      },
      ...candidateGroups.slice(0, deps.candidateGroupLimit).map((group) => ({
        cardId: `group-${queryRunId}-${group.groupId}`,
        kind: "conversation" as const,
        title: group.summary,
        summary: `通讯对 ${group.conversationCount} 条，成功 ${group.successCount} 条，异常 ${group.failureCount} 条。`,
        conversationId: group.selectedConversationId,
        queryRunId,
        actions: ["select_conversation", "open_wireshark"] as Array<"select_conversation" | "open_wireshark">
      })),
      ...(selectedConversation ? [{
        cardId: `conversation-${queryRunId}-${selectedConversation.conversationId}`,
        kind: "conversation" as const,
        title: `${selectedConversation.srcIp}:${selectedConversation.srcPort} -> ${selectedConversation.dstIp}:${selectedConversation.dstPort}`,
        summary: `${selectedConversation.packetCount} 个包，RST ${selectedConversation.rstCount}，重传 ${selectedConversation.retransmissionCount}。`,
        pcapFilename: selectedConversation.pcapFilename,
        displayFilter: selectedConversation.displayFilter,
        conversationId: selectedConversation.conversationId,
        queryRunId,
        actions: ["select_conversation", "open_wireshark"] as Array<"select_conversation" | "open_wireshark">
      }] : []),
      ...selectedPackets.filter((packet) => packet.tcpFlags.includes("RST") || packet.tcpFlags.includes("SYN") || packet.tcpAnalysis.retransmission || packet.tcpAnalysis.fastRetransmission).slice(0, deps.evidencePacketSampleLimit).map((packet) => ({
        cardId: `packet-${queryRunId}-${packet.packetId}`,
        kind: "packet" as const,
        title: `Frame ${packet.frameNumber}`,
        summary: `${packet.srcIp}:${packet.srcPort} -> ${packet.dstIp}:${packet.dstPort} ${packet.tcpFlags.join(", ") || packet.protocol}`,
        pcapFilename: packet.pcapFilename,
        frameNumber: packet.frameNumber,
        displayFilter: `frame.number == ${packet.frameNumber}`,
        queryRunId,
        actions: ["open_wireshark"] as Array<"open_wireshark">
      }))
    ];
    const queryRun = QueryRunSchema.parse({
      queryRunId,
      caseId: graph.spec.caseId,
      question: input.question,
      timeRange: input.timeRange,
      srcIp: input.srcIp,
      dstIp: input.dstIp,
      port: input.port,
      protocol: input.protocol || "tcp",
      displayFilter,
      totalConversationCount: listedConversations.length,
      candidateGroups,
      selectedCandidateGroupId,
      conversations,
      conversationIds: conversations.map((conversation) => conversation.conversationId),
      selectedConversationId,
      path: pathResult,
      selectedDiagnosis,
      evidenceCards,
      createdAt: new Date().toISOString()
    });
    const nextGraph: CaseGraph = {
      ...graph,
      packets,
      analysisFilter: AnalysisFilterSchema.parse({
        client: input.srcIp,
        server: input.dstIp,
        protocol: input.protocol,
        port: input.port
      }),
      queryRuns: [queryRun, ...(graph.queryRuns || [])].slice(0, deps.retainedQueryRunLimit),
      activeQueryRunId: queryRunId
    };
    deps.writeCaseGraph(nextGraph);
    deps.setGraph(graph.spec.caseId, nextGraph);
    deps.recordQueryRunMcp(graph.spec.caseId, "list_tcp_conversations", input.question, queryRun, "按 display filter 查询并聚合 TCP conversations。", `captures=${captures.length}; displayFilters=${displayFilters.join(" || ")}`, `listed=${listedConversations.length}; ranked=${conversations.length}; packets=${packets.length}; selected=${selectedConversationId || "-"}`);
    return nextGraph;
  }

  async function selectConversation(graph: CaseGraph, queryRunId: string, conversationId: string) {
    const queryRunIndex = graph.queryRuns.findIndex((run) => run.queryRunId === queryRunId);
    if (queryRunIndex < 0) return { status: "query_not_found" as const };
    const queryRun = graph.queryRuns[queryRunIndex];
    const conversation = queryRun.conversations.find((item) => item.conversationId === conversationId);
    if (!conversation) return { status: "conversation_not_found" as const };
    const queryInput = QueryRunInputSchema.parse({
      question: queryRun.question,
      timeRange: queryRun.timeRange,
      srcIp: queryRun.srcIp,
      dstIp: queryRun.dstIp,
      port: queryRun.port,
      protocol: queryRun.protocol
    });
    const capture = graph.captures.find((item) => item.nodeId === conversation.nodeId && item.pcapFilename === conversation.pcapFilename);
    if (!capture?.pcapFilename) return { status: "capture_not_found" as const };
    const selectedPackets = (await getConversationPacketsWithMcp({
      capture: {
        nodeId: capture.nodeId,
        name: capture.name,
        pcapFilename: capture.pcapFilename,
        pcapPath: path.join(deps.capturesDirectory(graph.spec.caseId), capture.pcapFilename)
      },
      displayFilter: conversation.displayFilter,
      limit: deps.conversationPacketLimit
    })).packets;
    const refinedConversation = {
      ...conversation,
      packetCount: selectedPackets.length || conversation.packetCount,
      byteCount: selectedPackets.reduce((sum, packet) => sum + (packet.length || 0), 0) || conversation.byteCount,
      tcpFlags: [...new Set(selectedPackets.flatMap((packet) => packet.tcpFlags))],
      rstCount: selectedPackets.filter((packet) => packet.tcpFlags.includes("RST")).length || conversation.rstCount,
      retransmissionCount: selectedPackets.filter((packet) => packet.tcpAnalysis.retransmission || packet.tcpAnalysis.fastRetransmission).length || conversation.retransmissionCount,
      zeroWindowCount: selectedPackets.filter((packet) => packet.tcpAnalysis.zeroWindow).length || conversation.zeroWindowCount
    };
    const baseConversations = queryRun.conversations.map((item) => item.conversationId === conversation.conversationId ? refinedConversation : item);
    const candidateConversations = rankedCandidateConversations(baseConversations, queryInput);
    const conversations = candidateConversations.some((item) => item.conversationId === conversation.conversationId)
      ? candidateConversations
      : [rankedConversation(refinedConversation, queryInput), ...candidateConversations];
    const selectedCandidateGroup = buildAccessCandidateGroups(conversations, queryInput).find((group) => group.conversationIds.includes(refinedConversation.conversationId));
    const candidateGroups = buildAccessCandidateGroups(conversations, queryInput).map((group) => (
      group.groupId === selectedCandidateGroup?.groupId ? { ...group, selectedConversationId: refinedConversation.conversationId } : group
    ));
    const pathResult = buildQueryPath(graph, queryRun.queryRunId, refinedConversation.conversationId, conversations);
    const nextQueryRun = QueryRunSchema.parse({
      ...queryRun,
      totalConversationCount: queryRun.totalConversationCount || queryRun.conversations.length,
      candidateGroups,
      selectedCandidateGroupId: selectedCandidateGroup?.groupId || queryRun.selectedCandidateGroupId,
      conversations,
      conversationIds: conversations.map((item) => item.conversationId),
      selectedConversationId: refinedConversation.conversationId,
      path: pathResult,
      selectedDiagnosis: buildQueryDiagnosis(graph, queryRun.queryRunId, refinedConversation, selectedPackets, pathResult)
    });
    const queryRuns = [...graph.queryRuns];
    queryRuns[queryRunIndex] = nextQueryRun;
    const nextGraph: CaseGraph = { ...graph, queryRuns, activeQueryRunId: queryRun.queryRunId, packets: selectedPackets };
    deps.writeCaseGraph(nextGraph);
    deps.setGraph(graph.spec.caseId, nextGraph);
    deps.recordMcpRun(graph.spec.caseId, {
      target: "get_conversation_packets",
      summary: "精读选中 TCP session 并生成确定性诊断。",
      inputSummary: `queryRun=${queryRun.queryRunId}; conversation=${conversation.conversationId}; displayFilter=${conversation.displayFilter}; limit=${deps.conversationPacketLimit}`,
      outputSummary: `packets=${selectedPackets.length}; checks=${nextQueryRun.selectedDiagnosis?.checks.length || 0}`,
      queryRunId: queryRun.queryRunId,
      evidenceCardIds: nextQueryRun.evidenceCards.map((card) => card.cardId),
      pcapFilename: conversation.pcapFilename,
      displayFilter: conversation.displayFilter
    });
    return {
      status: "success" as const,
      graph: nextGraph,
      queryRun: nextQueryRun,
      conversation: refinedConversation
    };
  }
  
  function requestedLimit(question: string, fallback = 10) {
    const match = question.match(/(?:前|top\s*)(\d{1,3})/i) || question.match(/\b(\d{1,3})\s*(?:个|条)/);
    const value = match ? Number(match[1]) : fallback;
    return Number.isFinite(value) ? Math.max(1, Math.min(100, value)) : fallback;
  }
  
  async function displayFilterFromQuestion(graph: CaseGraph, question: string, fallbackProtocol = "tcp") {
    const inferred = inferQueryRunInput(question, graph);
    const filter = await buildDisplayFilterWithMcp({
      start: inferred.timeRange.start,
      end: inferred.timeRange.end,
      srcIp: inferred.srcIp,
      dstIp: inferred.dstIp,
      port: inferred.port,
      protocol: inferred.protocol || fallbackProtocol
    });
    return {
      input: QueryRunInputSchema.parse({ ...inferred, question, protocol: inferred.protocol || fallbackProtocol }),
      displayFilter: filter.displayFilter
    };
  }
  

  return {
    nodeName,
    captureQueryInputs,
    buildAccessCandidateGroups,
    rankedCandidateConversations,
    rankedConversation,
    buildQueryPath,
    buildQueryDiagnosis,
    inferQueryRunInput,
    requestedLimit,
    displayFilterFromQuestion,
    createQueryRun,
    selectConversation,
    createCaptureCorrelationQueryRun,
    applyCorrelationContextAndRerun,
    activeCorrelationNeedsContext,
    shouldApplyCorrelationContext,
    shouldCorrelateCaptures,
    shouldCreateQueryRun
  };
}
