import type { ProtocolAdapter, ProtocolAdapterContext, ProtocolPairGroup, ProtocolPacket } from "./types.js";
import type { Conversation } from "../../../../packages/shared/src/index.js";
import { listTcpConversationsWithMcp } from "../mcp/tsharkQueryClient.js";
import { classifyConversationHealthFromSummary, type ConversationHealth } from "../services/conversationHealth.js";

function shouldListResetSessionPairs(question: string) {
  return /(?:RST|reset|Reset|复位|重置)/i.test(question) && /(?:session|pair|会话|通信对|通讯对|事件|列表|查询|包|异常|个数|数量|统计)/i.test(question);
}

function shouldListRetransmissionSessionPairs(question: string) {
  return /(?:重传|retransmission|fast retransmission|retrans)/i.test(question) && /(?:session|pair|会话|通信对|通讯对|连接|事件|列表|查询|包|异常|个数|数量|统计)/i.test(question);
}

function shouldListZeroWindowSessionPairs(question: string) {
  return /(?:zero\s*window|Zero Window|零窗口|窗口为0|窗口为 0)/i.test(question) && /(?:session|pair|会话|通信对|通讯对|连接|事件|列表|查询|包|异常|个数|数量|统计)/i.test(question);
}

function shouldListSynNoSynAckPairs(question: string) {
  return /(?:SYN|syn)/i.test(question) && /(?:SYN-ACK|synack|syn ack|ack)/i.test(question) && /(?:没有|无|未见|缺失|no|missing)/i.test(question);
}

function shouldListOneWayPairs(question: string) {
  return /(?:单向|只有一个方向|有去无回|one.?way|单方向)/i.test(question) && /(?:session|pair|会话|通信对|通讯对|连接|流量)/i.test(question);
}

function shouldListTcpIssues(question: string) {
  const isOtherProtocol = /(?:dns|解析|域名|icmp|unreachable|不可达|ttl|跳数|tls|ssl|sni|证书|alert|握手|http|状态码|udp)/i.test(question);
  if (isOtherProtocol) return false;
  return /(?:tcp|传输层|连接|异常|问题|故障|session|会话|通信)/i.test(question) && !shouldListResetSessionPairs(question) && !shouldListRetransmissionSessionPairs(question) && !shouldListZeroWindowSessionPairs(question) && !shouldListSynNoSynAckPairs(question) && !shouldListOneWayPairs(question) && !shouldListConnectionHealthMatrix(question);
}

function shouldListConnectionHealthMatrix(question: string) {
  // 匹配"全景/全部连接/所有连接/正常/连接清单/健康状况"等，需同时含连接类词
  const isConnectionQuery = /(?:tcp|连接|session|会话|通信|connection)/i.test(question);
  if (!isConnectionQuery) return false;
  return /(?:全景|全貌|全部连接|所有连接|每个连接|每条连接|正常|连接清单|健康状况|健康|health|matrix|总览.*连接|连接.*总览|正常.*异常|异常.*正常)/i.test(question);
}

async function resetSessionPairsAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const limit = ctx.requestedLimit(question, 10);
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const result = await ctx.listTcpResets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined });
  return ctx.packetPairAnswer({
    graph,
    queryInput: query.input,
    displayFilter: query.displayFilter,
    pairs: ctx.groupPacketPairs(result.packets, query.displayFilter),
    limit,
    title: `前 ${limit} 个包含 RST 的 TCP session pair`,
    metricLabel: "RST",
    metricKind: "rst",
    noResult: "当前已上传抓包中没有查询到带 RST 的 TCP session pair。",
    thoughts: [
      "识别为 RST 通信对列表查询。",
      `构造基础 display filter：${query.displayFilter}`,
      "调用 tshark-query MCP 的 list_tcp_resets 工具，只读取 tcp.flags.reset == 1 的包。",
      "按无方向 endpoint pair 聚合，并按 RST 数量排序返回前 N 个。"
    ],
    cardPrefix: "rst-pair",
    suggestedAction: "点击证据卡片的 Wireshark 按钮打开该 TCP session filter。"
  });
}

async function retransmissionSessionPairsAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const limit = ctx.requestedLimit(question, 10);
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const result = await ctx.listTcpRetransmissions({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined });
  return ctx.packetPairAnswer({
    graph,
    queryInput: query.input,
    displayFilter: query.displayFilter,
    pairs: ctx.groupPacketPairs(result.packets, query.displayFilter),
    limit,
    title: `前 ${limit} 个重传最多的 TCP session pair`,
    metricLabel: "重传",
    metricKind: "retransmission",
    noResult: "当前已上传抓包中没有查询到 TCP 重传包。",
    thoughts: [
      "识别为 TCP 重传通信对列表查询。",
      `构造基础 display filter：${query.displayFilter}`,
      "调用 tshark-query MCP 的 list_tcp_retransmissions 工具，只读取 tcp.analysis.retransmission / fast_retransmission。",
      "按无方向 endpoint pair 聚合，并按重传数量排序返回前 N 个。"
    ],
    cardPrefix: "retrans-pair",
    suggestedAction: "点击证据卡片的 Wireshark 按钮打开该 TCP session filter。"
  });
}

async function zeroWindowSessionPairsAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const limit = ctx.requestedLimit(question, 10);
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const result = await ctx.listTcpZeroWindow({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined });
  return ctx.packetPairAnswer({
    graph,
    queryInput: query.input,
    displayFilter: query.displayFilter,
    pairs: ctx.groupPacketPairs(result.packets, query.displayFilter),
    limit,
    title: `前 ${limit} 个包含 Zero Window 的 TCP session pair`,
    metricLabel: "Zero Window",
    metricKind: "zero_window",
    noResult: "当前已上传抓包中没有查询到 TCP Zero Window 包。",
    thoughts: [
      "识别为 TCP Zero Window 通信对列表查询。",
      `构造基础 display filter：${query.displayFilter}`,
      "调用 tshark-query MCP 的 list_tcp_zero_window 工具，只读取 tcp.analysis.zero_window。",
      "按无方向 endpoint pair 聚合，并按 Zero Window 数量排序返回前 N 个。"
    ],
    cardPrefix: "zero-window-pair",
    suggestedAction: "点击证据卡片的 Wireshark 按钮打开该 TCP session filter。"
  });
}

async function synNoSynAckSessionPairsAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const limit = ctx.requestedLimit(question, 10);
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const synFilter = `${query.displayFilter} && tcp.flags.syn == 1`;
  const result = await ctx.queryPackets({ captures, displayFilter: synFilter, limit: ctx.queryPacketLimit || undefined });
  const groups = new Map<string, ProtocolPacket[]>();
  for (const packet of result.packets) {
    groups.set(ctx.pairKey(packet), [...(groups.get(ctx.pairKey(packet)) || []), packet]);
  }
  const pairs = [...groups.values()]
    .map((packets) => {
      const synOnlyPackets = packets.filter((packet) => packet.tcpFlags.includes("SYN") && !packet.tcpFlags.includes("ACK"));
      const synAckPackets = packets.filter((packet) => packet.tcpFlags.includes("SYN") && packet.tcpFlags.includes("ACK"));
      return synOnlyPackets.length && !synAckPackets.length ? ctx.pairGroupFromPackets(synOnlyPackets, synOnlyPackets.length, query.displayFilter) : null;
    })
    .filter((pair): pair is ProtocolPairGroup => Boolean(pair))
    .sort((left, right) => right.count - left.count || left.firstSeen - right.firstSeen);
  return ctx.packetPairAnswer({
    graph,
    queryInput: query.input,
    displayFilter: synFilter,
    pairs,
    limit,
    title: `前 ${limit} 个 SYN 无 SYN-ACK 的 TCP session pair`,
    metricLabel: "SYN 未应答",
    metricKind: "syn_no_synack",
    noResult: "当前已上传抓包中没有查询到 SYN 无 SYN-ACK 的 TCP session pair。",
    thoughts: [
      "识别为 SYN 无 SYN-ACK 查询。",
      `构造基础 display filter：${query.displayFilter}`,
      "调用 tshark-query MCP 查询 tcp.flags.syn == 1 的包。",
      "按 endpoint pair 聚合，保留看到 SYN 但未看到 SYN-ACK 的通信对。"
    ],
    cardPrefix: "syn-no-synack-pair",
    suggestedAction: "点击证据卡片的 Wireshark 按钮打开该 TCP session filter。"
  });
}

async function oneWaySessionPairsAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const limit = ctx.requestedLimit(question, 10);
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const result = await ctx.queryPackets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined });
  const groups = new Map<string, ProtocolPacket[]>();
  for (const packet of result.packets) {
    if (!packet.srcIp || !packet.dstIp || packet.srcPort === undefined || packet.dstPort === undefined) continue;
    groups.set(ctx.pairKey(packet), [...(groups.get(ctx.pairKey(packet)) || []), packet]);
  }
  const pairs = [...groups.values()]
    .map((packets) => {
      const directions = new Set(packets.map((packet) => `${packet.srcIp || "*"}:${packet.srcPort ?? "*"} -> ${packet.dstIp || "*"}:${packet.dstPort ?? "*"}`));
      return directions.size === 1 ? ctx.pairGroupFromPackets(packets, packets.length, query.displayFilter) : null;
    })
    .filter((pair): pair is ProtocolPairGroup => Boolean(pair))
    .sort((left, right) => right.count - left.count || left.firstSeen - right.firstSeen);
  return ctx.packetPairAnswer({
    graph,
    queryInput: query.input,
    displayFilter: query.displayFilter,
    pairs,
    limit,
    title: `前 ${limit} 个单向 TCP session pair`,
    metricLabel: "单向包",
    metricKind: "one_way",
    noResult: "当前查询样本中没有发现只有单方向流量的 TCP session pair。",
    thoughts: [
      "识别为单向流量查询。",
      `构造基础 display filter：${query.displayFilter}`,
      "调用 tshark-query MCP 按基础 filter 读取有限样本包。",
      "按 endpoint pair 聚合，保留样本中只出现一个方向的通信对。"
    ],
    cardPrefix: "one-way-pair",
    suggestedAction: "点击证据卡片的 Wireshark 按钮打开该 TCP session filter。"
  });
}

async function tcpIssuesOverviewAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const [rstResult, retransResult, zeroWinResult] = await Promise.all([
    ctx.listTcpResets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined }),
    ctx.listTcpRetransmissions({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined }),
    ctx.listTcpZeroWindow({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit || undefined })
  ]);
  const allPackets = [...rstResult.packets, ...retransResult.packets, ...zeroWinResult.packets];
  if (!allPackets.length) {
    return ctx.protocolQueryAnswer({
      graph,
      queryRunId: `tcp-overview-${Date.now()}`,
      queryInput: query.input,
      displayFilter: query.displayFilter,
      protocol: "tcp",
      title: "TCP 异常总览",
      packets: [],
      noResult: "当前查询范围内未发现 TCP RST、重传或 Zero Window 事件。",
      thoughts: ["识别为通用 TCP 异常查询，同时查询 RST、重传、Zero Window。", `构造 display filter：${query.displayFilter}`, "三种指标均为空，TCP 连接在查询范围内正常。"],
      evidenceCards: [],
      protocolCorrelations: [],
      checks: [
        { key: "rst" as const, label: "TCP RST", status: "ok" as const, summary: "未发现 RST 包。", packetIds: [], nextSteps: [] },
        { key: "retransmission" as const, label: "TCP 重传", status: "ok" as const, summary: "未发现重传包。", packetIds: [], nextSteps: [] },
        { key: "zero_window" as const, label: "TCP Zero Window", status: "ok" as const, summary: "未发现 Zero Window 包。", packetIds: [], nextSteps: [] }
      ],
      suggestedActions: ["尝试调整时间范围或 IP/端口过滤条件。"],
      handoffAgent: "HypothesisAgent"
    });
  }
  const rstPairs = ctx.groupPacketPairs(rstResult.packets, query.displayFilter);
  const retransPairs = ctx.groupPacketPairs(retransResult.packets, query.displayFilter);
  const zeroWinPairs = ctx.groupPacketPairs(zeroWinResult.packets, query.displayFilter);
  const allPairGroups = [...rstPairs, ...retransPairs, ...zeroWinPairs];
  const queryRunId = `tcp-overview-${Date.now()}`;
  const now = Date.now();
  const evidenceCards = allPairGroups.slice(0, 20).map((pair, index) => {
    const kind = rstPairs.includes(pair) ? "RST" : retransPairs.includes(pair) ? "重传" : "Zero Window";
    return {
      cardId: `tcp-overview-${now}-${index + 1}`,
      kind: "conversation" as const,
      title: `${index + 1}. ${pair.src} <-> ${pair.dst}（${kind} ${pair.count} 个）`,
      summary: `${kind} ${pair.count} 个，时间 ${ctx.formatBeijingTime(pair.firstSeen)} - ${ctx.formatBeijingTime(pair.lastSeen)}。`,
      pcapFilename: pair.pcapFilename,
      displayFilter: pair.displayFilter,
      actions: ["open_wireshark" as const, "copy_filter" as const]
    };
  });
  const checks = [
    { key: "rst" as const, label: "TCP RST", status: (rstPairs.length ? "problem" : "ok") as "problem" | "ok", summary: rstPairs.length ? `发现 ${rstResult.packets.length} 个 RST 包，涉及 ${rstPairs.length} 个 session。` : "未发现 RST 包。", packetIds: rstResult.packets.slice(0, 5).map((p) => p.packetId), nextSteps: rstPairs.length ? ["点击证据卡片查看 RST session，或用 \"查看 RST 通信对\" 查看详细统计。"] : [] },
    { key: "retransmission" as const, label: "TCP 重传", status: (retransPairs.length ? "problem" : "ok") as "problem" | "ok", summary: retransPairs.length ? `发现 ${retransResult.packets.length} 个重传包，涉及 ${retransPairs.length} 个 session。` : "未发现重传包。", packetIds: retransResult.packets.slice(0, 5).map((p) => p.packetId), nextSteps: retransPairs.length ? ["点击证据卡片查看重传 session，或用 \"查看重传通信对\" 查看详细统计。"] : [] },
    { key: "zero_window" as const, label: "TCP Zero Window", status: (zeroWinPairs.length ? "warn" : "ok") as "warn" | "ok", summary: zeroWinPairs.length ? `发现 ${zeroWinResult.packets.length} 个 Zero Window 包，涉及 ${zeroWinPairs.length} 个 session。` : "未发现 Zero Window 包。", packetIds: zeroWinResult.packets.slice(0, 5).map((p) => p.packetId), nextSteps: zeroWinPairs.length ? ["点击证据卡片查看 Zero Window session，或用 \"查看 Zero Window 通信对\" 查看详细统计。"] : [] }
  ];
  return ctx.protocolQueryAnswer({
    graph,
    queryRunId,
    queryInput: query.input,
    displayFilter: query.displayFilter,
    protocol: "tcp",
    title: `TCP 异常总览：${rstPairs.length} RST、${retransPairs.length} 重传、${zeroWinPairs.length} Zero Window`,
    packets: [],
    noResult: "当前查询范围内未发现 TCP 异常。",
    thoughts: [
      "识别为通用 TCP 异常查询，同时查询 RST、重传、Zero Window 三种指标。",
      `构造 display filter：${query.displayFilter}`,
      `RST=${rstResult.packets.length}，重传=${retransResult.packets.length}，Zero Window=${zeroWinResult.packets.length}。`
    ],
    evidenceCards,
    protocolCorrelations: [],
    checks,
    suggestedActions: [
      "点击证据卡片在 Wireshark 中查看具体 TCP session。",
      rstPairs.length ? "用 \"查看 RST 通信对\" 查看详细 RST 统计。" : "",
      retransPairs.length ? "用 \"查看重传通信对\" 查看详细重传统计。" : "",
      zeroWinPairs.length ? "用 \"查看 Zero Window 通信对\" 查看详细 Zero Window 统计。" : ""
    ].filter(Boolean),
    handoffAgent: "HypothesisAgent"
  });
}

// TCP 连接健康全景：全量枚举会话，逐条标注正常/重传/RST/握手未建立/零窗口/单向。
// 与 tcp_issues_overview（只看 RST/重传/零窗口 3 类、不标正常）互补，给出完整连接清单。
// 全量枚举用 limit=5000 保护上限，避免极端 pcap 撑爆内存；truncated 时声明覆盖范围。
const HEALTH_MATRIX_PACKET_LIMIT = 5000;
const HEALTH_MATRIX_RETRANSMISSION_BURST = 3; // 与 config diagnosis.retransmissionBurstThreshold 一致

// 单条会话健康分类：委托给 classifyConversationHealthFromSummary（基于 MCP 方向级摘要字段），
// 与 query-run 深诊断的包级 classifyConversationHealth 同口径，保证两处结论一致。
function classifyConversationBySummary(conv: Conversation): ConversationHealth {
  return classifyConversationHealthFromSummary(conv, { retransmissionBurst: HEALTH_MATRIX_RETRANSMISSION_BURST });
}

async function connectionHealthMatrixAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const result = await listTcpConversationsWithMcp({ captures, displayFilter: query.displayFilter, limit: HEALTH_MATRIX_PACKET_LIMIT });
  const conversations = result.conversations;
  const queryRunId = `tcp-health-${Date.now()}`;
  const now = Date.now();

  if (!conversations.length) {
    return ctx.protocolQueryAnswer({
      graph,
      queryRunId,
      queryInput: query.input,
      displayFilter: query.displayFilter,
      protocol: "tcp",
      title: "TCP 连接健康全景",
      packets: [],
      noResult: "当前查询范围内未发现 TCP 连接。",
      thoughts: ["识别为 TCP 连接健康全景查询。", `构造 display filter：${query.displayFilter}`, "全量枚举 TCP 会话，未匹配到任何连接。"],
      evidenceCards: [],
      protocolCorrelations: [],
      checks: [],
      suggestedActions: ["调整时间范围或 IP/端口过滤条件后重试。"],
      handoffAgent: "HypothesisAgent"
    });
  }

  // 逐条分类
  const classified = conversations.map((conv) => ({ conv, health: classifyConversationBySummary(conv) }));
  // 三态划分：摘要级判定已基于 MCP 方向级字段，能精确标 problem/warn，但握手 none（抓包晚于建连）
  // 和流量方向无包等场景仍为 unknown，需单独成桶避免误并入 normal。
  // - abnormal：有 problem/warn 项（握手未建立/RST/重传/零窗口/单向等确定性异常）
  // - undecided：无确定性异常，但存在 unknown 维度（握手起点或方向无法判定）
  // - normal：所有维度都是 ok（不含 unknown）
  const DIMENSIONS = (h: ReturnType<typeof classifyConversationBySummary>) =>
    [h.handshake, h.rst, h.trafficDirection, h.retransmission, h.zeroWindow] as const;
  const abnormalConnections = classified.filter((item) => item.health.issues.length > 0);
  const undecidedConnections = classified.filter((item) => item.health.issues.length === 0 && DIMENSIONS(item.health).some((s) => s === "unknown"));
  const normalConnections = classified.filter((item) => item.health.issues.length === 0 && !DIMENSIONS(item.health).some((s) => s === "unknown"));

  // 按异常类型统计。握手/流量方向现在基于 MCP 方向级字段（handshakePhase/forward-reversePacketCount），
  // 能精确标 problem，与包级 classifyConversationHealth 同口径。
  const handshakeProblems = classified.filter((item) => item.health.handshake === "problem");
  const handshakeWarn = classified.filter((item) => item.health.handshake === "warn");
  const handshakeUnknown = classified.filter((item) => item.health.handshake === "unknown");
  const rstProblems = classified.filter((item) => item.health.rst === "problem");
  const retransProblems = classified.filter((item) => item.health.retransmission === "problem");
  const zeroWinProblems = classified.filter((item) => item.health.zeroWindow === "problem");
  const oneWayProblems = classified.filter((item) => item.health.trafficDirection === "problem");
  const directionUnknown = classified.filter((item) => item.health.trafficDirection === "unknown");

  const total = conversations.length;
  const normalCount = normalConnections.length;
  const abnormalCount = abnormalConnections.length;
  const undecidedCount = undecidedConnections.length;

  // 证据卡：异常连接逐条（上限 20），正常连接 1 张汇总卡
  const evidenceCards = [];
  abnormalConnections.slice(0, 20).forEach((item, index) => {
    evidenceCards.push({
      cardId: `tcp-health-${now}-abnormal-${index + 1}`,
      kind: "conversation" as const,
      title: `${index + 1}. ${item.conv.srcIp}:${item.conv.srcPort} -> ${item.conv.dstIp}:${item.conv.dstPort}（${item.health.issues.join("、")}）`,
      summary: `${item.health.issues.join("、")}，${item.conv.packetCount} 包，时间 ${ctx.formatBeijingTime(item.conv.startTime)} - ${ctx.formatBeijingTime(item.conv.endTime)}。`,
      pcapFilename: item.conv.pcapFilename,
      displayFilter: item.conv.displayFilter,
      actions: ["open_wireshark" as const, "copy_filter" as const]
    });
  });
  if (normalCount) {
    evidenceCards.push({
      cardId: `tcp-health-${now}-normal-summary`,
      kind: "conversation" as const,
      title: `正常连接（${normalCount} 条）`,
      summary: `${normalCount} 条连接未检测到异常。点击可查看代表性正常连接的 display filter。`,
      displayFilter: normalConnections[0]?.conv.displayFilter,
      actions: ["copy_filter" as const]
    });
  }
  if (undecidedCount) {
    evidenceCards.push({
      cardId: `tcp-health-${now}-undecided-summary`,
      kind: "conversation" as const,
      title: `待确认连接（${undecidedCount} 条）`,
      summary: `${undecidedCount} 条连接未检出确定性异常，但握手起点或流量方向在摘要层无法判定（可能抓包晚于建连）。点击可查看代表性连接的 display filter。`,
      displayFilter: undecidedConnections[0]?.conv.displayFilter,
      actions: ["copy_filter" as const]
    });
  }

  // 全局 checks：每维度标注正常/异常条数。握手与流量方向在摘要层存在 unknown，需三态表达。
  const checks: Array<{ key: "handshake" | "rst" | "retransmission" | "zero_window" | "traffic_direction"; label: string; status: "ok" | "warn" | "problem" | "unknown"; summary: string; packetIds: string[]; nextSteps: string[] }> = [
    {
      key: "handshake",
      label: "握手完整性",
      status: handshakeProblems.length ? "problem" : handshakeWarn.length ? "warn" : handshakeUnknown.length ? "unknown" : "ok",
      summary: handshakeProblems.length
        ? `${handshakeProblems.length} 条连接握手未建立（SYN 无 SYN-ACK）`
        : handshakeWarn.length
          ? `${handshakeWarn.length} 条连接握手不完整（SYN+SYN-ACK 但样本内无第三次 ACK）`
          : handshakeUnknown.length
            ? `${handshakeUnknown.length}/${total} 条连接握手状态无法判定（未观察到 SYN 起点，可能抓包晚于建连）`
            : `${total} 条连接握手均完整`,
      packetIds: [],
      nextSteps: handshakeProblems.length ? ['用 "查看 SYN 无 SYN-ACK 通信对" 查看握手异常详情。'] : []
    },
    {
      key: "rst",
      label: "TCP RST",
      status: rstProblems.length ? "problem" : "ok",
      summary: rstProblems.length ? `${rstProblems.length} 条连接含 RST` : `${total} 条连接无 RST`,
      packetIds: [],
      nextSteps: rstProblems.length ? ['用 "查看 RST 通信对" 查看 RST 详情。'] : []
    },
    {
      key: "retransmission",
      label: "TCP 重传",
      status: retransProblems.length ? "problem" : "ok",
      summary: retransProblems.length ? `${retransProblems.length} 条连接重传突发（≥${HEALTH_MATRIX_RETRANSMISSION_BURST}）` : `${total} 条连接无重传突发`,
      packetIds: [],
      nextSteps: retransProblems.length ? ['用 "查看重传通信对" 查看重传详情。'] : []
    },
    {
      key: "zero_window",
      label: "Zero Window",
      status: zeroWinProblems.length ? "problem" : "ok",
      summary: zeroWinProblems.length ? `${zeroWinProblems.length} 条连接含 Zero Window` : `${total} 条连接无 Zero Window`,
      packetIds: [],
      nextSteps: zeroWinProblems.length ? ['用 "查看 Zero Window 通信对" 查看详情。'] : []
    },
    {
      key: "traffic_direction",
      label: "流量方向",
      status: oneWayProblems.length ? "problem" : directionUnknown.length ? "unknown" : "ok",
      summary: oneWayProblems.length
        ? `${oneWayProblems.length} 条连接单向（仅一个方向有包）`
        : directionUnknown.length
          ? `${directionUnknown.length}/${total} 条连接方向无法判定（forward/reverse 均无包）`
          : `${total} 条连接均双向`,
      packetIds: [],
      nextSteps: oneWayProblems.length ? ['用 "查看单向通信对" 确认单向详情。'] : []
    }
  ];

  const coverageNote = result.truncated
    ? `注意：基于采样 ${result.packetCount} 包（已达上限 ${HEALTH_MATRIX_PACKET_LIMIT}，非全量），实际连接数可能更多。`
    : "";

  return ctx.protocolQueryAnswer({
    graph,
    queryRunId,
    queryInput: query.input,
    displayFilter: query.displayFilter,
    protocol: "tcp",
    title: `TCP 连接健康全景：共 ${total} 条，正常 ${normalCount} 条，异常 ${abnormalCount} 条${undecidedCount ? `，待确认 ${undecidedCount} 条` : ""}`,
    packets: [],
    noResult: "当前查询范围内未发现 TCP 连接。",
    thoughts: [
      "识别为 TCP 连接健康全景查询。",
      `构造 display filter：${query.displayFilter}`,
      `全量枚举 TCP 会话（limit ${HEALTH_MATRIX_PACKET_LIMIT}），共 ${total} 条。`,
      `逐条判定：正常 ${normalCount} 条，异常 ${abnormalCount} 条${undecidedCount ? `，待确认 ${undecidedCount} 条（握手起点或方向在摘要层无法判定）` : ""}。`,
      ...(coverageNote ? [coverageNote] : [])
    ],
    evidenceCards,
    protocolCorrelations: [],
    checks,
    suggestedActions: [
      coverageNote,
      ...(abnormalCount ? ["点击异常连接证据卡片在 Wireshark 中查看具体 session。"] : []),
      ...(undecidedCount ? [`${undecidedCount} 条连接握手起点或方向待确认，建议对代表性连接执行 query-run 深诊断。`] : []),
      ...(normalCount ? [`正常连接 ${normalCount} 条，可用 display filter 进一步筛选。`] : [])
    ].filter(Boolean),
    handoffAgent: "HypothesisAgent"
  });
}

export function createTcpAdapters(ctx: ProtocolAdapterContext): ProtocolAdapter[] {
  return [
    { id: "tcp_rst_pairs", protocol: "tcp", status: "deterministic_rst_pairs", errorPrefix: "RST 通信对查询失败", match: shouldListResetSessionPairs, run: (graph, question) => resetSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_retransmission_pairs", protocol: "tcp", status: "deterministic_retransmission_pairs", errorPrefix: "重传通信对查询失败", match: shouldListRetransmissionSessionPairs, run: (graph, question) => retransmissionSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_zero_window_pairs", protocol: "tcp", status: "deterministic_zero_window_pairs", errorPrefix: "Zero Window 通信对查询失败", match: shouldListZeroWindowSessionPairs, run: (graph, question) => zeroWindowSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_syn_no_synack_pairs", protocol: "tcp", status: "deterministic_syn_no_synack_pairs", errorPrefix: "SYN 无 SYN-ACK 查询失败", match: shouldListSynNoSynAckPairs, run: (graph, question) => synNoSynAckSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_one_way_pairs", protocol: "tcp", status: "deterministic_one_way_pairs", errorPrefix: "单向通信对查询失败", match: shouldListOneWayPairs, run: (graph, question) => oneWaySessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_issues_overview", protocol: "tcp", status: "deterministic_tcp_overview", errorPrefix: "TCP 异常总览查询失败", match: shouldListTcpIssues, run: (graph, question) => tcpIssuesOverviewAnswer(ctx, graph, question) },
    { id: "tcp_connection_health_matrix", protocol: "tcp", status: "deterministic_connection_health_matrix", errorPrefix: "TCP 连接健康全景查询失败", match: shouldListConnectionHealthMatrix, run: (graph, question) => connectionHealthMatrixAnswer(ctx, graph, question) }
  ];
}
