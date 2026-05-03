import type { ProtocolAdapter, ProtocolAdapterContext, ProtocolPairGroup, ProtocolPacket } from "./types.js";

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
  return /(?:tcp|传输层|连接|异常|问题|故障|session|会话|通信)/i.test(question) && !shouldListResetSessionPairs(question) && !shouldListRetransmissionSessionPairs(question) && !shouldListZeroWindowSessionPairs(question) && !shouldListSynNoSynAckPairs(question) && !shouldListOneWayPairs(question);
}

async function resetSessionPairsAnswer(ctx: ProtocolAdapterContext, graph: Parameters<ProtocolAdapter["run"]>[0], question: string) {
  const limit = ctx.requestedLimit(question, 10);
  const captures = ctx.captureQueryInputs(graph);
  if (!captures.length) return ctx.noCaptureAnswer();
  const query = await ctx.displayFilterFromQuestion(graph, question);
  const result = await ctx.listTcpResets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit });
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
  const result = await ctx.listTcpRetransmissions({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit });
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
  const result = await ctx.listTcpZeroWindow({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit });
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
  const result = await ctx.queryPackets({ captures, displayFilter: synFilter, limit: ctx.queryPacketLimit });
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
  const result = await ctx.queryPackets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit });
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
    ctx.listTcpResets({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit }),
    ctx.listTcpRetransmissions({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit }),
    ctx.listTcpZeroWindow({ captures, displayFilter: query.displayFilter, limit: ctx.queryPacketLimit })
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
      handoffAgent: "EvidenceAgent"
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
    handoffAgent: "EvidenceAgent"
  });
}

export function createTcpAdapters(ctx: ProtocolAdapterContext): ProtocolAdapter[] {
  return [
    { id: "tcp_rst_pairs", protocol: "tcp", status: "deterministic_rst_pairs", errorPrefix: "RST 通信对查询失败", match: shouldListResetSessionPairs, run: (graph, question) => resetSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_retransmission_pairs", protocol: "tcp", status: "deterministic_retransmission_pairs", errorPrefix: "重传通信对查询失败", match: shouldListRetransmissionSessionPairs, run: (graph, question) => retransmissionSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_zero_window_pairs", protocol: "tcp", status: "deterministic_zero_window_pairs", errorPrefix: "Zero Window 通信对查询失败", match: shouldListZeroWindowSessionPairs, run: (graph, question) => zeroWindowSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_syn_no_synack_pairs", protocol: "tcp", status: "deterministic_syn_no_synack_pairs", errorPrefix: "SYN 无 SYN-ACK 查询失败", match: shouldListSynNoSynAckPairs, run: (graph, question) => synNoSynAckSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_one_way_pairs", protocol: "tcp", status: "deterministic_one_way_pairs", errorPrefix: "单向通信对查询失败", match: shouldListOneWayPairs, run: (graph, question) => oneWaySessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_issues_overview", protocol: "tcp", status: "deterministic_tcp_overview", errorPrefix: "TCP 异常总览查询失败", match: shouldListTcpIssues, run: (graph, question) => tcpIssuesOverviewAnswer(ctx, graph, question) }
  ];
}
