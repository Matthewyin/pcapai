import type { ProtocolAdapter, ProtocolAdapterContext, ProtocolPairGroup, ProtocolPacket } from "./types.js";

function shouldListResetSessionPairs(question: string) {
  return /(?:RST|reset|Reset|复位|重置)/i.test(question) && /(?:session|pair|会话|通信对|通讯对)/i.test(question);
}

function shouldListRetransmissionSessionPairs(question: string) {
  return /(?:重传|retransmission|fast retransmission|retrans)/i.test(question) && /(?:session|pair|会话|通信对|通讯对|连接)/i.test(question);
}

function shouldListZeroWindowSessionPairs(question: string) {
  return /(?:zero\s*window|Zero Window|零窗口|窗口为0|窗口为 0)/i.test(question) && /(?:session|pair|会话|通信对|通讯对|连接)/i.test(question);
}

function shouldListSynNoSynAckPairs(question: string) {
  return /(?:SYN|syn)/i.test(question) && /(?:SYN-ACK|synack|syn ack|ack)/i.test(question) && /(?:没有|无|未见|缺失|no|missing)/i.test(question);
}

function shouldListOneWayPairs(question: string) {
  return /(?:单向|只有一个方向|有去无回|one.?way|单方向)/i.test(question) && /(?:session|pair|会话|通信对|通讯对|连接|流量)/i.test(question);
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

export function createTcpAdapters(ctx: ProtocolAdapterContext): ProtocolAdapter[] {
  return [
    { id: "tcp_rst_pairs", protocol: "tcp", status: "deterministic_rst_pairs", errorPrefix: "RST 通信对查询失败", match: shouldListResetSessionPairs, run: (graph, question) => resetSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_retransmission_pairs", protocol: "tcp", status: "deterministic_retransmission_pairs", errorPrefix: "重传通信对查询失败", match: shouldListRetransmissionSessionPairs, run: (graph, question) => retransmissionSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_zero_window_pairs", protocol: "tcp", status: "deterministic_zero_window_pairs", errorPrefix: "Zero Window 通信对查询失败", match: shouldListZeroWindowSessionPairs, run: (graph, question) => zeroWindowSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_syn_no_synack_pairs", protocol: "tcp", status: "deterministic_syn_no_synack_pairs", errorPrefix: "SYN 无 SYN-ACK 查询失败", match: shouldListSynNoSynAckPairs, run: (graph, question) => synNoSynAckSessionPairsAnswer(ctx, graph, question) },
    { id: "tcp_one_way_pairs", protocol: "tcp", status: "deterministic_one_way_pairs", errorPrefix: "单向通信对查询失败", match: shouldListOneWayPairs, run: (graph, question) => oneWaySessionPairsAnswer(ctx, graph, question) }
  ];
}
