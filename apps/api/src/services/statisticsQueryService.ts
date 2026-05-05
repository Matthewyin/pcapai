import {
  AnalysisFilterSchema,
  QueryDiagnosisSchema,
  QueryRunSchema,
  type AgentAnswer,
  type CaseGraph,
  type EvidenceCard,
  type QueryRun
} from "../../../../packages/shared/src/index.js";
import {
  getNetworkStatisticsWithMcp,
  listProtocolsWithMcp,
  listTcpConversationsWithMcp,
  type CaptureQueryInput
} from "../mcp/tsharkQueryClient.js";

type NetworkStatistics = Awaited<ReturnType<typeof getNetworkStatisticsWithMcp>>;

export function createStatisticsQueryService(input: {
  retainedQueryRunLimit: number;
  captureQueryInputs: (graph: CaseGraph) => CaptureQueryInput[];
  writeCaseGraph: (graph: CaseGraph) => void;
  setGraph: (caseId: string, graph: CaseGraph) => void;
  recordMcpRun: (caseId: string, runInput: {
    target: string;
    question?: string;
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
  }) => unknown;
  recordQueryRunMcp: (caseId: string, target: string, question: string, queryRun: QueryRun, summary: string, inputSummary: string, outputSummary: string) => unknown;
  formatBeijingTime: (epochSeconds: number) => string;
}) {
  function timeRangeFromPackets(packets: Array<{ timestamp?: number }>) {
    const timestamps = packets.map((packet) => packet.timestamp).filter((timestamp): timestamp is number => Number.isFinite(timestamp));
    if (!timestamps.length) return null;
    const start = Math.min(...timestamps);
    const end = Math.max(...timestamps);
    return {
      packetCount: packets.length,
      timestampCount: timestamps.length,
      start,
      end,
      durationSeconds: Math.max(0, end - start)
    };
  }

  function timeRangeFromCaptures(captures: Array<{ packetCount?: number; firstPacketTime?: number; lastPacketTime?: number }>) {
    const ranges = captures.filter((capture) => Number.isFinite(capture.firstPacketTime) && Number.isFinite(capture.lastPacketTime));
    if (!ranges.length) return null;
    const start = Math.min(...ranges.map((capture) => capture.firstPacketTime!));
    const end = Math.max(...ranges.map((capture) => capture.lastPacketTime!));
    const packetCount = ranges.reduce((sum, capture) => sum + (capture.packetCount || 0), 0);
    return {
      packetCount,
      timestampCount: packetCount,
      start,
      end,
      durationSeconds: Math.max(0, end - start)
    };
  }

  function noCaptureStatisticsAnswer(target: string): AgentAnswer {
    return {
      answer: `当前会话还没有可查询的 pcap 文件，无法统计${target}。`,
      evidenceIds: [],
      packetIds: [],
      sessionLinkIds: [],
      findingIds: [],
      missingContext: ["缺少 pcap 文件"],
      confidence: "needs_context",
      suggestedActions: ["先在聊天输入框上传 pcap/pcapng/cap 文件。"],
      handoffAgent: "HypothesisAgent"
    };
  }

  function topLines<T>(items: T[], formatter: (item: T, index: number) => string, empty = "- 无数据。") {
    const lines = items.slice(0, 20).map(formatter);
    return lines.length ? lines : [empty];
  }

  function dnsRcodeLabel(rcode: number) {
    const labels: Record<number, string> = {
      0: "NOERROR",
      1: "FORMERR",
      2: "SERVFAIL",
      3: "NXDOMAIN",
      4: "NOTIMP",
      5: "REFUSED"
    };
    return labels[rcode] || `RCODE ${rcode}`;
  }

  function statisticPcapFilename(captures: CaptureQueryInput[]) {
    return captures.length === 1 ? captures[0].pcapFilename : undefined;
  }

  function statisticEvidenceCards(
    queryRunId: string,
    captures: CaptureQueryInput[],
    cards: Array<{ title: string; summary: string; displayFilter?: string }>
  ): EvidenceCard[] {
    const pcapFilename = statisticPcapFilename(captures);
    return cards.map((card, index) => ({
      cardId: `stat-${queryRunId}-${index + 1}`,
      kind: "statistic" as const,
      title: card.title,
      summary: card.summary,
      pcapFilename,
      displayFilter: card.displayFilter,
      queryRunId,
      actions: card.displayFilter ? ["copy_filter" as const, ...(pcapFilename ? ["open_wireshark" as const] : [])] : ["copy_filter" as const]
    }));
  }

  function persistStatisticsQueryRun(persistInput: {
    graph: CaseGraph;
    question: string;
    protocol: string;
    displayFilter: string;
    totalCount: number;
    evidenceCards: EvidenceCard[];
    summary: string;
    nextSteps: string[];
  }) {
    const queryRunId = persistInput.evidenceCards[0]?.queryRunId || `query-${Date.now()}`;
    const selectedDiagnosis = QueryDiagnosisSchema.parse({
      conversationId: queryRunId,
      summary: persistInput.summary,
      confidence: "certain",
      checks: [{
        key: "protocol",
        label: "确定性统计",
        status: "ok",
        summary: persistInput.summary,
        packetIds: [],
        nextSteps: persistInput.nextSteps
      }],
      diagnosticTags: [],
      evidence: [],
      findings: [],
      nextSteps: persistInput.nextSteps
    });
    const queryRun = QueryRunSchema.parse({
      queryRunId,
      caseId: persistInput.graph.spec.caseId,
      question: persistInput.question,
      protocol: persistInput.protocol,
      displayFilter: persistInput.displayFilter,
      totalConversationCount: persistInput.totalCount,
      evidenceCards: persistInput.evidenceCards,
      selectedEvidenceCardId: persistInput.evidenceCards[0]?.cardId,
      selectedDiagnosis,
      createdAt: new Date().toISOString()
    });
    const nextGraph: CaseGraph = {
      ...persistInput.graph,
      queryRuns: [queryRun, ...(persistInput.graph.queryRuns || [])].slice(0, input.retainedQueryRunLimit),
      activeQueryRunId: queryRunId,
      analysisFilter: AnalysisFilterSchema.parse({ protocol: persistInput.protocol })
    };
    input.writeCaseGraph(nextGraph);
    input.setGraph(persistInput.graph.spec.caseId, nextGraph);
    return queryRun;
  }

  function topIpCards(kind: "src" | "dst", queryRunId: string, captures: CaptureQueryInput[], items: NetworkStatistics["sourceIps"]) {
    const field = kind === "src" ? "ip.src" : "ip.dst";
    const label = kind === "src" ? "源 IP" : "目的 IP";
    return statisticEvidenceCards(queryRunId, captures, items.slice(0, 10).map((item, index) => ({
      title: `${label} Top ${index + 1}: ${item.ip}`,
      summary: `${item.packetCount} 包。点击可用 ${field} 过滤该 IP。`,
      displayFilter: `${field} == ${item.ip}`
    })));
  }

  function portFilter(protocol: string, port: number) {
    return `${protocol}.port == ${port}`;
  }

  function protocolDisplayFilter(protocol: string) {
    const value = protocol.toLowerCase();
    if (value.startsWith("tls")) return "tls";
    if (value === "tcp") return "tcp";
    if (value === "udp") return "udp";
    if (value === "dns") return "dns";
    if (value === "http") return "http";
    if (value === "icmp" || value === "icmpv6") return "icmp || icmpv6";
    if (value === "arp") return "arp";
    return value;
  }

  function isProtocolStatisticsQuestion(question: string) {
    return /协议.*(多少|几|数量|种类|类型|分布|列表|排行|排名)|多少.*协议|几个.*协议|有.*协议|协议种类|协议类型|protocol/i.test(question);
  }

  async function deterministicStatisticsAnswer(graph: CaseGraph, rawQuestion: string): Promise<AgentAnswer | null> {
    if (/源\s*IP.*(排名|排行|top|最多)|src\s*ip/i.test(rawQuestion) || /目的\s*IP.*(排名|排行|top|最多)|dst\s*ip|目标\s*IP.*(排名|排行|top|最多)/i.test(rawQuestion) || /IP.*(数量|多少|几个|排名|排行|分布)|多少.*IP|几个.*IP/i.test(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("IP 数量和排名");
      const stats = await getNetworkStatisticsWithMcp({ captures });
      const wantsSourceOnly = /源\s*IP|src\s*ip/i.test(rawQuestion) && !/目的\s*IP|dst\s*ip|目标\s*IP/i.test(rawQuestion);
      const wantsDestinationOnly = /目的\s*IP|dst\s*ip|目标\s*IP/i.test(rawQuestion) && !/源\s*IP|src\s*ip/i.test(rawQuestion);
      const queryRunId = `query-${Date.now()}`;
      const sections = [
        `当前文件中共发现 ${stats.ipCount} 个 IP；其中源 IP ${stats.sourceIpCount} 个，目的 IP ${stats.destinationIpCount} 个，覆盖 ${stats.packetCount} 个包。`
      ];
      if (!wantsDestinationOnly) {
        sections.push("", "源 IP 排名（前 20）：", ...topLines(stats.sourceIps, (item, index) => `${index + 1}. ${item.ip}: ${item.packetCount} 包`));
      }
      if (!wantsSourceOnly) {
        sections.push("", "目的 IP 排名（前 20）：", ...topLines(stats.destinationIps, (item, index) => `${index + 1}. ${item.ip}: ${item.packetCount} 包`));
      }
      sections.push("", "统计口径：使用 tshark 读取 ip.src/ipv6.src 与 ip.dst/ipv6.dst；同一包的源和目的分别计入对应排名。");
      const evidenceCards = [
        ...statisticEvidenceCards(queryRunId, captures, [{
          title: "IP 统计总览",
          summary: `共 ${stats.ipCount} 个 IP；源 IP ${stats.sourceIpCount} 个，目的 IP ${stats.destinationIpCount} 个。`,
          displayFilter: "ip || ipv6"
        }]),
        ...(!wantsDestinationOnly ? topIpCards("src", queryRunId, captures, stats.sourceIps) : []),
        ...(!wantsSourceOnly ? topIpCards("dst", queryRunId, captures, stats.destinationIps) : [])
      ];
      const queryRun = persistStatisticsQueryRun({
        graph,
        question: rawQuestion,
        protocol: "ip",
        displayFilter: "ip || ipv6",
        totalCount: stats.ipCount,
        evidenceCards,
        summary: sections[0],
        nextSteps: ["点击某个 IP 证据卡下钻到 Wireshark filter，或继续追问该 IP 的通信对和端口分布。"]
      });
      input.recordQueryRunMcp(graph.spec.caseId, "get_network_statistics", rawQuestion, queryRun, "统计 IP 数量和源/目的 IP 排名。", `captures=${captures.length}`, `ip=${stats.ipCount}; src=${stats.sourceIpCount}; dst=${stats.destinationIpCount}; packets=${stats.packetCount}`);
      return {
        answer: sections.join("\n"),
        thoughts: [
          "识别为 IP 统计问题。",
          "调用 tshark-query MCP 的 get_network_statistics。",
          `已保存轻量 QueryRun：${queryRun.queryRunId}，并生成可复用 EvidenceCard。`
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["可继续按某个 IP 追问通信对、端口分布或异常包。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (/端口.*(分布|排名|排行|数量|最多)|port.*(distribution|top|count)|哪些端口|多少.*端口/i.test(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("端口分布");
      const stats = await getNetworkStatisticsWithMcp({ captures });
      const queryRunId = `query-${Date.now()}`;
      const evidenceCards = statisticEvidenceCards(queryRunId, captures, [
        {
          title: "端口分布总览",
          summary: `共 ${stats.ports.length} 个传输层端口，按 tcp/udp 区分。`,
          displayFilter: "tcp || udp"
        },
        ...stats.destinationPorts.slice(0, 10).map((item, index) => ({
          title: `目的端口 Top ${index + 1}: ${item.protocol}/${item.port}`,
          summary: `${item.packetCount} 次出现。点击可过滤该目的端口相关流量。`,
          displayFilter: `${item.protocol}.dstport == ${item.port}`
        })),
        ...stats.ports.slice(0, 10).map((item, index) => ({
          title: `端口 Top ${index + 1}: ${item.protocol}/${item.port}`,
          summary: `${item.packetCount} 次出现。点击可过滤该端口双向流量。`,
          displayFilter: portFilter(item.protocol, item.port)
        }))
      ]);
      const queryRun = persistStatisticsQueryRun({
        graph,
        question: rawQuestion,
        protocol: "tcp",
        displayFilter: "tcp || udp",
        totalCount: stats.ports.length,
        evidenceCards,
        summary: `当前文件端口分布覆盖 ${stats.ports.length} 个传输层端口。`,
        nextSteps: ["点击目标端口证据卡进入 Wireshark，或继续追问该端口的通信对、RST、重传。"]
      });
      input.recordQueryRunMcp(graph.spec.caseId, "get_network_statistics", rawQuestion, queryRun, "统计 TCP/UDP 端口分布。", `captures=${captures.length}`, `ports=${stats.ports.length}; dstPorts=${stats.destinationPorts.length}`);
      return {
        answer: [
          `当前文件端口分布覆盖 ${stats.ports.length} 个传输层端口（按协议区分 tcp/udp）。`,
          "",
          "端口分布（前 20）：",
          ...topLines(stats.ports, (item, index) => `${index + 1}. ${item.protocol}/${item.port}: ${item.packetCount} 次出现`),
          "",
          "目的端口分布（前 20）：",
          ...topLines(stats.destinationPorts, (item, index) => `${index + 1}. ${item.protocol}/${item.port}: ${item.packetCount} 次出现`),
          "",
          "统计口径：使用 tshark 读取 tcp/udp 源端口和目的端口；总端口分布会同时统计源端口与目的端口出现次数。"
        ].join("\n"),
        thoughts: [
          "识别为端口分布统计问题。",
          "调用 tshark-query MCP 的 get_network_statistics。",
          `已保存轻量 QueryRun：${queryRun.queryRunId}，并生成端口 EvidenceCard。`
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["可继续指定端口生成 QueryRun，例如“分析到 443 端口的 TCP 通信”。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (/\bRST\b|reset|复位/i.test(rawQuestion) && /(数量|多少|几个|统计|count)/i.test(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("TCP RST 数量");
      const stats = await getNetworkStatisticsWithMcp({ captures });
      const queryRunId = `query-${Date.now()}`;
      const evidenceCards = statisticEvidenceCards(queryRunId, captures, [{
        title: "TCP RST 统计",
        summary: `共 ${stats.tcpRstCount} 个 TCP RST 包。`,
        displayFilter: "tcp.flags.reset == 1"
      }]);
      const queryRun = persistStatisticsQueryRun({
        graph,
        question: rawQuestion,
        protocol: "tcp",
        displayFilter: "tcp.flags.reset == 1",
        totalCount: stats.tcpRstCount,
        evidenceCards,
        summary: `当前文件中发现 ${stats.tcpRstCount} 个 TCP RST 包。`,
        nextSteps: ["点击 RST 证据卡查看 RST 包，或继续问“给出前 10 个有 reset 的 TCP session pair”。"]
      });
      input.recordQueryRunMcp(graph.spec.caseId, "get_network_statistics", rawQuestion, queryRun, "统计 TCP RST 包数量。", `captures=${captures.length}; field=tcp.flags.reset`, `tcpRstCount=${stats.tcpRstCount}`);
      return {
        answer: `当前文件中发现 ${stats.tcpRstCount} 个 TCP RST 包。\n\n统计口径：使用 tshark 读取 tcp.flags.reset。`,
        thoughts: [
          "识别为 TCP RST 数量统计问题。",
          "调用 tshark-query MCP 的 get_network_statistics。",
          `已保存轻量 QueryRun：${queryRun.queryRunId}，并生成 RST EvidenceCard。`
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["如需定位具体会话，可以继续问“给出前 10 个有 reset 的 TCP session pair”。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (/重传|retransmission|fast retransmission/i.test(rawQuestion) && /(数量|多少|几个|统计|count)/i.test(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("TCP 重传数量");
      const stats = await getNetworkStatisticsWithMcp({ captures });
      const queryRunId = `query-${Date.now()}`;
      const displayFilter = "tcp.analysis.retransmission || tcp.analysis.fast_retransmission";
      const evidenceCards = statisticEvidenceCards(queryRunId, captures, [{
        title: "TCP 重传统计",
        summary: `共 ${stats.tcpRetransmissionCount} 个 TCP 重传包。`,
        displayFilter
      }]);
      const queryRun = persistStatisticsQueryRun({
        graph,
        question: rawQuestion,
        protocol: "tcp",
        displayFilter,
        totalCount: stats.tcpRetransmissionCount,
        evidenceCards,
        summary: `当前文件中发现 ${stats.tcpRetransmissionCount} 个 TCP 重传包。`,
        nextSteps: ["点击重传证据卡查看重传包，或继续问“列出重传连接”。"]
      });
      input.recordQueryRunMcp(graph.spec.caseId, "get_network_statistics", rawQuestion, queryRun, "统计 TCP 重传包数量。", `captures=${captures.length}; filter=${displayFilter}`, `tcpRetransmissionCount=${stats.tcpRetransmissionCount}`);
      return {
        answer: `当前文件中发现 ${stats.tcpRetransmissionCount} 个 TCP 重传包。\n\n统计口径：使用 tshark 读取 tcp.analysis.retransmission 和 tcp.analysis.fast_retransmission。`,
        thoughts: [
          "识别为 TCP 重传数量统计问题。",
          "调用 tshark-query MCP 的 get_network_statistics。",
          `已保存轻量 QueryRun：${queryRun.queryRunId}，并生成重传 EvidenceCard。`
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["如需定位重传会话，可以继续问“列出重传连接”。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (/HTTP.*(状态码|status)|状态码.*HTTP|http.*(code|distribution|分布)/i.test(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("HTTP 状态码分布");
      const stats = await getNetworkStatisticsWithMcp({ captures });
      const queryRunId = `query-${Date.now()}`;
      const evidenceCards = statisticEvidenceCards(queryRunId, captures, [
        {
          title: "HTTP 状态码总览",
          summary: `共 ${stats.httpStatusCodes.length} 类 HTTP 状态码。`,
          displayFilter: "http.response.code"
        },
        ...stats.httpStatusCodes.slice(0, 20).map((item, index) => ({
          title: `HTTP 状态码 Top ${index + 1}: ${item.code}`,
          summary: `${item.packetCount} 包。点击可过滤该状态码。`,
          displayFilter: `http.response.code == ${item.code}`
        }))
      ]);
      const queryRun = persistStatisticsQueryRun({
        graph,
        question: rawQuestion,
        protocol: "http",
        displayFilter: "http.response.code",
        totalCount: stats.httpStatusCodes.length,
        evidenceCards,
        summary: `当前文件中发现 ${stats.httpStatusCodes.length} 类 HTTP 状态码。`,
        nextSteps: ["点击具体 HTTP 状态码证据卡查看响应包，或继续追问 HTTP 4xx/5xx。"]
      });
      input.recordQueryRunMcp(graph.spec.caseId, "get_network_statistics", rawQuestion, queryRun, "统计 HTTP 状态码分布。", `captures=${captures.length}; field=http.response.code`, `httpStatusCodes=${stats.httpStatusCodes.length}`);
      return {
        answer: [
          `当前文件中发现 ${stats.httpStatusCodes.length} 类 HTTP 状态码。`,
          "",
          "HTTP 状态码分布：",
          ...topLines(stats.httpStatusCodes, (item, index) => `${index + 1}. ${item.code}: ${item.packetCount} 包`),
          "",
          "统计口径：使用 tshark 读取 http.response.code。"
        ].join("\n"),
        thoughts: [
          "识别为 HTTP 状态码分布统计问题。",
          "调用 tshark-query MCP 的 get_network_statistics。",
          `已保存轻量 QueryRun：${queryRun.queryRunId}，并生成 HTTP 状态码 EvidenceCard。`
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["如需看失败请求，可以继续问“列出 HTTP 4xx/5xx”。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (/DNS.*(rcode|返回码|响应码|状态码|分布)|rcode.*DNS/i.test(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("DNS rcode 分布");
      const stats = await getNetworkStatisticsWithMcp({ captures });
      const queryRunId = `query-${Date.now()}`;
      const evidenceCards = statisticEvidenceCards(queryRunId, captures, [
        {
          title: "DNS rcode 总览",
          summary: `共 ${stats.dnsRcodes.length} 类 DNS rcode。`,
          displayFilter: "dns.flags.rcode"
        },
        ...stats.dnsRcodes.slice(0, 20).map((item, index) => ({
          title: `DNS rcode Top ${index + 1}: ${dnsRcodeLabel(item.rcode)}`,
          summary: `${item.packetCount} 包。点击可过滤该 rcode。`,
          displayFilter: `dns.flags.rcode == ${item.rcode}`
        }))
      ]);
      const queryRun = persistStatisticsQueryRun({
        graph,
        question: rawQuestion,
        protocol: "dns",
        displayFilter: "dns.flags.rcode",
        totalCount: stats.dnsRcodes.length,
        evidenceCards,
        summary: `当前文件中发现 ${stats.dnsRcodes.length} 类 DNS rcode。`,
        nextSteps: ["点击具体 DNS rcode 证据卡查看响应包，或继续追问 DNS 失败。"]
      });
      input.recordQueryRunMcp(graph.spec.caseId, "get_network_statistics", rawQuestion, queryRun, "统计 DNS rcode 分布。", `captures=${captures.length}; field=dns.flags.rcode`, `dnsRcodes=${stats.dnsRcodes.length}`);
      return {
        answer: [
          `当前文件中发现 ${stats.dnsRcodes.length} 类 DNS rcode。`,
          "",
          "DNS rcode 分布：",
          ...topLines(stats.dnsRcodes, (item, index) => `${index + 1}. ${dnsRcodeLabel(item.rcode)} (${item.rcode}): ${item.packetCount} 包`),
          "",
          "统计口径：使用 tshark 读取 dns.flags.rcode。"
        ].join("\n"),
        thoughts: [
          "识别为 DNS rcode 分布统计问题。",
          "调用 tshark-query MCP 的 get_network_statistics。",
          `已保存轻量 QueryRun：${queryRun.queryRunId}，并生成 DNS rcode EvidenceCard。`
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["如需看解析失败，可以继续问“列出 DNS 失败”。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (/通信对|通讯对|会话对|连接数|session\s*pair|tcp\s*session|tcp.*连接/i.test(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("TCP 通信对");
      const result = await listTcpConversationsWithMcp({ captures, displayFilter: "tcp" });
      input.recordMcpRun(graph.spec.caseId, {
        target: "list_tcp_conversations",
        question: rawQuestion,
        summary: "按 TCP 五元组统计通信对。",
        inputSummary: `captures=${captures.length}; displayFilter=tcp`,
        outputSummary: `conversations=${result.conversations.length}; packets=${result.packetCount}`,
        displayFilter: "tcp"
      });
      const topConversations = result.conversations.slice(0, 10).map((conversation, index) => [
        `${index + 1}. ${conversation.srcIp || "*"}:${conversation.srcPort ?? "*"} -> ${conversation.dstIp || "*"}:${conversation.dstPort ?? "*"}`,
        `${conversation.packetCount} 包`,
        conversation.rstCount ? `RST ${conversation.rstCount}` : "",
        conversation.retransmissionCount ? `重传 ${conversation.retransmissionCount}` : "",
        conversation.zeroWindowCount ? `Zero Window ${conversation.zeroWindowCount}` : ""
      ].filter(Boolean).join("；"));
      return {
        answer: [
          `当前文件中按 TCP 五元组聚合，共发现 ${result.conversations.length} 个 TCP 通信对，覆盖 ${result.packetCount} 个 TCP 包。`,
          "",
          "通信对样本（前 10）：",
          ...(topConversations.length ? topConversations : ["- 未发现 TCP 通信对。"]),
          "",
          "统计口径：使用 tshark 查询 tcp 包，再按节点、pcap 文件、协议、源/目的 IP:Port 端点对聚合。"
        ].join("\n"),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["如需查看异常通信对，可以继续问“给出前 10 个有 reset 的 TCP session pair”或“列出重传连接”。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (isProtocolStatisticsQuestion(rawQuestion)) {
      const captures = input.captureQueryInputs(graph);
      if (!captures.length) return noCaptureStatisticsAnswer("协议种类");
      const result = await listProtocolsWithMcp({ captures });
      const queryRunId = `query-${Date.now()}`;
      const topProtocols = result.protocols.slice(0, 20).map((item, index) => `${index + 1}. ${item.protocol}: ${item.packetCount} 包`);
      const captureLines = result.captures.map((capture) => `${capture.pcapFilename}: ${capture.protocols.length} 种协议，${capture.packetCount} 包`);
      const evidenceCards = statisticEvidenceCards(queryRunId, captures, [
        {
          title: "协议统计总览",
          summary: `共 ${result.protocolCount} 种协议，覆盖 ${result.packetCount} 个包。`
        },
        ...result.protocols.slice(0, 20).map((item, index) => ({
          title: `协议 Top ${index + 1}: ${item.protocol}`,
          summary: `${item.packetCount} 包。点击可复制或打开该协议过滤器。`,
          displayFilter: protocolDisplayFilter(item.protocol)
        }))
      ]);
      const queryRun = persistStatisticsQueryRun({
        graph,
        question: rawQuestion,
        protocol: "protocol",
        displayFilter: "_ws.col.Protocol",
        totalCount: result.protocolCount,
        evidenceCards,
        summary: `当前文件中按 Wireshark 协议列统计，共发现 ${result.protocolCount} 种协议，覆盖 ${result.packetCount} 个包。`,
        nextSteps: ["点击具体协议证据卡复制或打开过滤器，继续下钻该协议的包和通信对象。"]
      });
      input.recordQueryRunMcp(graph.spec.caseId, "list_protocols", rawQuestion, queryRun, "统计 Wireshark 协议列分布。", `captures=${captures.length}; field=_ws.col.Protocol`, `protocols=${result.protocolCount}; packets=${result.packetCount}`);
      return {
        answer: [
          `当前文件中按 Wireshark 协议列统计，共发现 ${result.protocolCount} 种协议，覆盖 ${result.packetCount} 个包。`,
          "",
          "协议分布（前 20）：",
          ...topProtocols,
          "",
          "按文件统计：",
          ...captureLines,
          "",
          "统计口径：使用 tshark 读取 _ws.col.Protocol，每个包按 Wireshark 展示协议列计入一种协议。"
        ].join("\n"),
        thoughts: [
          "识别为协议种类/协议分布统计问题。",
          "调用 tshark-query MCP 的 list_protocols 读取原始 pcap 协议列。",
          `已保存轻量 QueryRun：${queryRun.queryRunId}，并生成协议 EvidenceCard。`
        ],
        evidenceCards: queryRun.evidenceCards,
        actions: queryRun.evidenceCards.flatMap((card) => card.actions),
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: [],
        confidence: "certain",
        suggestedActions: ["如需某个协议的包列表，可以继续问“列出 DNS/HTTP/TLS/ICMP 包”。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    if (!/时间范围|时间窗口|起止时间|开始时间|结束时间/.test(rawQuestion)) return null;
    const allCaptured = timeRangeFromPackets(graph.rawPackets);
    const filtered = timeRangeFromPackets(graph.packets);
    const captureRange = timeRangeFromCaptures(graph.captures);
    const selected = /筛选|当前数据包|当前包|命中/.test(rawQuestion) && filtered ? filtered : allCaptured || captureRange || filtered;
    if (!selected) {
      return {
        answer: "当前 case graph 中没有可用于计算时间范围的数据包时间戳。请先上传 pcap，或重新读取抓包文件元信息。",
        evidenceIds: [],
        packetIds: [],
        sessionLinkIds: [],
        findingIds: [],
        missingContext: ["缺少 packet timestamp"],
        confidence: "needs_context",
        suggestedActions: ["重新上传或重新查询 pcap，确认 tshark/capinfos 能读取抓包时间。"],
        handoffAgent: "HypothesisAgent"
      };
    }

    const lines = [
      `当前数据包时间范围：${input.formatBeijingTime(selected.start)} 到 ${input.formatBeijingTime(selected.end)}（北京时间）。`,
      `UTC：${new Date(selected.start * 1000).toISOString()} 到 ${new Date(selected.end * 1000).toISOString()}。`,
      `持续时间：${selected.durationSeconds.toFixed(3)} 秒。`,
      `覆盖包数：${selected.packetCount}，其中 ${selected.timestampCount} 个包有时间戳。`
    ];
    if (allCaptured && filtered && (allCaptured.start !== filtered.start || allCaptured.end !== filtered.end || allCaptured.packetCount !== filtered.packetCount)) {
      lines.push(`补充：全部捕获包范围为 ${input.formatBeijingTime(allCaptured.start)} 到 ${input.formatBeijingTime(allCaptured.end)}；当前筛选包范围为 ${input.formatBeijingTime(filtered.start)} 到 ${input.formatBeijingTime(filtered.end)}。`);
    }
    if (!allCaptured && captureRange) {
      lines.push("说明：这是从抓包文件元信息读取的范围，上传阶段没有全量解析 packet summary。");
    }

    return {
      answer: lines.join("\n"),
      evidenceIds: [],
      packetIds: [],
      sessionLinkIds: [],
      findingIds: [],
      missingContext: [],
      confidence: "certain",
      suggestedActions: [],
      handoffAgent: "HypothesisAgent"
    };
  }

  return {
    deterministicStatisticsAnswer,
    isProtocolStatisticsQuestion
  };
}
