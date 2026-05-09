import type { PacketSummary } from "../../../../packages/shared/src/index.js";
import { buildProtocolCorrelations, buildHttpCrossConnectionCorrelation } from "./builders.js";
import type { ProtocolAdapter, ProtocolAdapterContext } from "./types.js";

function shouldListHttpTransactions(question: string) {
  return /(?<!\w)http|状态码|status|[45]xx|(?<!\d)[45]\d\d(?!\d)|host|uri|url/i.test(question) && !/\bhttps\b|tls|ssl/i.test(question);
}

function httpStatusFilter(question: string) {
  if (/[45]xx|4xx|5xx|错误状态|异常状态/i.test(question)) return "http.response.code >= 400";
  const statusCode = question.match(/(?<!\d)([1-5]\d\d)(?!\d)/)?.[1];
  if (statusCode) return `http.response.code == ${statusCode}`;
  return "";
}

function httpLabel(packet: PacketSummary) {
  if (packet.httpResponseCode !== undefined) return `HTTP ${packet.httpResponseCode}`;
  if (packet.httpRequestMethod) return `${packet.httpRequestMethod} ${packet.httpRequestUri || "/"}`;
  return "HTTP packet";
}

function httpCardSummary(packet: PacketSummary) {
  const host = packet.httpHost ? `Host=${packet.httpHost}，` : "";
  const uri = packet.httpRequestUri ? `URI=${packet.httpRequestUri}，` : "";
  const server = packet.httpServer ? `Server=${packet.httpServer}，` : "";
  const code = packet.httpResponseCode !== undefined ? `Status=${packet.httpResponseCode} ${packet.httpResponseCodeDescription || ""}，` : "";
  const latency = packet.httpTime !== undefined ? `耗时=${packet.httpTime}s，` : "";
  return `${packet.srcIp || "*"} -> ${packet.dstIp || "*"}，${host}${uri}${server}${code}${latency}${packet.summary || "HTTP 事件"}`;
}

function httpCheck(packets: PacketSummary[]) {
  const requests = packets.filter((packet) => packet.httpRequestMethod);
  const responses = packets.filter((packet) => packet.httpResponseCode !== undefined);
  const errorResponses = responses.filter((packet) => packet.httpResponseCode !== undefined && packet.httpResponseCode >= 400);
  const unansweredRequests = requests.filter((packet) => packet.httpResponseIn === undefined);
  if (errorResponses.length) {
    return {
      status: "problem" as const,
      summary: `发现 ${errorResponses.length} 个 HTTP 4xx/5xx 响应。`,
      packetIds: errorResponses.map((packet) => packet.packetId)
    };
  }
  if (unansweredRequests.length && !responses.length) {
    return {
      status: "problem" as const,
      summary: `发现 ${unansweredRequests.length} 个 HTTP request，但当前查询范围内未看到 response。`,
      packetIds: unansweredRequests.map((packet) => packet.packetId)
    };
  }
  if (requests.length && responses.length) {
    return {
      status: "ok" as const,
      summary: `发现 ${requests.length} 个 request 和 ${responses.length} 个 response，未发现 4xx/5xx。`,
      packetIds: [...requests.slice(0, 3), ...responses.slice(0, 3)].map((packet) => packet.packetId)
    };
  }
  return {
    status: packets.length ? "unknown" as const : "ok" as const,
    summary: packets.length ? "发现 HTTP 包，但未形成明确 request/response 判断。" : "当前查询范围内没有发现 HTTP 包。",
    packetIds: packets.map((packet) => packet.packetId)
  };
}

function httpStatusCodeDistribution(responses: PacketSummary[]) {
  const distribution = new Map<number, { code: number; count: number; packetIds: string[] }>();
  for (const packet of responses) {
    if (packet.httpResponseCode === undefined) continue;
    const current = distribution.get(packet.httpResponseCode);
    if (current) {
      current.count += 1;
      current.packetIds.push(packet.packetId);
    } else {
      distribution.set(packet.httpResponseCode, { code: packet.httpResponseCode, count: 1, packetIds: [packet.packetId] });
    }
  }
  return [...distribution.values()].sort((a, b) => b.count - a.count);
}

function httpLatencyStats(packets: PacketSummary[]) {
  const pairedPackets = packets.filter((p) => p.httpTime !== undefined);
  if (!pairedPackets.length) return null;
  const times = pairedPackets.map((p) => p.httpTime!);
  const max = Math.max(...times);
  const avg = times.reduce((sum, t) => sum + t, 0) / times.length;
  const outliers = pairedPackets.filter((p) => p.httpTime !== undefined && p.httpTime > avg * 3);
  return { count: times.length, avg: avg.toFixed(3), max: max.toFixed(3), outlierCount: outliers.length, outlierPacketIds: outliers.map((p) => p.packetId) };
}

function httpHostDistribution(requests: PacketSummary[]) {
  const hosts = new Map<string, number>();
  for (const packet of requests) {
    if (!packet.httpHost) continue;
    hosts.set(packet.httpHost, (hosts.get(packet.httpHost) || 0) + 1);
  }
  return [...hosts.entries()].sort((a, b) => b[1] - a[1]).map(([host, count]) => ({ host, count }));
}

function compareSameEndpointRequests(
  requests: PacketSummary[],
  responses: PacketSummary[],
  allPackets: PacketSummary[]
) {
  // 按 (method, uri_path) 聚合请求，匹配对应响应
  type ReqResp = { request: PacketSummary; response?: PacketSummary };
  const byEndpoint = new Map<string, ReqResp[]>();
  for (const req of requests) {
    const method = req.httpRequestMethod || "";
    const uri = req.httpRequestUri || "/";
    const key = `${method} ${uri}`;
    const list = byEndpoint.get(key) || [];
    const resp = responses.find((r) => r.httpResponseIn === req.frameNumber);
    list.push({ request: req, response: resp });
    byEndpoint.set(key, list);
  }

  for (const [, reqResps] of byEndpoint) {
    if (reqResps.length < 2) continue;
    const codes = new Set(reqResps.map((rr) => rr.response?.httpResponseCode).filter((c): c is number => c !== undefined));
    if (codes.size < 2) continue;

    const hasError = [...codes].some((c) => c >= 400);
    const hasOk = [...codes].some((c) => c < 400);
    if (!hasError || !hasOk) continue;

    const grouped = [...codes].sort((a, b) => a - b).map((code) => {
      const matching = reqResps.filter((rr) => rr.response?.httpResponseCode === code);
      const servers = [...new Set(matching.map((rr) => rr.response?.httpServer).filter(Boolean))];
      const dstIps = [...new Set(matching.map((rr) => rr.request.dstIp).filter(Boolean))];
      return `${code}(${matching.length}次)${servers.length ? ` Server=${servers.join("/")}` : ""}${dstIps.length > 1 ? ` 目标=${dstIps.join(",")}` : ""}`;
    });

    const sampleIds = reqResps.flatMap((rr) => [rr.request.packetId, rr.response?.packetId]).filter(Boolean) as string[];

    return {
      key: "http" as const,
      label: "同接口不同响应对比",
      status: "problem" as const,
      summary: `相同接口 ${reqResps[0].request.httpRequestMethod} ${reqResps[0].request.httpRequestUri} 出现不同响应码：${grouped.join("；")}。`,
      packetIds: sampleIds.slice(0, 10),
      nextSteps: ["对比正常和异常请求的 URI 编码、Header、目标 IP 差异，定位错误来源。"]
    };
  }
  return null;
}

function buildHttpChecks(packets: PacketSummary[], correlations: unknown[]) {
  const requests = packets.filter((packet) => packet.httpRequestMethod);
  const responses = packets.filter((packet) => packet.httpResponseCode !== undefined);
  const errorResponses = responses.filter((packet) => packet.httpResponseCode !== undefined && packet.httpResponseCode >= 400);
  const checks: Array<{ key: "http"; label: string; status: "ok" | "warn" | "problem" | "unknown"; summary: string; packetIds: string[]; nextSteps: string[] }> = [];

  const mainCheck = httpCheck(packets);
  checks.push({
    key: "http",
    label: "HTTP transaction",
    status: mainCheck.status,
    summary: `${mainCheck.summary}${correlations.length ? ` 已生成 ${correlations.length} 条 HTTP-to-TCP 关联。` : ""}`,
    packetIds: mainCheck.packetIds,
    nextSteps: ["查看 HTTP 状态码、request/response 是否成对，以及底层 TCP 是否存在 RST 或重传。"]
  });

  if (responses.length) {
    const distribution = httpStatusCodeDistribution(responses);
    const errorCodes = distribution.filter((d) => d.code >= 400);
    if (errorCodes.length) {
      const detail = errorCodes.map((d) => `${d.code}×${d.count}`).join("、");
      const errorPackets = errorCodes.flatMap((d) => d.packetIds.map((pid) => packets.find((p) => p.packetId === pid)).filter(Boolean)) as PacketSummary[];
      const servers = [...new Set(errorPackets.map((p) => p.httpServer).filter(Boolean))] as string[];
      const serverInfo = servers.length ? `返回者：${servers.join("、")}。` : "";
      checks.push({
        key: "http",
        label: "HTTP 状态码分布",
        status: "problem",
        summary: `响应码分布：${distribution.map((d) => `${d.code}(${d.count})`).join("、")}。异常码：${detail}。${serverInfo}`,
        packetIds: errorCodes.flatMap((d) => d.packetIds.slice(0, 3)),
        nextSteps: ["对比不同节点（如 nginx 前后）的 HTTP 状态码差异，定位错误来源。"]
      });
    } else {
      checks.push({
        key: "http",
        label: "HTTP 状态码分布",
        status: "ok",
        summary: `响应码分布：${distribution.map((d) => `${d.code}(${d.count})`).join("、")}，全部正常。`,
        packetIds: distribution.flatMap((d) => d.packetIds.slice(0, 1)),
        nextSteps: []
      });
    }
  }

  const latencyStats = httpLatencyStats(packets);
  if (latencyStats && latencyStats.outlierCount > 0) {
    checks.push({
      key: "http",
      label: "HTTP 响应延迟",
      status: "warn",
      summary: `平均 ${latencyStats.avg}s，最大 ${latencyStats.max}s，${latencyStats.outlierCount} 个超过 3 倍平均。`,
      packetIds: latencyStats.outlierPacketIds.slice(0, 5),
      nextSteps: ["检查延迟异常的请求是否集中在特定后端或时间段。"]
    });
  }

  if (requests.length > 1) {
    const hostDist = httpHostDistribution(requests);
    if (hostDist.length > 1) {
      checks.push({
        key: "http",
        label: "HTTP Host 分布",
        status: "ok",
        summary: `涉及 ${hostDist.length} 个 Host：${hostDist.slice(0, 5).map((h) => `${h.host}(${h.count})`).join("、")}。`,
        packetIds: [],
        nextSteps: []
      });
    }
  }

  // 同接口正常/异常请求对比
  if (errorResponses.length && requests.length && responses.length) {
    const sameEndpointDiff = compareSameEndpointRequests(requests, responses, packets);
    if (sameEndpointDiff) checks.push(sameEndpointDiff);
  }

  return checks;
}

export function createHttpAdapter(ctx: ProtocolAdapterContext): ProtocolAdapter {
  return {
    id: "http_transactions",
    protocol: "http",
    status: "deterministic_http",
    errorPrefix: "HTTP 查询失败",
    match: shouldListHttpTransactions,
    async run(graph, question) {
      const captures = ctx.captureQueryInputs(graph);
      if (!captures.length) return ctx.noCaptureAnswer();
      const displayLimit = ctx.requestedLimit(question, 20);
      const query = await ctx.displayFilterFromQuestion(graph, question, "http");
      const statusFilter = httpStatusFilter(question);
      const displayFilter = [query.displayFilter, statusFilter].filter(Boolean).join(" && ");
      const result = await ctx.listHttpPackets({ captures, displayFilter, limit: ctx.queryPacketLimit || undefined });
      const allPackets = result.packets;
      const displayPackets = allPackets.slice(0, displayLimit);
      const queryRunId = `http-${Date.now()}`;
      const cards = displayPackets.map((packet) => ctx.protocolPacketCard(
        packet,
        queryRunId,
        `${httpLabel(packet)} / Frame ${packet.frameNumber}`,
        httpCardSummary(packet),
        "transaction"
      ));
      const protocolCorrelations = [
        ...buildProtocolCorrelations(queryRunId, "http", allPackets, cards),
        ...buildHttpCrossConnectionCorrelation(queryRunId, allPackets, cards)
      ];
      const checks = buildHttpChecks(allPackets, protocolCorrelations);
      return ctx.protocolQueryAnswer({
        graph,
        queryRunId,
        queryInput: query.input,
        displayFilter,
        protocol: "http",
        title: allPackets.length > displayLimit ? `共 ${allPackets.length} 个 HTTP transaction（展示前 ${displayLimit} 个）` : `${allPackets.length} 个 HTTP transaction 证据`,
        packets: displayPackets,
        noResult: "当前查询范围内没有发现 HTTP request/response。",
        thoughts: [
          "识别为 L7 HTTP transaction 查询。",
          `构造 display filter：${displayFilter}`,
          `tshark 查询返回 ${allPackets.length} 个匹配包。`,
          "调用 tshark-query MCP 查询 HTTP 包，并提取 method、host、uri、status code 和响应耗时。",
          "将 HTTP Host/URI 关联回承载它的 TCP flow。"
        ],
        evidenceCards: cards,
        protocolCorrelations,
        checks,
        suggestedActions: ["结合 HTTP 状态码、响应耗时和底层 TCP session 判断失败发生在应用层还是传输层。"],
        handoffAgent: "ProtocolAgent"
      });
    }
  };
}
