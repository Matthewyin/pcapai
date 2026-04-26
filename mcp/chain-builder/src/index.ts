import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "chain-builder-mcp", version: "0.1.0" });

type Confidence = "certain" | "high" | "low" | "needs_context";
type CaptureNode = {
  nodeId: string;
  name: string;
  role: string;
};
type SessionSegment = {
  segmentId: string;
  nodeId: string;
  protocol: string;
  clientIp?: string;
  clientPort?: number;
  serverIp?: string;
  serverPort?: number;
  startTime: number;
  endTime: number;
  packetIds: string[];
  eventKinds: string[];
};
type MappingHint = {
  hintId: string;
  kind: "nat" | "slb" | "proxy" | "gateway" | "tunnel";
  fromNodeId?: string;
  toNodeId?: string;
  originalSrcIp?: string;
  originalSrcPort?: number;
  originalDstIp?: string;
  originalDstPort?: number;
  translatedSrcIp?: string;
  translatedSrcPort?: number;
  translatedDstIp?: string;
  translatedDstPort?: number;
  note?: string;
};
type TimeOffsetHint = {
  hintId: string;
  fromNodeId?: string;
  toNodeId?: string;
  offsetSeconds: number;
  note?: string;
};
type SessionLink = {
  linkId: string;
  fromSegmentId: string;
  toSegmentId: string;
  fromNodeId: string;
  toNodeId: string;
  matchReasons: string[];
  counterEvidence: string[];
  confidence: Confidence;
  score: number;
};
type CaseGraphInput = {
  captures: CaptureNode[];
  sessions: SessionSegment[];
  mappingHints?: MappingHint[];
  timeOffsetHints?: TimeOffsetHint[];
};

function sameOptional<T>(left?: T, right?: T) {
  return left !== undefined && right !== undefined && left === right;
}

function timeGap(left: SessionSegment, right: SessionSegment, offsetSeconds = 0) {
  const adjustedRightStart = right.startTime + offsetSeconds;
  const adjustedRightEnd = right.endTime + offsetSeconds;
  return Math.max(0, adjustedRightStart - left.endTime, left.startTime - adjustedRightEnd);
}

function confidenceFor(score: number, counterEvidence: string[]): Confidence {
  if (counterEvidence.length >= 2) return "needs_context";
  if (score >= 80) return "high";
  if (score >= 45) return "low";
  return "needs_context";
}

function valueMatches<T>(expected: T | undefined, actual: T | undefined) {
  return expected === undefined || actual === expected;
}

function hintAppliesToPair(hint: MappingHint, left: SessionSegment, right: SessionSegment) {
  const hasEndpointCondition = [
    hint.originalSrcIp,
    hint.originalSrcPort,
    hint.originalDstIp,
    hint.originalDstPort,
    hint.translatedSrcIp,
    hint.translatedSrcPort,
    hint.translatedDstIp,
    hint.translatedDstPort
  ].some((value) => value !== undefined);
  if (!hasEndpointCondition) return false;
  if (hint.fromNodeId && hint.fromNodeId !== left.nodeId) return false;
  if (hint.toNodeId && hint.toNodeId !== right.nodeId) return false;
  return valueMatches(hint.originalSrcIp, left.clientIp)
    && valueMatches(hint.originalSrcPort, left.clientPort)
    && valueMatches(hint.originalDstIp, left.serverIp)
    && valueMatches(hint.originalDstPort, left.serverPort)
    && valueMatches(hint.translatedSrcIp, right.clientIp)
    && valueMatches(hint.translatedSrcPort, right.clientPort)
    && valueMatches(hint.translatedDstIp, right.serverIp)
    && valueMatches(hint.translatedDstPort, right.serverPort);
}

function timeOffsetForPair(left: SessionSegment, right: SessionSegment, timeOffsetHints: TimeOffsetHint[]) {
  const hint = timeOffsetHints.find((item) => {
    if (item.fromNodeId && item.fromNodeId !== left.nodeId) return false;
    if (item.toNodeId && item.toNodeId !== right.nodeId) return false;
    return true;
  });
  return hint ? { offsetSeconds: hint.offsetSeconds, hintId: hint.hintId } : { offsetSeconds: 0 };
}

function scorePair(left: SessionSegment, right: SessionSegment, mappingHints: MappingHint[], timeOffsetHints: TimeOffsetHint[]) {
  let score = 0;
  const matchReasons: string[] = [];
  const counterEvidence: string[] = [];
  const matchedHint = mappingHints.find((hint) => hintAppliesToPair(hint, left, right));
  const timeOffset = timeOffsetForPair(left, right, timeOffsetHints);

  if (left.protocol === right.protocol) {
    score += 20;
    matchReasons.push("协议一致");
  } else {
    counterEvidence.push("协议不一致");
  }

  if (sameOptional(left.clientIp, right.clientIp)) {
    score += 20;
    matchReasons.push("客户端地址一致");
  }
  if (sameOptional(left.clientPort, right.clientPort)) {
    score += 10;
    matchReasons.push("客户端端口一致");
  }
  if (sameOptional(left.serverIp, right.serverIp)) {
    score += 20;
    matchReasons.push("服务端地址一致");
  }
  if (sameOptional(left.serverPort, right.serverPort)) {
    score += 10;
    matchReasons.push("服务端端口一致");
  }

  const gap = timeGap(left, right, timeOffset.offsetSeconds);
  if (gap <= 1) {
    score += 15;
    matchReasons.push(timeOffset.hintId ? `时间窗口接近，已应用偏移 ${timeOffset.offsetSeconds}s (${timeOffset.hintId})` : "时间窗口接近");
  } else if (gap > 10) {
    counterEvidence.push(timeOffset.hintId ? `应用偏移 ${timeOffset.offsetSeconds}s 后时间窗口仍间隔较大` : "时间窗口间隔较大");
  }

  const commonEvents = left.eventKinds.filter((kind) => right.eventKinds.includes(kind));
  if (commonEvents.length) {
    score += Math.min(commonEvents.length * 5, 15);
    matchReasons.push(`关键事件一致：${commonEvents.join(",")}`);
  }

  if (left.packetIds.length && right.packetIds.length) {
    score += 5;
    matchReasons.push("两侧均有包级证据");
  }

  if (matchedHint) {
    score += 45;
    matchReasons.push(`命中 ${matchedHint.kind.toUpperCase()} 转换线索 ${matchedHint.hintId}`);
  } else if (!sameOptional(left.clientIp, right.clientIp) && !sameOptional(left.serverIp, right.serverIp)) {
    counterEvidence.push("端点地址未直接匹配，可能需要 NAT/SLB/代理线索");
  }

  return { score, matchReasons, counterEvidence };
}

function adjacentCapturePairs(captures: CaptureNode[]) {
  return captures.slice(0, -1).map((capture, index) => [capture, captures[index + 1]] as const);
}

function matchCrossNodeSessions(graph: CaseGraphInput) {
  const links: SessionLink[] = [];
  const mappingHints = graph.mappingHints || [];
  const timeOffsetHints = graph.timeOffsetHints || [];
  for (const [fromCapture, toCapture] of adjacentCapturePairs(graph.captures)) {
    const fromSessions = graph.sessions.filter((session) => session.nodeId === fromCapture.nodeId);
    const toSessions = graph.sessions.filter((session) => session.nodeId === toCapture.nodeId);
    for (const fromSession of fromSessions) {
      const candidates = toSessions
        .map((toSession) => ({ toSession, ...scorePair(fromSession, toSession, mappingHints, timeOffsetHints) }))
        .filter((candidate) => candidate.score >= 35)
        .sort((left, right) => right.score - left.score);
      const best = candidates[0];
      if (!best) continue;
      links.push({
        linkId: `link-${links.length + 1}`,
        fromSegmentId: fromSession.segmentId,
        toSegmentId: best.toSession.segmentId,
        fromNodeId: fromSession.nodeId,
        toNodeId: best.toSession.nodeId,
        matchReasons: best.matchReasons,
        counterEvidence: best.counterEvidence,
        confidence: confidenceFor(best.score, best.counterEvidence),
        score: best.score
      });
    }
  }
  return links;
}

function buildPathGraph(graph: CaseGraphInput, links: SessionLink[]) {
  return {
    nodes: graph.captures.map((capture) => ({
      nodeId: capture.nodeId,
      label: capture.name,
      role: capture.role,
      status: graph.sessions.some((session) => session.nodeId === capture.nodeId) ? "observed" as const : "missing" as const
    })),
    edges: adjacentCapturePairs(graph.captures).map(([fromCapture, toCapture], index) => {
      const edgeLinks = links.filter((link) => link.fromNodeId === fromCapture.nodeId && link.toNodeId === toCapture.nodeId);
      const hasHigh = edgeLinks.some((link) => link.confidence === "high");
      const hasLow = edgeLinks.some((link) => link.confidence === "low");
      const status = hasHigh ? "observed" as const : hasLow ? "suspect" as const : "unknown" as const;
      return {
        edgeId: `edge-${index + 1}`,
        fromNodeId: fromCapture.nodeId,
        toNodeId: toCapture.nodeId,
        status,
        label: status === "observed" ? "已关联" : status === "suspect" ? "低置信关联" : "待匹配"
      };
    })
  };
}

server.registerTool(
  "match_cross_node_sessions",
  {
    title: "Match cross-node sessions",
    description: "Match session segments across capture nodes.",
    inputSchema: {
      caseGraphJson: z.string()
    }
  },
  async ({ caseGraphJson }) => {
    const graph = JSON.parse(caseGraphJson) as CaseGraphInput;
    return { content: [{ type: "text", text: JSON.stringify({ links: matchCrossNodeSessions(graph) }) }] };
  }
);

server.registerTool(
  "build_path_graph",
  {
    title: "Build path graph",
    description: "Build an access path graph from captures, mappings, and session links.",
    inputSchema: {
      caseGraphJson: z.string(),
      sessionLinksJson: z.string()
    }
  },
  async ({ caseGraphJson, sessionLinksJson }) => {
    const graph = JSON.parse(caseGraphJson) as CaseGraphInput;
    const links = JSON.parse(sessionLinksJson) as SessionLink[];
    return { content: [{ type: "text", text: JSON.stringify(buildPathGraph(graph, links)) }] };
  }
);

await server.connect(new StdioServerTransport());
