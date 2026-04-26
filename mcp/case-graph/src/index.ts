import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

type CaseGraph = {
  spec: { caseId: string; title: string };
  captures: Array<{ nodeId: string; name: string; role: string; interfaceDirection: string; capturePosition: string }>;
  mappingHints: unknown[];
  timeOffsetHints: unknown[];
  rawPackets: Array<{ packetId: string }>;
  analysisFilter: Record<string, unknown>;
  packets: Array<{ packetId: string }>;
  sessions: unknown[];
  sessionLinks: Array<{ linkId: string; fromNodeId: string; toNodeId: string; fromSegmentId: string; toSegmentId: string; confidence: string; score: number }>;
  evidence: Array<{ evidenceId: string; kind: string; title: string; nodeId?: string; packetIds: string[]; confidence?: string }>;
  findings: Array<{ findingId: string; title: string; summary: string; confidence: string; evidenceIds: string[]; packetIds?: string[]; nextSteps: string[] }>;
  path: { edges: Array<{ fromNodeId: string; toNodeId: string; label: string; status: string }> };
};

const server = new McpServer({ name: "case-graph-mcp", version: "0.1.0" });

function loadGraph(): CaseGraph {
  const graphPath = process.env.PCAPAI_CASE_GRAPH_PATH;
  if (!graphPath) throw new Error("PCAPAI_CASE_GRAPH_PATH is required");
  return JSON.parse(readFileSync(graphPath, "utf8")) as CaseGraph;
}

function graphSummary(graph: CaseGraph) {
  return {
    spec: graph.spec,
    analysisFilter: graph.analysisFilter,
    counts: {
      captures: graph.captures.length,
      rawPackets: graph.rawPackets.length,
      packets: graph.packets.length,
      sessions: graph.sessions.length,
      sessionLinks: graph.sessionLinks.length,
      evidence: graph.evidence.length,
      findings: graph.findings.length,
      mappingHints: graph.mappingHints.length,
      timeOffsetHints: graph.timeOffsetHints.length
    },
    captures: graph.captures.map(({ nodeId, name, role, interfaceDirection, capturePosition }) => ({
      nodeId,
      name,
      role,
      interfaceDirection,
      capturePosition
    })),
    path: graph.path,
    findings: graph.findings.map(({ findingId, title, confidence, evidenceIds, packetIds, nextSteps }) => ({
      findingId,
      title,
      confidence,
      evidenceIds,
      packetIds,
      nextSteps
    })),
    evidence: graph.evidence.map(({ evidenceId, kind, title, nodeId, packetIds, confidence }) => ({
      evidenceId,
      kind,
      title,
      nodeId,
      packetIds,
      confidence
    })),
    sessionLinks: graph.sessionLinks.map(({ linkId, fromNodeId, toNodeId, fromSegmentId, toSegmentId, confidence, score }) => ({
      linkId,
      fromNodeId,
      toNodeId,
      fromSegmentId,
      toSegmentId,
      confidence,
      score
    }))
  };
}

function reportMarkdown(graph: CaseGraph) {
  return [
    `# ${graph.spec.title}`,
    "",
    "## 路径",
    ...graph.path.edges.map((edge) => `- ${edge.fromNodeId} -> ${edge.toNodeId}: ${edge.label} (${edge.status})`),
    "",
    "## 判断",
    ...graph.findings.map((finding) => [
      `- ${finding.title} (${finding.confidence})`,
      `  - ${finding.summary}`,
      `  - 证据: ${finding.evidenceIds.join(", ") || "-"}`
    ].join("\n")),
    "",
    "## 跨节点关联",
    ...graph.sessionLinks.map((link) => `- ${link.linkId}: ${link.fromNodeId} -> ${link.toNodeId}, ${link.confidence}, score=${link.score}`)
  ].join("\n");
}

server.registerTool(
  "load_case_graph",
  {
    title: "Load case graph",
    description: "读取当前 case graph 摘要，不返回完整 packet 列表。",
    inputSchema: {}
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify(graphSummary(loadGraph())) }]
  })
);

server.registerTool(
  "get_finding",
  {
    title: "Get finding",
    description: "按 findingId 读取判断结果。",
    inputSchema: { findingId: z.string() }
  },
  async ({ findingId }) => ({
    content: [{ type: "text", text: JSON.stringify(loadGraph().findings.find((finding) => finding.findingId === findingId) || null) }]
  })
);

server.registerTool(
  "get_evidence",
  {
    title: "Get evidence",
    description: "按 evidenceId 读取证据事件。",
    inputSchema: { evidenceId: z.string() }
  },
  async ({ evidenceId }) => ({
    content: [{ type: "text", text: JSON.stringify(loadGraph().evidence.find((event) => event.evidenceId === evidenceId) || null) }]
  })
);

server.registerTool(
  "get_session_link",
  {
    title: "Get session link",
    description: "按 sessionLinkId 读取跨节点会话关联。",
    inputSchema: { sessionLinkId: z.string() }
  },
  async ({ sessionLinkId }) => ({
    content: [{ type: "text", text: JSON.stringify(loadGraph().sessionLinks.find((link) => link.linkId === sessionLinkId) || null) }]
  })
);

server.registerTool(
  "get_packet_detail",
  {
    title: "Get packet detail",
    description: "按 packetId 读取数据包详情。",
    inputSchema: { packetId: z.string() }
  },
  async ({ packetId }) => {
    const graph = loadGraph();
    return {
      content: [{
        type: "text",
        text: JSON.stringify(graph.packets.find((packet) => packet.packetId === packetId) || graph.rawPackets.find((packet) => packet.packetId === packetId) || null)
      }]
    };
  }
);

server.registerTool(
  "explain_path",
  {
    title: "Explain path",
    description: "读取路径图和每条路径边对应的 session links。",
    inputSchema: {}
  },
  async () => {
    const graph = loadGraph();
    return {
      content: [{ type: "text", text: JSON.stringify({ path: graph.path, sessionLinks: graph.sessionLinks, findings: graph.findings }) }]
    };
  }
);

server.registerTool(
  "export_report",
  {
    title: "Export report",
    description: "导出基于当前 case graph 的 Markdown 报告草稿。只整理已有证据，不新增判断。",
    inputSchema: {}
  },
  async () => ({
    content: [{ type: "text", text: reportMarkdown(loadGraph()) }]
  })
);

await server.connect(new StdioServerTransport());
