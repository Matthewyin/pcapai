import path from "node:path";
import type { CaseGraph, Conversation, QueryRun } from "../../../../packages/shared/src/index.js";
import { openInWiresharkWithMcp } from "../mcp/evidenceOpenerClient.js";

export function createEvidenceOpenService(input: {
  capturesDirectory: (caseId: string) => string;
  writeGraph: (graph: CaseGraph) => void;
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
}) {
  async function openConversation(graph: CaseGraph, queryRun: QueryRun, conversation: Conversation, summary = "打开 TCP session 的 Wireshark filter。") {
    const capture = graph.captures.find((item) => item.nodeId === conversation.nodeId && item.pcapFilename === conversation.pcapFilename);
    if (!capture?.pcapFilename) return null;
    const wireshark = await openInWiresharkWithMcp({
      pcapPath: path.join(input.capturesDirectory(graph.spec.caseId), capture.pcapFilename),
      displayFilter: conversation.displayFilter
    });
    input.recordMcpRun(graph.spec.caseId, {
      target: "open_in_wireshark",
      summary,
      inputSummary: `pcap=${capture.pcapFilename}; displayFilter=${conversation.displayFilter}`,
      outputSummary: `launcher=${wireshark.launch?.launcher || "unknown"}`,
      queryRunId: queryRun.queryRunId,
      pcapFilename: capture.pcapFilename,
      displayFilter: conversation.displayFilter
    });
    return wireshark;
  }

  async function openEvidence(graph: CaseGraph, request: {
    pcapFilename: string;
    displayFilter: string;
    frameNumber?: number;
    queryRunId?: string;
    cardId?: string;
  }) {
    const capture = graph.captures.find((item) => item.pcapFilename === request.pcapFilename);
    if (!capture?.pcapFilename) return null;
    const nextGraph = request.queryRunId && request.cardId ? {
      ...graph,
      activeQueryRunId: request.queryRunId,
      queryRuns: graph.queryRuns.map((run) => run.queryRunId === request.queryRunId ? { ...run, selectedEvidenceCardId: request.cardId } : run)
    } : graph;
    if (nextGraph !== graph) {
      input.writeGraph(nextGraph);
      input.setGraph(graph.spec.caseId, nextGraph);
    }
    const wireshark = await openInWiresharkWithMcp({
      pcapPath: path.join(input.capturesDirectory(graph.spec.caseId), capture.pcapFilename),
      displayFilter: request.displayFilter,
      frameNumber: request.frameNumber
    });
    input.recordMcpRun(graph.spec.caseId, {
      target: "open_in_wireshark",
      summary: request.frameNumber ? "打开证据 filter 并定位 frame。" : "打开证据 display filter。",
      inputSummary: `pcap=${capture.pcapFilename}; displayFilter=${request.displayFilter}${request.frameNumber ? `; frame=${request.frameNumber}` : ""}`,
      outputSummary: `launcher=${wireshark.launch?.launcher || "unknown"}`,
      queryRunId: request.queryRunId,
      evidenceCardIds: request.cardId ? [request.cardId] : [],
      pcapFilename: capture.pcapFilename,
      displayFilter: request.displayFilter,
      frameNumber: request.frameNumber
    });
    return { wireshark, graph: nextGraph };
  }

  return {
    openConversation,
    openEvidence
  };
}
