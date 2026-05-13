import path from "node:path";
import type { z } from "zod";
import { QueryRunInputSchema, type CaseGraph, type PacketSummary } from "../../../../packages/shared/src/index.js";

type ServiceResult<T> =
  | { ok: true; data: T; status?: number }
  | { ok: false; status: number; error: string };

type EvidenceOpenService = {
  openConversation: (graph: CaseGraph, queryRun: CaseGraph["queryRuns"][number], conversation: CaseGraph["queryRuns"][number]["conversations"][number], reason?: string) => Promise<unknown>;
};

type QueryRunApiServiceInput = {
  loadGraph: (caseId: string) => CaseGraph;
  writeCaseGraph: (graph: CaseGraph) => void;
  setGraph: (caseId: string, graph: CaseGraph) => void;
  capturesDirectory: (caseId: string) => string;
  conversationPacketLimit: number;
  inferQueryRunInput: (question: string, graph: CaseGraph) => unknown;
  createQueryRun: (graph: CaseGraph, input: z.infer<typeof QueryRunInputSchema>) => Promise<CaseGraph>;
  selectConversation: (graph: CaseGraph, queryRunId: string, conversationId: string) => Promise<
    | { status: "success"; graph: CaseGraph; queryRun: CaseGraph["queryRuns"][number]; conversation: CaseGraph["queryRuns"][number]["conversations"][number] }
    | { status: "query_not_found" | "conversation_not_found" | "capture_not_found" }
  >;
  getConversationPackets: (input: {
    capture: { nodeId: string; name: string; pcapFilename: string; pcapPath: string };
    displayFilter: string;
    limit: number;
  }) => Promise<{ packets: PacketSummary[] }>;
  evidenceOpenService: EvidenceOpenService;
};

function findQueryRun(graph: CaseGraph, queryRunId: string) {
  return graph.queryRuns.find((run) => run.queryRunId === queryRunId);
}

function captureForConversation(graph: CaseGraph, conversation: CaseGraph["queryRuns"][number]["conversations"][number]) {
  return graph.captures.find((item) => item.nodeId === conversation.nodeId && item.pcapFilename === conversation.pcapFilename);
}

export function createQueryRunApiService(input: QueryRunApiServiceInput) {
  async function create(caseId: string, body: Record<string, unknown>): Promise<ServiceResult<{ graph: CaseGraph; queryRun: CaseGraph["queryRuns"][number] | undefined }>> {
    const graph = input.loadGraph(caseId);
    const inferred = input.inferQueryRunInput(String(body.question || ""), graph);
    const parsed = QueryRunInputSchema.safeParse({ ...(inferred as object), ...body });
    if (!parsed.success) return { ok: false, status: 400, error: JSON.stringify(parsed.error.flatten()) };
    const nextGraph = await input.createQueryRun(graph, parsed.data);
    const queryRun = nextGraph.queryRuns.find((run) => run.queryRunId === nextGraph.activeQueryRunId);
    return { ok: true, status: 201, data: { graph: nextGraph, queryRun } };
  }

  function get(caseId: string, queryRunId: string): ServiceResult<{ queryRun: CaseGraph["queryRuns"][number] }> {
    const graph = input.loadGraph(caseId);
    const queryRun = findQueryRun(graph, queryRunId);
    if (!queryRun) return { ok: false, status: 404, error: "query run not found" };
    return { ok: true, data: { queryRun } };
  }

  function activate(caseId: string, queryRunId: string, cardId: string): ServiceResult<CaseGraph> {
    const graph = input.loadGraph(caseId);
    const queryRun = findQueryRun(graph, queryRunId);
    if (!queryRun) return { ok: false, status: 404, error: "query run not found" };
    const nextGraph: CaseGraph = {
      ...graph,
      activeQueryRunId: queryRunId,
      queryRuns: graph.queryRuns.map((run) => run.queryRunId === queryRunId && cardId ? { ...run, selectedEvidenceCardId: cardId } : run)
    };
    input.writeCaseGraph(nextGraph);
    input.setGraph(graph.spec.caseId, nextGraph);
    return { ok: true, data: nextGraph };
  }

  async function select(caseId: string, queryRunId: string, conversationId: string, openWireshark: boolean): Promise<ServiceResult<{ graph: CaseGraph; queryRun: CaseGraph["queryRuns"][number]; wireshark: unknown }>> {
    const graph = input.loadGraph(caseId);
    const selected = await input.selectConversation(graph, queryRunId, conversationId);
    if (selected.status === "query_not_found") return { ok: false, status: 404, error: "query run not found" };
    if (selected.status === "conversation_not_found") return { ok: false, status: 404, error: "conversation not found" };
    if (selected.status === "capture_not_found") return { ok: false, status: 404, error: "capture file not found" };
    if (selected.status !== "success") return { ok: false, status: 500, error: "conversation selection failed" };
    const wireshark = openWireshark && selected.conversation.pcapFilename
      ? await input.evidenceOpenService.openConversation(selected.graph, selected.queryRun, selected.conversation, "打开选中 TCP session 的 Wireshark filter。")
      : null;
    return { ok: true, data: { graph: selected.graph, queryRun: selected.queryRun, wireshark } };
  }

  async function packets(caseId: string, queryRunId: string, conversationId: string): Promise<ServiceResult<{ packets: PacketSummary[] }>> {
    const graph = input.loadGraph(caseId);
    const queryRun = findQueryRun(graph, queryRunId);
    if (!queryRun) return { ok: false, status: 404, error: "query run not found" };
    const conversation = queryRun.conversations.find((item) => item.conversationId === conversationId);
    if (!conversation) return { ok: false, status: 404, error: "conversation not found" };
    const capture = captureForConversation(graph, conversation);
    if (!capture?.pcapFilename) return { ok: false, status: 404, error: "capture file not found" };
    return {
      ok: true,
      data: await input.getConversationPackets({
        capture: {
          nodeId: capture.nodeId,
          name: capture.name,
          pcapFilename: capture.pcapFilename,
          pcapPath: path.join(input.capturesDirectory(graph.spec.caseId), capture.pcapFilename)
        },
        displayFilter: conversation.displayFilter,
        limit: input.conversationPacketLimit
      })
    };
  }

  async function openWireshark(caseId: string, queryRunId: string, conversationId: string): Promise<ServiceResult<unknown>> {
    const graph = input.loadGraph(caseId);
    const queryRun = findQueryRun(graph, queryRunId);
    if (!queryRun) return { ok: false, status: 404, error: "query run not found" };
    const selectedConversationId = conversationId || queryRun.selectedConversationId || "";
    const conversation = queryRun.conversations.find((item) => item.conversationId === selectedConversationId);
    if (!conversation) return { ok: false, status: 404, error: "conversation not found" };
    const capture = captureForConversation(graph, conversation);
    if (!capture?.pcapFilename) return { ok: false, status: 404, error: "capture file not found" };
    const wireshark = await input.evidenceOpenService.openConversation(graph, queryRun, conversation);
    if (!wireshark) return { ok: false, status: 404, error: "capture file not found" };
    return { ok: true, data: wireshark };
  }

  return { create, get, activate, select, packets, openWireshark };
}
