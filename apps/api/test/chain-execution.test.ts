import assert from "node:assert/strict";
import test from "node:test";
import type { AgentAnswer, AnalysisChainPlan, CaseGraph } from "../../../packages/shared/src/index.js";
import { executeChain } from "../src/services/plannerService.js";

function graph(overrides: Partial<CaseGraph> = {}): CaseGraph {
  return {
    spec: { caseId: "case-chain", title: "chain-test", protocol: "tcp" },
    captures: [],
    mappingHints: [],
    timeOffsetHints: [],
    rawPackets: [],
    analysisFilter: {},
    packets: [],
    sessions: [],
    sessionLinks: [],
    diagnosticTags: [],
    evidence: [],
    findings: [],
    path: { nodes: [], edges: [] },
    queryRuns: [],
    analysisRuns: [],
    toolRuns: [],
    ...overrides
  } as CaseGraph;
}

function answer(text: string): AgentAnswer {
  return {
    answer: text,
    evidenceIds: [],
    packetIds: [],
    sessionLinkIds: [],
    findingIds: [],
    missingContext: [],
    confidence: "certain",
    suggestedActions: []
  };
}

function graphWithQueryRun(): CaseGraph {
  return graph({
    activeQueryRunId: "qr-1",
    queryRuns: [
      {
        queryRunId: "qr-1",
        question: "查询 DNS 异常",
        displayFilter: "dns",
        protocol: "dns",
        conversations: [
          {
            conversationId: "conv-1",
            nodeId: "node-a",
            pcapFilename: "a.pcap",
            srcIp: "10.0.0.1",
            srcPort: 53124,
            dstIp: "10.0.0.99",
            dstPort: 443,
            protocol: "tcp",
            packetCount: 12,
            byteCount: 1024,
            displayFilter: "tcp.stream == 1",
            rankReasons: []
          }
        ],
        selectedConversationId: "conv-1",
        candidateGroups: [],
        evidenceCards: [],
        protocolCorrelations: []
      }
    ]
  } as unknown as Partial<CaseGraph>);
}

const plan: AnalysisChainPlan = {
  chainId: "chain-test",
  planKind: "chain",
  question: "先查 DNS 再查 TCP",
  steps: [
    { stepId: "step-0", intent: "protocol_event_query", purpose: "查询 DNS 异常" },
    {
      stepId: "step-1",
      intent: "tcp_session_query",
      purpose: "用解析出的地址查 TCP",
      paramsFrom: { dstIp: "step-0.dstIp", port: "step-0.port" }
    }
  ],
  confidence: "high",
  reason: "",
  missingContext: []
};

test("executeChain 把前序步骤的结构化结果绑定到后续步骤参数", async () => {
  const receivedParams: Record<string, unknown>[] = [];
  const result = await executeChain(
    graph(),
    plan,
    async (_graph, _intent, params) => {
      receivedParams.push(params);
      return { status: "ok", answer: answer("step done") };
    },
    undefined,
    // 第一步执行后重载的 graph 带有 QueryRun，selected conversation 提供绑定来源
    () => graphWithQueryRun()
  );
  assert.equal(result.results.length, 2);
  // step-0 执行后 data 来自重载 graph 的 active QueryRun
  assert.equal(result.results[0].data?.dstIp, "10.0.0.99");
  assert.equal(result.results[0].data?.port, 443);
  // step-1 收到 paramsFrom 解析出的绑定值
  assert.equal(receivedParams[1].dstIp, "10.0.0.99");
  assert.equal(receivedParams[1].port, 443);
});

function graphWithDnsQueryRun(): CaseGraph {
  return graph({
    activeQueryRunId: "qr-dns",
    queryRuns: [
      {
        queryRunId: "qr-dns",
        question: "查询 DNS 解析",
        displayFilter: "dns",
        protocol: "dns",
        conversations: [],
        candidateGroups: [],
        evidenceCards: [],
        protocolCorrelations: [
          {
            correlationId: "corr-1",
            kind: "dns_to_tcp",
            sourcePacketId: "pkt-1",
            targetDisplayFilter: "tcp && ip.addr == 203.0.113.7",
            relation: "DNS 响应地址",
            confidence: "high",
            summary: "域名解析到 203.0.113.7",
            reasons: [],
            nextSteps: []
          }
        ]
      }
    ]
  } as unknown as Partial<CaseGraph>);
}

test("executeChain 从 DNS 关联提取解析 IP 作为绑定源", async () => {
  const receivedParams: Record<string, unknown>[] = [];
  await executeChain(
    graph(),
    plan,
    async (_graph, _intent, params) => {
      receivedParams.push(params);
      return { status: "ok", answer: answer("step done") };
    },
    undefined,
    () => graphWithDnsQueryRun()
  );
  // DNS 步骤没有 TCP 会话，dstIp 来自 dns_to_tcp 关联的解析地址
  assert.equal(receivedParams[1].dstIp, "203.0.113.7");
});

test("executeChain 在绑定源缺失时不阻塞步骤执行", async () => {
  const receivedParams: Record<string, unknown>[] = [];
  const result = await executeChain(
    graph(),
    plan,
    async (_graph, _intent, params) => {
      receivedParams.push(params);
      return { status: "ok", answer: answer("step done") };
    },
    undefined,
    // 重载的 graph 没有 QueryRun，step-0 不产出 data
    () => graph()
  );
  assert.equal(result.results.length, 2);
  assert.equal(result.results[0].data, undefined);
  assert.equal(receivedParams[1].dstIp, undefined);
});
