import assert from "node:assert/strict";
import test from "node:test";
import type { CaseGraph } from "../../../packages/shared/src/index.js";
import { buildCaseReportMarkdown } from "../src/http/reportBuilder.js";

function graph(): CaseGraph {
  return {
    spec: { caseId: "case-report", title: "报告收敛测试", protocol: "tcp" },
    captures: [
      { nodeId: "client", name: "客户端抓包", role: "client", pcapFilename: "client.pcap", interfaceDirection: "egress", capturePosition: "客户端出口" },
      { nodeId: "server", name: "服务端抓包", role: "server", pcapFilename: "server.pcap", interfaceDirection: "ingress", capturePosition: "服务端入口" }
    ],
    mappingHints: [],
    timeOffsetHints: [],
    rawPackets: [],
    analysisFilter: {},
    packets: [
      {
        packetId: "client-42",
        nodeId: "client",
        pcapFilename: "client.pcap",
        frameNumber: 42,
        timestamp: 100,
        srcIp: "10.0.0.1",
        srcPort: 51000,
        dstIp: "10.0.0.2",
        dstPort: 443,
        protocol: "TCP",
        tcpFlags: ["RST"],
        tcpAnalysis: {
          retransmission: false,
          fastRetransmission: false,
          duplicateAck: false,
          zeroWindow: false,
          lostSegment: false
        },
        summary: "RST first seen",
        raw: {}
      }
    ],
    sessions: [],
    sessionLinks: [],
    diagnosticTags: [],
    evidence: [],
    findings: [],
    path: { nodes: [], edges: [] },
    queryRuns: [
      {
        queryRunId: "query-1",
        caseId: "case-report",
        question: "分析 10.0.0.1 到 10.0.0.2 的 443",
        timeRange: { start: 90, end: 110 },
        srcIp: "10.0.0.1",
        dstIp: "10.0.0.2",
        port: 443,
        protocol: "tcp",
        displayFilter: "tcp && ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 443",
        totalConversationCount: 1,
        candidateGroups: [
          {
            groupId: "group-1",
            protocol: "tcp",
            srcIp: "10.0.0.1",
            dstIp: "10.0.0.2",
            dstPort: 443,
            conversationIds: ["conv-1"],
            selectedConversationId: "conv-1",
            conversationCount: 1,
            successCount: 0,
            failureCount: 1,
            rstCount: 1,
            retransmissionCount: 0,
            zeroWindowCount: 0,
            failureModes: [{ kind: "rst", label: "RST", count: 1, conversationIds: ["conv-1"] }],
            rankScore: 100,
            rankReasons: ["RST"],
            summary: "10.0.0.1 到 10.0.0.2:443 的异常链路"
          }
        ],
        selectedCandidateGroupId: "group-1",
        conversationIds: ["conv-1"],
        conversations: [
          {
            conversationId: "conv-1",
            nodeId: "client",
            pcapFilename: "client.pcap",
            protocol: "tcp",
            srcIp: "10.0.0.1",
            srcPort: 51000,
            dstIp: "10.0.0.2",
            dstPort: 443,
            startTime: 100,
            endTime: 101,
            packetCount: 5,
            byteCount: 500,
            tcpFlags: ["SYN", "RST"],
            rstCount: 1,
            retransmissionCount: 0,
            zeroWindowCount: 0,
            rankScore: 100,
            rankReasons: ["RST"],
            displayFilter: "tcp.stream == 7"
          }
        ],
        selectedConversationId: "conv-1",
        path: {
          queryRunId: "query-1",
          conversationId: "conv-1",
          hops: [
            {
              hopId: "hop-client",
              nodeId: "client",
              conversationId: "conv-1",
              observedTuple: "10.0.0.1:51000 -> 10.0.0.2:443",
              status: "observed",
              startTime: 100,
              endTime: 101,
              packetCount: 5,
              anomalies: ["RST"],
              wiresharkFilter: "tcp.stream == 7",
              correlation: "exact_tuple",
              correlationReasons: ["selected conversation"]
            }
          ],
          edges: [
            {
              edgeId: "edge-1",
              fromNodeId: "client",
              toNodeId: "server",
              status: "suspect",
              label: "下游缺失",
              diagnosis: "上游可见、下游缺失。",
              reasons: ["server capture no match"],
              nextSteps: ["检查客户端到服务端之间策略。"]
            }
          ],
          missingHops: ["server"],
          confidence: "high",
          summary: "只在客户端看到该 session。"
        },
        selectedDiagnosis: {
          conversationId: "conv-1",
          summary: "RST 出现在客户端抓包。",
          confidence: "high",
          checks: [
            { key: "rst", label: "RST", status: "problem", summary: "发现 RST。", packetIds: ["client-42"], nextSteps: ["定位 RST 前后包。"] },
            { key: "zero_window", label: "Zero Window", status: "ok", summary: "未见 Zero Window。", packetIds: [], nextSteps: [] }
          ],
          diagnosticTags: [],
          evidence: [],
          findings: [
            {
              findingId: "finding-1",
              title: "RST 中断",
              summary: "会话被 RST 结束。",
              tagIds: [],
              evidenceIds: ["card-1"],
              packetIds: ["client-42"],
              confidence: "high",
              nextSteps: ["确认 RST 发起端。"]
            }
          ],
          nextSteps: ["定位 RST 前后包。"]
        },
        evidenceCards: [
          {
            cardId: "card-1",
            kind: "conversation",
            title: "RST session",
            summary: "包含 RST 的 TCP session。",
            pcapFilename: "client.pcap",
            frameNumber: 42,
            displayFilter: "tcp.stream == 7",
            packetDisplayFilter: "tcp.stream == 7 && frame.number == 42",
            conversationId: "conv-1",
            queryRunId: "query-1",
            actions: ["open_wireshark", "copy_filter"]
          }
        ],
        protocolCorrelations: [
          {
            correlationId: "corr-1",
            kind: "tls_sni_to_tcp",
            sourcePacketId: "client-42",
            sourceEvidenceCardId: "card-1",
            targetConversationId: "conv-1",
            targetDisplayFilter: "tcp.stream == 7",
            relation: "same_flow",
            confidence: "high",
            summary: "TLS SNI app.example.com 关联到当前 TCP session。",
            reasons: ["SNI=app.example.com"],
            nextSteps: ["确认 TLS alert。"]
          }
        ],
        selectedEvidenceCardId: "card-1",
        createdAt: "2026-05-02T00:00:00.000Z"
      }
    ],
    activeQueryRunId: "query-1",
    analysisRuns: [],
    toolRuns: []
  };
}

test("buildCaseReportMarkdown is scoped to active QueryRun evidence and checks", () => {
  const markdown = buildCaseReportMarkdown(graph());

  assert.match(markdown, /## 1\. 问题与查询/);
  assert.match(markdown, /QueryRun: query-1/);
  assert.match(markdown, /## 4\. L7 关联/);
  assert.match(markdown, /TLS SNI app\.example\.com/);
  assert.match(markdown, /## 7\. 路径边判断/);
  assert.match(markdown, /上游可见、下游缺失/);
  assert.match(markdown, /## 8\. 确定性诊断/);
  assert.match(markdown, /RST 出现在客户端抓包/);
  assert.match(markdown, /## 11\. Wireshark 过滤器/);
  assert.match(markdown, /tcp\.stream == 7 && frame\.number == 42/);
  assert.match(markdown, /## 12\. 下一步动作/);
  assert.match(markdown, /定位 RST 前后包/);
  assert.match(markdown, /## 13\. 执行轨迹/);
  assert.match(markdown, /## 14\. 边界说明/);
});
