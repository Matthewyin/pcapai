import assert from "node:assert/strict";
import test from "node:test";
import type { CaseGraph, Conversation } from "../../../packages/shared/src/index.js";
import { pathCorrelationTestHooks } from "../src/http/routes.js";

function graph(overrides: Partial<CaseGraph> = {}): CaseGraph {
  return {
    spec: { caseId: "case-1", title: "phase2-test", protocol: "tcp" },
    captures: [
      { nodeId: "client", name: "client", role: "client", interfaceDirection: "egress", capturePosition: "client side" },
      { nodeId: "server", name: "server", role: "server", interfaceDirection: "ingress", capturePosition: "server side" }
    ],
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
    ...overrides
  };
}

function conversation(patch: Partial<Conversation> = {}): Conversation {
  return {
    conversationId: "client-conversation",
    nodeId: "client",
    pcapFilename: "client.pcap",
    protocol: "tcp",
    srcIp: "10.0.0.1",
    srcPort: 51000,
    dstIp: "10.0.0.2",
    dstPort: 443,
    startTime: 100,
    endTime: 102,
    packetCount: 8,
    byteCount: 800,
    tcpFlags: ["SYN", "ACK", "FIN"],
    rstCount: 0,
    retransmissionCount: 0,
    zeroWindowCount: 0,
    rankScore: 0,
    rankReasons: [],
    displayFilter: "ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 443",
    ...patch
  };
}

test("buildQueryPath links exact tuple across nodes when time overlaps", () => {
  const client = conversation();
  const server = conversation({
    conversationId: "server-conversation",
    nodeId: "server",
    pcapFilename: "server.pcap",
    startTime: 101,
    endTime: 103
  });

  const path = pathCorrelationTestHooks.buildQueryPath(graph(), "query-1", client.conversationId, [client, server]);

  assert.equal(path.hops.length, 2);
  assert.deepEqual(path.hops.map((hop) => hop.status), ["observed", "observed"]);
  assert.deepEqual(path.hops.map((hop) => hop.correlation), ["exact_tuple", "exact_tuple"]);
  assert.equal(path.edges[0].status, "observed");
  assert.equal(path.edges[0].label, "相邻节点 exact tuple 命中");
  assert.match(path.edges[0].diagnosis, /路径连续/);
});

test("buildQueryPath marks needs_context when tuple matches but time window does not overlap", () => {
  const client = conversation();
  const server = conversation({
    conversationId: "server-conversation",
    nodeId: "server",
    pcapFilename: "server.pcap",
    startTime: 200,
    endTime: 202
  });

  const path = pathCorrelationTestHooks.buildQueryPath(graph(), "query-1", client.conversationId, [client, server]);

  assert.equal(path.hops[0].status, "observed");
  assert.equal(path.hops[1].status, "missing");
  assert.equal(path.hops[1].correlation, "needs_context");
  assert.ok(path.hops[1].correlationReasons.some((reason) => reason.includes("时间窗口不重叠")));
  assert.equal(path.edges[0].status, "needs_context");
  assert.match(path.edges[0].diagnosis, /下游未形成可确认关联/);
});

test("buildQueryPath applies time offset before time overlap correlation", () => {
  const client = conversation();
  const server = conversation({
    conversationId: "server-conversation",
    nodeId: "server",
    pcapFilename: "server.pcap",
    startTime: 110,
    endTime: 112
  });

  const path = pathCorrelationTestHooks.buildQueryPath(graph({
    timeOffsetHints: [{ hintId: "offset-1", fromNodeId: "server", toNodeId: "client", offsetSeconds: -10, note: "" }]
  }), "query-1", client.conversationId, [client, server]);

  assert.deepEqual(path.hops.map((hop) => hop.status), ["observed", "observed"]);
  assert.ok(path.hops[1].correlationReasons.some((reason) => reason.includes("time offset -10s")));
  assert.equal(path.edges[0].status, "observed");
});

test("buildQueryPath links NAT-translated conversations through mapping hint", () => {
  const client = conversation();
  const translated = conversation({
    conversationId: "server-conversation",
    nodeId: "server",
    pcapFilename: "server.pcap",
    srcIp: "172.16.0.10",
    srcPort: 41000,
    dstIp: "10.0.0.2",
    dstPort: 443,
    startTime: 101,
    endTime: 103,
    displayFilter: "ip.addr == 172.16.0.10 && ip.addr == 10.0.0.2 && tcp.port == 443"
  });

  const path = pathCorrelationTestHooks.buildQueryPath(graph({
    mappingHints: [{
      hintId: "nat-1",
      kind: "nat",
      fromNodeId: "client",
      toNodeId: "server",
      originalSrcIp: "10.0.0.1",
      originalSrcPort: 51000,
      originalDstIp: "10.0.0.2",
      originalDstPort: 443,
      translatedSrcIp: "172.16.0.10",
      translatedSrcPort: 41000,
      translatedDstIp: "10.0.0.2",
      translatedDstPort: 443,
      note: ""
    }]
  }), "query-1", client.conversationId, [client, translated]);

  assert.deepEqual(path.hops.map((hop) => hop.status), ["observed", "observed"]);
  assert.equal(path.hops[1].correlation, "mapping_hint");
  assert.equal(path.edges[0].status, "observed");
  assert.equal(path.edges[0].label, "通过 mapping hint 关联");
});

test("buildQueryPath marks suspect edge when downstream conversation is absent", () => {
  const client = conversation();

  const path = pathCorrelationTestHooks.buildQueryPath(graph(), "query-1", client.conversationId, [client]);

  assert.deepEqual(path.hops.map((hop) => hop.status), ["observed", "missing"]);
  assert.equal(path.edges[0].status, "suspect");
  assert.match(path.edges[0].diagnosis, /上游可见、下游缺失/);
});
