import assert from "node:assert/strict";
import test from "node:test";
import type { CaseGraph, PacketSummary } from "../../../packages/shared/src/index.js";
import { runLevel1Insights } from "../src/services/insightEngine.js";

let pid = 0;
function packet(patch: Partial<PacketSummary>): PacketSummary {
  return {
    packetId: `pkt-${++pid}`,
    nodeId: "node-1",
    pcapFilename: "test.pcap",
    frameNumber: pid,
    timestamp: 0,
    protocol: "tcp",
    srcIp: "10.0.0.1",
    srcPort: 50000,
    dstIp: "10.0.0.2",
    dstPort: 80,
    tcpFlags: [],
    tcpAnalysis: { retransmission: false, fastRetransmission: false, duplicateAck: false, zeroWindow: false, lostSegment: false },
    summary: "",
    raw: {},
    ...patch,
  };
}

function makeGraph(packets: PacketSummary[]): CaseGraph {
  return {
    spec: { caseId: "test-case", title: "test", createdAt: new Date().toISOString() },
    captures: [],
    packets,
    sessions: [],
    sessionLinks: [],
    diagnosticTags: [],
    evidence: [],
    findings: [],
    path: { nodes: [], edges: [] },
    queryRuns: [],
    analysisRuns: [],
    toolRuns: [],
  };
}

function findInsight(graph: CaseGraph, type: string) {
  return runLevel1Insights(graph).find((i) => i.type === type);
}

function allInsights(graph: CaseGraph, type: string) {
  return runLevel1Insights(graph).filter((i) => i.type === type);
}

// ── analyzeIcmpEchoPair ─────────────────────────────────────────────────

test("icmp_echo_pair: 丢包检测 (5 Echo, 1 Reply)", () => {
  const echoes = Array.from({ length: 5 }, (_, i) =>
    packet({ protocol: "icmp", icmpType: 8, srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: i * 1.0 })
  );
  const reply = packet({ protocol: "icmp", icmpType: 0, srcIp: "10.0.0.2", dstIp: "10.0.0.1", timestamp: 0.05 });
  const graph = makeGraph([...echoes, reply]);
  const insights = allInsights(graph, "icmp_echo_pair");
  const loss = insights.find((i) => i.description.includes("丢包"));
  assert.ok(loss, "应检测到 ICMP 丢包");
});

test("icmp_echo_pair: RTT 统计 (3 pairs)", () => {
  const pkts: PacketSummary[] = [];
  for (let i = 0; i < 3; i++) {
    const t = i * 2.0;
    pkts.push(packet({ protocol: "icmp", icmpType: 8, srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: t }));
    pkts.push(packet({ protocol: "icmp", icmpType: 0, srcIp: "10.0.0.2", dstIp: "10.0.0.1", timestamp: t + 0.01 + i * 0.005 }));
  }
  const graph = makeGraph(pkts);
  const insights = allInsights(graph, "icmp_echo_pair");
  const rtt = insights.find((i) => i.description.includes("RTT"));
  assert.ok(rtt, "应报告 RTT 统计");
  const detail = rtt!.detail as Record<string, unknown>;
  assert.ok(detail.avgRttMs != null);
  assert.ok(detail.minRttMs != null);
  assert.ok(detail.maxRttMs != null);
  assert.ok(detail.jitterMs != null);
});

// ── analyzeHttpStatusChain ──────────────────────────────────────────────

test("http_status_chain: 重定向链 (3x 301)", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpResponseCode: 301, httpHost: "example.com", timestamp: 0 }),
    packet({ protocol: "http", httpResponseCode: 301, httpHost: "example.com", timestamp: 0.1 }),
    packet({ protocol: "http", httpResponseCode: 301, httpHost: "example.com", timestamp: 0.2 }),
  ]);
  const insights = allInsights(graph, "http_status_chain");
  const redirect = insights.find((i) => i.description.includes("重定向链"));
  assert.ok(redirect, "应检测到重定向链");
});

test("http_status_chain: 5xx 重复 (2x 502)", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpResponseCode: 502, httpHost: "api.example.com", timestamp: 0 }),
    packet({ protocol: "http", httpResponseCode: 502, httpHost: "api.example.com", timestamp: 1 }),
  ]);
  const insights = allInsights(graph, "http_status_chain");
  const err5xx = insights.find((i) => i.description.includes("502"));
  assert.ok(err5xx, "应检测到 502 重复");
  assert.equal(err5xx!.severity, "critical");
});

test("http_status_chain: 4xx 重复 (3x 404)", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpResponseCode: 404, httpHost: "example.com", httpRequestUri: "/missing", timestamp: 0 }),
    packet({ protocol: "http", httpResponseCode: 404, httpHost: "example.com", httpRequestUri: "/missing", timestamp: 1 }),
    packet({ protocol: "http", httpResponseCode: 404, httpHost: "example.com", httpRequestUri: "/missing", timestamp: 2 }),
  ]);
  const insights = allInsights(graph, "http_status_chain");
  const err4xx = insights.find((i) => i.description.includes("404"));
  assert.ok(err4xx, "应检测到 404 重复");
});

// ── analyzeHttpHeaderAnomaly ────────────────────────────────────────────

test("http_header_anomaly: 未匹配请求 (无 response)", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpRequestMethod: "GET", httpHost: "api.example.com", timestamp: 0 }),
    packet({ protocol: "http", httpRequestMethod: "POST", httpHost: "api.example.com", timestamp: 1 }),
  ]);
  const insights = allInsights(graph, "http_header_anomaly");
  const unmatched = insights.find((i) => i.description.includes("未收到响应"));
  assert.ok(unmatched, "应检测到未匹配请求");
});

test("http_header_anomaly: 混合 HTTP/HTTPS (port 80 + 443)", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpRequestMethod: "GET", httpHost: "example.com", dstPort: 80, timestamp: 0 }),
    packet({ protocol: "http", httpRequestMethod: "GET", httpHost: "example.com", dstPort: 443, timestamp: 1 }),
  ]);
  const insights = allInsights(graph, "http_header_anomaly");
  const mixed = insights.find((i) => i.description.includes("端口"));
  assert.ok(mixed, "应检测到混合 HTTP/HTTPS");
});

// ── analyzeHttpTiming ───────────────────────────────────────────────────

test("http_timing: 响应耗时报告", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpResponseCode: 200, httpHost: "api.example.com", httpTime: 0.5, timestamp: 0 }),
  ]);
  const insight = findInsight(graph, "http_timing");
  assert.ok(insight);
  const detail = insight!.detail as Record<string, unknown>;
  assert.equal(detail.responseTimeMs, 500);
});

test("http_timing: 主机聚合 (同一 host 2+ 响应)", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpResponseCode: 200, httpHost: "slow.example.com", httpTime: 0.3, timestamp: 0 }),
    packet({ protocol: "http", httpResponseCode: 200, httpHost: "slow.example.com", httpTime: 0.4, timestamp: 1 }),
  ]);
  const insights = allInsights(graph, "http_timing");
  const aggregate = insights.find((i) => i.description.includes("慢响应") || i.description.includes("平均"));
  assert.ok(aggregate, "应聚合同一 host 的慢响应");
});

// ── analyzeHttpAdvanced ─────────────────────────────────────────────────

test("http_header_anomaly: Host/SNI 不匹配", () => {
  const graph = makeGraph([
    packet({ protocol: "tls", tlsHandshakeType: 1, tlsSni: "cdn.example.com", srcIp: "10.0.0.1", srcPort: 51000, dstIp: "10.0.0.2", dstPort: 443, timestamp: 0 }),
    packet({ protocol: "http", httpRequestMethod: "GET", httpHost: "api.example.com", srcIp: "10.0.0.1", srcPort: 51000, dstIp: "10.0.0.2", dstPort: 443, timestamp: 0.5 }),
  ]);
  const insights = allInsights(graph, "http_header_anomaly");
  const mismatch = insights.find((i) => i.description.includes("SNI") && i.description.includes("不一致"));
  assert.ok(mismatch, "应检测到 Host/SNI 不匹配");
});

test("http_status_chain: 错误突发 (5 个 ≥400 在 10s 内)", () => {
  const pkts = Array.from({ length: 5 }, (_, i) =>
    packet({ protocol: "http", httpResponseCode: 500, httpHost: "api.example.com", timestamp: i * 1.5 })
  );
  const graph = makeGraph(pkts);
  const insights = allInsights(graph, "http_status_chain");
  const burst = insights.find((i) => i.description.includes("突发"));
  assert.ok(burst, "应检测到错误突发");
});

test("http_header_anomaly: 认证失败 (401 无 Authorization)", () => {
  const graph = makeGraph([
    packet({ protocol: "http", httpResponseCode: 401, httpHost: "api.example.com", timestamp: 0 }),
    packet({ protocol: "http", httpResponseCode: 401, httpHost: "api.example.com", timestamp: 1 }),
  ]);
  const insights = allInsights(graph, "http_header_anomaly");
  const auth = insights.find((i) => i.description.includes("401") && i.description.includes("Authorization"));
  assert.ok(auth, "应检测到认证失败");
});

test("http_header_anomaly: 压缩缺失 (大响应无 Content-Encoding)", () => {
  const pkts = [
    packet({ protocol: "http", httpResponseCode: 200, httpHost: "example.com", httpContentLength: 5000, timestamp: 0 }),
    packet({ protocol: "http", httpResponseCode: 200, httpHost: "example.com", httpContentLength: 5000, timestamp: 1 }),
    packet({ protocol: "http", httpResponseCode: 200, httpHost: "example.com", httpContentLength: 5000, timestamp: 2 }),
  ];
  const graph = makeGraph(pkts);
  const insights = allInsights(graph, "http_header_anomaly");
  const uncompressed = insights.find((i) => i.description.includes("未压缩") || i.description.includes("压缩"));
  assert.ok(uncompressed, "应检测到未压缩的大响应体");
});

// ── analyzeTlsHandshake ─────────────────────────────────────────────────

test("tls_handshake: Fatal Alert → critical", () => {
  const graph = makeGraph([
    packet({ protocol: "tls", tlsAlertLevel: 2, tlsAlertDescription: 48, timestamp: 0 }),
  ]);
  const insight = findInsight(graph, "tls_handshake");
  assert.ok(insight);
  assert.equal(insight!.severity, "critical");
});

test("tls_handshake: Warning Alert → warning", () => {
  const graph = makeGraph([
    packet({ protocol: "tls", tlsAlertLevel: 1, tlsAlertDescription: 0, timestamp: 0 }),
  ]);
  const insight = findInsight(graph, "tls_handshake");
  assert.ok(insight);
  assert.equal(insight!.severity, "warning");
});

// ── analyzeTlsAdvanced ──────────────────────────────────────────────────

test("tls_handshake: TLS 1.0 (已弃用) → warning", () => {
  const graph = makeGraph([
    packet({ protocol: "tls", tlsHandshakeType: 1, tlsHandshakeVersion: "0x0301", timestamp: 0 }),
  ]);
  const insights = allInsights(graph, "tls_handshake");
  const deprecated = insights.find((i) => i.description.includes("弃用"));
  assert.ok(deprecated, "应检测到 TLS 1.0 已弃用");
  assert.equal(deprecated!.severity, "warning");
});

test("tls_handshake: 弱加密套件 → critical", () => {
  const graph = makeGraph([
    packet({ protocol: "tls", tlsHandshakeType: 2, tlsCipherSuite: "TLS_RSA_WITH_RC4_128_SHA", timestamp: 0 }),
  ]);
  const insights = allInsights(graph, "tls_handshake");
  const weak = insights.find((i) => i.description.includes("弱加密"));
  assert.ok(weak, "应检测到弱加密套件");
  assert.equal(weak!.severity, "critical");
});

test("tls_handshake: 证书 SAN 不匹配 SNI", () => {
  const graph = makeGraph([
    packet({ protocol: "tls", tlsHandshakeType: 1, tlsSni: "app.com", srcIp: "10.0.0.1", srcPort: 51000, dstIp: "10.0.0.2", dstPort: 443, timestamp: 0 }),
    packet({ protocol: "tls", tlsHandshakeType: 11, tlsCertDnsName: "other.com", srcIp: "10.0.0.2", srcPort: 443, dstIp: "10.0.0.1", dstPort: 51000, timestamp: 0.1 }),
  ]);
  const insights = allInsights(graph, "tls_handshake");
  const sanMismatch = insights.find((i) => i.description.includes("SAN") && i.description.includes("不匹配"));
  assert.ok(sanMismatch, "应检测到证书 SAN 不匹配");
  assert.equal(sanMismatch!.severity, "warning");
});

// ── analyzeDnsAnomaly ───────────────────────────────────────────────────

test("dns_anomaly: 无响应 (query 无 reply)", () => {
  const graph = makeGraph([
    packet({ protocol: "dns", dnsQueryName: "missing.example.com", srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: 0 }),
  ]);
  const insights = allInsights(graph, "dns_anomaly");
  const noReply = insights.find((i) => i.description.includes("无响应"));
  assert.ok(noReply, "应检测到 DNS 无响应");
  assert.equal(noReply!.severity, "warning");
});

test("dns_anomaly: NXDOMAIN", () => {
  const graph = makeGraph([
    packet({ protocol: "dns", dnsQueryName: "nx.example.com", srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: 0 }),
    packet({ protocol: "dns", dnsQueryName: "nx.example.com", dnsIsResponse: true, dnsRcode: 3, srcIp: "10.0.0.2", dstIp: "10.0.0.1", timestamp: 0.05 }),
  ]);
  const insights = allInsights(graph, "dns_anomaly");
  const nxdomain = insights.find((i) => i.description.includes("NXDOMAIN"));
  assert.ok(nxdomain, "应检测到 NXDOMAIN");
});

test("dns_anomaly: SERVFAIL → warning", () => {
  const graph = makeGraph([
    packet({ protocol: "dns", dnsQueryName: "fail.example.com", srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: 0 }),
    packet({ protocol: "dns", dnsQueryName: "fail.example.com", dnsIsResponse: true, dnsRcode: 2, srcIp: "10.0.0.2", dstIp: "10.0.0.1", timestamp: 0.05 }),
  ]);
  const insights = allInsights(graph, "dns_anomaly");
  const servfail = insights.find((i) => i.description.includes("SERVFAIL"));
  assert.ok(servfail, "应检测到 SERVFAIL");
  assert.equal(servfail!.severity, "warning");
});

test("dns_anomaly: 响应耗时", () => {
  const graph = makeGraph([
    packet({ protocol: "dns", dnsQueryName: "time.example.com", srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: 0 }),
    packet({ protocol: "dns", dnsQueryName: "time.example.com", dnsIsResponse: true, dnsRcode: 0, srcIp: "10.0.0.2", dstIp: "10.0.0.1", timestamp: 0.1 }),
  ]);
  const insights = allInsights(graph, "dns_anomaly");
  const timing = insights.find((i) => (i.detail as Record<string, unknown>).responseTimeMs != null);
  assert.ok(timing, "应报告 DNS 响应耗时");
  const ms = (timing!.detail as Record<string, unknown>).responseTimeMs as number;
  assert.ok(Math.abs(ms - 100) < 10, `耗时应约 100ms，实际 ${ms}`);
});

// ── analyzeDnsAdvanced ──────────────────────────────────────────────────

test("dns_anomaly: 查询突发 (5 query 在 5s 内)", () => {
  const pkts = Array.from({ length: 5 }, (_, i) =>
    packet({ protocol: "dns", dnsQueryName: `burst${i}.example.com`, srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: i * 0.5 })
  );
  const graph = makeGraph(pkts);
  const insights = allInsights(graph, "dns_anomaly");
  const burst = insights.find((i) => i.description.includes("突发"));
  assert.ok(burst, "应检测到 DNS 查询突发");
});

test("dns_anomaly: AXFR 查询 → warning", () => {
  const graph = makeGraph([
    packet({ protocol: "dns", dnsQueryName: "zone.example.com", dnsQueryType: 252, srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: 0 }),
  ]);
  const insights = allInsights(graph, "dns_anomaly");
  const axfr = insights.find((i) => i.description.includes("Zone Transfer"));
  assert.ok(axfr, "应检测到 AXFR 查询");
  assert.equal(axfr!.severity, "warning");
});

test("dns_anomaly: 截断响应 (TC=1)", () => {
  const graph = makeGraph([
    packet({ protocol: "dns", dnsQueryName: "large.example.com", srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: 0 }),
    packet({ protocol: "dns", dnsQueryName: "large.example.com", dnsIsResponse: true, dnsTruncated: true, srcIp: "10.0.0.2", dstIp: "10.0.0.1", timestamp: 0.05 }),
  ]);
  const insights = allInsights(graph, "dns_anomaly");
  const truncated = insights.find((i) => i.description.includes("截断"));
  assert.ok(truncated, "应检测到 DNS 截断响应");
});

// ── analyzeCrossProtocolChain ───────────────────────────────────────────

test("cross_protocol_chain: 完整链路 (DNS→TCP→TLS→HTTP)", () => {
  const graph = makeGraph([
    packet({ protocol: "dns", dnsQueryName: "app.example.com", srcIp: "10.0.0.1", dstIp: "10.0.0.2", timestamp: 0 }),
    packet({ protocol: "dns", dnsQueryName: "app.example.com", dnsIsResponse: true, dnsResponseAddress: "10.0.0.3", srcIp: "10.0.0.2", dstIp: "10.0.0.1", timestamp: 0.05 }),
    packet({ protocol: "tcp", tcpFlags: ["SYN"], srcIp: "10.0.0.1", srcPort: 51000, dstIp: "10.0.0.3", dstPort: 443, timestamp: 0.1 }),
    packet({ protocol: "tcp", tcpFlags: ["SYN", "ACK"], srcIp: "10.0.0.3", srcPort: 443, dstIp: "10.0.0.1", dstPort: 51000, timestamp: 0.15 }),
    packet({ protocol: "tls", tlsHandshakeType: 1, tlsSni: "app.example.com", srcIp: "10.0.0.1", srcPort: 51000, dstIp: "10.0.0.3", dstPort: 443, timestamp: 0.2 }),
    packet({ protocol: "tls", tlsHandshakeType: 2, srcIp: "10.0.0.3", srcPort: 443, dstIp: "10.0.0.1", dstPort: 51000, timestamp: 0.3 }),
    packet({ protocol: "http", httpRequestMethod: "GET", httpRequestUri: "/api", httpHost: "app.example.com", srcIp: "10.0.0.1", srcPort: 51000, dstIp: "10.0.0.3", dstPort: 443, timestamp: 0.5 }),
    packet({ protocol: "http", httpResponseCode: 200, srcIp: "10.0.0.3", srcPort: 443, dstIp: "10.0.0.1", dstPort: 51000, timestamp: 0.8 }),
  ]);
  const insight = findInsight(graph, "cross_protocol_chain");
  assert.ok(insight, "完整链路应产生 cross_protocol_chain insight");
  const detail = insight!.detail as Record<string, unknown>;
  const stages = detail.stages as Array<{ stage: string }>;
  assert.ok(stages.length >= 5, `至少 5 个阶段，实际 ${stages.length}`);
});

// ── analyzeUdp ──────────────────────────────────────────────────────────

test("udp_anomaly: 多端口访问 (1 srcIp, 10 dstPorts)", () => {
  const pkts = Array.from({ length: 10 }, (_, i) =>
    packet({ protocol: "udp", srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 1000 + i, timestamp: i * 0.1 })
  );
  const graph = makeGraph(pkts);
  const insight = findInsight(graph, "udp_anomaly");
  assert.ok(insight, "应检测到 UDP 多端口访问");
});

test("udp_flow: 单向 UDP (A→B 有包, B→A 无包)", () => {
  const pkts = Array.from({ length: 5 }, (_, i) =>
    packet({ protocol: "udp", srcIp: "10.0.0.1", srcPort: 50001, dstIp: "10.0.0.2", dstPort: 5000, timestamp: i * 0.1 })
  );
  const graph = makeGraph(pkts);
  const insights = allInsights(graph, "udp_flow");
  const oneWay = insights.find((i) => i.description.includes("单向"));
  assert.ok(oneWay, "应检测到单向 UDP 流");
});

test("udp_flow: QUIC 检测", () => {
  const pkts = [
    packet({ protocol: "udp", srcIp: "10.0.0.1", srcPort: 50002, dstIp: "10.0.0.2", dstPort: 443, quicVersion: "00000001", timestamp: 0 }),
    packet({ protocol: "udp", srcIp: "10.0.0.2", srcPort: 443, dstIp: "10.0.0.1", dstPort: 50002, quicVersion: "00000001", timestamp: 0.05 }),
  ];
  const graph = makeGraph(pkts);
  const insights = allInsights(graph, "udp_flow");
  const quic = insights.find((i) => i.description.includes("QUIC"));
  assert.ok(quic, "应检测到 QUIC 流量");
});

// ── analyzeIcmpAdvanced ─────────────────────────────────────────────────

test("icmp_unreachable: ICMP Unreachable 检测", () => {
  const pkts = Array.from({ length: 3 }, (_, i) =>
    packet({ protocol: "icmp", icmpType: 3, icmpCode: 1, srcIp: "192.168.1.1", dstIp: "10.0.0.1", timestamp: i })
  );
  const graph = makeGraph(pkts);
  const insight = findInsight(graph, "icmp_unreachable");
  assert.ok(insight, "应检测到 ICMP Unreachable");
});

test("icmp_mtu: ICMP Fragmentation Needed", () => {
  const graph = makeGraph([
    packet({ protocol: "icmp", icmpType: 3, icmpCode: 4, srcIp: "192.168.1.1", dstIp: "10.0.0.1", timestamp: 0 }),
  ]);
  const insight = findInsight(graph, "icmp_mtu");
  assert.ok(insight, "应检测到 ICMP Fragmentation Needed");
  assert.match(insight!.description, /Fragmentation Needed/);
});

// ── analyzeQuic ─────────────────────────────────────────────────────────

test("quic_anomaly: QUIC 连接概览", () => {
  const pkts = Array.from({ length: 3 }, (_, i) =>
    packet({ protocol: "udp", quicConnectionId: "conn-abc123", quicVersion: "00000001", quicPacketType: "0", srcIp: "10.0.0.1", srcPort: 50003, dstIp: "10.0.0.2", dstPort: 443, timestamp: i * 0.1 })
  );
  const graph = makeGraph(pkts);
  const insight = findInsight(graph, "quic_anomaly");
  assert.ok(insight, "QUIC 包应产生 quic_anomaly insight");
});

test("quic_anomaly: 握手未完成 (Initial 无 Handshake)", () => {
  const graph = makeGraph([
    packet({ protocol: "udp", quicConnectionId: "conn-def456", quicVersion: "00000001", quicPacketType: "Initial", srcIp: "10.0.0.1", srcPort: 50004, dstIp: "10.0.0.2", dstPort: 443, timestamp: 0 }),
    packet({ protocol: "udp", quicConnectionId: "conn-def456", quicVersion: "00000001", quicPacketType: "Initial", srcIp: "10.0.0.1", srcPort: 50004, dstIp: "10.0.0.2", dstPort: 443, timestamp: 0.5 }),
  ]);
  const insights = allInsights(graph, "quic_anomaly");
  const incomplete = insights.find((i) => i.description.includes("Handshake"));
  assert.ok(incomplete, "应检测到 QUIC 握手未完成");
});

// ── analyzeNtp ──────────────────────────────────────────────────────────

test("ntp_anomaly: Stratum 统计", () => {
  const graph = makeGraph([
    packet({ protocol: "udp", ntpStratum: 2, ntpRefid: "GPS", dstPort: 123, timestamp: 0 }),
  ]);
  const insight = findInsight(graph, "ntp_anomaly");
  assert.ok(insight, "NTP 包应产生 ntp_anomaly insight");
  assert.match(insight!.description, /Stratum/);
});

test("ntp_anomaly: 高 Stratum (>=10)", () => {
  const graph = makeGraph([
    packet({ protocol: "udp", ntpStratum: 12, ntpRefid: "LOCL", dstPort: 123, timestamp: 0 }),
  ]);
  const insights = allInsights(graph, "ntp_anomaly");
  const high = insights.find((i) => i.description.includes(">= 10"));
  assert.ok(high, "应检测到高 Stratum NTP");
});

// ── analyzeSsh ──────────────────────────────────────────────────────────

test("ssh_anomaly: SSH 消息分布", () => {
  const graph = makeGraph([
    packet({ protocol: "tcp", sshMessage: "KEX_INIT", sshDirection: "client", dstPort: 22, timestamp: 0 }),
    packet({ protocol: "tcp", sshMessage: "KEX_DH_GEX_INIT", sshDirection: "client", dstPort: 22, timestamp: 0.1 }),
    packet({ protocol: "tcp", sshMessage: "NEWKEYS", sshDirection: "client", dstPort: 22, timestamp: 0.2 }),
  ]);
  const insight = findInsight(graph, "ssh_anomaly");
  assert.ok(insight, "SSH 包应产生 ssh_anomaly insight");
});

test("ssh_anomaly: SSH 断开", () => {
  const graph = makeGraph([
    packet({ protocol: "tcp", sshMessage: "KEX_INIT", sshDirection: "client", dstPort: 22, timestamp: 0 }),
    packet({ protocol: "tcp", sshMessage: "disconnect", sshDirection: "client", dstPort: 22, timestamp: 1 }),
  ]);
  const insights = allInsights(graph, "ssh_anomaly");
  const disconnect = insights.find((i) => i.description.includes("断开"));
  assert.ok(disconnect, "应检测到 SSH 断开");
});

test("ssh_anomaly: SSH 认证重试", () => {
  const graph = makeGraph([
    packet({ protocol: "tcp", sshMessage: "auth_request", sshDirection: "client", dstPort: 22, timestamp: 0 }),
    packet({ protocol: "tcp", sshMessage: "auth_failure", sshDirection: "server", dstPort: 22, timestamp: 0.5 }),
  ]);
  const insights = allInsights(graph, "ssh_anomaly");
  const auth = insights.find((i) => i.description.includes("认证"));
  assert.ok(auth, "应检测到 SSH 认证相关消息");
});
