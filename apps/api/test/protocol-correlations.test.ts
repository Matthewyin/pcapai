import assert from "node:assert/strict";
import test from "node:test";
import type { EvidenceCard, PacketSummary } from "../../../packages/shared/src/index.js";
import { buildProtocolCorrelations } from "../src/protocolAdapters/builders.js";

function packet(patch: Partial<PacketSummary>): PacketSummary {
  return {
    packetId: "packet-1",
    nodeId: "node-1",
    pcapFilename: "node.pcap",
    frameNumber: 1,
    timestamp: 100,
    protocol: "tcp",
    tcpFlags: [],
    tcpAnalysis: {
      retransmission: false,
      fastRetransmission: false,
      duplicateAck: false,
      zeroWindow: false,
      lostSegment: false
    },
    summary: "",
    raw: {},
    ...patch
  };
}

function card(packet: PacketSummary): EvidenceCard {
  return {
    cardId: `card-${packet.packetId}`,
    kind: "protocol_event",
    title: "evidence",
    summary: "summary",
    pcapFilename: packet.pcapFilename,
    frameNumber: packet.frameNumber,
    displayFilter: "frame.number == 1",
    actions: ["open_wireshark"]
  };
}

test("buildProtocolCorrelations links DNS response address to TCP filter", () => {
  const dns = packet({
    protocol: "dns",
    dnsIsResponse: true,
    dnsQueryName: "example.com",
    dnsResponseAddress: "10.0.0.10",
    dnsRcode: 0
  });

  const correlations = buildProtocolCorrelations("query-1", "dns", [dns], [card(dns)]);

  assert.equal(correlations.length, 1);
  assert.equal(correlations[0].kind, "dns_to_tcp");
  assert.equal(correlations[0].targetDisplayFilter, "tcp && ip.addr == 10.0.0.10");
  assert.equal(correlations[0].sourceEvidenceCardId, "card-packet-1");
});

test("buildProtocolCorrelations links TLS SNI to carrying TCP flow", () => {
  const tls = packet({
    packetId: "packet-2",
    protocol: "tls",
    srcIp: "10.0.0.1",
    srcPort: 51000,
    dstIp: "10.0.0.2",
    dstPort: 443,
    tlsSni: "app.example.com"
  });

  const correlations = buildProtocolCorrelations("query-1", "tls", [tls], [card(tls)]);

  assert.equal(correlations.length, 1);
  assert.equal(correlations[0].kind, "tls_sni_to_tcp");
  assert.equal(correlations[0].targetDisplayFilter, "tcp && ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 51000 && tcp.port == 443");
  assert.match(correlations[0].summary, /app.example.com/);
});

test("buildProtocolCorrelations links HTTP Host to carrying TCP flow", () => {
  const http = packet({
    packetId: "packet-3",
    protocol: "http",
    srcIp: "10.0.0.1",
    srcPort: 51000,
    dstIp: "10.0.0.2",
    dstPort: 80,
    httpHost: "www.example.com",
    httpRequestUri: "/health"
  });

  const correlations = buildProtocolCorrelations("query-1", "http", [http], [card(http)]);

  assert.equal(correlations.length, 1);
  assert.equal(correlations[0].kind, "http_host_to_tcp");
  assert.equal(correlations[0].targetDisplayFilter, "tcp && ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2 && tcp.port == 51000 && tcp.port == 80");
  assert.deepEqual(correlations[0].reasons, ["Host=www.example.com", "URI=/health", "frame=1"]);
});

test("buildProtocolCorrelations links ICMP Unreachable to TCP filter", () => {
  const icmp = packet({
    packetId: "packet-4",
    protocol: "icmp",
    srcIp: "192.168.1.1",
    dstIp: "10.0.0.5",
    icmpType: 3,
    icmpCode: 3
  });

  const correlations = buildProtocolCorrelations("query-1", "icmp", [icmp], [card(icmp)]);

  assert.equal(correlations.length, 1);
  assert.equal(correlations[0].kind, "icmp_to_tcp");
  assert.match(correlations[0].targetDisplayFilter, /10\.0\.0\.5/);
});

test("buildProtocolCorrelations ICMP Fragmentation Needed mentions PMTU", () => {
  const icmp = packet({
    packetId: "packet-5",
    protocol: "icmp",
    srcIp: "192.168.1.1",
    dstIp: "10.0.0.5",
    icmpType: 3,
    icmpCode: 4
  });

  const correlations = buildProtocolCorrelations("query-1", "icmp", [icmp], [card(icmp)]);

  assert.equal(correlations.length, 1);
  assert.ok(correlations[0].nextSteps.some((s: string) => s.includes("PMTU") || s.includes("Path MTU")));
});

test("buildProtocolCorrelations ICMP Echo does not produce icmp_to_tcp", () => {
  const icmp = packet({
    packetId: "packet-6",
    protocol: "icmp",
    srcIp: "10.0.0.1",
    dstIp: "10.0.0.2",
    icmpType: 8
  });

  const correlations = buildProtocolCorrelations("query-1", "icmp", [icmp], [card(icmp)]);

  assert.equal(correlations.length, 0);
});
