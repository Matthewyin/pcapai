import assert from "node:assert/strict";
import test from "node:test";
import { parseNetworkStatisticsRows, parseTsharkRows } from "../src/index.js";

test("parseTsharkRows parses TCP analysis fields", () => {
  const row = [
    "7",
    "1769249100.123",
    "10.0.0.1",
    "",
    "49152",
    "",
    "10.0.0.2",
    "",
    "443",
    "",
    "TCP",
    "1",
    "0",
    "0",
    "0",
    "0",
    "100",
    "0",
    "0",
    "64240",
    "1",
    "",
    "1",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "74",
    "SYN retransmission"
  ].join("\t");

  const packets = parseTsharkRows(row, { nodeId: "node-1", name: "client", pcapFilename: "client.pcap" });
  assert.equal(packets.length, 1);
  assert.equal(packets[0].packetId, "node-1:7");
  assert.deepEqual(packets[0].tcpFlags, ["SYN"]);
  assert.equal(packets[0].tcpAnalysis.retransmission, true);
  assert.equal(packets[0].tcpAnalysis.duplicateAck, true);
  assert.equal(packets[0].icmpType, undefined);
  assert.equal(packets[0].dnsRcode, undefined);
  assert.equal(packets[0].tlsHandshakeType, undefined);
  assert.equal(packets[0].httpResponseCode, undefined);
});

test("parseTsharkRows parses DNS fields", () => {
  const row = [
    "12",
    "1769249200.456",
    "10.0.0.2",
    "",
    "",
    "53",
    "10.0.0.1",
    "",
    "",
    "49152",
    "DNS",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "1234",
    "example.com",
    "1",
    "3",
    "",
    "",
    "96",
    "Standard query response 0x1234 NXDomain A example.com"
  ].join("\t");

  const packets = parseTsharkRows(row, { nodeId: "node-1", name: "client", pcapFilename: "client.pcap" });
  assert.equal(packets.length, 1);
  assert.equal(packets[0].protocol, "dns");
  assert.equal(packets[0].srcPort, 53);
  assert.equal(packets[0].dstPort, 49152);
  assert.equal(packets[0].dnsId, "1234");
  assert.equal(packets[0].dnsQueryName, "example.com");
  assert.equal(packets[0].dnsIsResponse, true);
  assert.equal(packets[0].dnsRcode, 3);
});

test("parseTsharkRows parses TLS fields", () => {
  const row = [
    "21",
    "1769249300.789",
    "10.0.0.1",
    "",
    "49152",
    "",
    "10.0.0.2",
    "",
    "443",
    "",
    "TLSv1.2",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "517",
    "Client Hello",
    "1",
    "example.com",
    "0x0303",
    "0x0303",
    "",
    ""
  ].join("\t");

  const packets = parseTsharkRows(row, { nodeId: "node-1", name: "client", pcapFilename: "client.pcap" });
  assert.equal(packets.length, 1);
  assert.equal(packets[0].protocol, "tlsv1.2");
  assert.equal(packets[0].tlsHandshakeType, 1);
  assert.equal(packets[0].tlsSni, "example.com");
  assert.equal(packets[0].tlsRecordVersion, "0x0303");
});

test("parseTsharkRows parses HTTP fields", () => {
  const row = [
    "31",
    "1769249400.111",
    "10.0.0.1",
    "",
    "49152",
    "",
    "10.0.0.2",
    "",
    "80",
    "",
    "HTTP",
    "",
    "1",
    "",
    "",
    "1",
    "1",
    "1",
    "128",
    "64240",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "512",
    "GET /api HTTP/1.1",
    "",
    "",
    "",
    "",
    "",
    "",
    "GET",
    "example.com",
    "/api",
    "",
    "",
    "",
    "",
    "37",
    ""
  ].join("\t");

  const packets = parseTsharkRows(row, { nodeId: "node-1", name: "client", pcapFilename: "client.pcap" });
  assert.equal(packets.length, 1);
  assert.equal(packets[0].protocol, "http");
  assert.equal(packets[0].httpRequestMethod, "GET");
  assert.equal(packets[0].httpHost, "example.com");
  assert.equal(packets[0].httpRequestUri, "/api");
  assert.equal(packets[0].httpResponseIn, 37);
});

test("parseNetworkStatisticsRows aggregates IP, port and protocol statistics", () => {
  const rows = [
    [
      "10.0.0.1",
      "",
      "10.0.0.2",
      "",
      "49152",
      "",
      "80",
      "",
      "1",
      "",
      "",
      "500",
      ""
    ].join("\t"),
    [
      "10.0.0.1",
      "",
      "10.0.0.2",
      "",
      "49152",
      "",
      "80",
      "",
      "",
      "",
      "1",
      "",
      ""
    ].join("\t"),
    [
      "10.0.0.3",
      "",
      "8.8.8.8",
      "",
      "",
      "53333",
      "",
      "53",
      "",
      "",
      "",
      "",
      "3"
    ].join("\t")
  ].join("\n");

  const stats = parseNetworkStatisticsRows(rows, { nodeId: "node-1", name: "client", pcapFilename: "client.pcap" });

  assert.equal(stats.packetCount, 3);
  assert.equal(stats.ipCount, 4);
  assert.equal(stats.sourceIpCount, 2);
  assert.equal(stats.destinationIpCount, 2);
  assert.deepEqual(stats.sourceIps[0], { ip: "10.0.0.1", packetCount: 2 });
  assert.deepEqual(stats.destinationIps[0], { ip: "10.0.0.2", packetCount: 2 });
  assert.deepEqual(stats.ports[0], { protocol: "tcp", port: 80, packetCount: 2 });
  assert.equal(stats.tcpRstCount, 1);
  assert.equal(stats.tcpRetransmissionCount, 1);
  assert.deepEqual(stats.httpStatusCodes, [{ code: 500, packetCount: 1 }]);
  assert.deepEqual(stats.dnsRcodes, [{ rcode: 3, packetCount: 1 }]);
});
