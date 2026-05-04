import assert from "node:assert/strict";
import test from "node:test";
import type { PacketSummary } from "../../../packages/shared/src/index.js";
import { endpointText, groupPacketPairs, pairGroupFromPackets } from "../src/protocolAdapters/builders.js";

// TCP Stream API 的集成测试需要启动 MCP server 和 tshark，这里测试辅助函数和参数构造逻辑。

type ProtocolPacket = {
  packetId: string;
  nodeId: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol?: string;
  timestamp: number;
  pcapFilename?: string;
  frameNumber?: number;
};

function protoPacket(patch: Partial<ProtocolPacket>): ProtocolPacket {
  return {
    packetId: "pkt-1",
    nodeId: "node-1",
    srcIp: "10.0.0.1",
    srcPort: 50000,
    dstIp: "10.0.0.2",
    dstPort: 80,
    protocol: "tcp",
    timestamp: 0,
    pcapFilename: "test.pcap",
    frameNumber: 1,
    ...patch,
  };
}

test("endpointText: 格式化 IP:Port", () => {
  assert.equal(endpointText("10.0.0.1", 80), "10.0.0.1:80");
  assert.equal(endpointText("10.0.0.1"), "10.0.0.1:*");
  assert.equal(endpointText(undefined, 80), "*:80");
  assert.equal(endpointText(), "*:*");
});

test("groupPacketPairs: 按端点对分组", () => {
  const packets = [
    protoPacket({ srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 80, timestamp: 0 }),
    protoPacket({ srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 80, timestamp: 1 }),
    protoPacket({ srcIp: "10.0.0.2", srcPort: 80, dstIp: "10.0.0.1", dstPort: 50000, timestamp: 2 }),
  ];
  const groups = groupPacketPairs(packets as any);
  assert.equal(groups.length, 1, "同一对端点应归为一组");
  assert.equal(groups[0].count, 3);
});

test("pairGroupFromPackets: 从包列表构建 pair group", () => {
  const packets = [
    protoPacket({ srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 80, timestamp: 1 }),
    protoPacket({ srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 80, timestamp: 2 }),
  ];
  const group = pairGroupFromPackets(packets as any, 2, "tcp");
  assert.equal(group.count, 2);
  assert.equal(group.src, "10.0.0.1:50000");
  assert.equal(group.dst, "10.0.0.2:80");
});

test("groupPacketPairs: 按包数排序（最多的在前）", () => {
  const packets = [
    ...Array.from({ length: 5 }, (_, i) => protoPacket({ srcIp: "10.0.0.1", srcPort: 50000, dstIp: "10.0.0.2", dstPort: 80, timestamp: i })),
    ...Array.from({ length: 3 }, (_, i) => protoPacket({ srcIp: "10.0.0.1", srcPort: 50001, dstIp: "10.0.0.3", dstPort: 443, timestamp: i })),
  ];
  const groups = groupPacketPairs(packets as any);
  assert.equal(groups.length, 2);
  assert.ok(groups[0].count >= groups[1].count, "包数最多的应排在前面");
});
