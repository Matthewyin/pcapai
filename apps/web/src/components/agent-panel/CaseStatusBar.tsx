/*
 * CaseStatusBar — 右栏"基础统计 + 包级统计"section（阶段 1c 从 main.tsx 抽出）。
 *
 * 行为等价于原 main.tsx:2336-2391 的 <section className="caseStatusBar">。
 * 所有派生计数（tcpConnectionCount / tcpCommunicationPairCount / timeRange / 包级计数）
 * 原本散落在 main.tsx 顶层,只被本 section 使用 → 全部内化到组件 useMemo。
 */
import React from "react";
import type { CaseGraph } from "../../types";
import { capturePacketTotal, formatPacketTime } from "../../lib/format";

type CaseStatusBarProps = {
  graph: CaseGraph | null;
};

export function CaseStatusBar(props: CaseStatusBarProps) {
  const { graph } = props;

  const stats = React.useMemo(() => {
    const tcpConnectionCount = graph?.sessions.filter((s) => s.protocol.toLowerCase() === "tcp").length || 0;
    const tcpCommunicationPairCount = (() => {
      if (!graph) return 0;
      const sessionPairs = new Set(
        graph.sessions
          .filter((s) => s.protocol.toLowerCase() === "tcp" && s.clientIp && s.serverIp && s.clientPort !== undefined && s.serverPort !== undefined)
          .map((s) => [`${s.clientIp}:${s.clientPort}`, `${s.serverIp}:${s.serverPort}`].sort().join(" <-> "))
      );
      if (sessionPairs.size) return sessionPairs.size;
      return new Set(
        graph.packets
          .filter((p) => p.protocol.toLowerCase() === "tcp" && p.srcIp && p.dstIp && p.srcPort !== undefined && p.dstPort !== undefined)
          .map((p) => [`${p.srcIp}:${p.srcPort}`, `${p.dstIp}:${p.dstPort}`].sort().join(" <-> "))
      ).size;
    })();
    const packetTimes = (graph?.packets || []).map((p) => p.timestamp).filter(Number.isFinite);
    const timeRange = packetTimes.length
      ? `${formatPacketTime(Math.min(...packetTimes))} - ${formatPacketTime(Math.max(...packetTimes))}`
      : "-";
    const tcpPackets = (graph?.packets || []).filter((p) => p.protocol.toLowerCase() === "tcp");
    const packetCountByFlag = (flag: string) => tcpPackets.filter((p) => p.tcpFlags.includes(flag)).length;
    const retransmissionPacketCount = tcpPackets.filter((p) => p.tcpAnalysis?.retransmission || p.tcpAnalysis?.fastRetransmission).length;
    const duplicateAckPacketCount = tcpPackets.filter((p) => p.tcpAnalysis?.duplicateAck).length;
    const zeroWindowPacketCount = tcpPackets.filter((p) => p.tcpAnalysis?.zeroWindow).length;
    return {
      tcpConnectionCount,
      tcpCommunicationPairCount,
      timeRange,
      rstCount: packetCountByFlag("RST"),
      retransmissionPacketCount,
      duplicateAckPacketCount,
      zeroWindowPacketCount,
      tcpPacketCount: tcpPackets.length
    };
  }, [graph]);

  return (
    <section className="caseStatusBar">
      <h3 className="metricGroupTitle">基础统计</h3>
      <article>
        <span>抓包节点</span>
        <strong>{graph?.captures.length || 0}</strong>
      </article>
      <article>
        <span>捕获包</span>
        <strong>{capturePacketTotal(graph)}</strong>
      </article>
      <article>
        <span>筛选包</span>
        <strong>{graph?.packets.length || 0}</strong>
      </article>
      <article>
        <span>TCP 通信对</span>
        <strong>{stats.tcpCommunicationPairCount}</strong>
      </article>
      <article>
        <span>TCP 会话片段</span>
        <strong>{stats.tcpConnectionCount}</strong>
      </article>
      <article>
        <span>TCP 包</span>
        <strong>{stats.tcpPacketCount}</strong>
      </article>
      <article>
        <span>跨节点关联</span>
        <strong>{graph?.sessionLinks.length || 0}</strong>
      </article>
      <article>
        <span>判断</span>
        <strong>{graph?.findings.length || 0}</strong>
      </article>
      <article className="metricWide">
        <span>当前筛选时间区间</span>
        <b>{stats.timeRange}</b>
      </article>
      <h3 className="metricGroupTitle">包级统计</h3>
      <article>
        <span>RST 包</span>
        <strong>{stats.rstCount}</strong>
      </article>
      <article>
        <span>重传包</span>
        <strong>{stats.retransmissionPacketCount}</strong>
      </article>
      <article>
        <span>Dup ACK 包</span>
        <strong>{stats.duplicateAckPacketCount}</strong>
      </article>
      <article>
        <span>Zero Window 包</span>
        <strong>{stats.zeroWindowPacketCount}</strong>
      </article>
    </section>
  );
}
