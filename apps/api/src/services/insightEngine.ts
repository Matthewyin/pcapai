import type { CaseGraph, PacketInsight, PacketSummary } from "../../../../packages/shared/src/index.js";

type InsightAccumulator = PacketInsight[];

function insightId(type: string, index: number) {
  return `insight-${type}-${index}`;
}

function fmtEndpoint(ip?: string, port?: number) {
  return ip && port != null ? `${ip}:${port}` : ip || "";
}

// ── TCP Connection Tracking ──────────────────────────────────────────

type TcpFlowKey = string;
type TcpConnection = {
  flowKey: TcpFlowKey;
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  packets: PacketSummary[];
  hasSyn: boolean;
  hasSynAck: boolean;
  hasAck: boolean;
  hasFin: boolean;
  hasRst: boolean;
  startTime: number;
  endTime: number;
};

function tcpFlowKey(p: PacketSummary): TcpFlowKey {
  if (!p.srcIp || !p.dstIp || p.srcPort == null || p.dstPort == null) return "";
  return [p.srcIp, p.srcPort, p.dstIp, p.dstPort].join(":");
}

function tcpFlowKeyReverse(p: PacketSummary): TcpFlowKey {
  if (!p.srcIp || !p.dstIp || p.srcPort == null || p.dstPort == null) return "";
  return [p.dstIp, p.dstPort, p.srcIp, p.srcPort].join(":");
}

function extractTcpConnections(packets: PacketSummary[]): Map<TcpFlowKey, TcpConnection> {
  const connections = new Map<TcpFlowKey, TcpConnection>();

  for (const p of packets) {
    if (p.protocol.toLowerCase() !== "tcp") continue;
    if (!p.srcIp || !p.dstIp || p.srcPort == null || p.dstPort == null) continue;

    const fwdKey = tcpFlowKey(p);
    const revKey = tcpFlowKeyReverse(p);

    let conn = connections.get(fwdKey) || connections.get(revKey);
    if (!conn) {
      conn = {
        flowKey: fwdKey < revKey ? fwdKey : revKey,
        srcIp: p.srcIp, srcPort: p.srcPort,
        dstIp: p.dstIp, dstPort: p.dstPort,
        packets: [],
        hasSyn: false, hasSynAck: false, hasAck: false,
        hasFin: false, hasRst: false,
        startTime: p.timestamp, endTime: p.timestamp
      };
      connections.set(conn.flowKey, conn);
    }

    conn.packets.push(p);
    conn.startTime = Math.min(conn.startTime, p.timestamp);
    conn.endTime = Math.max(conn.endTime, p.timestamp);

    const flags = p.tcpFlags.map(f => f.toUpperCase());
    if (flags.includes("SYN") && !flags.includes("ACK")) conn.hasSyn = true;
    if (flags.includes("SYN") && flags.includes("ACK")) conn.hasSynAck = true;
    if (flags.includes("ACK") && !flags.includes("SYN")) conn.hasAck = true;
    if (flags.includes("FIN")) conn.hasFin = true;
    if (flags.includes("RST")) conn.hasRst = true;
  }

  return connections;
}

// ── Analyzer: Connection Lifecycle ────────────────────────────────────

function analyzeConnectionLifecycle(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);

    if (conn.hasSyn && !conn.hasSynAck) {
      acc.push({
        insightId: insightId("conn-lifecycle", idx++),
        type: "connection_lifecycle",
        severity: "critical",
        packetIds: sorted.map(p => p.packetId),
        description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)} 发送了 SYN 但未收到 SYN/ACK，握手未完成`,
        detail: {
          srcIp: conn.srcIp, srcPort: conn.srcPort,
          dstIp: conn.dstIp, dstPort: conn.dstPort,
          synSent: true, synAckReceived: false,
          handshakeComplete: false,
          packetCount: sorted.length,
          durationMs: (conn.endTime - conn.startTime) * 1000
        },
        scenario: "防火墙丢弃 SYN、服务端 SYN backlog 满、路由不可达"
      });
      continue;
    }

    if (conn.hasSyn && conn.hasSynAck && conn.hasRst) {
      const dataPackets = sorted.filter(p => {
        const flags = p.tcpFlags.map(f => f.toUpperCase());
        return !flags.includes("SYN") && !flags.includes("FIN") && !flags.includes("RST")
          && (p.tcpPayloadLength ?? 0) > 0;
      });

      const rstPacket = sorted.find(p => p.tcpFlags.map(f => f.toUpperCase()).includes("RST"));
      const firstDataIdx = sorted.findIndex(p => (p.tcpPayloadLength ?? 0) > 0);
      const rstIdx = sorted.indexOf(rstPacket!);

      if (dataPackets.length === 0 || (rstIdx >= 0 && firstDataIdx >= 0 && rstIdx < firstDataIdx)) {
        acc.push({
          insightId: insightId("conn-lifecycle", idx++),
          type: "connection_lifecycle",
          severity: "critical",
          packetIds: sorted.map(p => p.packetId),
          description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)} 握手完成后被 RST（无数据传输）`,
          detail: {
            srcIp: conn.srcIp, srcPort: conn.srcPort,
            dstIp: conn.dstIp, dstPort: conn.dstPort,
            handshakeComplete: true, rstAfterHandshake: true,
            dataPacketsBeforeRst: rstIdx < firstDataIdx ? 0 : dataPackets.length,
            rstFromIp: rstPacket?.srcIp,
            packetCount: sorted.length
          },
          scenario: "中间设备（防火墙/WAF/LB）拒绝连接、服务端拒绝连接"
        });
      }
    }

    if (conn.hasFin && !conn.hasRst) {
      const finPackets = sorted.filter(p => p.tcpFlags.map(f => f.toUpperCase()).includes("FIN"));
      const finDirections = new Set(finPackets.map(p => tcpFlowKey(p)));
      if (finDirections.size === 1) {
        acc.push({
          insightId: insightId("conn-lifecycle", idx++),
          type: "connection_lifecycle",
          severity: "warning",
          packetIds: finPackets.map(p => p.packetId),
          description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)} 单侧 FIN 关闭，对端未回应 FIN`,
          detail: {
            srcIp: conn.srcIp, srcPort: conn.srcPort,
            dstIp: conn.dstIp, dstPort: conn.dstPort,
            halfClose: true,
            finFromIp: finPackets[0]?.srcIp
          },
          scenario: "应用层超时、对端处理能力不足无法正常关闭"
        });
      }
    }
  }
}

// ── Analyzer: ACK Gap Detection ───────────────────────────────────────

function analyzeAckGap(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);
    const retransmissions = sorted.filter(p => p.tcpAnalysis?.retransmission || p.tcpAnalysis?.fastRetransmission);
    if (!retransmissions.length) continue;

    const bySeq = new Map<number, PacketSummary[]>();
    for (const p of retransmissions) {
      if (p.tcpSeq == null) continue;
      const group = bySeq.get(p.tcpSeq) || [];
      group.push(p);
      bySeq.set(p.tcpSeq, group);
    }

    for (const [seq, retxPackets] of bySeq) {

      const original = sorted.find(p =>
        p.tcpSeq === seq && !p.tcpAnalysis?.retransmission && !p.tcpAnalysis?.fastRetransmission
        && (p.tcpPayloadLength ?? 0) > 0
      );

      const lastRetxTime = Math.max(...retxPackets.map(p => p.timestamp));
      const rstAfter = sorted.find(p =>
        p.tcpFlags.map(f => f.toUpperCase()).includes("RST") && p.timestamp > lastRetxTime
      );

      const retxTimes = retxPackets.map(p => p.timestamp).sort();
      const intervals = retxTimes.slice(1).map((t, i) => t - retxTimes[i]);

      const allPacketIds = original ? [original.packetId, ...retxPackets.map(p => p.packetId)] : retxPackets.map(p => p.packetId);
      if (rstAfter) allPacketIds.push(rstAfter.packetId);

      const payloadLen = original?.tcpPayloadLength ?? retxPackets[0]?.tcpPayloadLength ?? 0;

      acc.push({
        insightId: insightId("ack-gap", idx++),
        type: "ack_gap",
        severity: rstAfter ? "critical" : "warning",
        packetIds: allPacketIds,
        description: rstAfter
          ? `${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)}: seq=${seq} 发送 ${retxPackets.length + (original ? 1 : 0)} 次后无 ACK，最终 RST 断开`
          : `${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)}: seq=${seq} 重传 ${retxPackets.length} 次，可能未收到 ACK`,
        detail: {
          srcIp: conn.srcIp, srcPort: conn.srcPort,
          dstIp: conn.dstIp, dstPort: conn.dstPort,
          seqNumber: seq,
          payloadLength: payloadLen,
          totalAttempts: retxPackets.length + (original ? 1 : 0),
          retransmissionCount: retxPackets.length,
          retransmissionIntervalsSec: intervals,
          rstAfter: !!rstAfter,
          rstFromIp: rstAfter?.srcIp,
          exponentialBackoff: intervals.length >= 2 ? checkExponentialBackoff(intervals) : undefined
        },
        scenario: rstAfter
          ? "服务端处理挂死或网络单向丢包导致 ACK 丢失，TCP 栈最终放弃连接"
          : "网络间歇性丢包、接收端处理延迟、TCP 窗口限制"
      });
    }
  }
}

function checkExponentialBackoff(intervals: number[]): boolean {
  if (intervals.length < 2) return false;
  for (let i = 1; i < intervals.length; i++) {
    const ratio = intervals[i] / intervals[i - 1];
    if (ratio < 1.5 || ratio > 4) return false;
  }
  return true;
}

// ── Analyzer: TCP Timing ──────────────────────────────────────────────

function analyzeTcpTiming(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);
    if (sorted.length < 3) continue;

    // RTT estimation from SYN → SYN/ACK
    const synPacket = sorted.find(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && !flags.includes("ACK");
    });
    const synAckPacket = sorted.find(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && flags.includes("ACK");
    });

    const rttSynSec = synPacket && synAckPacket ? synAckPacket.timestamp - synPacket.timestamp : undefined;

    // Idle gap detection
    let maxIdleGap = 0;
    let maxIdleGapStartIdx = 0;
    for (let i = 1; i < sorted.length; i++) {
      const gap = sorted[i].timestamp - sorted[i - 1].timestamp;
      if (gap > maxIdleGap) {
        maxIdleGap = gap;
        maxIdleGapStartIdx = i - 1;
      }
    }

    // Report RTT
    if (rttSynSec != null) {
      acc.push({
        insightId: insightId("tcp-timing", idx++),
        type: "tcp_timing",
        severity: "info",
        packetIds: [synPacket!.packetId, synAckPacket!.packetId],
        description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)} 握手 RTT ${(rttSynSec * 1000).toFixed(0)}ms（SYN→SYN/ACK）`,
        detail: {
          srcIp: conn.srcIp, srcPort: conn.srcPort,
          dstIp: conn.dstIp, dstPort: conn.dstPort,
          rttMs: rttSynSec * 1000,
          measuredFrom: "syn_synack"
        },
        scenario: "握手往返延迟"
      });
    }

    // Report idle gaps
    if (maxIdleGap > 0) {
      const gapStart = sorted[maxIdleGapStartIdx];
      const gapEnd = sorted[maxIdleGapStartIdx + 1];
      acc.push({
        insightId: insightId("tcp-timing", idx++),
        type: "tcp_timing",
        severity: "info",
        packetIds: [gapStart.packetId, gapEnd.packetId],
        description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)} 最大空闲间隔 ${(maxIdleGap).toFixed(1)}s`,
        detail: {
          srcIp: conn.srcIp, srcPort: conn.srcPort,
          dstIp: conn.dstIp, dstPort: conn.dstPort,
          idleGapSec: maxIdleGap,
          gapStartTimestamp: gapStart.timestamp,
          gapEndTimestamp: gapEnd.timestamp,
          gapStartSummary: gapStart.summary,
          gapEndSummary: gapEnd.summary
        },
        scenario: "应用层处理延迟或等待响应"
      });
    }

    // Burst → stall pattern detection
    const timeWindows: Array<{ start: number; end: number; count: number }> = [];
    const WINDOW_SIZE_SEC = 0.1;
    for (let i = 0; i < sorted.length; i++) {
      const windowEnd = sorted[i].timestamp + WINDOW_SIZE_SEC;
      let count = 0;
      for (let j = i; j < sorted.length && sorted[j].timestamp <= windowEnd; j++) count++;
      timeWindows.push({ start: sorted[i].timestamp, end: windowEnd, count });
    }

    const maxBurst = timeWindows.reduce((max, w) => Math.max(max, w.count), 0);
    if (maxBurst > 1) {
      const burstWindow = timeWindows.find(w => w.count === maxBurst)!;
      const burstPackets = sorted.filter(p => p.timestamp >= burstWindow.start && p.timestamp <= burstWindow.end);
      acc.push({
        insightId: insightId("tcp-timing", idx++),
        type: "tcp_timing",
        severity: "info",
        packetIds: burstPackets.map(p => p.packetId).slice(0, 20),
        description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)} 在 100ms 内出现 ${maxBurst} 个包的突发传输`,
        detail: {
          srcIp: conn.srcIp, srcPort: conn.srcPort,
          dstIp: conn.dstIp, dstPort: conn.dstPort,
          burstPacketCount: maxBurst,
          burstWindowSec: WINDOW_SIZE_SEC,
          totalPackets: sorted.length
        },
        scenario: "应用层批量发送、数据同步、大文件传输片段"
      });
    }
  }
}

// ── Analyzer: ICMP Echo Pair ──────────────────────────────────────────

function analyzeIcmpEchoPair(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  const echoes = packets.filter(p => p.protocol.toLowerCase() === "icmp" && p.icmpType === 8);
  const replies = packets.filter(p => p.protocol.toLowerCase() === "icmp" && p.icmpType === 0);

  if (!echoes.length) return;

  // Match echo → reply by src/dst pair and sequence (from summary or raw data)
  const matched = new Map<string, { echo: PacketSummary; reply?: PacketSummary }>();

  for (const echo of echoes) {
    const key = `${echo.srcIp}-${echo.dstIp}`;
    if (!matched.has(key)) matched.set(key, { echo, reply: undefined });

    // Find matching reply
    const reply = replies.find(r =>
      r.srcIp === echo.dstIp && r.dstIp === echo.srcIp && r.timestamp >= echo.timestamp && r.timestamp - echo.timestamp < 30
    );

    if (reply) {
      const entry = matched.get(key);
      if (entry) entry.reply = reply;
    }
  }

  // Also check for multiple echo/reply pairs
  const pairGroups = new Map<string, { echoes: PacketSummary[]; replies: PacketSummary[]; rtts: number[] }>();

  for (const echo of echoes) {
    const key = [echo.srcIp, echo.dstIp].sort().join("-");
    if (!pairGroups.has(key)) pairGroups.set(key, { echoes: [], replies: [], rtts: [] });
    pairGroups.get(key)!.echoes.push(echo);

    const reply = replies.find(r =>
      r.srcIp === echo.dstIp && r.dstIp === echo.srcIp && r.timestamp >= echo.timestamp && r.timestamp - echo.timestamp < 30
    );
    if (reply) {
      pairGroups.get(key)!.replies.push(reply);
      pairGroups.get(key)!.rtts.push((reply.timestamp - echo.timestamp) * 1000);
    }
  }

  for (const [key, group] of pairGroups) {
    const src = group.echoes[0];
    const dst = group.echoes[0];

    // 丢包情况（无论丢包率多少都报告）
    if (group.echoes.length > group.rtts.length) {
      const lost = group.echoes.length - group.rtts.length;
      acc.push({
        insightId: insightId("icmp-echo", idx++),
        type: "icmp_echo_pair",
        severity: "info",
        packetIds: [...group.echoes.map(p => p.packetId), ...group.replies.map(p => p.packetId)],
        description: `${src.srcIp} → ${dst.dstIp}: ICMP Echo 丢包率 ${((lost / group.echoes.length) * 100).toFixed(0)}%（${lost}/${group.echoes.length} 未收到 Reply）`,
        detail: {
          srcIp: src.srcIp,
          dstIp: dst.dstIp,
          totalEchoes: group.echoes.length,
          totalReplies: group.rtts.length,
          lostPackets: lost,
          lossRate: lost / group.echoes.length
        },
        scenario: "链路丢包、对端 ICMP 被过滤、中间设备限速"
      });
    }

    // RTT 统计（有回复就报告）
    if (group.rtts.length >= 1) {
      const avgRtt = group.rtts.reduce((a, b) => a + b, 0) / group.rtts.length;
      const maxRtt = Math.max(...group.rtts);
      const minRtt = Math.min(...group.rtts);
      const jitter = maxRtt - minRtt;

      acc.push({
        insightId: insightId("icmp-echo", idx++),
        type: "icmp_echo_pair",
        severity: "info",
          packetIds: [...group.echoes.map(p => p.packetId), ...group.replies.map(p => p.packetId)],
          description: `${src.srcIp} → ${dst.dstIp}: ICMP RTT 平均 ${avgRtt.toFixed(0)}ms，抖动 ${(jitter).toFixed(0)}ms（最小 ${minRtt.toFixed(0)}ms / 最大 ${maxRtt.toFixed(0)}ms）`,
          detail: {
            srcIp: src.srcIp,
            dstIp: dst.dstIp,
            avgRttMs: avgRtt,
            minRttMs: minRtt,
            maxRttMs: maxRtt,
            jitterMs: jitter,
            sampleCount: group.rtts.length
          },
          scenario: "ICMP Echo RTT 统计"
        });
    }
  }
}

// ── Analyzer: HTTP Status Chain ───────────────────────────────────────

function analyzeHttpStatusChain(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const httpPackets = packets.filter(p => p.httpRequestMethod || p.httpResponseCode != null);
  if (!httpPackets.length) return;

  // Group HTTP packets by connection (srcIp:srcPort ↔ dstIp:dstPort)
  const byConnection = new Map<string, PacketSummary[]>();
  for (const p of httpPackets) {
    const key = [p.srcIp, p.srcPort, p.dstIp, p.dstPort].join(":");
    const revKey = [p.dstIp, p.dstPort, p.srcIp, p.srcPort].join(":");
    const existing = byConnection.get(key) || byConnection.get(revKey);
    if (existing) {
      existing.push(p);
    } else {
      byConnection.set(key, [p]);
    }
  }

  // Check for redirect chains (3xx sequence)
  for (const [, connPackets] of byConnection) {
    const sorted = [...connPackets].sort((a, b) => a.timestamp - b.timestamp);
    const redirects = sorted.filter(p => p.httpResponseCode != null && p.httpResponseCode >= 300 && p.httpResponseCode < 400);
    if (redirects.length >= 2) {
      acc.push({
        insightId: insightId("http-status", idx++),
        type: "http_status_chain",
        severity: redirects.length >= 3 ? "warning" : "info",
        packetIds: redirects.map(p => p.packetId),
        description: `HTTP 重定向链：${redirects.map(p => `${p.httpResponseCode}`).join(" → ")}（${redirects.length} 次重定向）`,
        detail: {
          redirectCodes: redirects.map(p => p.httpResponseCode),
          redirectUris: redirects.map(p => p.httpRequestUri || p.summary).slice(0, 5),
          host: redirects[0]?.httpHost,
          redirectCount: redirects.length
        },
        scenario: redirects.length >= 5
          ? "可能存在重定向循环、URL 配置错误"
          : "重定向次数偏多，可能影响延迟"
      });
    }
  }

  // Aggregate error status codes
  const errors4xx = httpPackets.filter(p => p.httpResponseCode != null && p.httpResponseCode >= 400 && p.httpResponseCode < 500);
  const errors5xx = httpPackets.filter(p => p.httpResponseCode != null && p.httpResponseCode >= 500);

  if (errors5xx.length >= 2) {
    const byCode = new Map<number, PacketSummary[]>();
    for (const p of errors5xx) {
      const group = byCode.get(p.httpResponseCode!) || [];
      group.push(p);
      byCode.set(p.httpResponseCode!, group);
    }

    for (const [code, pkts] of byCode) {
      if (pkts.length < 2) continue;
      acc.push({
        insightId: insightId("http-status", idx++),
        type: "http_status_chain",
        severity: code >= 502 ? "critical" : "warning",
        packetIds: pkts.map(p => p.packetId).slice(0, 20),
        description: `HTTP ${code} 出现 ${pkts.length} 次（${pkts[0]?.httpHost || "unknown host"}）`,
        detail: {
          statusCode: code,
          count: pkts.length,
          host: pkts[0]?.httpHost,
          uris: pkts.map(p => p.httpRequestUri || "").filter(Boolean).slice(0, 5),
          firstTimestamp: pkts[0]?.timestamp,
          lastTimestamp: pkts[pkts.length - 1]?.timestamp
        },
        scenario: code === 502 ? "网关/代理无法连接后端服务" : code === 503 ? "服务过载或维护中" : code === 504 ? "网关等待后端超时" : "服务端内部错误"
      });
    }
  }

  if (errors4xx.length >= 3) {
    const byCode = new Map<number, PacketSummary[]>();
    for (const p of errors4xx) {
      const group = byCode.get(p.httpResponseCode!) || [];
      group.push(p);
      byCode.set(p.httpResponseCode!, group);
    }

    for (const [code, pkts] of byCode) {
      if (pkts.length < 3) continue;
      acc.push({
        insightId: insightId("http-status", idx++),
        type: "http_status_chain",
        severity: code === 401 || code === 403 ? "warning" : "info",
        packetIds: pkts.map(p => p.packetId).slice(0, 10),
        description: `HTTP ${code} 出现 ${pkts.length} 次（${pkts[0]?.httpHost || "unknown host"}）`,
        detail: {
          statusCode: code,
          count: pkts.length,
          host: pkts[0]?.httpHost,
          uris: pkts.map(p => p.httpRequestUri || "").filter(Boolean).slice(0, 5)
        },
        scenario: code === 401 ? "认证失败，可能是 token 过期或 cookie 失效" : code === 403 ? "权限被拒，可能是 WAF 拦截或权限配置错误" : code === 404 ? "请求路径不存在" : "客户端请求错误"
      });
    }
  }
}

// ── Analyzer: HTTP Header Anomaly ─────────────────────────────────────

function analyzeHttpHeaderAnomaly(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const httpRequests = packets.filter(p => p.httpRequestMethod);
  const httpResponses = packets.filter(p => p.httpResponseCode != null);

  if (!httpRequests.length && !httpResponses.length) return;

  // Check for requests without responses (paired via httpRequestIn)
  const unmatchedRequests = httpRequests.filter(req => {
    if (req.httpResponseIn != null) return false;
    // No matching response by time proximity
    const hasResponse = httpResponses.some(res =>
      res.srcIp === req.dstIp && res.dstIp === req.srcIp
      && res.srcPort === req.dstPort && res.dstPort === req.srcPort
      && res.timestamp >= req.timestamp && res.timestamp - req.timestamp < 60
    );
    return !hasResponse;
  });

  if (unmatchedRequests.length >= 2) {
    acc.push({
      insightId: insightId("http-header", idx++),
      type: "http_header_anomaly",
      severity: "warning",
      packetIds: unmatchedRequests.map(p => p.packetId),
      description: `${unmatchedRequests.length} 个 HTTP 请求未收到响应（${[...new Set(unmatchedRequests.map(p => p.httpHost).filter(Boolean))].join(", ")}）`,
      detail: {
        unmatchedCount: unmatchedRequests.length,
        methods: unmatchedRequests.map(p => p.httpRequestMethod),
        uris: unmatchedRequests.map(p => p.httpRequestUri || "").filter(Boolean).slice(0, 10),
        hosts: [...new Set(unmatchedRequests.map(p => p.httpHost).filter(Boolean))]
      },
      scenario: "服务端不响应（挂死或丢弃请求）、连接超时、中间设备拦截"
    });
  }

  // Detect mixed HTTP/HTTPS (requests to same host on both port 80 and 443)
  const byHost = new Map<string, PacketSummary[]>();
  for (const p of httpRequests) {
    if (!p.httpHost) continue;
    const group = byHost.get(p.httpHost) || [];
    group.push(p);
    byHost.set(p.httpHost, group);
  }

  for (const [host, reqs] of byHost) {
    const ports = new Set(reqs.map(p => p.dstPort));
    if (ports.size > 1 && ports.has(80) && (ports.has(443) || ports.has(8443))) {
      acc.push({
        insightId: insightId("http-header", idx++),
        type: "http_header_anomaly",
        severity: "info",
        packetIds: reqs.map(p => p.packetId).slice(0, 10),
        description: `Host ${host} 同时向端口 ${[...ports].join(", ")} 发送 HTTP 请求（可能存在 HTTP→HTTPS 重定向）`,
        detail: { host, ports: [...ports] },
        scenario: "HTTP→HTTPS 重定向、混合内容加载、配置不一致"
      });
    }
  }
}

// ── Analyzer: HTTP Timing ─────────────────────────────────────────────

function analyzeHttpTiming(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  const httpResponses = packets.filter(p => p.httpResponseCode != null && p.httpTime != null);
  if (!httpResponses.length) return;

  // 报告所有 HTTP 响应时间
  for (const resp of httpResponses) {
    acc.push({
      insightId: insightId("http-timing", idx++),
      type: "http_timing",
      severity: "info",
      packetIds: [resp.packetId],
      description: `HTTP ${resp.httpResponseCode} 响应耗时 ${(resp.httpTime! * 1000).toFixed(0)}ms（${resp.httpHost || "unknown"}${resp.httpRequestUri || ""}）`,
      detail: {
        statusCode: resp.httpResponseCode,
        responseTimeMs: resp.httpTime! * 1000,
        host: resp.httpHost,
        uri: resp.httpRequestUri
      },
      scenario: "HTTP 响应耗时"
    });
  }

  // Aggregate responses by host
  const slowByHost = new Map<string, PacketSummary[]>();
  for (const resp of httpResponses) {
    const host = resp.httpHost || "unknown";
    const group = slowByHost.get(host) || [];
    group.push(resp);
    slowByHost.set(host, group);
  }

  for (const [host, resps] of slowByHost) {
    if (resps.length < 2) continue;
    const avgTime = resps.reduce((sum, r) => sum + (r.httpTime ?? 0), 0) / resps.length;
    acc.push({
      insightId: insightId("http-timing", idx++),
      type: "http_timing",
      severity: "warning",
      packetIds: resps.map(p => p.packetId).slice(0, 10),
      description: `${host} 共 ${resps.length} 次慢响应，平均 ${(avgTime * 1000).toFixed(0)}ms`,
      detail: {
        host,
        slowResponseCount: resps.length,
        avgResponseTimeMs: avgTime * 1000,
        statusCodes: [...new Set(resps.map(r => r.httpResponseCode))]
      },
      scenario: "服务端性能瓶颈、后端依赖超时、数据库慢查询"
    });
  }
}

// ── Analyzer: Cross-Protocol Chain ────────────────────────────────────

function analyzeCrossProtocolChain(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  // Group by flow key (client IP ↔ server IP)
  type FlowKey = string;
  const flowKey = (src?: string, dst?: string) => [src, dst].sort().join(" <-> ");

  // Collect DNS, TCP, TLS, HTTP events per flow
  const flows = new Map<FlowKey, {
    dns: PacketSummary[];
    tcpSyns: PacketSummary[];
    tcpSynAcks: PacketSummary[];
    tlsClientHellos: PacketSummary[];
    tlsServerHellos: PacketSummary[];
    tlsAlerts: PacketSummary[];
    httpRequests: PacketSummary[];
    httpResponses: PacketSummary[];
  }>();

  const getOrCreate = (key: FlowKey) => {
    if (!flows.has(key)) flows.set(key, {
      dns: [], tcpSyns: [], tcpSynAcks: [],
      tlsClientHellos: [], tlsServerHellos: [], tlsAlerts: [],
      httpRequests: [], httpResponses: []
    });
    return flows.get(key)!;
  };

  for (const p of packets) {
    const fKey = flowKey(p.srcIp, p.dstIp);

    if (p.dnsQueryName) {
      getOrCreate(fKey).dns.push(p);
    }
    if (p.protocol.toLowerCase() === "tcp") {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      if (flags.includes("SYN") && !flags.includes("ACK")) getOrCreate(fKey).tcpSyns.push(p);
      if (flags.includes("SYN") && flags.includes("ACK")) getOrCreate(fKey).tcpSynAcks.push(p);
    }
    if (p.tlsHandshakeType === 1) getOrCreate(fKey).tlsClientHellos.push(p);
    if (p.tlsHandshakeType === 2) getOrCreate(fKey).tlsServerHellos.push(p);
    if (p.tlsAlertLevel != null) getOrCreate(fKey).tlsAlerts.push(p);
    if (p.httpRequestMethod) getOrCreate(fKey).httpRequests.push(p);
    if (p.httpResponseCode != null) getOrCreate(fKey).httpResponses.push(p);
  }

  for (const [fKey, flow] of flows) {
    // Build waterfall: DNS → TCP SYN → SYN/ACK → TLS ClientHello → ServerHello → HTTP Request → Response
    const steps: Array<{ stage: string; timestamp: number; packetId: string; summary: string }> = [];

    // DNS
    const firstDnsQuery = flow.dns.find(p => !p.dnsIsResponse);
    const firstDnsReply = flow.dns.find(p => p.dnsIsResponse);
    if (firstDnsQuery) steps.push({ stage: "DNS Query", timestamp: firstDnsQuery.timestamp, packetId: firstDnsQuery.packetId, summary: firstDnsQuery.dnsQueryName || "" });
    if (firstDnsReply) steps.push({ stage: "DNS Reply", timestamp: firstDnsReply.timestamp, packetId: firstDnsReply.packetId, summary: firstDnsReply.dnsResponseAddress || "" });

    // TCP
    const firstSyn = flow.tcpSyns[0];
    const firstSynAck = flow.tcpSynAcks[0];
    if (firstSyn) steps.push({ stage: "TCP SYN", timestamp: firstSyn.timestamp, packetId: firstSyn.packetId, summary: fmtEndpoint(firstSyn.srcIp, firstSyn.srcPort) + " → " + fmtEndpoint(firstSyn.dstIp, firstSyn.dstPort) });
    if (firstSynAck) steps.push({ stage: "TCP SYN/ACK", timestamp: firstSynAck.timestamp, packetId: firstSynAck.packetId, summary: "" });

    // TLS
    const firstClientHello = flow.tlsClientHellos[0];
    const firstServerHello = flow.tlsServerHellos[0];
    const firstTlsAlert = flow.tlsAlerts[0];
    if (firstClientHello) steps.push({ stage: "TLS ClientHello", timestamp: firstClientHello.timestamp, packetId: firstClientHello.packetId, summary: firstClientHello.tlsSni || "" });
    if (firstServerHello) steps.push({ stage: "TLS ServerHello", timestamp: firstServerHello.timestamp, packetId: firstServerHello.packetId, summary: "" });

    // TLS alert means handshake failed
    if (firstTlsAlert && firstClientHello && (!firstServerHello || firstTlsAlert.timestamp < firstServerHello.timestamp)) {
      steps.push({ stage: "TLS Alert", timestamp: firstTlsAlert.timestamp, packetId: firstTlsAlert.packetId, summary: `level=${firstTlsAlert.tlsAlertLevel} desc=${firstTlsAlert.tlsAlertDescription}` });
    }

    // HTTP
    const firstRequest = flow.httpRequests[0];
    const firstResponse = flow.httpResponses[0];
    if (firstRequest) steps.push({ stage: "HTTP Request", timestamp: firstRequest.timestamp, packetId: firstRequest.packetId, summary: `${firstRequest.httpRequestMethod} ${firstRequest.httpRequestUri || ""}` });
    if (firstResponse) steps.push({ stage: "HTTP Response", timestamp: firstResponse.timestamp, packetId: firstResponse.packetId, summary: `${firstResponse.httpResponseCode}` });

    if (steps.length < 3) continue;

    // Sort by timestamp
    steps.sort((a, b) => a.timestamp - b.timestamp);

    // Calculate deltas
    const totalTime = steps[steps.length - 1].timestamp - steps[0].timestamp;
    const deltas: Array<{ stage: string; deltaMs: number }> = [];
    for (let i = 1; i < steps.length; i++) {
      deltas.push({ stage: `${steps[i - 1].stage} → ${steps[i].stage}`, deltaMs: (steps[i].timestamp - steps[i - 1].timestamp) * 1000 });
    }

    // Find the slowest hop
    const slowestHop = deltas.reduce((max, d) => d.deltaMs > max.deltaMs ? d : max, deltas[0]);

    // 报告完整链路时序
    {
      const waterfall = deltas.map(d => `${d.stage}: ${d.deltaMs.toFixed(0)}ms`).join(", ");

      acc.push({
        insightId: insightId("cross-proto", idx++),
        type: "cross_protocol_chain",
        severity: "info",
        packetIds: steps.map(s => s.packetId),
        description: `${fKey} 完整请求链路耗时 ${(totalTime * 1000).toFixed(0)}ms，最慢阶段: ${slowestHop.stage} (${slowestHop.deltaMs.toFixed(0)}ms)`,
        detail: {
          flow: fKey,
          totalTimeMs: totalTime * 1000,
          slowestStage: slowestHop.stage,
          slowestMs: slowestHop.deltaMs,
          waterfall,
          stages: steps.map((s, i) => ({
            stage: s.stage,
            timestamp: s.timestamp,
            deltaMs: i > 0 ? (s.timestamp - steps[i - 1].timestamp) * 1000 : 0,
            summary: s.summary
          }))
        },
        scenario: slowestHop.stage.includes("TLS")
          ? "TLS 握手慢（证书链长、OCSP 检查、cipher 协商）"
          : slowestHop.stage.includes("HTTP Response")
            ? "服务端应用处理慢"
            : slowestHop.stage.includes("DNS")
              ? "DNS 解析慢"
              : "网络延迟或中间设备处理慢"
      });
    }

    // Report if chain is broken (stage missing where expected)
    if (firstSyn && !firstSynAck && firstRequest) {
      // HTTP request exists but TCP handshake incomplete in capture — possible interception
      acc.push({
        insightId: insightId("cross-proto", idx++),
        type: "cross_protocol_chain",
        severity: "info",
        packetIds: [firstSyn.packetId, firstRequest.packetId],
        description: `${fKey}: 存在 TCP SYN 和 HTTP 请求但无 SYN/ACK（抓包可能未覆盖双向）`,
        detail: { flow: fKey, hasSyn: true, hasSynAck: false, hasHttpRequest: true },
        scenario: "抓包只捕获了单方向流量"
      });
    }

    if (firstClientHello && !firstServerHello && !firstTlsAlert && firstSynAck) {
      // TLS ClientHello sent, TCP handshake completed, but no ServerHello and no Alert
      acc.push({
        insightId: insightId("cross-proto", idx++),
        type: "cross_protocol_chain",
        severity: "warning",
        packetIds: [firstClientHello.packetId, firstSynAck.packetId],
        description: `${fKey}: TCP 握手完成但 TLS ClientHello 无回应（ServerHello 缺失）`,
        detail: {
          flow: fKey,
          sni: firstClientHello.tlsSni,
          hasSynAck: true,
          hasServerHello: false,
          hasAlert: false
        },
        scenario: "服务端不支持该 TLS 版本、SNI 被拦截、防火墙阻断 TLS 握手"
      });
    }
  }
}

// ── Analyzer: TLS Handshake Issues ────────────────────────────────────

function analyzeTlsHandshake(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  const alerts = packets.filter(p => p.tlsAlertLevel != null);
  for (const alert of alerts) {
    const level = alert.tlsAlertLevel === 2 ? "fatal" : alert.tlsAlertLevel === 1 ? "warning" : "unknown";
    const descMap: Record<number, string> = {
      10: "unexpected_message", 40: "handshake_failure", 42: "bad_certificate",
      43: "unsupported_certificate", 44: "certificate_revoked", 45: "certificate_expired",
      46: "certificate_unknown", 48: "unknown_ca", 49: "access_denied",
      50: "decode_error", 51: "decrypt_error", 70: "protocol_version",
      71: "insufficient_security", 80: "internal_error", 90: "user_canceled",
      100: "no_renegotiation", 120: "no_application_protocol"
    };

    acc.push({
      insightId: insightId("tls-hs", idx++),
      type: "tls_handshake",
      severity: level === "fatal" ? "critical" : "warning",
      packetIds: [alert.packetId],
      description: `TLS Alert: ${level} (${descMap[alert.tlsAlertDescription ?? 0] || `description=${alert.tlsAlertDescription}`}) ${alert.srcIp} → ${alert.dstIp}`,
      detail: {
        srcIp: alert.srcIp,
        dstIp: alert.dstIp,
        alertLevel: level,
        alertDescription: alert.tlsAlertDescription,
        alertDescriptionName: descMap[alert.tlsAlertDescription ?? 0],
        sni: alert.tlsSni,
        version: alert.tlsRecordVersion
      },
      scenario: alert.tlsAlertDescription === 48
        ? "CA 证书不被信任，客户端不认可服务端证书签发机构"
        : alert.tlsAlertDescription === 40
          ? "TLS 握手失败，可能是 cipher 不兼容或协议版本不匹配"
          : alert.tlsAlertDescription === 45
            ? "服务端证书已过期"
            : alert.tlsAlertDescription === 49
              ? "客户端证书认证被拒绝"
              : "TLS 安全告警"
    });
  }
}

// ── Analyzer: DNS Anomaly ─────────────────────────────────────────────

function analyzeDnsAnomaly(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  const dnsQueries = packets.filter(p => p.dnsQueryName && !p.dnsIsResponse);
  const dnsReplies = packets.filter(p => p.dnsQueryName && p.dnsIsResponse);

  for (const query of dnsQueries) {
    // Find matching reply
    const reply = dnsReplies.find(r =>
      r.dnsQueryName === query.dnsQueryName
      && r.srcIp === query.dstIp
      && r.timestamp >= query.timestamp
      && r.timestamp - query.timestamp < 30
    );

    // No reply
    if (!reply) {
      acc.push({
        insightId: insightId("dns", idx++),
        type: "dns_anomaly",
        severity: "warning",
        packetIds: [query.packetId],
        description: `DNS 查询 ${query.dnsQueryName} 无响应（${query.srcIp} → ${query.dstIp}）`,
        detail: {
          queryName: query.dnsQueryName,
          srcIp: query.srcIp,
          dnsServer: query.dstIp
        },
        scenario: "DNS 服务器不可达、DNS 请求被过滤、网络中断"
      });
      continue;
    }

    // NXDOMAIN
    if (reply.dnsRcode === 3) {
      acc.push({
        insightId: insightId("dns", idx++),
        type: "dns_anomaly",
        severity: "info",
        packetIds: [query.packetId, reply.packetId],
        description: `DNS NXDOMAIN: ${query.dnsQueryName} 域名不存在`,
        detail: {
          queryName: query.dnsQueryName,
          rcode: reply.dnsRcode,
          responseAddress: reply.dnsResponseAddress
        },
        scenario: "域名拼写错误、域名已注销、DNS 配置错误"
      });
    }

    // DNS response with error code
    if (reply.dnsRcode != null && reply.dnsRcode !== 0 && reply.dnsRcode !== 3) {
      const rcodeMap: Record<number, string> = { 1: "FORMERR", 2: "SERVFAIL", 4: "NOTIMP", 5: "REFUSED" };
      acc.push({
        insightId: insightId("dns", idx++),
        type: "dns_anomaly",
        severity: reply.dnsRcode === 2 ? "warning" : "info",
        packetIds: [query.packetId, reply.packetId],
        description: `DNS ${rcodeMap[reply.dnsRcode] || `RCODE=${reply.dnsRcode}`}: ${query.dnsQueryName}`,
        detail: {
          queryName: query.dnsQueryName,
          rcode: reply.dnsRcode,
          rcodeName: rcodeMap[reply.dnsRcode]
        },
        scenario: reply.dnsRcode === 2
          ? "DNS 服务器返回 SERVFAIL，上游 DNS 问题或 DNSSEC 验证失败"
          : reply.dnsRcode === 5
            ? "DNS 查询被拒绝，可能是 ACL 限制"
            : "DNS 解析异常"
      });
    }

    // DNS 响应耗时
    const dnsTime = reply.timestamp - query.timestamp;
    acc.push({
      insightId: insightId("dns", idx++),
      type: "dns_anomaly",
      severity: "info",
      packetIds: [query.packetId, reply.packetId],
      description: `DNS 解析 ${query.dnsQueryName} 耗时 ${(dnsTime * 1000).toFixed(0)}ms`,
      detail: {
        queryName: query.dnsQueryName,
        responseTimeMs: dnsTime * 1000
      },
      scenario: "DNS 查询响应耗时"
    });
  }
}

// ── Main Engine ───────────────────────────────────────────────────────

// ── Analyzer: TCP Window Trend ────────────────────────────────────────

function analyzeTcpWindowTrend(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);
    if (sorted.length < 4) continue;

    // Separate packets by direction, track window size
    const fwdKey = tcpFlowKey(conn as unknown as PacketSummary);
    type WindowPoint = { timestamp: number; window: number; packetId: string };
    const byDir = new Map<string, WindowPoint[]>();
    for (const p of sorted) {
      if (p.tcpWindowSize == null) continue;
      const key = tcpFlowKey(p);
      const arr = byDir.get(key) || [];
      arr.push({ timestamp: p.timestamp, window: p.tcpWindowSize, packetId: p.packetId });
      byDir.set(key, arr);
    }

    for (const [dirKey, points] of byDir) {
      if (points.length < 3) continue;
      const direction = dirKey === fwdKey
        ? `${conn.srcIp}:${conn.srcPort} → ${conn.dstIp}:${conn.dstPort}`
        : `${conn.dstIp}:${conn.dstPort} → ${conn.srcIp}:${conn.srcPort}`;

      // Detect consecutive window shrinking
      let shrinkSteps = 0;
      let maxShrink = 0;
      let startIdx = 0;
      let bestStart = 0;
      let bestLen = 0;
      for (let i = 1; i < points.length; i++) {
        if (points[i].window < points[i - 1].window && points[i - 1].window > 0) {
          if (shrinkSteps === 0) startIdx = i - 1;
          shrinkSteps++;
          maxShrink = Math.max(maxShrink, points[i - 1].window - points[i].window);
          if (shrinkSteps > bestLen) { bestLen = shrinkSteps; bestStart = startIdx; }
        } else {
          shrinkSteps = 0;
        }
      }

      if (bestLen >= 3) {
        const first = points[bestStart];
        const last = points[Math.min(bestStart + bestLen, points.length - 1)];
        acc.push({
          insightId: insightId("window-trend", idx++),
          type: "tcp_window_trend",
          severity: last.window === 0 ? "critical" : "warning",
          packetIds: points.slice(bestStart, bestStart + bestLen + 1).map(w => w.packetId),
          description: `${direction}: TCP 接收窗口从 ${first.window} 持续缩小至 ${last.window}（${bestLen} 步缩减）`,
          detail: { direction, initialWindow: first.window, finalWindow: last.window, shrinkSteps: bestLen, maxShrinkPerStep: maxShrink },
          scenario: "接收端应用处理速度跟不上数据到达速度，缓冲区逐渐填满。检查接收端应用日志和内存使用。"
        });
      }

      // Zero Window Probe detection
      const zeroIdx = points.findIndex(p => p.window === 0);
      if (zeroIdx >= 0 && zeroIdx < points.length - 1) {
        const zeroTime = points[zeroIdx].timestamp;
        // Find a 1-byte probe after zero window
        const probe = sorted.find(p =>
          p.timestamp > zeroTime && p.tcpPayloadLength === 1
          && tcpFlowKey(p) !== dirKey // probe comes from the other side
        );
        if (probe) {
          const reopened = points.find(p => p.timestamp > probe.timestamp && p.window > 0);
          acc.push({
            insightId: insightId("window-trend", idx++),
            type: "tcp_window_trend",
            severity: reopened ? "info" : "warning",
            packetIds: [points[zeroIdx].packetId, probe.packetId, reopened?.packetId].filter(Boolean) as string[],
            description: `${direction}: Zero Window 后发送探测包${reopened ? "，窗口已恢复至 " + reopened.window : "，窗口未恢复"}`,
            detail: { direction, zeroWindowAt: zeroTime, probeAt: probe.timestamp, windowReopened: !!reopened, reopenedWindow: reopened?.window },
            scenario: reopened ? "短暂 Zero Window，接收端处理完后恢复" : "接收端持续卡住，应用可能挂死"
          });
        }
      }
    }
  }
}

// ── Analyzer: RST Direction ───────────────────────────────────────────

function analyzeRstDirection(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);
    const rstPackets = sorted.filter(p => p.tcpFlags.map(f => f.toUpperCase()).includes("RST"));
    if (!rstPackets.length) continue;

    for (const rst of rstPackets) {
      const isFromClient = rst.srcIp === conn.srcIp && rst.srcPort === conn.srcPort;
      const isFromServer = rst.srcIp === conn.dstIp && rst.srcPort === conn.dstPort;
      // If neither endpoint, it could be from a middle device
      const isFromMiddle = !isFromClient && !isFromServer;

      // Only report if there's something notable about the RST source
      // (middle device, or RST with data, or RST storm)
      const hasData = (rst.tcpPayloadLength ?? 0) > 0;

      if (!isFromMiddle && !hasData) continue; // Skip normal endpoint RSTs (covered by existing adapters)

      if (isFromMiddle) {
        acc.push({
          insightId: insightId("rst-dir", idx++),
          type: "tcp_rst_direction",
          severity: "critical",
          packetIds: [rst.packetId],
          description: `RST 来自非端点 IP ${rst.srcIp}:${rst.srcPort}（连接 ${conn.srcIp}:${conn.srcPort} ↔ ${conn.dstIp}:${conn.dstPort}），疑似中间设备发送`,
          detail: {
            rstFromIp: rst.srcIp, rstFromPort: rst.srcPort,
            clientIp: conn.srcIp, clientPort: conn.srcPort,
            serverIp: conn.dstIp, serverPort: conn.dstPort,
            rstIsFromMiddleDevice: true,
            frameNumber: rst.frameNumber, timestamp: rst.timestamp
          },
          scenario: "中间设备（防火墙/LB/IDS）注入了 RST 包强制断开连接。结合拓扑信息确认是哪个设备。"
        });
      }

      if (hasData) {
        acc.push({
          insightId: insightId("rst-dir", idx++),
          type: "tcp_rst_direction",
          severity: "info",
          packetIds: [rst.packetId],
          description: `RST 包携带 ${rst.tcpPayloadLength} 字节数据（${rst.srcIp}:${rst.srcPort} → ${rst.dstIp}:${rst.dstPort}）`,
          detail: { rstFromIp: rst.srcIp, payloadLength: rst.tcpPayloadLength, frameNumber: rst.frameNumber },
          scenario: "某些实现会在 RST 中携带数据，或者这是被篡改的 RST"
        });
      }
    }

    // RST storm: 3+ RSTs in rapid succession
    if (rstPackets.length >= 3) {
      const times = rstPackets.map(p => p.timestamp).sort();
      const span = times[times.length - 1] - times[0];
      if (span < 1) { // All RSTs within 1 second
        acc.push({
          insightId: insightId("rst-dir", idx++),
          type: "tcp_rst_direction",
          severity: "warning",
          packetIds: rstPackets.map(p => p.packetId),
          description: `RST 风暴：${rstPackets.length} 个 RST 在 ${span.toFixed(3)}s 内（${conn.srcIp}:${conn.srcPort} ↔ ${conn.dstIp}:${conn.dstPort}）`,
          detail: { rstCount: rstPackets.length, spanSec: span, rstSources: [...new Set(rstPackets.map(p => p.srcIp))] },
          scenario: "连接被反复 RST，可能是攻击、中间设备策略触发、或应用层反复重连失败"
        });
      }
    }
  }
}

// ── Analyzer: Handshake Retry ─────────────────────────────────────────

function analyzeHandshakeRetry(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);

    // SYN retransmissions: multiple SYN with same src/dst/seq
    const syns = sorted.filter(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && !flags.includes("ACK");
    });

    if (syns.length >= 2) {
      // Group by seq number
      const bySeq = new Map<number, PacketSummary[]>();
      for (const s of syns) {
        if (s.tcpSeq == null) continue;
        const arr = bySeq.get(s.tcpSeq) || [];
        arr.push(s);
        bySeq.set(s.tcpSeq, arr);
      }
      for (const [, synGroup] of bySeq) {
        if (synGroup.length < 2) continue;
        const intervals = synGroup.slice(1).map((s, i) => s.timestamp - synGroup[i].timestamp);
        acc.push({
          insightId: insightId("hs-retry", idx++),
          type: "tcp_handshake_retry",
          severity: synGroup.length >= 4 ? "warning" : "info",
          packetIds: synGroup.map(p => p.packetId),
          description: `SYN 重传 ${synGroup.length - 1} 次（${conn.srcIp}:${conn.srcPort} → ${conn.dstIp}:${conn.dstPort}，间隔 ${intervals.map(i => (i * 1000).toFixed(0) + "ms").join(", ")}）`,
          detail: {
            direction: "client→server", retryCount: synGroup.length - 1,
            intervalsMs: intervals.map(i => i * 1000),
            exponentialBackoff: checkExponentialBackoff(intervals),
            seq: synGroup[0].tcpSeq
          },
          scenario: "服务端未响应 SYN（SYN backlog 满、防火墙丢弃、路由问题）。指数退避说明是正常 TCP 栈行为。"
        });
      }
    }

    // SYN/ACK retransmissions
    const synacks = sorted.filter(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && flags.includes("ACK");
    });

    if (synacks.length >= 2) {
      const intervals = synacks.slice(1).map((s, i) => s.timestamp - synacks[i].timestamp);
      acc.push({
        insightId: insightId("hs-retry", idx++),
        type: "tcp_handshake_retry",
        severity: "info",
        packetIds: synacks.map(p => p.packetId),
        description: `SYN/ACK 重传 ${synacks.length - 1} 次（${conn.dstIp}:${conn.dstPort} → ${conn.srcIp}:${conn.srcPort}），客户端未完成握手`,
        detail: { direction: "server→client", retryCount: synacks.length - 1, intervalsMs: intervals.map(i => i * 1000) },
        scenario: "客户端收到 SYN/ACK 后未回复 ACK，可能是客户端掉线、SYN flood 攻击、或网络单向中断"
      });
    }

    // Simultaneous open: both sides send SYN (rare)
    if (syns.length >= 2) {
      const synDirs = new Set(syns.map(s => tcpFlowKey(s)));
      if (synDirs.size >= 2) {
        acc.push({
          insightId: insightId("hs-retry", idx++),
          type: "tcp_handshake_retry",
          severity: "info",
          packetIds: syns.map(p => p.packetId),
          description: `TCP 同时打开：${conn.srcIp}:${conn.srcPort} 和 ${conn.dstIp}:${conn.dstPort} 同时发起 SYN`,
          detail: { simultaneousOpen: true },
          scenario: "双方同时发起连接（罕见），某些 P2P 协议会出现此行为"
        });
      }
    }

    // Simultaneous close: both sides send FIN
    const fins = sorted.filter(p => p.tcpFlags.map(f => f.toUpperCase()).includes("FIN"));
    if (fins.length >= 2) {
      const finDirs = new Set(fins.map(f => tcpFlowKey(f)));
      if (finDirs.size >= 2) {
        const finTimes = fins.map(f => f.timestamp).sort();
        if (finTimes[1] - finTimes[0] < 0.1) { // Within 100ms
          acc.push({
            insightId: insightId("hs-retry", idx++),
            type: "tcp_handshake_retry",
            severity: "info",
            packetIds: fins.map(p => p.packetId),
            description: `TCP 同时关闭：双方几乎同时发送 FIN`,
            detail: { simultaneousClose: true, finGapMs: (finTimes[1] - finTimes[0]) * 1000 },
            scenario: "双方同时关闭连接，属于正常 TCP 行为"
          });
        }
      }
    }
  }
}

// ── Analyzer: Delayed ACK ─────────────────────────────────────────────

function analyzeDelayedAck(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;
  const DELAYED_ACK_MIN_MS = 40;
  const DELAYED_ACK_MAX_MS = 500;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);
    if (sorted.length < 4) continue;

    // For each data packet, find the corresponding ACK
    const delayedAckCount: Array<{ dataPacket: PacketSummary; ackPacket: PacketSummary; delayMs: number }> = [];

    for (let i = 0; i < sorted.length; i++) {
      const p = sorted[i];
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      if ((p.tcpPayloadLength ?? 0) === 0) continue; // Skip non-data packets
      if (flags.includes("SYN") || flags.includes("FIN") || flags.includes("RST")) continue;

      // Find ACK from the receiver (opposite direction)
      const receiverKey = tcpFlowKeyReverse(p);
      for (let j = i + 1; j < sorted.length; j++) {
        const candidate = sorted[j];
        if (candidate.timestamp - p.timestamp > 1) break; // Don't look beyond 1s
        if (tcpFlowKey(candidate) !== receiverKey) continue;
        if (!candidate.tcpFlags.map(f => f.toUpperCase()).includes("ACK")) continue;

        const delayMs = (candidate.timestamp - p.timestamp) * 1000;
        if (delayMs >= DELAYED_ACK_MIN_MS && delayMs <= DELAYED_ACK_MAX_MS) {
          delayedAckCount.push({ dataPacket: p, ackPacket: candidate, delayMs });
        }
        break;
      }
    }

    if (delayedAckCount.length >= 3) {
      const avgDelay = delayedAckCount.reduce((s, d) => s + d.delayMs, 0) / delayedAckCount.length;
      const count = delayedAckCount.length;
      acc.push({
        insightId: insightId("delayed-ack", idx++),
        type: "tcp_delayed_ack",
        severity: "info",
        packetIds: delayedAckCount.slice(0, 10).flatMap(d => [d.dataPacket.packetId, d.ackPacket.packetId]),
        description: `${fmtEndpoint(conn.srcIp, conn.srcPort)} ↔ ${fmtEndpoint(conn.dstIp, conn.dstPort)}: ${count} 次 Delayed ACK（平均延迟 ${avgDelay.toFixed(0)}ms）`,
        detail: {
          count, avgDelayMs: avgDelay,
          minDelayMs: Math.min(...delayedAckCount.map(d => d.delayMs)),
          maxDelayMs: Math.max(...delayedAckCount.map(d => d.delayMs))
        },
        scenario: "Delayed ACK 可能导致发送端在等待 ACK 超时后触发 Nagle 或重传，尤其在请求-响应模式中会放大延迟"
      });
    }
  }
}

// ── Analyzer: Connection Flood / SYN Flood ─────────────────────────────

function analyzeConnectionFlood(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  const syns = packets.filter(p => {
    const flags = p.tcpFlags.map(f => f.toUpperCase());
    return p.protocol.toLowerCase() === "tcp" && flags.includes("SYN") && !flags.includes("ACK");
  });

  if (!syns.length) return;

  // Group SYNs by time windows of 1 second
  const timeBins = new Map<number, PacketSummary[]>();
  for (const s of syns) {
    const bin = Math.floor(s.timestamp);
    const arr = timeBins.get(bin) || [];
    arr.push(s);
    timeBins.set(bin, arr);
  }

  for (const [binStart, binSyns] of timeBins) {
    if (binSyns.length < 2) continue;

    // Count unique destination IP:port combinations
    const targets = new Set(binSyns.map(s => `${s.dstIp}:${s.dstPort}`));

    acc.push({
      insightId: insightId("conn-flood", idx++),
      type: "tcp_connection_flood",
      severity: binSyns.length >= 200 ? "critical" : "warning",
      packetIds: binSyns.map(p => p.packetId).slice(0, 20),
      description: `SYN 突发：${binSyns.length} 个 SYN/s 在 ${new Date(binStart * 1000).toISOString()}（目标 ${targets.size} 个）`,
      detail: {
        synsPerSecond: binSyns.length,
        timeWindowStart: binStart,
        targetCount: targets.size,
        targets: [...targets].slice(0, 10),
        sourceIps: [...new Set(binSyns.map(s => s.srcIp))].slice(0, 10)
      },
      scenario: binSyns.length >= 200
        ? "疑似 SYN Flood 攻击或连接风暴"
        : "大量并发连接请求，可能是正常流量高峰或扫描行为"
    });
  }

  // Half-open connections: SYN without completion
  const connections = extractTcpConnections(packets);
  const halfOpenConns: TcpConnection[] = [];
  for (const conn of connections.values()) {
    if (conn.hasSyn && !conn.hasSynAck) halfOpenConns.push(conn);
  }
  if (halfOpenConns.length >= 10) {
    acc.push({
      insightId: insightId("conn-flood", idx++),
      type: "tcp_connection_flood",
      severity: "warning",
      packetIds: halfOpenConns.flatMap(c => c.packets.map(p => p.packetId)).slice(0, 30),
      description: `${halfOpenConns.length} 个半开连接（SYN 已发送，无 SYN/ACK），可能消耗服务端 SYN backlog`,
      detail: {
        halfOpenCount: halfOpenConns.length,
        targets: [...new Set(halfOpenConns.map(c => `${c.dstIp}:${c.dstPort}`))].slice(0, 10)
      },
      scenario: "大量半开连接可能是 SYN Flood 攻击，也可能说明服务端 SYN backlog 满了或网络不通"
    });
  }
}

// ── Analyzer: Segment Anomaly ──────────────────────────────────────────

function analyzeSegmentAnomaly(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;
  const SMALL_SEGMENT_THRESHOLD = 8;

  for (const conn of connections.values()) {
    const dataPackets = conn.packets.filter(p => {
      const len = p.tcpPayloadLength ?? 0;
      return len > 0 && !p.tcpFlags.map(f => f.toUpperCase()).includes("SYN");
    });
    if (!dataPackets.length) continue;

    const smallSegments = dataPackets.filter(p => (p.tcpPayloadLength ?? 0) > 0 && (p.tcpPayloadLength ?? 0) <= SMALL_SEGMENT_THRESHOLD);

    // 小段统计
    if (smallSegments.length > 0) {
      acc.push({
        insightId: insightId("segment", idx++),
        type: "tcp_segment_anomaly",
        severity: "info",
        packetIds: smallSegments.map(p => p.packetId).slice(0, 20),
        description: `${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)}: ${smallSegments.length}/${dataPackets.length} 个小包（≤${SMALL_SEGMENT_THRESHOLD}B，占 ${(smallSegments.length / dataPackets.length * 100).toFixed(0)}%）`,
        detail: {
          smallSegmentCount: smallSegments.length,
          totalDataPackets: dataPackets.length,
          ratio: smallSegments.length / dataPackets.length,
          sizeDistribution: smallSegments.map(p => p.tcpPayloadLength).filter(Boolean)
        },
        scenario: "Nagle 算法未启用或应用层频繁发送小数据块（如键盘输入、心跳、日志）。大量小包降低网络效率。"
      });
    }

    // Unusually large segments (potential MTU issue if fragmenting)
    const mss = 1460; // Standard Ethernet MSS
    const oversized = dataPackets.filter(p => (p.tcpPayloadLength ?? 0) > mss);
    if (oversized.length >= 3) {
      acc.push({
        insightId: insightId("segment", idx++),
        type: "tcp_segment_anomaly",
        severity: "info",
        packetIds: oversized.map(p => p.packetId),
        description: `${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)}: ${oversized.length} 个超大段（>${mss}B）`,
        detail: { oversizedCount: oversized.length, maxSize: Math.max(...oversized.map(p => p.tcpPayloadLength ?? 0)) },
        scenario: "TCP offload 或 TSO 导致的超大段，通常在抓包时被 offload 分割，不影响实际传输"
      });
    }
  }
}

// ── Analyzer: Keep-Alive ───────────────────────────────────────────────

function analyzeKeepalive(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);
    if (sorted.length < 4) continue;

    // Keep-alive probe: ACK-only packet with seq = last_ack - 1, no payload
    const probes: PacketSummary[] = [];
    for (let i = 1; i < sorted.length; i++) {
      const p = sorted[i];
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      if (p.tcpPayloadLength !== 0 && p.tcpPayloadLength != null) continue;
      if (flags.includes("SYN") || flags.includes("FIN") || flags.includes("RST")) continue;
      if (p.tcpSeq == null) continue;

      // Check if seq is one less than expected (keep-alive probe)
      // Keep-alive probe has seq = last ack - 1
      const prev = sorted[i - 1];
      if (tcpFlowKey(p) === tcpFlowKey(prev) || tcpFlowKey(p) === tcpFlowKeyReverse(prev)) {
        if (prev.tcpAck != null && p.tcpSeq === prev.tcpAck - 1) {
          probes.push(p);
        }
      }
    }

    if (probes.length >= 2) {
      const intervals = probes.slice(1).map((p, i) => p.timestamp - probes[i].timestamp);
      const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;

      acc.push({
        insightId: insightId("keepalive", idx++),
        type: "tcp_keepalive",
        severity: "info",
        packetIds: probes.map(p => p.packetId).slice(0, 10),
        description: `${fmtEndpoint(conn.srcIp, conn.srcPort)} ↔ ${fmtEndpoint(conn.dstIp, conn.dstPort)}: ${probes.length} 次 Keep-Alive 探测（平均间隔 ${(avgInterval).toFixed(1)}s）`,
        detail: {
          probeCount: probes.length,
          avgIntervalSec: avgInterval,
          keepaliveDirection: probes[0]?.srcIp,
          intervalsSec: intervals
        },
        scenario: "连接空闲期间发送 Keep-Alive 探测以维持连接。频繁探测可能触发中间设备超时。"
      });

      // Keep-alive failure: probe followed by RST
      const failedProbes = probes.filter(probe => {
        const rstAfter = sorted.find(p =>
          p.tcpFlags.map(f => f.toUpperCase()).includes("RST")
          && p.timestamp > probe.timestamp && p.timestamp - probe.timestamp < 5
        );
        return !!rstAfter;
      });
      if (failedProbes.length >= 1) {
        acc.push({
          insightId: insightId("keepalive", idx++),
          type: "tcp_keepalive",
          severity: "warning",
          packetIds: failedProbes.flatMap(p => {
            const rst = sorted.find(r =>
              r.tcpFlags.map(f => f.toUpperCase()).includes("RST")
              && r.timestamp > p.timestamp && r.timestamp - p.timestamp < 5
            );
            return rst ? [p.packetId, rst.packetId] : [p.packetId];
          }),
          description: `${failedProbes.length} 次 Keep-Alive 探测后收到 RST（连接被中间设备超时断开）`,
          detail: { failedProbeCount: failedProbes.length, rstFromIp: sorted.find(p => p.tcpFlags.map(f => f.toUpperCase()).includes("RST") && failedProbes.some(fp => p.timestamp > fp.timestamp))?.srcIp },
          scenario: "中间设备（LB/防火墙）的 idle timeout 短于 Keep-Alive 间隔，导致连接被断开。建议减小 Keep-Alive 间隔或增大中间设备超时配置。"
        });
      }
    }
  }
}

// ── Analyzer: Throughput ───────────────────────────────────────────────

function analyzeThroughput(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);
    const duration = conn.endTime - conn.startTime;
    if (duration <= 0 || sorted.length < 2) continue;

    // Separate by direction
    const fwdKey = tcpFlowKey(conn as unknown as PacketSummary);
    const fwdPayload = sorted.filter(p => tcpFlowKey(p) === fwdKey).reduce((sum, p) => sum + (p.tcpPayloadLength ?? 0), 0);
    const revPayload = sorted.filter(p => tcpFlowKey(p) !== fwdKey).reduce((sum, p) => sum + (p.tcpPayloadLength ?? 0), 0);
    const totalPayload = fwdPayload + revPayload;
    const retransBytes = sorted.filter(p => p.tcpAnalysis?.retransmission).reduce((sum, p) => sum + (p.tcpPayloadLength ?? 0), 0);
    const goodput = totalPayload - retransBytes;

    const throughputBps = (totalPayload * 8) / duration;
    const goodputBps = (goodput * 8) / duration;
    const retransOverhead = totalPayload > 0 ? retransBytes / totalPayload : 0;

    // Estimate RTT from SYN/SYNACK for BDP
    const syn = sorted.find(p => p.tcpFlags.map(f => f.toUpperCase()).includes("SYN") && !p.tcpFlags.map(f => f.toUpperCase()).includes("ACK"));
    const synack = sorted.find(p => p.tcpFlags.map(f => f.toUpperCase()).includes("SYN") && p.tcpFlags.map(f => f.toUpperCase()).includes("ACK"));
    const rttSec = syn && synack ? synack.timestamp - syn.timestamp : undefined;

    // Report high retransmission overhead
    if (retransOverhead > 0.1) {
      acc.push({
        insightId: insightId("throughput", idx++),
        type: "tcp_throughput",
        severity: retransOverhead > 0.3 ? "warning" : "info",
        packetIds: sorted.filter(p => p.tcpAnalysis?.retransmission).map(p => p.packetId).slice(0, 10),
        description: `${fmtEndpoint(conn.srcIp, conn.srcPort)} ↔ ${fmtEndpoint(conn.dstIp, conn.dstPort)}: 重传开销 ${(retransOverhead * 100).toFixed(1)}%（${retransBytes}/${totalPayload} 字节）`,
        detail: {
          totalBytes: totalPayload,
          retransBytes,
          goodputBytes: goodput,
          retransOverheadRate: retransOverhead,
          throughputKbps: throughputBps / 1000,
          goodputKbps: goodputBps / 1000,
          durationSec: duration
        },
        scenario: retransOverhead > 0.3
          ? "超过 30% 的数据是重传，网络质量差。检查链路丢包率和带宽瓶颈。"
          : "重传比例偏高，可能存在间歇性丢包"
      });
    }

    // Report BDP if we have RTT
    if (rttSec != null && rttSec > 0 && throughputBps > 0) {
      const bdp = throughputBps * rttSec;
      const bdpKB = bdp / 8 / 1024;
      if (bdpKB > 64) { // BDP > 64KB
        acc.push({
          insightId: insightId("throughput", idx++),
          type: "tcp_throughput",
          severity: "info",
          packetIds: [],
          description: `${fmtEndpoint(conn.srcIp, conn.srcPort)} ↔ ${fmtEndpoint(conn.dstIp, conn.dstPort)}: BDP ${bdpKB.toFixed(0)}KB（吞吐 ${(throughputBps / 1000).toFixed(0)}Kbps × RTT ${(rttSec * 1000).toFixed(0)}ms）`,
          detail: {
            bandwidthDelayProductKB: bdpKB,
            throughputKbps: throughputBps / 1000,
            rttMs: rttSec * 1000,
            windowScaleNeeded: Math.ceil(bdpKB / 64)
          },
          scenario: "高 BDP 环境需要 Window Scale 选项和足够的 TCP 缓冲区。如果窗口不够大，吞吐量受限于流控而非带宽。"
        });
      }
    }
  }
}

// ── Analyzer: TCP Options & SACK ───────────────────────────────────────

function analyzeTcpOptions(
  connections: Map<TcpFlowKey, TcpConnection>,
  acc: InsightAccumulator
) {
  let idx = acc.length;

  for (const conn of connections.values()) {
    const sorted = [...conn.packets].sort((a, b) => a.timestamp - b.timestamp);

    // Check SYN packets for TCP options (in raw field)
    const syn = sorted.find(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && !flags.includes("ACK");
    });
    const synack = sorted.find(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && flags.includes("ACK");
    });

    // Extract options from raw field
    const extractOpts = (p: PacketSummary | undefined) => {
      if (!p?.raw) return null;
      const r = p.raw as Record<string, unknown>;
      return {
        mss: r["tcp.options.mss_val"] ?? r["tcp.mss"] ?? null,
        wscale: r["tcp.options.wscale.shift"] ?? r["tcp.window_size_scalefactor"] ?? null,
        sackPermitted: r["tcp.options.sack_permitted"] ?? r["tcp.sack_permitted"] ?? null,
        timestamps: r["tcp.options.timestamp.tsval"] != null || r["tcp.options.timestamp"] != null,
        fastOpen: r["tcp.options.fast_open.cookie"] ?? r["tcp.fast_open"] ?? null
      };
    };

    const synOpts = extractOpts(syn);
    const synackOpts = extractOpts(synack);

    // TCP Fast Open detection: SYN with payload
    if (syn && (syn.tcpPayloadLength ?? 0) > 0) {
      acc.push({
        insightId: insightId("tcp-opts", idx++),
        type: "tcp_options",
        severity: "info",
        packetIds: [syn.packetId],
        description: `TCP Fast Open: SYN 携带 ${(syn.tcpPayloadLength ?? 0)} 字节数据（${syn.srcIp}:${syn.srcPort} → ${syn.dstIp}:${syn.dstPort}）`,
        detail: { payloadInSyn: syn.tcpPayloadLength, fastOpenCookie: synOpts?.fastOpen },
        scenario: "TCP Fast Open 允许在 SYN 中携带数据，减少一次 RTT 延迟。需要客户端和服务端都支持 TFO。"
      });
    }

    // Report missing options that affect performance
    if (synOpts && !synOpts.sackPermitted) {
      acc.push({
        insightId: insightId("tcp-opts", idx++),
        type: "tcp_options",
        severity: "info",
        packetIds: syn ? [syn.packetId] : [],
        description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)}: SACK 未协商`,
        detail: { sackPermitted: false },
        scenario: "缺少 SACK 支持时，丢包恢复只能通过重复 ACK 触发快速重传，效率较低。多丢包场景下性能下降明显。"
      });
    }

    if (synOpts && !synOpts.timestamps) {
      acc.push({
        insightId: insightId("tcp-opts", idx++),
        type: "tcp_options",
        severity: "info",
        packetIds: syn ? [syn.packetId] : [],
        description: `TCP 连接 ${fmtEndpoint(conn.srcIp, conn.srcPort)} → ${fmtEndpoint(conn.dstIp, conn.dstPort)}: Timestamps 选项未启用`,
        detail: { timestampsEnabled: false },
        scenario: "缺少 Timestamps 选项会导致 RTT 测量不精确，且在高带宽链路上无法防止序列号回绕（PAWS）。"
      });
    }

    // SACK analysis: count duplicate ACKs with SACK
    const dupAcks = sorted.filter(p => p.tcpAnalysis?.duplicateAck);
    if (dupAcks.length >= 3) {
      // Check if SACK blocks are in raw data
      const sackAcks = dupAcks.filter(p => {
        const r = p.raw as Record<string, unknown>;
        return r["tcp.options.sack"] != null || r["tcp.sack"] != null || r["tcp.sack_le"] != null;
      });

      acc.push({
        insightId: insightId("tcp-opts", idx++),
        type: "tcp_options",
        severity: "info",
        packetIds: dupAcks.map(p => p.packetId).slice(0, 10),
        description: `${fmtEndpoint(conn.srcIp, conn.srcPort)} ↔ ${fmtEndpoint(conn.dstIp, conn.dstPort)}: ${dupAcks.length} 个重复 ACK${sackAcks.length ? `（${sackAcks.length} 个含 SACK 块）` : ""}`,
        detail: {
          duplicateAckCount: dupAcks.length,
          sackAckCount: sackAcks.length,
          hasSack: sackAcks.length > 0
        },
        scenario: dupAcks.length >= 10
          ? "大量重复 ACK 说明存在多段丢失。SACK 帮助发送端精确重传丢失段。"
          : "重复 ACK 触发快速重传，少量重复 ACK 属于正常丢包恢复。"
      });
    }
  }
}

// ── Advanced HTTP Analyzers ───────────────────────────────────────────

function analyzeHttpAdvanced(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const httpReqs = packets.filter(p => p.httpRequestMethod);
  const httpResps = packets.filter(p => p.httpResponseCode != null);
  if (!httpReqs.length && !httpResps.length) return;

  // 1. Host vs SNI mismatch
  for (const req of httpReqs) {
    if (!req.httpHost) continue;
    // Find TLS ClientHello for same flow
    const sni = packets.find(p =>
      p.tlsSni && p.tlsHandshakeType === 1
      && ((p.srcIp === req.srcIp && p.srcPort === req.srcPort) || (p.dstIp === req.dstIp && p.dstPort === req.dstPort))
      && Math.abs(p.timestamp - req.timestamp) < 10
    )?.tlsSni;
    if (sni && sni !== req.httpHost) {
      acc.push({
        insightId: insightId("http-adv", idx++),
        type: "http_header_anomaly",
        severity: "warning",
        packetIds: [req.packetId],
        description: `HTTP Host "${req.httpHost}" 与 TLS SNI "${sni}" 不一致`,
        detail: { httpHost: req.httpHost, tlsSni: sni, uri: req.httpRequestUri },
        scenario: "Host 与 SNI 不匹配可能导致 CDN/代理路由错误、证书验证失败、或请求被 WAF 拦截"
      });
    }
  }

  // 2. Error burst detection
  const errors = httpResps.filter(p => p.httpResponseCode! >= 400).sort((a, b) => a.timestamp - b.timestamp);
  if (errors.length >= 5) {
    // Find bursts: ≥5 errors within 10s
    for (let i = 4; i < errors.length; i++) {
      const span = errors[i].timestamp - errors[i - 4].timestamp;
      if (span < 10) {
        acc.push({
          insightId: insightId("http-adv", idx++),
          type: "http_status_chain",
          severity: "warning",
          packetIds: errors.slice(i - 4, i + 1).map(p => p.packetId),
          description: `HTTP 错误突发：5 个 ≥400 响应在 ${span.toFixed(1)}s 内`,
          detail: {
            codes: errors.slice(i - 4, i + 1).map(p => p.httpResponseCode),
            hosts: [...new Set(errors.slice(i - 4, i + 1).map(p => p.httpHost).filter(Boolean))]
          },
          scenario: "错误突发可能对应后端服务异常、过载、或上游依赖故障"
        });
        break; // Report first burst only
      }
    }
  }

  // 3. Repeated URI requests
  const uriCounts = new Map<string, { count: number; packets: PacketSummary[] }>();
  for (const req of httpReqs) {
    if (!req.httpRequestUri) continue;
    const key = `${req.httpRequestMethod} ${req.httpHost || ""} ${req.httpRequestUri}`;
    const entry = uriCounts.get(key) || { count: 0, packets: [] };
    entry.count++;
    entry.packets.push(req);
    uriCounts.set(key, entry);
  }
  for (const [key, entry] of uriCounts) {
    if (entry.count < 10) continue;
    const span = entry.packets[entry.packets.length - 1].timestamp - entry.packets[0].timestamp;
    if (span < 60) { // 10+ requests to same URI within 60s
      acc.push({
        insightId: insightId("http-adv", idx++),
        type: "http_status_chain",
        severity: "info",
        packetIds: entry.packets.map(p => p.packetId).slice(0, 10),
        description: `URI ${key} 被请求 ${entry.count} 次在 ${span.toFixed(1)}s 内`,
        detail: { uri: key, count: entry.count, spanSec: span },
        scenario: "频繁重试或轮询。可能是客户端超时重试、健康检查、或循环请求"
      });
    }
  }

  // 4. HTTP method distribution
  const methodCounts = new Map<string, number>();
  for (const req of httpReqs) methodCounts.set(req.httpRequestMethod!, (methodCounts.get(req.httpRequestMethod!) || 0) + 1);
  const unusualMethods = [...methodCounts.entries()].filter(([m]) => !["GET", "POST"].includes(m));
  if (unusualMethods.length) {
    const total = [...methodCounts.values()].reduce((a, b) => a + b, 0);
    const unusualTotal = unusualMethods.reduce((sum, [, c]) => sum + c, 0);
    if (unusualTotal / total > 0.3) {
      acc.push({
        insightId: insightId("http-adv", idx++),
        type: "http_header_anomaly",
        severity: "info",
        packetIds: [],
        description: `非标准 HTTP 方法占比 ${(unusualTotal / total * 100).toFixed(0)}%：${unusualMethods.map(([m, c]) => `${m}(${c})`).join(", ")}`,
        detail: { methods: Object.fromEntries(methodCounts) },
        scenario: "大量 PUT/DELETE/OPTIONS 等方法可能是 REST API 调用，也可能是扫描或攻击行为"
      });
    }
  }

  // 5. Full status code spectrum
  const codeGroups = new Map<string, number>();
  for (const resp of httpResps) {
    const code = resp.httpResponseCode!;
    const group = `${Math.floor(code / 100)}xx`;
    codeGroups.set(group, (codeGroups.get(group) || 0) + 1);
  }
  // Report if notable distribution
  const resp1xx = codeGroups.get("1xx") || 0;
  const resp2xx = codeGroups.get("2xx") || 0;
  const resp3xx = codeGroups.get("3xx") || 0;
  const resp4xx = codeGroups.get("4xx") || 0;
  const resp5xx = codeGroups.get("5xx") || 0;
  const totalResps = resp1xx + resp2xx + resp3xx + resp4xx + resp5xx;
  if (resp4xx + resp5xx > 0) {
    acc.push({
      insightId: insightId("http-adv", idx++),
      type: "http_status_chain",
      severity: "info",
      packetIds: [],
      description: `HTTP 响应码分布：1xx=${resp1xx} 2xx=${resp2xx} 3xx=${resp3xx} 4xx=${resp4xx} 5xx=${resp5xx}（错误率 ${((resp4xx + resp5xx) / totalResps * 100).toFixed(0)}%）`,
      detail: { "1xx": resp1xx, "2xx": resp2xx, "3xx": resp3xx, "4xx": resp4xx, "5xx": resp5xx, total: totalResps },
      scenario: "超过 30% 的响应是错误码，说明服务端或客户端存在系统性问题"
    });
  }

  // 6. Cookie analysis
  const reqsWithCookie = httpReqs.filter(p => p.httpCookie);
  const reqsWithoutCookie = httpReqs.filter(p => !p.httpCookie && p.httpRequestMethod !== "OPTIONS");
  const respsWithSetCookie = httpResps.filter(p => p.httpSetCookie);
  if (reqsWithoutCookie.length > 0 && reqsWithCookie.length > 0) {
    // Some requests have cookies, some don't
    const noCookieHosts = new Set(reqsWithoutCookie.map(p => p.httpHost).filter(Boolean));
    const hasCookieHosts = new Set(reqsWithCookie.map(p => p.httpHost).filter(Boolean));
    const inconsistent = [...noCookieHosts].filter(h => hasCookieHosts.has(h));
    if (inconsistent.length) {
      acc.push({
        insightId: insightId("http-adv", idx++),
        type: "http_header_anomaly",
        severity: "info",
        packetIds: reqsWithoutCookie.filter(p => inconsistent.includes(p.httpHost)).slice(0, 5).map(p => p.packetId),
        description: `Host ${inconsistent.join(", ")}：部分请求缺少 Cookie（${reqsWithCookie.length} 有 vs ${reqsWithoutCookie.length} 无）`,
        detail: { hosts: inconsistent, withCookie: reqsWithCookie.length, withoutCookie: reqsWithoutCookie.length },
        scenario: "Cookie 不一致可能导致会话丢失、认证失败、或负载均衡路由问题"
      });
    }
  }
  if (respsWithSetCookie.length > 0) {
    // Multiple Set-Cookie to same host
    const setCookieByHost = new Map<string, number>();
    for (const r of respsWithSetCookie) {
      if (r.httpHost) setCookieByHost.set(r.httpHost, (setCookieByHost.get(r.httpHost) || 0) + 1);
    }
    for (const [host, count] of setCookieByHost) {
      if (count >= 5) {
        acc.push({
          insightId: insightId("http-adv", idx++),
          type: "http_header_anomaly",
          severity: "info",
          packetIds: respsWithSetCookie.filter(r => r.httpHost === host).slice(0, 5).map(p => p.packetId),
          description: `Host ${host} 发送了 ${count} 次 Set-Cookie（可能频繁刷新 session）`,
          detail: { host, setCookieCount: count },
          scenario: "频繁 Set-Cookie 说明服务端不断创建新 session，可能是 session 管理问题或 cookie 属性配置错误（Missing Secure/HttpOnly/SameSite）"
        });
      }
    }
  }

  // 7. X-Forwarded-For analysis
  const xffPackets = httpReqs.filter(p => p.httpXForwardedFor);
  if (xffPackets.length >= 2) {
    const xffChains = xffPackets.map(p => ({ host: p.httpHost, xff: p.httpXForwardedFor!, srcIp: p.srcIp, packetId: p.packetId }));
    // Check for multiple proxy hops
    const multiHop = xffChains.filter(x => x.xff.split(",").length >= 3);
    if (multiHop.length) {
      acc.push({
        insightId: insightId("http-adv", idx++),
        type: "http_header_anomaly",
        severity: "info",
        packetIds: multiHop.slice(0, 5).map(x => x.packetId),
        description: `X-Forwarded-For 包含 ≥3 跳代理：${multiHop[0].xff}`,
        detail: { xff: multiHop[0].xff, hopCount: multiHop[0].xff.split(",").length },
        scenario: "多跳代理链可能增加延迟、导致源 IP 丢失、或触发安全策略。确认每跳代理都正确追加 XFF。"
      });
    }
  }

  // 8. Content-Length mismatch (approximation: check if Content-Length declared but connection RSTs)
  const contentLenResps = httpResps.filter(p => p.httpContentLength != null && p.httpContentLength > 0);
  if (contentLenResps.length >= 2) {
    // Check for responses with Content-Length but connection terminated early
    for (const resp of contentLenResps) {
      const rstAfter = packets.find(p =>
        p.tcpFlags.map(f => f.toUpperCase()).includes("RST")
        && p.timestamp > resp.timestamp && p.timestamp - resp.timestamp < 5
        && ((p.srcIp === resp.srcIp && p.srcPort === resp.srcPort) || (p.dstIp === resp.dstIp && p.dstPort === resp.dstPort))
      );
      if (rstAfter) {
        acc.push({
          insightId: insightId("http-adv", idx++),
          type: "http_header_anomaly",
          severity: "warning",
          packetIds: [resp.packetId, rstAfter.packetId],
          description: `HTTP ${resp.httpResponseCode} 声明 Content-Length: ${resp.httpContentLength} 但连接被 RST 截断`,
          detail: { statusCode: resp.httpResponseCode, declaredContentLength: resp.httpContentLength, uri: resp.httpRequestUri, host: resp.httpHost },
          scenario: "响应被截断，客户端可能收到不完整数据。可能是服务端崩溃、中间设备超时、或网络中断。"
        });
      }
    }
  }

  // 9. Cache-Control analysis
  const cacheableResps = httpResps.filter(p => p.httpResponseCode! === 200 && p.httpCacheControl);
  const nonCachedResps = httpResps.filter(p => p.httpResponseCode! === 200 && !p.httpCacheControl);
  if (cacheableResps.length > 0 && nonCachedResps.length > 0) {
    acc.push({
      insightId: insightId("http-adv", idx++),
      type: "http_header_anomaly",
      severity: "info",
      packetIds: [],
      description: `${nonCachedResps.length} 个 200 响应缺少 Cache-Control（可能重复传输可缓存内容）`,
      detail: { withCacheControl: cacheableResps.length, withoutCacheControl: nonCachedResps.length },
      scenario: "缺少缓存头导致客户端和代理每次都重新请求，增加延迟和带宽消耗"
    });
  }

  // 10. Authentication flow
  const auth401 = httpResps.filter(p => p.httpResponseCode === 401);
  const auth403 = httpResps.filter(p => p.httpResponseCode === 403);
  const authReqs = httpReqs.filter(p => p.httpAuthorization);
  if (auth401.length >= 1 && authReqs.length === 0) {
    acc.push({
      insightId: insightId("http-adv", idx++),
      type: "http_header_anomaly",
      severity: "warning",
      packetIds: auth401.map(p => p.packetId).slice(0, 10),
      description: `${auth401.length} 次 401 未授权响应，但请求中无 Authorization header（认证凭据缺失）`,
      detail: { count401: auth401.length, hasAuthHeader: false, hosts: [...new Set(auth401.map(p => p.httpHost).filter(Boolean))] },
      scenario: "客户端未携带认证信息，可能是 token 过期、cookie 丢失、或配置错误"
    });
  }
  if (auth401.length >= 1 && authReqs.length > 0) {
    // Auth provided but still 401 — check if same host
    const auth401Hosts = new Set(auth401.map(p => p.httpHost).filter(Boolean));
    const authReqHosts = new Set(authReqs.map(p => p.httpHost).filter(Boolean));
    const overlap = [...auth401Hosts].filter(h => authReqHosts.has(h));
    if (overlap.length) {
      acc.push({
        insightId: insightId("http-adv", idx++),
        type: "http_header_anomaly",
        severity: "warning",
        packetIds: [...auth401.slice(0, 3).map(p => p.packetId), ...authReqs.slice(0, 3).map(p => p.packetId)],
        description: `${overlap.join(", ")}：携带 Authorization 但仍收到 ${auth401.length} 次 401（凭据可能无效或过期）`,
        detail: { hosts: overlap, count401: auth401.length, authRequestCount: authReqs.length },
        scenario: "认证凭据被拒绝。可能是 token 过期、密码错误、或认证服务配置问题"
      });
    }
  }

  // 11. Content-Type mismatch (request Accept vs response Content-Type)
  // This is a basic check — we don't have Accept header, but can check unexpected Content-Type
  const jsonResps = httpResps.filter(p => p.httpContentType?.includes("json") && p.httpResponseCode! >= 400);
  const htmlResps = httpResps.filter(p => p.httpContentType?.includes("html") && p.httpResponseCode! === 200);
  // Report if API returns HTML for error
  if (jsonResps.length && htmlResps.length) {
    const apiHosts = new Set(jsonResps.map(p => p.httpHost).filter(Boolean));
    const htmlFromApi = htmlResps.filter(p => apiHosts.has(p.httpHost));
    if (htmlFromApi.length >= 2) {
      acc.push({
        insightId: insightId("http-adv", idx++),
        type: "http_header_anomaly",
        severity: "info",
        packetIds: htmlFromApi.slice(0, 5).map(p => p.packetId),
        description: `API Host ${[...apiHosts].join(", ")} 同时返回 JSON 错误和 HTML 成功（Content-Type 混合）`,
        detail: { hosts: [...apiHosts] },
        scenario: "API 端点返回 HTML 而非 JSON 可能是代理/LB 的默认错误页、或 API 路由配置错误"
      });
    }
  }

  // 12. Connection keep-alive / close pattern
  const connClose = httpResps.filter(p => p.httpConnection?.toLowerCase().includes("close"));
  const connKeepalive = httpResps.filter(p => p.httpConnection?.toLowerCase().includes("keep-alive"));
  if (connClose.length > 0) {
    acc.push({
      insightId: insightId("http-adv", idx++),
      type: "http_header_anomaly",
      severity: "info",
      packetIds: connClose.slice(0, 5).map(p => p.packetId),
      description: `${connClose.length} 个响应使用 Connection: close（不复用连接，每次新建 TCP）`,
      detail: { closeCount: connClose.length, keepAliveCount: connKeepalive.length },
      scenario: "Connection: close 导致每次请求都新建 TCP 连接（含 TLS 握手），增加延迟。建议启用 keep-alive。"
    });
  }

  // 13. WebSocket upgrade detection
  const wsUpgrades = httpReqs.filter(p => p.httpUpgrade?.toLowerCase().includes("websocket"));
  if (wsUpgrades.length) {
    acc.push({
      insightId: insightId("http-adv", idx++),
      type: "http_header_anomaly",
      severity: "info",
      packetIds: wsUpgrades.map(p => p.packetId),
      description: `检测到 ${wsUpgrades.length} 次 WebSocket 升级请求`,
      detail: { upgradeCount: wsUpgrades.length, hosts: [...new Set(wsUpgrades.map(p => p.httpHost).filter(Boolean))] },
      scenario: "WebSocket 流量在 pcap 中以 HTTP Upgrade 开始，后续为二进制帧"
    });
  }

  // 14. Compression negotiation
  const gzipResps = httpResps.filter(p => p.httpContentEncoding?.includes("gzip") || p.httpContentEncoding?.includes("br") || p.httpContentEncoding?.includes("deflate"));
  const uncompressedResps = httpResps.filter(p => p.httpResponseCode! === 200 && p.httpContentLength != null && p.httpContentLength > 1000 && !p.httpContentEncoding);
  if (uncompressedResps.length > 0) {
    acc.push({
      insightId: insightId("http-adv", idx++),
      type: "http_header_anomaly",
      severity: "info",
      packetIds: uncompressedResps.slice(0, 5).map(p => p.packetId),
      description: `${uncompressedResps.length} 个大响应体（>${uncompressedResps[0].httpContentLength}B）未压缩`,
      detail: { uncompressedCount: uncompressedResps.length, compressedCount: gzipResps.length },
      scenario: "响应体未压缩浪费带宽，服务端可能未启用 gzip/brotli 压缩"
    });
  }

  // 15. Transfer-Encoding chunked issues (chunked but no Content-Length)
  const chunkedResps = httpResps.filter(p => p.httpTransferEncoding?.toLowerCase().includes("chunked"));
  if (chunkedResps.length >= 5) {
    acc.push({
      insightId: insightId("http-adv", idx++),
      type: "http_header_anomaly",
      severity: "info",
      packetIds: [],
      description: `${chunkedResps.length} 个响应使用 Transfer-Encoding: chunked`,
      detail: { chunkedCount: chunkedResps.length },
      scenario: "chunked 编码用于流式响应或未知长度的响应体。如果响应突然中断，可能丢失尾部数据。"
    });
  }
}

// ── Advanced TLS Analyzers ────────────────────────────────────────────

function analyzeTlsAdvanced(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const tlsPackets = packets.filter(p => p.tlsHandshakeType != null || p.tlsRecordVersion || p.tlsCipherSuite);
  if (!tlsPackets.length) return;

  // 1. TLS version analysis — detect deprecated versions
  const versionMap: Record<string, string> = {
    "0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3",
    "768": "TLS 1.0", "769": "TLS 1.1", "771": "TLS 1.2", "772": "TLS 1.3"
  };
  const deprecatedVersions = new Set(["0x0301", "0x0302", "768", "769"]);

  const clientHellos = tlsPackets.filter(p => p.tlsHandshakeType === 1);
  const serverHellos = tlsPackets.filter(p => p.tlsHandshakeType === 2);

  for (const ch of clientHellos) {
    const ver = ch.tlsHandshakeVersion || ch.tlsRecordVersion || "";
    const verStr = versionMap[ver] || ver;
    if (deprecatedVersions.has(ver)) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "warning",
        packetIds: [ch.packetId],
        description: `TLS ClientHello 声明 ${verStr}（已弃用协议）`,
        detail: { version: verStr, rawVersion: ver, srcIp: ch.srcIp, sni: ch.tlsSni },
        scenario: "TLS 1.0/1.1 已被弃用（RFC 8996），存在安全风险。建议升级到 TLS 1.2+。"
      });
    }
  }

  // Detect version downgrade: ClientHello says 1.3 but ServerHello says 1.2
  if (clientHellos.length && serverHellos.length) {
    const chVer = clientHellos[0].tlsHandshakeVersion || "";
    const shVer = serverHellos[0].tlsHandshakeVersion || "";
    const chStr = versionMap[chVer] || chVer;
    const shStr = versionMap[shVer] || shVer;
    if (chStr !== shStr && chStr && shStr) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "info",
        packetIds: [clientHellos[0].packetId, serverHellos[0].packetId],
        description: `TLS 版本协商降级：ClientHello ${chStr} → ServerHello ${shStr}`,
        detail: { clientVersion: chStr, serverVersion: shStr, sni: clientHellos[0].tlsSni },
        scenario: "服务端不支持客户端请求的最高 TLS 版本，降级协商。正常行为但需确认不是协议降级攻击。"
      });
    }
  }

  // 2. SNI vs Host mismatch (cross-referenced from HTTP analyzer, but also standalone)
  for (const ch of clientHellos) {
    if (!ch.tlsSni) continue;
    const matchingReq = packets.find(p =>
      p.httpRequestMethod && p.httpHost
      && ((p.srcIp === ch.srcIp && p.srcPort === ch.srcPort) || (p.dstIp === ch.dstIp && p.dstPort === ch.dstPort))
      && Math.abs(p.timestamp - ch.timestamp) < 10
    );
    if (matchingReq && matchingReq.httpHost !== ch.tlsSni) {
      // Already covered in HTTP analyzer, skip duplicate
    } else if (!matchingReq && ch.tlsSni) {
      // TLS without matching HTTP — could be non-HTTP TLS or different timing
    }
  }

  // 3. Handshake phase completeness (detailed state machine)
  for (const ch of clientHellos) {
    const flow = [ch.srcIp, ch.srcPort, ch.dstIp, ch.dstPort].join(":");
    const flowRev = [ch.dstIp, ch.dstPort, ch.srcIp, ch.srcPort].join(":");

    const sh = tlsPackets.find(p =>
      p.tlsHandshakeType === 2
      && (tcpFlowKey(p) === flow || tcpFlowKey(p) === flowRev || tcpFlowKeyReverse(p) === flow || tcpFlowKeyReverse(p) === flowRev)
      && p.timestamp >= ch.timestamp
    );

    // Certificate (type 11)
    const cert = tlsPackets.find(p =>
      p.tlsHandshakeType === 11
      && p.timestamp >= ch.timestamp
    );

    // ServerHelloDone (type 14)
    const shDone = tlsPackets.find(p =>
      p.tlsHandshakeType === 14
      && p.timestamp >= ch.timestamp
    );

    // Finished (type 20)
    const finished = tlsPackets.find(p =>
      p.tlsHandshakeType === 20
      && p.timestamp >= ch.timestamp
    );

    if (sh && !cert && !shDone) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "warning",
        packetIds: [ch.packetId, sh.packetId],
        description: `TLS 握手在 ServerHello 后中断（缺少 Certificate/ServerHelloDone）：${ch.tlsSni || ch.dstIp}`,
        detail: { sni: ch.tlsSni, hasServerHello: true, hasCertificate: false, hasServerHelloDone: false, hasFinished: false },
        scenario: "服务端在发送 ServerHello 后中断握手。可能是内部错误、证书加载失败、或中间设备干扰。"
      });
    } else if (sh && shDone && !finished) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "warning",
        packetIds: [ch.packetId, sh.packetId, shDone.packetId].filter(Boolean) as string[],
        description: `TLS 握手未完成（服务端发了 ServerHelloDone 但未收到 Finished）：${ch.tlsSni || ch.dstIp}`,
        detail: { sni: ch.tlsSni, hasServerHello: true, hasCertificate: !!cert, hasServerHelloDone: true, hasFinished: false },
        scenario: "客户端在收到服务端握手消息后未完成。可能是客户端证书验证失败、密钥交换错误、或网络中断。"
      });
    }
  }

  // 4. Cipher suite analysis
  const cipherSuites = serverHellos.filter(p => p.tlsCipherSuite);
  for (const sh of cipherSuites) {
    const cipher = sh.tlsCipherSuite || "";
    const weakCiphers = ["NULL", "EXPORT", "RC4", "DES", "MD5", "3DES"];
    const isWeak = weakCiphers.some(w => cipher.toUpperCase().includes(w));
    if (isWeak) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "critical",
        packetIds: [sh.packetId],
        description: `弱加密套件协商成功：${cipher}`,
        detail: { cipherSuite: cipher, sni: clientHellos.find(ch => ch.timestamp < sh.timestamp)?.tlsSni },
        scenario: "弱加密套件（NULL/EXPORT/RC4/DES/MD5）已被认为不安全。可能遭受 BEAST、POODLE 等攻击。"
      });
    }

    // Check for forward secrecy
    const forwardSecrecyCiphers = ["ECDHE", "DHE"];
    const hasPFS = forwardSecrecyCiphers.some(c => cipher.toUpperCase().includes(c));
    if (!hasPFS && cipher && !isWeak) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "info",
        packetIds: [sh.packetId],
        description: `TLS 加密套件不支持前向保密：${cipher}`,
        detail: { cipherSuite: cipher, hasPFS: false },
        scenario: "没有前向保密（PFS）意味着如果私钥泄露，历史流量可以被解密。建议使用 ECDHE/DHE 套件。"
      });
    }
  }

  // 5. Certificate analysis (basic — from tlsCertDnsName)
  const certPackets = tlsPackets.filter(p => p.tlsHandshakeType === 11 && p.tlsCertDnsName);
  for (const cert of certPackets) {
    const ch = clientHellos.find(c =>
      c.tlsSni && c.timestamp < cert.timestamp
      && Math.abs(c.timestamp - cert.timestamp) < 10
    );
    if (ch?.tlsSni && cert.tlsCertDnsName) {
      const certNames = cert.tlsCertDnsName.split(",").map(n => n.trim());
      const sniMatches = certNames.some(n => {
        if (n.startsWith("*.")) {
          const domain = n.slice(2);
          return ch.tlsSni!.endsWith(domain) || ch.tlsSni === n;
        }
        return n === ch.tlsSni;
      });
      if (!sniMatches) {
        acc.push({
          insightId: insightId("tls-adv", idx++),
          type: "tls_handshake",
          severity: "warning",
          packetIds: [ch.packetId, cert.packetId],
          description: `证书 SAN (${cert.tlsCertDnsName.slice(0, 80)}) 不匹配 SNI "${ch.tlsSni}"`,
          detail: { sni: ch.tlsSni, certDnsNames: cert.tlsCertDnsName },
          scenario: "证书不覆盖请求的域名，客户端会报证书错误。可能是证书配置错误、SNI 路由错误、或通配符覆盖不足。"
        });
      }
    }
  }

  // 6. Session resumption detection
  const sessionIds = serverHellos.filter(p => p.tlsSessionId);
  const tickets = serverHellos.filter(p => p.tlsSessionTicket);
  const resumed = sessionIds.filter(p => p.tlsSessionId && p.tlsSessionId.length > 10);
  if (resumed.length >= 2) {
    // Check if same session ID used multiple times (resumption)
    const uniqueIds = new Set(resumed.map(p => p.tlsSessionId));
    const reusedIds = [...uniqueIds].filter(id => resumed.filter(p => p.tlsSessionId === id).length >= 2);
    if (reusedIds.length) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "info",
        packetIds: resumed.slice(0, 5).map(p => p.packetId),
        description: `TLS 会话恢复：${reusedIds.length} 个 Session ID 被复用`,
        detail: { resumedSessionCount: reusedIds.length, totalServerHellos: serverHellos.length },
        scenario: "TLS 会话恢复减少握手延迟（跳过完整握手）。正常优化行为。"
      });
    }
  }

  // 7. ALPN negotiation
  const alpnResults = serverHellos.filter(p => p.tlsAlpnProtocol);
  if (alpnResults.length) {
    const alpnCounts = new Map<string, number>();
    for (const sh of alpnResults) alpnCounts.set(sh.tlsAlpnProtocol!, (alpnCounts.get(sh.tlsAlpnProtocol!) || 0) + 1);
    for (const [proto, count] of alpnCounts) {
      if (proto !== "h2" && count > 0) {
        acc.push({
          insightId: insightId("tls-adv", idx++),
          type: "tls_handshake",
          severity: "info",
          packetIds: alpnResults.filter(p => p.tlsAlpnProtocol === proto).slice(0, 3).map(p => p.packetId),
          description: `ALPN 协商结果: ${proto}（${count} 次，非 HTTP/2）`,
          detail: { alpnProtocol: proto, count },
          scenario: "ALPN 协商了非 h2 协议。如果是期望使用 HTTP/2 的场景，说明服务端或客户端未启用 h2 支持。"
        });
      }
    }
  }

  // 8. TLS renegotiation detection
  // Look for ClientHello after a Finished in the same flow
  for (let i = 0; i < clientHellos.length; i++) {
    const ch = clientHellos[i];
    // Find a Finished before this ClientHello in the same flow
    const prevFinished = tlsPackets.find(p =>
      p.tlsHandshakeType === 20
      && p.timestamp < ch.timestamp && ch.timestamp - p.timestamp < 30
      && (p.srcIp === ch.srcIp || p.dstIp === ch.srcIp)
    );
    if (prevFinished) {
      acc.push({
        insightId: insightId("tls-adv", idx++),
        type: "tls_handshake",
        severity: "info",
        packetIds: [prevFinished.packetId, ch.packetId],
        description: `TLS 重协商：在 Finished 之后再次发送 ClientHello（${ch.srcIp}）`,
        detail: { srcIp: ch.srcIp, sni: ch.tlsSni },
        scenario: "TLS 重协商用于更新密钥或请求客户端证书。频繁重协商可能影响性能。某些实现容易受到重协商 DoS 攻击。"
      });
    }
  }
}

// ── UDP Analyzers ─────────────────────────────────────────────────────

function analyzeUdp(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const udpPackets = packets.filter(p => p.protocol.toLowerCase() === "udp");
  if (!udpPackets.length) return;

  // 1. UDP port scan: one source, many destination ports
  const bySrc = new Map<string, PacketSummary[]>();
  for (const p of udpPackets) {
    const key = p.srcIp || "unknown";
    const arr = bySrc.get(key) || [];
    arr.push(p);
    bySrc.set(key, arr);
  }
  for (const [srcIp, srcPkts] of bySrc) {
    const dstPorts = new Set(srcPkts.map(p => p.dstPort));
    if (dstPorts.size > 1) {
      const span = srcPkts[srcPkts.length - 1].timestamp - srcPkts[0].timestamp;
      acc.push({
        insightId: insightId("udp", idx++),
        type: "udp_anomaly",
        severity: "info",
        packetIds: srcPkts.slice(0, 20).map(p => p.packetId),
        description: `UDP 多端口访问：${srcIp} 访问 ${dstPorts.size} 个不同端口（${srcPkts.length} 包，${span.toFixed(1)}s）`,
        detail: { srcIp, uniqueDstPorts: dstPorts.size, packetCount: srcPkts.length, spanSec: span, dstIp: [...new Set(srcPkts.map(p => p.dstIp))].slice(0, 5) },
        scenario: "可能是端口扫描、服务发现、或应用轮询多个端口"
      });
    }
  }

  // 2. UDP flood: high rate to single target
  const byDst = new Map<string, PacketSummary[]>();
  for (const p of udpPackets) {
    const key = `${p.dstIp}:${p.dstPort}`;
    const arr = byDst.get(key) || [];
    arr.push(p);
    byDst.set(key, arr);
  }
  for (const [dst, dstPkts] of byDst) {
    if (dstPkts.length < 2) continue;
    const sorted = [...dstPkts].sort((a, b) => a.timestamp - b.timestamp);
    let maxRate = 0;
    for (let i = 0; i < sorted.length; i++) {
      const windowEnd = sorted[i].timestamp + 1;
      let count = 0;
      for (let j = i; j < sorted.length && sorted[j].timestamp <= windowEnd; j++) count++;
      maxRate = Math.max(maxRate, count);
    }
    if (maxRate >= 2) {
      acc.push({
        insightId: insightId("udp", idx++),
        type: "udp_anomaly",
        severity: "info",
        packetIds: sorted.slice(0, 20).map(p => p.packetId),
        description: `UDP 突发：${maxRate} 包/s 到 ${dst}`,
        detail: { destination: dst, maxPacketsPerSec: maxRate, totalPackets: sorted.length, srcIps: [...new Set(sorted.map(p => p.srcIp))].slice(0, 5) },
        scenario: "高 UDP 速率可能是 UDP Flood 攻击、DNS 放大攻击、或正常的高频 UDP 应用"
      });
    }
  }

  // 3. One-way UDP flow
  const flowPairs = new Map<string, { fwd: PacketSummary[]; rev: PacketSummary[] }>();
  for (const p of udpPackets) {
    if (!p.srcIp || !p.dstIp || p.srcPort == null || p.dstPort == null) continue;
    const fwdKey = `${p.srcIp}:${p.srcPort}-${p.dstIp}:${p.dstPort}`;
    const revKey = `${p.dstIp}:${p.dstPort}-${p.srcIp}:${p.srcPort}`;
    const pairKey = fwdKey < revKey ? fwdKey : revKey;
    const entry = flowPairs.get(pairKey) || { fwd: [], rev: [] };
    if (fwdKey === pairKey) entry.fwd.push(p);
    else entry.rev.push(p);
    flowPairs.set(pairKey, entry);
  }
  for (const [, pair] of flowPairs) {
    if (pair.fwd.length >= 1 && pair.rev.length === 0) {
      acc.push({
        insightId: insightId("udp", idx++),
        type: "udp_flow",
        severity: "info",
        packetIds: pair.fwd.slice(0, 10).map(p => p.packetId),
        description: `UDP 单向流：${fmtEndpoint(pair.fwd[0].srcIp, pair.fwd[0].srcPort)} → ${fmtEndpoint(pair.fwd[0].dstIp, pair.fwd[0].dstPort)}（${pair.fwd.length} 包，无回包）`,
        detail: { srcIp: pair.fwd[0].srcIp, srcPort: pair.fwd[0].srcPort, dstIp: pair.fwd[0].dstIp, dstPort: pair.fwd[0].dstPort, packetCount: pair.fwd.length },
        scenario: "UDP 无回包可能是：单向广播/组播、对端无响应、或抓包只覆盖了一个方向"
      });
    }
  }

  // 4. Payload size anomalies
  const smallUdp = udpPackets.filter(p => (p.length ?? 0) > 0 && (p.length ?? 0) <= 8);
  const largeUdp = udpPackets.filter(p => (p.length ?? 0) > 1400);
  if (smallUdp.length >= 1) {
    acc.push({
      insightId: insightId("udp", idx++),
      type: "udp_anomaly",
      severity: "info",
      packetIds: smallUdp.slice(0, 10).map(p => p.packetId),
      description: `UDP 小包占比 ${(smallUdp.length / udpPackets.length * 100).toFixed(0)}%（${smallUdp.length}/${udpPackets.length}，≤8B）`,
      detail: { smallCount: smallUdp.length, totalUdp: udpPackets.length },
      scenario: "大量极小 UDP 包可能是探测、心跳、或应用层碎片"
    });
  }
  if (largeUdp.length >= 5) {
    const maxSize = Math.max(...largeUdp.map(p => p.length ?? 0));
    acc.push({
      insightId: insightId("udp", idx++),
      type: "udp_anomaly",
      severity: "info",
      packetIds: largeUdp.slice(0, 5).map(p => p.packetId),
      description: `${largeUdp.length} 个大 UDP 包（>1400B，最大 ${maxSize}B），可能触发 IP 分片`,
      detail: { largeCount: largeUdp.length, maxSize },
      scenario: "超过 MTU 的 UDP 包会被 IP 层分片，增加丢包风险。建议检查应用层 MTU 设置或启用 Path MTU Discovery。"
    });
  }

  // 5. DNS over TCP fallback detection (DNS truncated + subsequent TCP DNS)
  // Handled in DNS analyzer below

  // 6. QUIC detection
  const quicPackets = udpPackets.filter(p => p.quicVersion);
  if (quicPackets.length >= 2) {
    const versions = [...new Set(quicPackets.map(p => p.quicVersion))];
    const connIds = [...new Set(quicPackets.map(p => p.quicConnectionId).filter(Boolean))];
    acc.push({
      insightId: insightId("udp", idx++),
      type: "udp_flow",
      severity: "info",
      packetIds: quicPackets.slice(0, 10).map(p => p.packetId),
      description: `QUIC 流量：${quicPackets.length} 包，${connIds.length} 个连接，版本 ${versions.join(", ")}`,
      detail: { quicPacketCount: quicPackets.length, connectionCount: connIds.length, versions },
      scenario: "QUIC 基于 UDP 实现 HTTP/3。注意防火墙可能误拦截 UDP 443 端口的 QUIC 流量。"
    });
  }
}

// ── Advanced DNS Analyzers ────────────────────────────────────────────

function analyzeDnsAdvanced(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const dnsQueries = packets.filter(p => p.dnsQueryName && !p.dnsIsResponse);
  const dnsReplies = packets.filter(p => p.dnsQueryName && p.dnsIsResponse);
  if (!dnsQueries.length) return;

  // 1. DNS query burst
  const sorted = [...dnsQueries].sort((a, b) => a.timestamp - b.timestamp);
  if (sorted.length >= 5) {
    for (let i = 4; i < sorted.length; i++) {
      const span = sorted[i].timestamp - sorted[i - 4].timestamp;
      if (span < 5) {
        acc.push({
          insightId: insightId("dns-adv", idx++),
          type: "dns_anomaly",
          severity: "info",
          packetIds: sorted.slice(i - 4, i + 1).map(p => p.packetId),
          description: `DNS 查询突发：5 个查询在 ${span.toFixed(2)}s 内`,
          detail: { queriesPerSec: 5 / span, uniqueDomains: [...new Set(sorted.slice(i - 4, i + 1).map(p => p.dnsQueryName))].length, dnsServers: [...new Set(sorted.slice(i - 4, i + 1).map(p => p.dstIp))] },
          scenario: "DNS 查询突发可能是 DNS tunnel、恶意软件 C2、或应用启动时批量解析域名"
        });
        break;
      }
    }
  }

  // 2. DNS response success rate
  if (dnsQueries.length >= 1) {
    const noReply = dnsQueries.filter(q => !dnsReplies.find(r => r.dnsQueryName === q.dnsQueryName && r.srcIp === q.dstIp && r.timestamp >= q.timestamp && r.timestamp - q.timestamp < 10));
    const errorReplies = dnsReplies.filter(r => r.dnsRcode != null && r.dnsRcode !== 0);
    const successReplies = dnsReplies.filter(r => r.dnsRcode === 0);
    const total = dnsQueries.length;
    const successRate = total > 0 ? successReplies.length / total : 0;
    acc.push({
        insightId: insightId("dns-adv", idx++),
        type: "dns_anomaly",
        severity: successRate < 0.5 ? "warning" : "info",
        packetIds: [],
        description: `DNS 成功率 ${(successRate * 100).toFixed(0)}%（${successReplies.length}/${total}，${noReply.length} 无响应，${errorReplies.length} 错误响应）`,
        detail: { total, success: successReplies.length, noReply: noReply.length, errors: errorReplies.length, successRate },
        scenario: "DNS 响应统计"
      });
  }

  // 3. Single domain repeated queries
  const domainCounts = new Map<string, PacketSummary[]>();
  for (const q of dnsQueries) {
    const arr = domainCounts.get(q.dnsQueryName!) || [];
    arr.push(q);
    domainCounts.set(q.dnsQueryName!, arr);
  }
  for (const [domain, qPkts] of domainCounts) {
    if (qPkts.length < 10) continue;
    const span = qPkts[qPkts.length - 1].timestamp - qPkts[0].timestamp;
    if (span < 30) {
      acc.push({
        insightId: insightId("dns-adv", idx++),
        type: "dns_anomaly",
        severity: "info",
        packetIds: qPkts.slice(0, 10).map(p => p.packetId),
        description: `域名 ${domain} 被查询 ${qPkts.length} 次在 ${span.toFixed(1)}s 内（可能是解析失败重试）`,
        detail: { domain, queryCount: qPkts.length, spanSec: span },
        scenario: "同一域名频繁查询通常说明解析失败、DNS 服务器不响应、或应用层重试逻辑过于激进"
      });
    }
  }

  // 4. DNS server distribution
  const dnsServers = new Map<string, number>();
  for (const q of dnsQueries) {
    if (q.dstIp) dnsServers.set(q.dstIp, (dnsServers.get(q.dstIp) || 0) + 1);
  }
  if (dnsServers.size > 1) {
    acc.push({
      insightId: insightId("dns-adv", idx++),
      type: "dns_anomaly",
      severity: "info",
      packetIds: [],
      description: `DNS 查询发往 ${dnsServers.size} 个不同服务器：${[...dnsServers.entries()].map(([ip, c]) => `${ip}(${c})`).join(", ")}`,
      detail: { servers: Object.fromEntries(dnsServers) },
      scenario: "DNS 服务器分散可能是正常的（多 DNS 配置），也可能包含异常的 DNS 服务器（如恶意 DNS）"
    });
  }

  // 5. DNS query type analysis
  const typeMap: Record<number, string> = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 251: "IXFR", 252: "AXFR", 255: "ANY" };
  const typeCounts = new Map<string, number>();
  for (const q of dnsQueries) {
    const t = q.dnsQueryType ?? 1;
    const name = typeMap[t] || `TYPE${t}`;
    typeCounts.set(name, (typeCounts.get(name) || 0) + 1);
  }
  // Report zone transfer attempts
  if ((typeCounts.get("AXFR") || 0) > 0 || (typeCounts.get("IXFR") || 0) > 0) {
    const axfrQueries = dnsQueries.filter(q => q.dnsQueryType === 252 || q.dnsQueryType === 251);
    acc.push({
      insightId: insightId("dns-adv", idx++),
      type: "dns_anomaly",
      severity: "warning",
      packetIds: axfrQueries.map(p => p.packetId),
      description: `DNS Zone Transfer 尝试：${axfrQueries.map(q => `${typeMap[q.dnsQueryType ?? 0] || q.dnsQueryType} ${q.dnsQueryName}`).join(", ")}`,
      detail: { queries: axfrQueries.map(q => ({ type: typeMap[q.dnsQueryType ?? 0], domain: q.dnsQueryName, srcIp: q.srcIp })) },
      scenario: "AXFR/IXFR 是 DNS Zone Transfer 请求，正常情况下只应来自授权的辅助 DNS 服务器。未经授权的请求可能是信息收集或攻击行为。"
    });
  }
  // Report unusual type distribution
  const unusualTypes = [...typeCounts.entries()].filter(([t]) => !["A", "AAAA", "CNAME", "PTR", "MX", "NS", "SRV", "TXT", "OPT"].includes(t));
  if (unusualTypes.length && dnsQueries.length >= 10) {
    const unusualTotal = unusualTypes.reduce((s, [, c]) => s + c, 0);
    if (unusualTotal / dnsQueries.length > 0.2) {
      acc.push({
        insightId: insightId("dns-adv", idx++),
        type: "dns_anomaly",
        severity: "info",
        packetIds: [],
        description: `DNS 查询类型分布：${[...typeCounts.entries()].map(([t, c]) => `${t}(${c})`).join(", ")}`,
        detail: { types: Object.fromEntries(typeCounts) },
        scenario: "非标准查询类型占比高，可能是 DNSSEC 部署、DNS tunnel、或特定应用协议"
      });
    }
  }

  // 6. DNS TTL analysis
  const ttls = dnsReplies.filter(p => p.dnsTtl != null && p.dnsTtl > 0).map(p => p.dnsTtl!);
  if (ttls.length >= 10) {
    const lowTtl = ttls.filter(t => t <= 10);
    if (lowTtl.length / ttls.length > 0.3) {
      acc.push({
        insightId: insightId("dns-adv", idx++),
        type: "dns_anomaly",
        severity: "info",
        packetIds: [],
        description: `${lowTtl.length}/${ttls.length} 个 DNS 响应 TTL ≤10s（DNS 负载均衡/GSLB 特征）`,
        detail: { lowTtlCount: lowTtl.length, totalTtls: ttls.length, minTtl: Math.min(...ttls), avgTtl: ttls.reduce((a, b) => a + b, 0) / ttls.length },
        scenario: "极低 TTL 是 DNS 负载均衡（GSLB、CDN）的典型特征。负面影响：增加 DNS 查询量、DNS 不可用时影响更大。"
      });
    }
  }

  // 7. CNAME chain depth
  const cnameReplies = dnsReplies.filter(p => p.dnsCname);
  if (cnameReplies.length >= 3) {
    // Check for long CNAME chains in same reply
    const longCnames = cnameReplies.filter(p => p.dnsCname && p.dnsCname.split(",").length >= 3);
    if (longCnames.length) {
      acc.push({
        insightId: insightId("dns-adv", idx++),
        type: "dns_anomaly",
        severity: "info",
        packetIds: longCnames.slice(0, 5).map(p => p.packetId),
        description: `${longCnames.length} 个 DNS 响应包含 ≥3 级 CNAME 链`,
        detail: { longChainCount: longCnames.length, example: longCnames[0]?.dnsCname?.slice(0, 100) },
        scenario: "长 CNAME 链增加 DNS 解析延迟（每个 CNAME 需要额外查询）。常见于 CDN 和第三方服务。"
      });
    }
  }

  // 8. DNS truncated (TC flag) — UDP response too large
  const truncated = dnsReplies.filter(p => p.dnsTruncated);
  if (truncated.length >= 1) {
    acc.push({
      insightId: insightId("dns-adv", idx++),
      type: "dns_anomaly",
      severity: "info",
      packetIds: truncated.map(p => p.packetId),
      description: `${truncated.length} 个 DNS 响应被截断（TC=1），客户端应回退到 TCP 查询`,
      detail: { truncatedCount: truncated.length, domains: [...new Set(truncated.map(p => p.dnsQueryName))] },
      scenario: "DNS 响应超过 UDP 限制（通常 512B）被截断。客户端需要通过 TCP 重新查询。如果 TCP 53 被防火墙阻断，则解析失败。"
    });
  }

  // 9. DNS response with zero answers
  const zeroAnswers = dnsReplies.filter(p => p.dnsAnswerCount === 0 && p.dnsRcode === 0);
  if (zeroAnswers.length >= 3) {
    acc.push({
      insightId: insightId("dns-adv", idx++),
      type: "dns_anomaly",
      severity: "info",
      packetIds: zeroAnswers.slice(0, 5).map(p => p.packetId),
      description: `${zeroAnswers.length} 个 DNS 响应 NOERROR 但 0 条回答（NODATA）`,
      detail: { nodataCount: zeroAnswers.length, domains: [...new Set(zeroAnswers.map(p => p.dnsQueryName))] },
      scenario: "NOERROR + 0 回答（NODATA）说明域名存在但请求的类型没有记录。例如请求 A 记录但只有 AAAA 记录。"
    });
  }
}

// ── Advanced ICMP Analyzers ───────────────────────────────────────────

function analyzeIcmpAdvanced(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const icmpPackets = packets.filter(p => p.protocol.toLowerCase() === "icmp" || p.protocol.toLowerCase() === "icmpv6");
  if (!icmpPackets.length) return;

  // 1. ICMP type/code full distribution
  const typeCodeCounts = new Map<string, number>();
  const typeDesc: Record<number, string> = { 0: "Echo Reply", 3: "Unreachable", 5: "Redirect", 8: "Echo", 11: "TTL Exceeded", 12: "Parameter Problem", 13: "Timestamp", 14: "Timestamp Reply" };
  const unreachableDesc: Record<number, string> = { 0: "Network Unreachable", 1: "Host Unreachable", 2: "Protocol Unreachable", 3: "Port Unreachable", 4: "Fragmentation Needed", 5: "Source Route Failed", 6: "Network Unknown", 7: "Host Unknown", 9: "Network Admin Prohibited", 10: "Host Admin Prohibited", 13: "Communication Admin Prohibited", 14: "Host Precedence Violation" };

  for (const p of icmpPackets) {
    const key = `${p.icmpType}/${p.icmpCode}`;
    typeCodeCounts.set(key, (typeCodeCounts.get(key) || 0) + 1);
  }

  // 2. Unreachable sub-type analysis
  const unreachable = icmpPackets.filter(p => p.icmpType === 3);
  if (unreachable.length >= 1) {
    const bySubType = new Map<string, PacketSummary[]>();
    for (const p of unreachable) {
      const desc = unreachableDesc[p.icmpCode ?? -1] || `Code ${p.icmpCode}`;
      const arr = bySubType.get(desc) || [];
      arr.push(p);
      bySubType.set(desc, arr);
    }
    const lines = [...bySubType.entries()].map(([desc, pkts]) => `${desc}: ${pkts.length} 次`);
    acc.push({
      insightId: insightId("icmp-adv", idx++),
      type: "icmp_unreachable",
      severity: "warning",
      packetIds: unreachable.slice(0, 20).map(p => p.packetId),
      description: `ICMP Unreachable ${unreachable.length} 次：${lines.join(", ")}`,
      detail: { total: unreachable.length, byType: Object.fromEntries([...bySubType.entries()].map(([d, pkts]) => [d, pkts.length])), sources: [...new Set(unreachable.map(p => p.srcIp))] },
      scenario: unreachable.some(p => p.icmpCode === 3) ? "Port Unreachable 说明目标端口无服务监听，可能是服务挂了或端口被关闭" : unreachable.some(p => p.icmpCode === 4) ? "Fragmentation Needed 说明 Path MTU Discovery 失败，可能是 ICMP 被过滤导致黑洞" : "Unreachable 消息说明数据包无法到达目标，结合拓扑判断是哪一跳设备发的"
    });
  }

  // 3. ICMP burst/rate limiting
  if (icmpPackets.length >= 20) {
    const sorted = [...icmpPackets].sort((a, b) => a.timestamp - b.timestamp);
    for (let i = 19; i < sorted.length; i++) {
      const span = sorted[i].timestamp - sorted[i - 19].timestamp;
      if (span < 1) {
        acc.push({
          insightId: insightId("icmp-adv", idx++),
          type: "icmp_unreachable",
          severity: "info",
          packetIds: sorted.slice(i - 19, i + 1).map(p => p.packetId),
          description: `ICMP 突发：20 条消息在 ${span.toFixed(3)}s 内`,
          detail: { messagesPerSec: 20 / span, types: Object.fromEntries(typeCodeCounts) },
          scenario: "ICMP 消息突发可能是网络问题导致的级联效应，或 ICMP 速率限制失效"
        });
        break;
      }
    }
  }

  // 4. Ping sweep detection
  const echoes = icmpPackets.filter(p => p.icmpType === 8);
  if (echoes.length >= 10) {
    const dstIps = new Set(echoes.map(p => p.dstIp));
    if (dstIps.size >= 10) {
      acc.push({
        insightId: insightId("icmp-adv", idx++),
        type: "icmp_unreachable",
        severity: "info",
        packetIds: echoes.slice(0, 20).map(p => p.packetId),
        description: `Ping sweep 嫌疑：${echoes[0].srcIp} 向 ${dstIps.size} 个不同目标发 ICMP Echo`,
        detail: { srcIp: echoes[0].srcIp, targetCount: dstIps.size, targets: [...dstIps].slice(0, 10) },
        scenario: "顺序 ping 多个 IP 可能是网络扫描（Nmap 等）、存活检测、或监控工具"
      });
    }
  }

  // 5. ICMP error ↔ TCP/UDP flow correlation
  for (const p of unreachable) {
    const nearbyTcp = packets.find(tcp =>
      tcp.protocol.toLowerCase() === "tcp"
      && tcp.srcIp === p.srcIp
      && tcp.timestamp >= p.timestamp - 0.1 && tcp.timestamp <= p.timestamp + 0.1
    );
    if (nearbyTcp) {
      acc.push({
        insightId: insightId("icmp-adv", idx++),
        type: "icmp_unreachable",
        severity: "warning",
        packetIds: [p.packetId, nearbyTcp.packetId],
        description: `ICMP ${unreachableDesc[p.icmpCode ?? -1] || `Unreachable(Code ${p.icmpCode})`} 来自 ${p.srcIp}，对应 TCP 流量到 ${nearbyTcp.dstIp}:${nearbyTcp.dstPort}`,
        detail: { icmpSrcIp: p.srcIp, icmpType: p.icmpType, icmpCode: p.icmpCode, tcpDstIp: nearbyTcp.dstIp, tcpDstPort: nearbyTcp.dstPort, description: unreachableDesc[p.icmpCode ?? -1] },
        scenario: "中间设备返回 ICMP Unreachable，说明数据包在到达目标前被丢弃。结合拓扑判断是哪个设备发的。"
      });
    }
  }

  // 6. Traceroute pattern: sequential TTL exceeded with decreasing source IPs
  const ttlExceeded = icmpPackets.filter(p => p.icmpType === 11).sort((a, b) => a.timestamp - b.timestamp);
  if (ttlExceeded.length >= 3) {
    const hops = ttlExceeded.map(p => p.srcIp);
    const uniqueHops = [...new Set(hops)];
    if (uniqueHops.length >= 3) {
      acc.push({
        insightId: insightId("icmp-adv", idx++),
        type: "icmp_unreachable",
        severity: "info",
        packetIds: ttlExceeded.map(p => p.packetId),
        description: `Traceroute 模式：${uniqueHops.length} 跳（${uniqueHops.join(" → ")}）`,
        detail: { hops: uniqueHops, hopCount: uniqueHops.length, dstIp: [...new Set(ttlExceeded.map(p => p.dstIp))] },
        scenario: "数据包经过的网络路径，可用于识别中间设备和判断延迟来源"
      });
    }
  }

  // 7. Precise Echo/Reply matching using icmpIdent + icmpSeq
  if (echoes.length >= 2) {
    const replies = icmpPackets.filter(p => p.icmpType === 0);
    const matchedById = new Map<string, { echo: PacketSummary; reply?: PacketSummary; rttMs?: number }>();
    for (const echo of echoes) {
      if (echo.icmpIdent == null && echo.icmpSeq == null) continue;
      const key = `${echo.icmpIdent}-${echo.icmpSeq}`;
      if (matchedById.has(key)) continue;
      const reply = replies.find(r =>
        r.icmpIdent === echo.icmpIdent && r.icmpSeq === echo.icmpSeq
        && r.srcIp === echo.dstIp && r.dstIp === echo.srcIp
        && r.timestamp >= echo.timestamp && r.timestamp - echo.timestamp < 30
      );
      matchedById.set(key, {
        echo,
        reply,
        rttMs: reply ? (reply.timestamp - echo.timestamp) * 1000 : undefined
      });
    }
    const rtts = [...matchedById.values()].filter(m => m.rttMs != null).map(m => m.rttMs!);
    const lost = [...matchedById.values()].filter(m => !m.reply).length;
    const total = matchedById.size;
    if (total >= 1) {
      // Check for loss + RTT stats
      if (lost > 0 && lost / total > 0.1) {
        acc.push({
          insightId: insightId("icmp-adv", idx++),
          type: "icmp_echo_pair",
          severity: lost / total > 0.5 ? "critical" : "warning",
          packetIds: [...matchedById.values()].flatMap(m => [m.echo.packetId, m.reply?.packetId]).filter(Boolean) as string[],
          description: `${echoes[0].srcIp} → ${echoes[0].dstIp}: ICMP 丢包 ${lost}/${total}（${(lost / total * 100).toFixed(0)}%）`,
          detail: { total, lost, lossRate: lost / total },
          scenario: "链路丢包、对端 ICMP 被过滤、或中间设备限速"
        });
      }
    }
  }

  // 8. Path MTU Discovery failure (DF=1 + ICMP fragmentation needed)
  const fragNeeded = icmpPackets.filter(p => p.icmpType === 3 && p.icmpCode === 4);
  if (fragNeeded.length >= 1) {
    acc.push({
      insightId: insightId("icmp-adv", idx++),
      type: "icmp_mtu",
      severity: "warning",
      packetIds: fragNeeded.map(p => p.packetId),
      description: `ICMP Fragmentation Needed：${fragNeeded.length} 次（Path MTU Discovery 问题）`,
      detail: { count: fragNeeded.length, nextHopMtu: fragNeeded[0].icmpMtuNextHop, from: [...new Set(fragNeeded.map(p => p.srcIp))] },
      scenario: "中间设备报告需要分片但 DF=1 不允许分片。会导致 TCP 连接挂起（黑洞问题）。建议：调整 MSS 或启用 ICMP Fragmentation Needed 放行。"
    });
  }

  // 9. ICMP Redirect
  const redirects = icmpPackets.filter(p => p.icmpType === 5);
  if (redirects.length >= 1) {
    const redirectDesc: Record<number, string> = { 0: "Network Redirect", 1: "Host Redirect", 2: "TOS Network Redirect", 3: "TOS Host Redirect" };
    acc.push({
      insightId: insightId("icmp-adv", idx++),
      type: "icmp_redirect",
      severity: "warning",
      packetIds: redirects.map(p => p.packetId),
      description: `ICMP Redirect ${redirects.length} 次：${redirects.map(p => redirectDesc[p.icmpCode ?? 0] || `Code ${p.icmpCode}`).join(", ")}`,
      detail: { count: redirects.length, from: [...new Set(redirects.map(p => p.srcIp))], codes: [...new Set(redirects.map(p => p.icmpCode))] },
      scenario: "路由器发送 ICMP Redirect 说明有更优路径。可能是路由配置问题，也可能被利用进行中间人攻击。"
    });
  }

  // 10. ICMP black hole detection: TCP with DF=1 and no response + no ICMP
  const tcpWithDf = packets.filter(p => p.protocol.toLowerCase() === "tcp" && p.ipDf && p.tcpPayloadLength != null && p.tcpPayloadLength > 1000);
  if (tcpWithDf.length >= 1) {
    // Check if these packets have no ACK and no ICMP Fragmentation Needed
    const suspicious = tcpWithDf.filter(p => {
      const hasAck = packets.find(ack =>
        ack.srcIp === p.dstIp && ack.dstIp === p.srcIp
        && ack.tcpFlags.map(f => f.toUpperCase()).includes("ACK")
        && ack.timestamp > p.timestamp && ack.timestamp - p.timestamp < 5
      );
      const hasIcmpFrag = fragNeeded.find(icmp =>
        icmp.timestamp > p.timestamp && icmp.timestamp - p.timestamp < 5
        && icmp.srcIp === p.dstIp
      );
      return !hasAck && !hasIcmpFrag;
    });
    if (suspicious.length >= 3) {
      acc.push({
        insightId: insightId("icmp-adv", idx++),
        type: "icmp_mtu",
        severity: "warning",
        packetIds: suspicious.slice(0, 10).map(p => p.packetId),
        description: `疑似 ICMP 黑洞：${suspicious.length} 个大包（DF=1）无 ACK 也无 ICMP Fragmentation Needed`,
        detail: { count: suspicious.length, dstIps: [...new Set(suspicious.map(p => p.dstIp))], avgPayloadSize: suspicious.reduce((s, p) => s + (p.tcpPayloadLength ?? 0), 0) / suspicious.length },
        scenario: "TCP 大包（DF=1）在网络中消失，没有 ACK 也没有 ICMP 错误。这是经典的 Path MTU Discovery 黑洞问题——防火墙丢弃了大包但也丢弃了 ICMP Fragmentation Needed 消息。"
      });
    }
  }
}

// ── Analyzer: QUIC ────────────────────────────────────────────────────

function analyzeQuic(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const quicPackets = packets.filter(p => p.quicVersion || p.quicConnectionId);
  if (!quicPackets.length) return;

  // 1. QUIC 版本分布
  const allVersions = [...new Set(quicPackets.map(p => p.quicVersion).filter(Boolean))];

  // 2. QUIC 连接汇总
  const byConnId = new Map<string, PacketSummary[]>();
  for (const p of quicPackets) {
    const cid = p.quicConnectionId || "unknown";
    const arr = byConnId.get(cid) || [];
    arr.push(p);
    byConnId.set(cid, arr);
  }

  for (const [cid, pkts] of byConnId) {
    const versions = [...new Set(pkts.map(p => p.quicVersion).filter(Boolean))];
    const packetTypes = [...new Set(pkts.map(p => p.quicPacketType).filter(Boolean))];
    const srcIps = [...new Set(pkts.map(p => p.srcIp).filter(Boolean))];
    const dstIps = [...new Set(pkts.map(p => p.dstIp).filter(Boolean))];

    acc.push({
      insightId: insightId("quic", idx++),
      type: "quic_anomaly",
      severity: "info",
      packetIds: pkts.slice(0, 20).map(p => p.packetId),
      description: `QUIC 连接 ${cid.slice(0, 12)}：${pkts.length} 包，版本 ${versions.join("/") || "?"}，类型 ${packetTypes.join(", ") || "unknown"}`,
      detail: { connectionId: cid, version: versions, packetTypes, srcIps, dstIps, packetCount: pkts.length },
      scenario: "QUIC 连接概览"
    });
  }

  // 2. QUIC 握手分析
  const initialPackets = quicPackets.filter(p => p.quicPacketType === "0" || p.quicPacketType?.toLowerCase().includes("initial"));
  const handshakePackets = quicPackets.filter(p => p.quicPacketType === "2" || p.quicPacketType?.toLowerCase().includes("handshake"));
  if (initialPackets.length > 0 && handshakePackets.length === 0) {
    acc.push({
      insightId: insightId("quic", idx++),
      type: "quic_anomaly",
      severity: "info",
      packetIds: initialPackets.slice(0, 10).map(p => p.packetId),
      description: `QUIC Initial 包 ${initialPackets.length} 个但无 Handshake 响应`,
      detail: { initialCount: initialPackets.length, handshakeCount: 0 },
      scenario: "QUIC 握手未完成，服务端可能不支持该版本或端口被阻止"
    });
  }

  // 3. QUIC 版本不匹配
  if (allVersions.length > 1) {
    const verCounts = new Map<string, number>();
    for (const p of quicPackets) {
      if (p.quicVersion) verCounts.set(p.quicVersion, (verCounts.get(p.quicVersion) || 0) + 1);
    }
    acc.push({
      insightId: insightId("quic", idx++),
      type: "quic_anomaly",
      severity: "info",
      packetIds: quicPackets.slice(0, 10).map(p => p.packetId),
      description: `QUIC 版本不一致：${[...verCounts.entries()].map(([v, c]) => `${v}(${c})`).join(", ")}`,
      detail: { versions: Object.fromEntries(verCounts) },
      scenario: "客户端和服务端可能协商了不同 QUIC 版本，检查版本兼容性"
    });
  }
}

// ── Analyzer: NTP ─────────────────────────────────────────────────────

function analyzeNtp(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const ntpPackets = packets.filter(p => p.ntpStratum != null || p.ntpRefid);
  if (!ntpPackets.length) return;

  // 1. NTP 分层统计
  const stratums = ntpPackets.filter(p => p.ntpStratum != null).map(p => p.ntpStratum!);
  const stratumCounts = new Map<number, number>();
  for (const s of stratums) stratumCounts.set(s, (stratumCounts.get(s) || 0) + 1);

  acc.push({
    insightId: insightId("ntp", idx++),
    type: "ntp_anomaly",
    severity: "info",
    packetIds: ntpPackets.slice(0, 20).map(p => p.packetId),
    description: `NTP 包 ${ntpPackets.length} 个，Stratum 分布：${[...stratumCounts.entries()].map(([s, c]) => `stratum-${s}(${c})`).join(", ")}`,
    detail: { packetCount: ntpPackets.length, stratums: Object.fromEntries(stratumCounts), refIds: [...new Set(ntpPackets.map(p => p.ntpRefid).filter(Boolean))] },
    scenario: "NTP 时间同步概览"
  });

  // 2. 高 Stratum（可能离参考时钟很远）
  const highStratum = ntpPackets.filter(p => p.ntpStratum != null && p.ntpStratum >= 10);
  if (highStratum.length > 0) {
    acc.push({
      insightId: insightId("ntp", idx++),
      type: "ntp_anomaly",
      severity: "info",
      packetIds: highStratum.slice(0, 10).map(p => p.packetId),
      description: `NTP Stratum >= 10：${highStratum.length} 个包，时间源质量差`,
      detail: { highStratumCount: highStratum.length, maxStratum: Math.max(...highStratum.map(p => p.ntpStratum!)) },
      scenario: "NTP 时间源 Stratum 过高，时钟精度不可靠"
    });
  }

  // 3. NTP 延迟分析
  const withDelay = ntpPackets.filter(p => p.ntpRootdelay != null && p.ntpRootdelay > 0);
  if (withDelay.length > 0) {
    const delays = withDelay.map(p => p.ntpRootdelay!);
    const avgDelay = delays.reduce((a, b) => a + b, 0) / delays.length;
    const maxDelay = Math.max(...delays);
    acc.push({
      insightId: insightId("ntp", idx++),
      type: "ntp_anomaly",
      severity: "info",
      packetIds: withDelay.slice(0, 10).map(p => p.packetId),
      description: `NTP Root Delay：平均 ${avgDelay.toFixed(2)}ms，最大 ${maxDelay.toFixed(2)}ms（${withDelay.length} 样本）`,
      detail: { avgDelay, maxDelay, minDelay: Math.min(...delays), sampleCount: withDelay.length },
      scenario: "NTP 根延迟反映到参考时钟的网络距离"
    });
  }
}

// ── Analyzer: SSH ─────────────────────────────────────────────────────

function analyzeSsh(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;
  const sshPackets = packets.filter(p => p.sshMessage || p.sshDirection || p.sshProtocol);
  if (!sshPackets.length) return;

  // 1. SSH 消息类型分布
  const msgTypes = new Map<string, number>();
  for (const p of sshPackets) {
    if (p.sshMessage) msgTypes.set(p.sshMessage, (msgTypes.get(p.sshMessage) || 0) + 1);
  }

  acc.push({
    insightId: insightId("ssh", idx++),
    type: "ssh_anomaly",
    severity: "info",
    packetIds: sshPackets.slice(0, 20).map(p => p.packetId),
    description: `SSH 会话 ${sshPackets.length} 包，消息类型：${[...msgTypes.entries()].map(([m, c]) => `${m}(${c})`).join(", ")}`,
    detail: { packetCount: sshPackets.length, messageTypes: Object.fromEntries(msgTypes), srcIps: [...new Set(sshPackets.map(p => p.srcIp).filter(Boolean))], dstIps: [...new Set(sshPackets.map(p => p.dstIp).filter(Boolean))] },
    scenario: "SSH 会话概览"
  });

  // 2. SSH 断开
  const disconnects = sshPackets.filter(p => p.sshMessage?.toLowerCase().includes("disconnect") || p.sshMessage === "MSG_DISCONNECT");
  if (disconnects.length > 0) {
    acc.push({
      insightId: insightId("ssh", idx++),
      type: "ssh_anomaly",
      severity: "info",
      packetIds: disconnects.map(p => p.packetId),
      description: `SSH 断开消息 ${disconnects.length} 次`,
      detail: { disconnectCount: disconnects.length, sources: [...new Set(disconnects.map(p => p.srcIp).filter(Boolean))] },
      scenario: "SSH 连接被主动断开，可能是认证失败、超时、或服务端拒绝"
    });
  }

  // 3. SSH 认证失败（多次重试）
  const authMessages = sshPackets.filter(p => p.sshMessage?.toLowerCase().includes("auth") || p.sshMessage?.toLowerCase().includes("failure"));
  if (authMessages.length >= 2) {
    acc.push({
      insightId: insightId("ssh", idx++),
      type: "ssh_anomaly",
      severity: "info",
      packetIds: authMessages.map(p => p.packetId),
      description: `SSH 认证相关消息 ${authMessages.length} 次，可能存在认证重试`,
      detail: { authMessageCount: authMessages.length, messages: authMessages.map(p => p.sshMessage).filter(Boolean) },
      scenario: "SSH 认证重试可能是密码错误、密钥不匹配、或暴力破解尝试"
    });
  }

  // 4. SSH 协议版本
  const protocols = [...new Set(sshPackets.map(p => p.sshProtocol).filter(Boolean))];
  if (protocols.length > 0) {
    acc.push({
      insightId: insightId("ssh", idx++),
      type: "ssh_anomaly",
      severity: "info",
      packetIds: sshPackets.filter(p => p.sshProtocol).slice(0, 5).map(p => p.packetId),
      description: `SSH 协议版本：${protocols.join(", ")}`,
      detail: { protocols },
      scenario: "SSH 协议版本信息"
    });
  }
}

// ── Analyzer: L7 Proxy Detection ──────────────────────────────────────

function analyzeL7ProxyDetection(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  const tcpPackets = packets.filter(p => p.protocol.toLowerCase() === "tcp");
  const httpRequests = packets.filter(p => p.httpRequestMethod);
  const httpResponses = packets.filter(p => p.httpResponseCode != null);

  // 1. Via 头检测——存在即表明经过代理
  const viaResponses = httpResponses.filter(p => p.httpVia);
  if (viaResponses.length > 0) {
    const viaValues = [...new Set(viaResponses.map(p => p.httpVia!).filter(Boolean))];
    acc.push({
      insightId: insightId("l7-proxy", idx++),
      type: "l7_proxy_detected",
      severity: "info",
      packetIds: viaResponses.map(p => p.packetId).slice(0, 10),
      description: `检测到 HTTP Via 头，表明存在中间代理（${viaValues.join(", ")}）`,
      detail: { viaValues, count: viaResponses.length },
      scenario: "Via 头表明请求经过了 HTTP 代理、CDN 或反向代理"
    });
  }

  // 2. XFF 头检测——可能暴露客户端真实 IP 和代理链
  const xffResponses = httpResponses.filter(p => p.httpXForwardedFor);
  if (xffResponses.length > 0) {
    const xffIps = [...new Set(xffResponses.flatMap(p => p.httpXForwardedFor!.split(",").map(s => s.trim())))];
    acc.push({
      insightId: insightId("l7-proxy", idx++),
      type: "l7_proxy_detected",
      severity: "info",
      packetIds: xffResponses.map(p => p.packetId).slice(0, 10),
      description: `检测到 X-Forwarded-For 头，客户端真实 IP 可能是 ${xffIps.join(", ")}`,
      detail: { xffIps, count: xffResponses.length },
      scenario: "XFF 头表明请求经过了一层或多层代理/LB，可用于还原真实客户端地址"
    });
  }

  // 3. TLS + 明文 HTTP 时序异常——同一时间窗口内客户端一侧用 TLS，服务端一侧用明文 HTTP
  const tlsClientHellos = packets.filter(p => p.tlsHandshakeType === 1);
  if (tlsClientHellos.length > 0 && httpRequests.length > 0) {
    const tlsIps = new Set(tlsClientHellos.flatMap(p => [p.srcIp, p.dstIp].filter(Boolean)));
    const httpIps = new Set(httpRequests.flatMap(p => [p.srcIp, p.dstIp].filter(Boolean)));
    const overlap = [...tlsIps].filter(ip => httpIps.has(ip));
    if (overlap.length > 0) {
      acc.push({
        insightId: insightId("l7-proxy", idx++),
        type: "l7_proxy_detected",
        severity: "warning",
        packetIds: [...tlsClientHellos.slice(0, 3), ...httpRequests.slice(0, 3)].map(p => p.packetId),
        description: `检测到 SSL 卸载模式：IP ${overlap.join(", ")} 同时参与 TLS 握手和明文 HTTP 通信`,
        detail: { overlapIps: overlap },
        scenario: "七层代理/SSL 卸载设备终止客户端 TLS 连接，用明文 HTTP 向后端发请求"
      });
    }
  }

  // 4. TCP 连接分离检测——相近时间窗口内出现两组不同五元组的 TCP 连接
  if (tcpPackets.length > 4) {
    const synPackets = tcpPackets.filter(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && !flags.includes("ACK") && p.srcIp && p.dstIp;
    });
    if (synPackets.length >= 2) {
      const bySrcIp = new Map<string, PacketSummary[]>();
      for (const syn of synPackets) {
        const group = bySrcIp.get(syn.srcIp!) || [];
        group.push(syn);
        bySrcIp.set(syn.srcIp!, group);
      }

      for (const [srcIp, syns] of bySrcIp) {
        if (syns.length < 2) continue;
        const targets = [...new Set(syns.map(s => `${s.dstIp}:${s.dstPort}`))];
        if (targets.length < 2) continue;

        const times = syns.map(s => s.timestamp).sort((a, b) => a - b);
        if (times[times.length - 1] - times[0] > 5) continue;

        acc.push({
          insightId: insightId("l7-proxy", idx++),
          type: "tcp_connection_split",
          severity: "info",
          packetIds: syns.map(p => p.packetId).slice(0, 10),
          description: `${srcIp} 在 ${(times[times.length - 1] - times[0]).toFixed(1)}s 内向 ${targets.length} 个不同目标发 SYN（${targets.join(", ")}）`,
          detail: { srcIp, targets, timeSpan: times[times.length - 1] - times[0] },
          scenario: "同一客户端短时间内连接多个不同后端，可能是代理/LB 分发、重试、或连接池行为"
        });
      }
    }
  }
}

// ── Analyzer: NAT Heuristic Detection ────────────────────────────────

function analyzeNatHeuristic(packets: PacketSummary[], acc: InsightAccumulator) {
  let idx = acc.length;

  const tcpPackets = packets.filter(p =>
    p.protocol.toLowerCase() === "tcp" && p.srcIp && p.dstIp
  );
  if (tcpPackets.length < 4) return;

  const synPackets = tcpPackets.filter(p => {
    const flags = p.tcpFlags.map(f => f.toUpperCase());
    return flags.includes("SYN") && !flags.includes("ACK");
  });

  // 1. 同一 srcIp 连接多个不同 dstIp（NAT 端口分配模式）
  if (synPackets.length >= 3) {
    const bySrcIp = new Map<string, PacketSummary[]>();
    for (const syn of synPackets) {
      const group = bySrcIp.get(syn.srcIp!) || [];
      group.push(syn);
      bySrcIp.set(syn.srcIp!, group);
    }

    for (const [srcIp, syns] of bySrcIp) {
      if (syns.length < 3) continue;
      const srcPorts = syns.map(s => s.srcPort!).sort((a, b) => a - b);
      const uniqueDstIps = [...new Set(syns.map(s => s.dstIp!))];

      if (uniqueDstIps.length >= 3) {
        acc.push({
          insightId: insightId("nat-heuristic", idx++),
          type: "nat_heuristic",
          severity: "info",
          packetIds: syns.map(p => p.packetId).slice(0, 10),
          description: `${srcIp} 向 ${uniqueDstIps.length} 个不同 IP 发起连接（端口范围 ${srcPorts[0]}-${srcPorts[srcPorts.length - 1]}），可能经过 NAT`,
          detail: {
            srcIp,
            dstIps: uniqueDstIps,
            connectionCount: syns.length,
            portRange: srcPorts[srcPorts.length - 1] - srcPorts[0],
            srcPorts: srcPorts.slice(0, 10)
          },
          scenario: "NAT 后的设备通常表现为单一 IP 向多个目标发起连接，端口频繁变化"
        });
      }
    }
  }

  // 2. TCP ISN 跳跃异常——暗示中间设备干预
  if (synPackets.length >= 2) {
    const byDst = new Map<string, PacketSummary[]>();
    for (const syn of synPackets) {
      const key = `${syn.srcIp}->${syn.dstIp}:${syn.dstPort}`;
      const group = byDst.get(key) || [];
      group.push(syn);
      byDst.set(key, group);
    }

    for (const [key, syns] of byDst) {
      if (syns.length < 2) continue;
      const seqs = syns.map(s => s.tcpSeq).filter((s): s is number => s != null);
      if (seqs.length < 2) continue;

      for (let i = 1; i < seqs.length; i++) {
        const diff = Math.abs(seqs[i] - seqs[i - 1]);
        if (diff > 100_000_000) {
          acc.push({
            insightId: insightId("nat-heuristic", idx++),
            type: "nat_heuristic",
            severity: "info",
            packetIds: syns.map(p => p.packetId).slice(0, 5),
            description: `${key} 的 TCP ISN 跳跃异常（差值 ${(diff / 1_000_000).toFixed(0)}M），可能存在中间设备`,
            detail: { key, seqs, diff },
            scenario: "TCP ISN 的异常跳跃可能表明中间设备（NAT/FW）修改了序列号"
          });
          break;
        }
      }
    }
  }

  // 3. 孤立 SYN——无对应 SYN/ACK（NAT 映射丢失或防火墙丢弃）
  if (synPackets.length >= 2) {
    const synAckPackets = tcpPackets.filter(p => {
      const flags = p.tcpFlags.map(f => f.toUpperCase());
      return flags.includes("SYN") && flags.includes("ACK");
    });

    const orphanSyns = synPackets.filter(syn => {
      return !synAckPackets.some(sa =>
        sa.srcIp === syn.dstIp && sa.dstIp === syn.srcIp
        && sa.srcPort === syn.dstPort && sa.dstPort === syn.srcPort
      );
    });

    if (orphanSyns.length >= 2) {
      const orphanTargets = [...new Set(orphanSyns.map(s => `${s.dstIp}:${s.dstPort}`))];
      acc.push({
        insightId: insightId("nat-heuristic", idx++),
        type: "nat_heuristic",
        severity: "warning",
        packetIds: orphanSyns.map(p => p.packetId).slice(0, 10),
        description: `${orphanSyns.length} 个 SYN 未收到 SYN/ACK（目标：${orphanTargets.join(", ")}）`,
        detail: {
          orphanCount: orphanSyns.length,
          targets: orphanTargets,
          srcIps: [...new Set(orphanSyns.map(s => s.srcIp!))]
        },
        scenario: "SYN 无 SYN/ACK 可能是服务端不响应、防火墙丢弃、或 NAT 映射丢失"
      });
    }
  }
}

// ── Main Engine ───────────────────────────────────────────────────────

export function runLevel1Insights(graph: CaseGraph): PacketInsight[] {
  const packets = graph.packets;
  if (!packets.length) return [];

  const acc: InsightAccumulator = [];

  // TCP-based analysis
  const connections = extractTcpConnections(packets);
  analyzeConnectionLifecycle(connections, acc);
  analyzeAckGap(connections, acc);
  analyzeTcpTiming(connections, acc);
  analyzeTcpWindowTrend(connections, acc);
  analyzeRstDirection(connections, acc);
  analyzeHandshakeRetry(connections, acc);
  analyzeDelayedAck(connections, acc);
  analyzeConnectionFlood(packets, acc);
  analyzeSegmentAnomaly(connections, acc);
  analyzeKeepalive(connections, acc);
  analyzeThroughput(connections, acc);
  analyzeTcpOptions(connections, acc);

  // Protocol-specific analysis
  analyzeIcmpEchoPair(packets, acc);
  analyzeHttpStatusChain(packets, acc);
  analyzeHttpHeaderAnomaly(packets, acc);
  analyzeHttpTiming(packets, acc);
  analyzeHttpAdvanced(packets, acc);
  analyzeTlsHandshake(packets, acc);
  analyzeTlsAdvanced(packets, acc);
  analyzeDnsAnomaly(packets, acc);
  analyzeDnsAdvanced(packets, acc);
  analyzeCrossProtocolChain(packets, acc);

  // UDP/ICMP advanced analysis
  analyzeUdp(packets, acc);
  analyzeIcmpAdvanced(packets, acc);

  // 新协议分析
  analyzeQuic(packets, acc);
  analyzeNtp(packets, acc);
  analyzeSsh(packets, acc);

  // NAT / L7 代理检测
  analyzeL7ProxyDetection(packets, acc);
  analyzeNatHeuristic(packets, acc);

  return acc;
}
