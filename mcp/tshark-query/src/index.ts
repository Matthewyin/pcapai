import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const execFileAsync = promisify(execFile);
const server = new McpServer({ name: "tshark-query-mcp", version: "0.1.0" });

type CaptureInput = {
  nodeId: string;
  name: string;
  pcapFilename?: string;
  pcapPath?: string;
};

const PacketSchema = z.object({
  packetId: z.string(),
  nodeId: z.string(),
  pcapFilename: z.string(),
  frameNumber: z.number().int(),
  timestamp: z.number(),
  srcIp: z.string().optional(),
  srcPort: z.number().int().optional(),
  dstIp: z.string().optional(),
  dstPort: z.number().int().optional(),
  protocol: z.string(),
  tcpFlags: z.array(z.string()).default([]),
  tcpSeq: z.number().int().optional(),
  tcpAck: z.number().int().optional(),
  tcpPayloadLength: z.number().int().optional(),
  tcpWindowSize: z.number().int().optional(),
  tcpAnalysis: z.object({
    retransmission: z.boolean().default(false),
    fastRetransmission: z.boolean().default(false),
    duplicateAck: z.boolean().default(false),
    zeroWindow: z.boolean().default(false),
    lostSegment: z.boolean().default(false)
  }).default({
    retransmission: false,
    fastRetransmission: false,
    duplicateAck: false,
    zeroWindow: false,
    lostSegment: false
  }),
  icmpType: z.number().int().optional(),
  icmpCode: z.number().int().optional(),
  dnsId: z.string().optional(),
  dnsQueryName: z.string().optional(),
  dnsIsResponse: z.boolean().optional(),
  dnsRcode: z.number().int().optional(),
  dnsResponseAddress: z.string().optional(),
  tlsHandshakeType: z.number().int().optional(),
  tlsSni: z.string().optional(),
  tlsRecordVersion: z.string().optional(),
  tlsHandshakeVersion: z.string().optional(),
  tlsAlertLevel: z.number().int().optional(),
  tlsAlertDescription: z.number().int().optional(),
  httpRequestMethod: z.string().optional(),
  httpHost: z.string().optional(),
  httpRequestUri: z.string().optional(),
  httpResponseCode: z.number().int().optional(),
  httpResponseCodeDescription: z.string().optional(),
  httpRequestIn: z.number().int().optional(),
  httpResponseIn: z.number().int().optional(),
  httpTime: z.number().optional(),
  length: z.number().int().optional(),
  summary: z.string(),
  raw: z.record(z.string(), z.unknown()).default({})
});

const workspaceRoot = (() => {
  const candidates = [
    process.env.PCAPAI_ROOT ? path.resolve(process.env.PCAPAI_ROOT) : "",
    process.cwd(),
    path.resolve(process.cwd(), "../..")
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(path.join(candidate, "config/defaults.json"))) || process.cwd();
})();

const defaults = JSON.parse(readFileSync(path.join(workspaceRoot, "config/defaults.json"), "utf8")) as {
  mcp: { tshark: { command: string; capinfosCommand?: string; maxBufferBytes: number } };
};

const tsharkCommand = process.env.PCAPAI_TSHARK_COMMAND || defaults.mcp.tshark.command;
const capinfosCommand = process.env.PCAPAI_CAPINFOS_COMMAND || defaults.mcp.tshark.capinfosCommand || "capinfos";
const maxBuffer = Number(process.env.PCAPAI_TSHARK_MAX_BUFFER_BYTES || defaults.mcp.tshark.maxBufferBytes || 10485760);

const tsharkFields = [
  "frame.number",
  "frame.time_epoch",
  "ip.src",
  "ipv6.src",
  "tcp.srcport",
  "udp.srcport",
  "ip.dst",
  "ipv6.dst",
  "tcp.dstport",
  "udp.dstport",
  "_ws.col.Protocol",
  "tcp.flags.syn",
  "tcp.flags.ack",
  "tcp.flags.reset",
  "tcp.flags.fin",
  "tcp.flags.push",
  "tcp.seq",
  "tcp.ack",
  "tcp.len",
  "tcp.window_size_value",
  "tcp.analysis.retransmission",
  "tcp.analysis.fast_retransmission",
  "tcp.analysis.duplicate_ack",
  "tcp.analysis.zero_window",
  "tcp.analysis.lost_segment",
  "icmp.type",
  "icmp.code",
  "icmpv6.type",
  "icmpv6.code",
  "dns.id",
  "dns.qry.name",
  "dns.flags.response",
  "dns.flags.rcode",
  "dns.a",
  "dns.aaaa",
  "frame.len",
  "_ws.col.Info",
  "tls.handshake.type",
  "tls.handshake.extensions_server_name",
  "tls.record.version",
  "tls.handshake.version",
  "tls.alert_message.level",
  "tls.alert_message.desc",
  "http.request.method",
  "http.host",
  "http.request.uri",
  "http.response.code",
  "http.response.code.desc",
  "http.request_in",
  "http.response_in",
  "http.time"
];

const networkStatFields = [
  "ip.src",
  "ipv6.src",
  "ip.dst",
  "ipv6.dst",
  "tcp.srcport",
  "udp.srcport",
  "tcp.dstport",
  "udp.dstport",
  "tcp.flags.reset",
  "tcp.analysis.retransmission",
  "tcp.analysis.fast_retransmission",
  "http.response.code",
  "dns.flags.rcode"
];

function numberOrUndefined(value: string | undefined) {
  if (value === undefined || value.trim() === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseFlag(value: string, label: string) {
  return value === "1" || value.toLowerCase() === "true" ? [label] : [];
}

function isTrueField(value: string | undefined) {
  return value === "1" || value?.toLowerCase() === "true";
}

function incrementCount(map: Map<string, number>, key?: string) {
  if (!key) return;
  map.set(key, (map.get(key) || 0) + 1);
}

function countEntries(map: Map<string, number>) {
  return [...map.entries()]
    .map(([value, packetCount]) => ({ value, packetCount }))
    .sort((left, right) => right.packetCount - left.packetCount || left.value.localeCompare(right.value));
}

function portEntries(map: Map<string, number>) {
  return [...map.entries()]
    .map(([key, packetCount]) => {
      const [protocol, port] = key.split(":");
      return { protocol, port: Number(port), packetCount };
    })
    .sort((left, right) => right.packetCount - left.packetCount || left.protocol.localeCompare(right.protocol) || left.port - right.port);
}

function quoteFilterValue(value: string) {
  return value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"");
}

function buildDisplayFilter(input: { start?: number; end?: number; srcIp?: string; dstIp?: string; port?: number; protocol?: string }) {
  const parts: string[] = [];
  if (input.start !== undefined) parts.push(`frame.time_epoch >= ${input.start}`);
  if (input.end !== undefined) parts.push(`frame.time_epoch <= ${input.end}`);
  if (input.srcIp && input.dstIp) parts.push(`ip.addr == ${quoteFilterValue(input.srcIp)} && ip.addr == ${quoteFilterValue(input.dstIp)}`);
  else if (input.srcIp) parts.push(`ip.addr == ${quoteFilterValue(input.srcIp)}`);
  else if (input.dstIp) parts.push(`ip.addr == ${quoteFilterValue(input.dstIp)}`);
  const protocol = (input.protocol || "").toLowerCase();
  if (input.port !== undefined) parts.push(protocol === "udp" || protocol === "dns" ? `udp.port == ${input.port}` : `tcp.port == ${input.port}`);
  if (protocol === "tcp") parts.push("tcp");
  if (protocol === "udp") parts.push("udp");
  if (protocol === "dns") parts.push("dns");
  if (protocol === "tls") parts.push("tls");
  if (protocol === "http") parts.push("http");
  if (protocol === "icmp") parts.push("(icmp || icmpv6)");
  if (protocol === "arp") parts.push("arp");
  return parts.join(" && ") || "tcp";
}

export function parseTsharkRows(output: string, capture: CaptureInput) {
  return output.split("\n").filter(Boolean).map((line) => {
    const columns = line.split("\t");
    const [
      frameNumber,
      timestamp,
      ipSrc,
      ipv6Src,
      tcpSrcPort,
      udpSrcPort,
      ipDst,
      ipv6Dst,
      tcpDstPort,
      udpDstPort,
      protocol,
      syn,
      ack,
      reset,
      fin,
      push,
      tcpSeq,
      tcpAck,
      tcpPayloadLength,
      tcpWindowSize,
      retransmission,
      fastRetransmission,
      duplicateAck,
      zeroWindow,
      lostSegment,
      icmpType,
      icmpCode,
      icmpv6Type,
      icmpv6Code,
      dnsId,
      dnsQueryName,
      dnsIsResponse,
      dnsRcode,
      dnsA,
      dnsAaaa,
      frameLength,
      info,
      tlsHandshakeType,
      tlsSni,
      tlsRecordVersion,
      tlsHandshakeVersion,
      tlsAlertLevel,
      tlsAlertDescription,
      httpRequestMethod,
      httpHost,
      httpRequestUri,
      httpResponseCode,
      httpResponseCodeDescription,
      httpRequestIn,
      httpResponseIn,
      httpTime
    ] = columns;
    const parsedFrameNumber = Number(frameNumber);
    return PacketSchema.parse({
      packetId: `${capture.nodeId}:${parsedFrameNumber}`,
      nodeId: capture.nodeId,
      pcapFilename: capture.pcapFilename || path.basename(capture.pcapPath || ""),
      frameNumber: parsedFrameNumber,
      timestamp: Number(timestamp),
      srcIp: ipSrc || ipv6Src || undefined,
      srcPort: numberOrUndefined(tcpSrcPort || udpSrcPort),
      dstIp: ipDst || ipv6Dst || undefined,
      dstPort: numberOrUndefined(tcpDstPort || udpDstPort),
      protocol: (protocol || "unknown").toLowerCase(),
      tcpFlags: [
        ...parseFlag(syn, "SYN"),
        ...parseFlag(ack, "ACK"),
        ...parseFlag(reset, "RST"),
        ...parseFlag(fin, "FIN"),
        ...parseFlag(push, "PSH")
      ],
      tcpSeq: numberOrUndefined(tcpSeq),
      tcpAck: numberOrUndefined(tcpAck),
      tcpPayloadLength: numberOrUndefined(tcpPayloadLength),
      tcpWindowSize: numberOrUndefined(tcpWindowSize),
      tcpAnalysis: {
        retransmission: parseFlag(retransmission, "retransmission").length > 0,
        fastRetransmission: parseFlag(fastRetransmission, "fastRetransmission").length > 0,
        duplicateAck: parseFlag(duplicateAck, "duplicateAck").length > 0,
        zeroWindow: parseFlag(zeroWindow, "zeroWindow").length > 0,
        lostSegment: parseFlag(lostSegment, "lostSegment").length > 0
      },
      icmpType: numberOrUndefined(icmpType || icmpv6Type),
      icmpCode: numberOrUndefined(icmpCode || icmpv6Code),
      dnsId: dnsId || undefined,
      dnsQueryName: dnsQueryName || undefined,
      dnsIsResponse: dnsIsResponse ? dnsIsResponse === "1" || dnsIsResponse.toLowerCase() === "true" : undefined,
      dnsRcode: numberOrUndefined(dnsRcode),
      dnsResponseAddress: dnsA || dnsAaaa || undefined,
      tlsHandshakeType: numberOrUndefined(tlsHandshakeType),
      tlsSni: tlsSni || undefined,
      tlsRecordVersion: tlsRecordVersion || undefined,
      tlsHandshakeVersion: tlsHandshakeVersion || undefined,
      tlsAlertLevel: numberOrUndefined(tlsAlertLevel),
      tlsAlertDescription: numberOrUndefined(tlsAlertDescription),
      httpRequestMethod: httpRequestMethod || undefined,
      httpHost: httpHost || undefined,
      httpRequestUri: httpRequestUri || undefined,
      httpResponseCode: numberOrUndefined(httpResponseCode),
      httpResponseCodeDescription: httpResponseCodeDescription || undefined,
      httpRequestIn: numberOrUndefined(httpRequestIn),
      httpResponseIn: numberOrUndefined(httpResponseIn),
      httpTime: numberOrUndefined(httpTime),
      length: numberOrUndefined(frameLength),
      summary: info || "",
      raw: Object.fromEntries(tsharkFields.map((field, index) => [field, columns[index] || ""]))
    });
  });
}

export function parseNetworkStatisticsRows(output: string, capture: CaptureInput) {
  const ips = new Map<string, number>();
  const sourceIps = new Map<string, number>();
  const destinationIps = new Map<string, number>();
  const ports = new Map<string, number>();
  const sourcePorts = new Map<string, number>();
  const destinationPorts = new Map<string, number>();
  const httpStatusCodes = new Map<string, number>();
  const dnsRcodes = new Map<string, number>();
  let packetCount = 0;
  let tcpRstCount = 0;
  let tcpRetransmissionCount = 0;

  for (const line of output.split("\n").filter(Boolean)) {
    packetCount += 1;
    const [
      ipSrc,
      ipv6Src,
      ipDst,
      ipv6Dst,
      tcpSrcPort,
      udpSrcPort,
      tcpDstPort,
      udpDstPort,
      reset,
      retransmission,
      fastRetransmission,
      httpStatusCode,
      dnsRcode
    ] = line.split("\t");
    const srcIp = ipSrc || ipv6Src;
    const dstIp = ipDst || ipv6Dst;
    incrementCount(sourceIps, srcIp);
    incrementCount(destinationIps, dstIp);
    incrementCount(ips, srcIp);
    incrementCount(ips, dstIp);

    const protocol = tcpSrcPort || tcpDstPort ? "tcp" : udpSrcPort || udpDstPort ? "udp" : "";
    const srcPort = tcpSrcPort || udpSrcPort;
    const dstPort = tcpDstPort || udpDstPort;
    if (protocol && srcPort) {
      incrementCount(sourcePorts, `${protocol}:${srcPort}`);
      incrementCount(ports, `${protocol}:${srcPort}`);
    }
    if (protocol && dstPort) {
      incrementCount(destinationPorts, `${protocol}:${dstPort}`);
      incrementCount(ports, `${protocol}:${dstPort}`);
    }

    if (isTrueField(reset)) tcpRstCount += 1;
    if (isTrueField(retransmission) || isTrueField(fastRetransmission)) tcpRetransmissionCount += 1;
    incrementCount(httpStatusCodes, httpStatusCode);
    incrementCount(dnsRcodes, dnsRcode);
  }

  return {
    nodeId: capture.nodeId,
    pcapFilename: capture.pcapFilename || path.basename(capture.pcapPath || ""),
    packetCount,
    ipCount: ips.size,
    sourceIpCount: sourceIps.size,
    destinationIpCount: destinationIps.size,
    ips: countEntries(ips).map((item) => ({ ip: item.value, packetCount: item.packetCount })),
    sourceIps: countEntries(sourceIps).map((item) => ({ ip: item.value, packetCount: item.packetCount })),
    destinationIps: countEntries(destinationIps).map((item) => ({ ip: item.value, packetCount: item.packetCount })),
    ports: portEntries(ports),
    sourcePorts: portEntries(sourcePorts),
    destinationPorts: portEntries(destinationPorts),
    tcpRstCount,
    tcpRetransmissionCount,
    httpStatusCodes: countEntries(httpStatusCodes).map((item) => ({ code: Number(item.value), packetCount: item.packetCount })),
    dnsRcodes: countEntries(dnsRcodes).map((item) => ({ rcode: Number(item.value), packetCount: item.packetCount }))
  };
}

async function queryCapturePackets(capture: CaptureInput, displayFilter = "tcp", limit?: number) {
  if (!capture.pcapPath) return [];
  const args = [
    "-r",
    capture.pcapPath,
    "-Y",
    displayFilter,
    "-T",
    "fields",
    "-E",
    "header=n",
    "-E",
    "separator=/t",
    "-E",
    "occurrence=f",
    ...tsharkFields.flatMap((field) => ["-e", field])
  ];
  const { stdout } = await execFileAsync(tsharkCommand, args, { maxBuffer });
  const rows = parseTsharkRows(stdout, capture);
  return limit ? rows.slice(0, limit) : rows;
}

async function getCaptureTimeRange(capture: CaptureInput) {
  if (!capture.pcapPath) {
    return { nodeId: capture.nodeId, pcapFilename: capture.pcapFilename || "", packetCount: 0 };
  }
  try {
    const { stdout } = await execFileAsync(capinfosCommand, ["-T", "-r", "-c", "-a", "-e", "-S", capture.pcapPath], { maxBuffer });
    const columns = stdout.trim().split(/\r?\n/).at(-1)?.split("\t") || [];
    const packetCount = Number.parseInt(columns[1] || "0", 10);
    return {
      nodeId: capture.nodeId,
      pcapFilename: capture.pcapFilename || path.basename(capture.pcapPath),
      packetCount: Number.isFinite(packetCount) ? packetCount : 0,
      firstPacketTime: numberOrUndefined(columns[2]),
      lastPacketTime: numberOrUndefined(columns[3])
    };
  } catch {
    const { stdout } = await execFileAsync(tsharkCommand, ["-r", capture.pcapPath, "-T", "fields", "-e", "frame.time_epoch"], { maxBuffer });
    const timestamps = stdout.trim().split(/\r?\n/).map(numberOrUndefined).filter((time): time is number => time !== undefined);
    return {
      nodeId: capture.nodeId,
      pcapFilename: capture.pcapFilename || path.basename(capture.pcapPath),
      packetCount: timestamps.length,
      firstPacketTime: timestamps[0],
      lastPacketTime: timestamps.at(-1)
    };
  }
}

async function getCaptureProtocols(capture: CaptureInput) {
  if (!capture.pcapPath) return { nodeId: capture.nodeId, pcapFilename: capture.pcapFilename || "", packetCount: 0, protocols: [] };
  const { stdout } = await execFileAsync(tsharkCommand, ["-r", capture.pcapPath, "-T", "fields", "-e", "_ws.col.Protocol"], { maxBuffer });
  const counts = new Map<string, number>();
  for (const row of stdout.split(/\r?\n/)) {
    const protocol = row.trim().toLowerCase();
    if (!protocol) continue;
    counts.set(protocol, (counts.get(protocol) || 0) + 1);
  }
  const protocols = [...counts.entries()]
    .map(([protocol, packetCount]) => ({ protocol, packetCount }))
    .sort((left, right) => right.packetCount - left.packetCount || left.protocol.localeCompare(right.protocol));
  return {
    nodeId: capture.nodeId,
    pcapFilename: capture.pcapFilename || path.basename(capture.pcapPath),
    packetCount: protocols.reduce((sum, item) => sum + item.packetCount, 0),
    protocols
  };
}

async function getCaptureNetworkStatistics(capture: CaptureInput) {
  if (!capture.pcapPath) return parseNetworkStatisticsRows("", capture);
  const args = [
    "-r",
    capture.pcapPath,
    "-T",
    "fields",
    "-E",
    "header=n",
    "-E",
    "separator=/t",
    "-E",
    "occurrence=f",
    ...networkStatFields.flatMap((field) => ["-e", field])
  ];
  const { stdout } = await execFileAsync(tsharkCommand, args, { maxBuffer });
  return parseNetworkStatisticsRows(stdout, capture);
}

function mergeNetworkStatistics(captures: Awaited<ReturnType<typeof getCaptureNetworkStatistics>>[]) {
  const sourceIps = new Map<string, number>();
  const destinationIps = new Map<string, number>();
  const ips = new Map<string, number>();
  const ports = new Map<string, number>();
  const sourcePorts = new Map<string, number>();
  const destinationPorts = new Map<string, number>();
  const httpStatusCodes = new Map<string, number>();
  const dnsRcodes = new Map<string, number>();
  const mergeIp = (map: Map<string, number>, items: Array<{ ip: string; packetCount: number }>) => items.forEach((item) => map.set(item.ip, (map.get(item.ip) || 0) + item.packetCount));
  const mergePort = (map: Map<string, number>, items: Array<{ protocol: string; port: number; packetCount: number }>) => items.forEach((item) => map.set(`${item.protocol}:${item.port}`, (map.get(`${item.protocol}:${item.port}`) || 0) + item.packetCount));
  const mergeValue = (map: Map<string, number>, items: Array<{ code?: number; rcode?: number; packetCount: number }>, field: "code" | "rcode") => items.forEach((item) => map.set(String(item[field]), (map.get(String(item[field])) || 0) + item.packetCount));

  for (const capture of captures) {
    mergeIp(sourceIps, capture.sourceIps);
    mergeIp(destinationIps, capture.destinationIps);
    mergeIp(ips, capture.ips);
    mergePort(ports, capture.ports);
    mergePort(sourcePorts, capture.sourcePorts);
    mergePort(destinationPorts, capture.destinationPorts);
    mergeValue(httpStatusCodes, capture.httpStatusCodes, "code");
    mergeValue(dnsRcodes, capture.dnsRcodes, "rcode");
  }

  return {
    packetCount: captures.reduce((sum, capture) => sum + capture.packetCount, 0),
    ipCount: ips.size,
    sourceIpCount: sourceIps.size,
    destinationIpCount: destinationIps.size,
    ips: countEntries(ips).map((item) => ({ ip: item.value, packetCount: item.packetCount })),
    sourceIps: countEntries(sourceIps).map((item) => ({ ip: item.value, packetCount: item.packetCount })),
    destinationIps: countEntries(destinationIps).map((item) => ({ ip: item.value, packetCount: item.packetCount })),
    ports: portEntries(ports),
    sourcePorts: portEntries(sourcePorts),
    destinationPorts: portEntries(destinationPorts),
    tcpRstCount: captures.reduce((sum, capture) => sum + capture.tcpRstCount, 0),
    tcpRetransmissionCount: captures.reduce((sum, capture) => sum + capture.tcpRetransmissionCount, 0),
    httpStatusCodes: countEntries(httpStatusCodes).map((item) => ({ code: Number(item.value), packetCount: item.packetCount })),
    dnsRcodes: countEntries(dnsRcodes).map((item) => ({ rcode: Number(item.value), packetCount: item.packetCount }))
  };
}

function endpoint(ip?: string, port?: number) {
  return ip && port !== undefined ? `${ip}:${port}` : "";
}

function transportProtocol(packet: z.infer<typeof PacketSchema>) {
  if (packet.srcPort !== undefined || packet.dstPort !== undefined) return "tcp";
  return packet.protocol;
}

function conversationKey(packet: z.infer<typeof PacketSchema>) {
  const endpoints = [endpoint(packet.srcIp, packet.srcPort), endpoint(packet.dstIp, packet.dstPort)].sort();
  return [packet.nodeId, packet.pcapFilename, transportProtocol(packet), ...endpoints].join("|");
}

function tupleFilter(conversation: { srcIp?: string; dstIp?: string; srcPort?: number; dstPort?: number; protocol: string }) {
  const parts = [];
  if (conversation.srcIp && conversation.dstIp) parts.push(`ip.addr == ${conversation.srcIp} && ip.addr == ${conversation.dstIp}`);
  if (conversation.srcPort !== undefined && conversation.dstPort !== undefined) {
    const field = conversation.protocol === "udp" ? "udp.port" : "tcp.port";
    parts.push(`${field} == ${conversation.srcPort} && ${field} == ${conversation.dstPort}`);
  }
  if (conversation.protocol === "tcp") parts.push("tcp");
  if (conversation.protocol === "udp") parts.push("udp");
  return parts.join(" && ") || "tcp";
}

function summarizeConversations(packets: Array<z.infer<typeof PacketSchema>>, baseFilter: string) {
  const groups = new Map<string, Array<z.infer<typeof PacketSchema>>>();
  for (const packet of packets) {
    if (!packet.srcIp || !packet.dstIp || packet.srcPort === undefined || packet.dstPort === undefined) continue;
    const key = conversationKey(packet);
    groups.set(key, [...(groups.get(key) || []), packet]);
  }
  return [...groups.values()].map((items, index) => {
    const first = items[0];
    const last = items[items.length - 1];
    const byteCount = items.reduce((sum, packet) => sum + (packet.length || 0), 0);
    const flags = [...new Set(items.flatMap((packet) => packet.tcpFlags))];
    const conversationFilter = tupleFilter(first);
    return {
      conversationId: `conv-${index + 1}`,
      nodeId: first.nodeId,
      pcapFilename: first.pcapFilename,
      protocol: transportProtocol(first),
      srcIp: first.srcIp,
      srcPort: first.srcPort,
      dstIp: first.dstIp,
      dstPort: first.dstPort,
      startTime: first.timestamp,
      endTime: last.timestamp,
      packetCount: items.length,
      byteCount,
      tcpFlags: flags,
      rstCount: items.filter((packet) => packet.tcpFlags.includes("RST")).length,
      retransmissionCount: items.filter((packet) => packet.tcpAnalysis.retransmission || packet.tcpAnalysis.fastRetransmission).length,
      zeroWindowCount: items.filter((packet) => packet.tcpAnalysis.zeroWindow).length,
      displayFilter: [baseFilter, conversationFilter].filter(Boolean).join(" && ")
    };
  }).sort((left, right) => left.startTime - right.startTime);
}

async function queryCaptures(capturesJson: string, displayFilter: string, limit?: number) {
  const captures = JSON.parse(capturesJson) as CaptureInput[];
  return (await Promise.all(captures.map((capture) => queryCapturePackets(capture, displayFilter, limit)))).flat();
}

function packetEvidence(packets: Array<z.infer<typeof PacketSchema>>) {
  return packets.map((packet) => ({
    packetId: packet.packetId,
    nodeId: packet.nodeId,
    pcapFilename: packet.pcapFilename,
    frameNumber: packet.frameNumber,
    timestamp: packet.timestamp,
    protocol: packet.protocol,
    srcIp: packet.srcIp,
    srcPort: packet.srcPort,
    dstIp: packet.dstIp,
    dstPort: packet.dstPort,
    tcpFlags: packet.tcpFlags,
    summary: packet.summary,
    displayFilter: `frame.number == ${packet.frameNumber}`
  }));
}

server.registerTool(
  "build_display_filter",
  {
    title: "Build display filter",
    description: "Build a tshark/Wireshark display filter from query conditions.",
    inputSchema: {
      start: z.number().optional(),
      end: z.number().optional(),
      srcIp: z.string().optional(),
      dstIp: z.string().optional(),
      port: z.number().int().optional(),
      protocol: z.string().optional()
    }
  },
  async (input) => ({
    content: [{ type: "text", text: JSON.stringify({ displayFilter: buildDisplayFilter(input) }) }]
  })
);

server.registerTool(
  "get_capture_time_range",
  {
    title: "Get capture time range",
    description: "Return first/last packet time for a pcap using tshark.",
    inputSchema: { captureJson: z.string() }
  },
  async ({ captureJson }) => ({
    content: [{ type: "text", text: JSON.stringify(await getCaptureTimeRange(JSON.parse(captureJson) as CaptureInput)) }]
  })
);

server.registerTool(
  "list_protocols",
  {
    title: "List protocols",
    description: "Return protocol distribution from captures using tshark _ws.col.Protocol.",
    inputSchema: { capturesJson: z.string() }
  },
  async ({ capturesJson }) => {
    const captures = JSON.parse(capturesJson) as CaptureInput[];
    const capturesResult = await Promise.all(captures.map(getCaptureProtocols));
    const totals = new Map<string, number>();
    for (const capture of capturesResult) {
      for (const item of capture.protocols) {
        totals.set(item.protocol, (totals.get(item.protocol) || 0) + item.packetCount);
      }
    }
    const protocols = [...totals.entries()]
      .map(([protocol, packetCount]) => ({ protocol, packetCount }))
      .sort((left, right) => right.packetCount - left.packetCount || left.protocol.localeCompare(right.protocol));
    return { content: [{ type: "text", text: JSON.stringify({ protocolCount: protocols.length, packetCount: protocols.reduce((sum, item) => sum + item.packetCount, 0), protocols, captures: capturesResult }) }] };
  }
);

server.registerTool(
  "get_network_statistics",
  {
    title: "Get network statistics",
    description: "Return IP, port, TCP RST/retransmission, HTTP status and DNS rcode distributions from captures.",
    inputSchema: { capturesJson: z.string() }
  },
  async ({ capturesJson }) => {
    const captures = JSON.parse(capturesJson) as CaptureInput[];
    const captureStats = await Promise.all(captures.map(getCaptureNetworkStatistics));
    return { content: [{ type: "text", text: JSON.stringify({ ...mergeNetworkStatistics(captureStats), captures: captureStats }) }] };
  }
);

server.registerTool(
  "list_tcp_conversations",
  {
    title: "List TCP conversations",
    description: "Run tshark over captures and return matching TCP conversations.",
    inputSchema: {
      capturesJson: z.string(),
      displayFilter: z.string()
    }
  },
  async ({ capturesJson, displayFilter }) => {
    const packets = await queryCaptures(capturesJson, displayFilter);
    return { content: [{ type: "text", text: JSON.stringify({ conversations: summarizeConversations(packets, displayFilter), packetCount: packets.length }) }] };
  }
);

server.registerTool(
  "query_packets",
  {
    title: "Query packets",
    description: "Run tshark over one or more captures and return matching packet summaries.",
    inputSchema: {
      capturesJson: z.string(),
      displayFilter: z.string(),
      limit: z.number().int().optional()
    }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, displayFilter, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets: limit ? packets.slice(0, limit) : packets }) }] };
  }
);

server.registerTool(
  "get_conversation_packets",
  {
    title: "Get conversation packets",
    description: "Return packets for a conversation using its display filter.",
    inputSchema: {
      captureJson: z.string(),
      displayFilter: z.string(),
      limit: z.number().int().default(200)
    }
  },
  async ({ captureJson, displayFilter, limit }) => {
    const capture = JSON.parse(captureJson) as CaptureInput;
    return { content: [{ type: "text", text: JSON.stringify({ packets: await queryCapturePackets(capture, displayFilter, limit) }) }] };
  }
);

server.registerTool(
  "get_tshark_packet_detail",
  {
    title: "Get packet detail",
    description: "Return verbose packet detail from tshark.",
    inputSchema: {
      pcapPath: z.string(),
      frameNumber: z.number().int()
    }
  },
  async ({ pcapPath, frameNumber }) => {
    const { stdout } = await execFileAsync(tsharkCommand, ["-r", pcapPath, "-Y", `frame.number == ${frameNumber}`, "-V"], { maxBuffer });
    return { content: [{ type: "text", text: JSON.stringify({ frameNumber, detail: stdout }) }] };
  }
);

server.registerTool(
  "list_tcp_resets",
  {
    title: "List TCP resets",
    description: "Return TCP RST packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && tcp.flags.reset == 1`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets: packetEvidence(packets) }) }] };
  }
);

server.registerTool(
  "list_tcp_retransmissions",
  {
    title: "List TCP retransmissions",
    description: "Return TCP retransmission packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && (tcp.analysis.retransmission || tcp.analysis.fast_retransmission)`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets: packetEvidence(packets) }) }] };
  }
);

server.registerTool(
  "list_tcp_zero_window",
  {
    title: "List TCP zero window",
    description: "Return TCP zero window packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && tcp.analysis.zero_window`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets: packetEvidence(packets) }) }] };
  }
);

server.registerTool(
  "list_icmp_events",
  {
    title: "List ICMP events",
    description: "Return ICMP/ICMPv6 packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && (icmp || icmpv6)`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets }) }] };
  }
);

server.registerTool(
  "list_dns_packets",
  {
    title: "List DNS packets",
    description: "Return DNS packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && dns`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets }) }] };
  }
);

server.registerTool(
  "list_udp_packets",
  {
    title: "List UDP packets",
    description: "Return UDP packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && udp`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets }) }] };
  }
);

server.registerTool(
  "list_tls_packets",
  {
    title: "List TLS packets",
    description: "Return TLS handshake and alert packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && tls`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets }) }] };
  }
);

server.registerTool(
  "list_http_packets",
  {
    title: "List HTTP packets",
    description: "Return HTTP request and response packets matching the filter.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && http`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets }) }] };
  }
);

if (process.env.NODE_ENV !== "test") {
  await server.connect(new StdioServerTransport());
}
