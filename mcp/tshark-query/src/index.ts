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
  httpServer: z.string().optional(),
  httpRequestIn: z.number().int().optional(),
  httpResponseIn: z.number().int().optional(),
  httpTime: z.number().optional(),
  httpCookie: z.string().optional(),
  httpSetCookie: z.string().optional(),
  httpXForwardedFor: z.string().optional(),
  httpContentType: z.string().optional(),
  httpContentLength: z.number().int().optional(),
  httpConnection: z.string().optional(),
  httpTransferEncoding: z.string().optional(),
  httpAuthorization: z.boolean().optional(),
  httpWwwAuthenticate: z.boolean().optional(),
  httpVia: z.string().optional(),
  httpUpgrade: z.string().optional(),
  httpAcceptEncoding: z.string().optional(),
  httpContentEncoding: z.string().optional(),
  httpCacheControl: z.string().optional(),
  tlsCipherSuite: z.string().optional(),
  tlsCertDnsName: z.string().optional(),
  tlsSessionId: z.string().optional(),
  tlsAlpnProtocol: z.string().optional(),
  tlsSessionTicket: z.string().optional(),
  dnsQueryType: z.number().int().optional(),
  dnsTtl: z.number().int().optional(),
  dnsCname: z.string().optional(),
  dnsTruncated: z.boolean().optional(),
  dnsAnswerCount: z.number().int().optional(),
  icmpIdent: z.number().int().optional(),
  icmpSeq: z.number().int().optional(),
  icmpMtuNextHop: z.number().int().optional(),
  ipDf: z.boolean().optional(),
  udpLength: z.number().int().optional(),
  quicVersion: z.string().optional(),
  quicConnectionId: z.string().optional(),
  quicPacketType: z.string().optional(),
  quicFrameType: z.string().optional(),
  ntpRefid: z.string().optional(),
  ntpStratum: z.number().int().optional(),
  ntpRootdelay: z.number().optional(),
  ntpXmt: z.number().optional(),
  ntpOrg: z.number().optional(),
  sshMessage: z.string().optional(),
  sshDirection: z.string().optional(),
  sshProtocol: z.string().optional(),
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
  "http.server",
  "http.request_in",
  "http.response_in",
  "http.time",
  "http.cookie",
  "http.set_cookie",
  "http.x_forwarded_for",
  "http.content_type",
  "http.content_length",
  "http.connection",
  "http.transfer_encoding",
  "http.authorization",
  "http.www_authenticate",
  "http.via",
  "http.upgrade",
  "http.accept_encoding",
  "http.content_encoding",
  "http.cache_control",
  "x509sat.printableString",
  "x509ce.dNSName",
  "dns.qry.type",
  "dns.cname",
  "dns.flags.truncated",
  "dns.a",
  "dns.count.answers",
  "dns.resp.ttl",
  "icmp.ident",
  "icmp.seq",
  "icmp.mtu",
  "ip.flags.df",
  "udp.length",
  "quic.version",
  "quic.frame_type",
  "quic.scid",
  "quic.dcid",
  "quic.header_form",
  "ntp.refid",
  "ntp.stratum",
  "ntp.rootdelay",
  "ntp.xmt",
  "ntp.org",
  "tls.handshake.ciphersuite",
  "tls.handshake.session_id",
  "tls.handshake.extensions.session_ticket",
  "ssh.direction",
  "ssh.protocol",
  "ssh.message_code"
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

function parseFlag(value: string | undefined, label: string) {
  if (!value) return [];
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
      httpServer,
      httpRequestIn,
      httpResponseIn,
      httpTime,
      httpCookie,
      httpSetCookie,
      httpXForwardedFor,
      httpContentType,
      httpContentLength,
      httpConnection,
      httpTransferEncoding,
      httpAuthorization,
      httpWwwAuthenticate,
      httpVia,
      httpUpgrade,
      httpAcceptEncoding,
      httpContentEncoding,
      httpCacheControl,
      tlsCipher,
      tlsCipherSuite,
      x509DnsName,
      tlsSessionId,
      tlsAlpn,
      tlsSessionTicket,
      dnsQueryType,
      dnsTtl,
      dnsCname,
      dnsTruncated,
      dnsAnswerCount,
      icmpIdent,
      icmpSeq,
      icmpMtuNextHop,
      ipDf,
      udpLength,
      quicVersion,
      quicConnectionId,
      quicPacketType,
      quicFrameType,
      ntpRefid,
      ntpStratum,
      ntpRootdelay,
      ntpXmt,
      ntpOrg,
      sshMessage,
      sshDirection,
      sshProtocol
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
      dnsIsResponse: dnsIsResponse ? dnsIsResponse === "1" || dnsIsResponse?.toLowerCase() === "true" : undefined,
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
      httpServer: httpServer || undefined,
      httpRequestIn: numberOrUndefined(httpRequestIn),
      httpResponseIn: numberOrUndefined(httpResponseIn),
      httpTime: numberOrUndefined(httpTime),
      httpCookie: httpCookie || undefined,
      httpSetCookie: httpSetCookie || undefined,
      httpXForwardedFor: httpXForwardedFor || undefined,
      httpContentType: httpContentType || undefined,
      httpContentLength: numberOrUndefined(httpContentLength),
      httpConnection: httpConnection || undefined,
      httpTransferEncoding: httpTransferEncoding || undefined,
      httpAuthorization: httpAuthorization ? true : undefined,
      httpWwwAuthenticate: httpWwwAuthenticate ? true : undefined,
      httpVia: httpVia || undefined,
      httpUpgrade: httpUpgrade || undefined,
      httpAcceptEncoding: httpAcceptEncoding || undefined,
      httpContentEncoding: httpContentEncoding || undefined,
      httpCacheControl: httpCacheControl || undefined,
      tlsCipherSuite: tlsCipher || tlsCipherSuite || undefined,
      tlsCertDnsName: x509DnsName || undefined,
      tlsSessionId: tlsSessionId || undefined,
      tlsAlpnProtocol: tlsAlpn || undefined,
      tlsSessionTicket: tlsSessionTicket || undefined,
      dnsQueryType: numberOrUndefined(dnsQueryType),
      dnsTtl: numberOrUndefined(dnsTtl),
      dnsCname: dnsCname || undefined,
      dnsTruncated: dnsTruncated === "1" || dnsTruncated?.toLowerCase() === "true",
      dnsAnswerCount: numberOrUndefined(dnsAnswerCount),
      icmpIdent: numberOrUndefined(icmpIdent),
      icmpSeq: numberOrUndefined(icmpSeq),
      icmpMtuNextHop: numberOrUndefined(icmpMtuNextHop),
      ipDf: ipDf === "1" || ipDf?.toLowerCase() === "true",
      udpLength: numberOrUndefined(udpLength),
      quicVersion: quicVersion || undefined,
      quicConnectionId: quicConnectionId || undefined,
      quicPacketType: quicPacketType || undefined,
      quicFrameType: quicFrameType || undefined,
      ntpRefid: ntpRefid || undefined,
      ntpStratum: numberOrUndefined(ntpStratum),
      ntpRootdelay: numberOrUndefined(ntpRootdelay),
      ntpXmt: numberOrUndefined(ntpXmt),
      ntpOrg: numberOrUndefined(ntpOrg),
      sshMessage: sshMessage || undefined,
      sshDirection: sshDirection || undefined,
      sshProtocol: sshProtocol || undefined,
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
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(tsharkCommand, args, { maxBuffer }));
  } catch (err: unknown) {
    // tshark 在存在不支持的字段名时仍可能输出有效数据，但退出码为 1
    const e = err as { stdout?: string; stderr?: string };
    if (e.stdout && e.stdout.trim().length > 0) {
      stdout = e.stdout;
    } else {
      throw err;
    }
  }
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
  if (packet.srcPort !== undefined && packet.dstPort !== undefined) return "tcp";
  return packet.protocol?.toLowerCase() || "unknown";
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

const DEFAULT_PACKET_LIMIT = 100;

async function queryCaptures(capturesJson: string, displayFilter: string, limit?: number) {
  const captures = JSON.parse(capturesJson) as CaptureInput[];
  const effectiveLimit = limit || DEFAULT_PACKET_LIMIT;
  return (await Promise.all(captures.map((capture) => queryCapturePackets(capture, displayFilter, effectiveLimit)))).flat().slice(0, effectiveLimit);
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
    description: "Run tshark over one or more captures and return matching packet summaries. Default limit 100; set limit explicitly for more.",
    inputSchema: {
      capturesJson: z.string(),
      displayFilter: z.string(),
      limit: z.number().int().optional()
    }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, displayFilter, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets }) }] };
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
    description: "Return TCP RST packets matching the filter. Default limit 100.",
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
    description: "Return TCP retransmission packets matching the filter. Default limit 100.",
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
    description: "Return TCP zero window packets matching the filter. Default limit 100.",
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
    description: "Return ICMP/ICMPv6 packets matching the filter. Default limit 100.",
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
    description: "Return DNS packets matching the filter. Default limit 100.",
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
    description: "Return UDP packets matching the filter. Default limit 100.",
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
    description: "Return TLS handshake and alert packets matching the filter. Default limit 100.",
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
    description: "Return HTTP request and response packets matching the filter. Default limit 100.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string(), limit: z.number().int().optional() }
  },
  async ({ capturesJson, displayFilter, limit }) => {
    const packets = await queryCaptures(capturesJson, `${displayFilter} && http`, limit);
    return { content: [{ type: "text", text: JSON.stringify({ packets }) }] };
  }
);

server.registerTool(
  "list_tcp_streams",
  {
    title: "List TCP streams",
    description: "Return TCP stream summary (stream index, endpoint tuple, packet count, byte count) by aggregating tcp.stream field.",
    inputSchema: { capturesJson: z.string(), displayFilter: z.string().default("tcp") }
  },
  async ({ capturesJson, displayFilter }) => {
    const inputs = JSON.parse(capturesJson) as CaptureInput[];
    const validInput = inputs.find(i => i.pcapPath);
    if (!validInput?.pcapPath) return { content: [{ type: "text", text: JSON.stringify({ streams: [] }) }] };
    const args = ["-r", validInput.pcapPath, "-Y", displayFilter ?? "tcp", "-T", "fields", "-e", "tcp.stream", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "frame.len", "-E", "header=n", "-E", "separator=\\t"];
    const { stdout } = await execFileAsync(tsharkCommand, args, { maxBuffer: 20 * 1024 * 1024 });
    const streamMap = new Map<number, { srcIp: string; srcPort: number; dstIp: string; dstPort: number; packetCount: number; byteCount: number }>();
    for (const line of stdout.trim().split("\n")) {
      if (!line.trim()) continue;
      const parts = line.split("\t");
      if (parts.length < 6) continue;
      const si = parseInt(parts[0], 10);
      if (isNaN(si)) continue;
      const existing = streamMap.get(si);
      if (existing) {
        existing.packetCount++;
        existing.byteCount += parseInt(parts[5], 10) || 0;
      } else {
        streamMap.set(si, { srcIp: parts[1], srcPort: parseInt(parts[3], 10) || 0, dstIp: parts[2], dstPort: parseInt(parts[4], 10) || 0, packetCount: 1, byteCount: parseInt(parts[5], 10) || 0 });
      }
    }
    const streams = [...streamMap.entries()].map(([streamIndex, s]) => ({ streamIndex, ...s, displayFilter: `tcp.stream eq ${streamIndex}` }));
    return { content: [{ type: "text", text: JSON.stringify({ streams }) }] };
  }
);

server.registerTool(
  "follow_tcp_stream",
  {
    title: "Follow TCP stream",
    description: "Reassemble TCP stream content (like Wireshark Follow TCP Stream). Returns client and server data separately.",
    inputSchema: { pcapPath: z.string(), streamIndex: z.number().int(), format: z.enum(["ascii", "raw"]).default("ascii"), maxBytes: z.number().int().default(65536) }
  },
  async ({ pcapPath, streamIndex, format, maxBytes }) => {
    const args = ["-r", pcapPath, "-q", "-z", `follow,tcp,${format},${streamIndex}`];
    const { stdout } = await execFileAsync(tsharkCommand, args, { maxBuffer: 10 * 1024 * 1024 });
    let content = stdout;
    const truncated = content.length > maxBytes;
    if (truncated) content = content.slice(0, maxBytes);

    // 解析 follow 输出：tshark follow ascii 输出中，客户端数据和非客户端数据交替出现
    // 格式：=== Stream N === 后面跟着方向标记
    let clientData = "";
    let serverData = "";
    const lines = content.split("\n");
    let inClient = false;
    let inServer = false;
    for (const line of lines) {
      if (line.startsWith("===") || line.trim() === "") {
        // 检查方向标记
        if (line.includes("->") || line.match(/^===\s+\d+/)) {
          // 新的 chunk 开始，交替方向
          if (inClient) { inClient = false; inServer = true; }
          else if (inServer) { inServer = false; inClient = true; }
          else { inClient = true; }
        }
        continue;
      }
      if (line.startsWith("\t") || line.startsWith("   ")) {
        // 缩进行通常是服务端数据
        serverData += line.replace(/^[\t ]+/, "") + "\n";
      } else {
        // 非缩进行通常是客户端数据
        clientData += line + "\n";
      }
    }

    const totalBytes = Buffer.byteLength(clientData, "utf8") + Buffer.byteLength(serverData, "utf8");
    return {
      content: [{
        type: "text",
        text: JSON.stringify({ streamIndex, format, clientData, serverData, totalBytes, truncated, displayFilter: `tcp.stream eq ${streamIndex}` })
      }]
    };
  }
);

server.registerTool(
  "get_expert_info",
  {
    title: "Get tshark Expert Info",
    description: "Run tshark expert info analysis on a capture file. Returns warnings, errors, and notes from tshark's built-in protocol analysis.",
    inputSchema: { capturesJson: z.string() }
  },
  async ({ capturesJson }) => {
    const inputs = JSON.parse(capturesJson) as CaptureInput[];
    const validInput = inputs.find(i => i.pcapPath);
    if (!validInput?.pcapPath) return { content: [{ type: "text", text: JSON.stringify({ expertInfo: [] }) }] };
    const args = ["-r", validInput.pcapPath, "-Y", "tcp.analysis.flags || tcp.analysis.retransmission || tcp.analysis.out_of_order || tcp.analysis.duplicate_ack || tcp.analysis.zero_window || tcp.analysis.keep_alive || tcp.analysis.window_full", "-T", "fields", "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.analysis.retransmission", "-e", "tcp.analysis.fast_retransmission", "-e", "tcp.analysis.out_of_order", "-e", "tcp.analysis.duplicate_ack", "-e", "tcp.analysis.zero_window", "-e", "tcp.analysis.keep_alive", "-e", "tcp.analysis.window_full", "-e", "tcp.analysis.lost_segment", "-E", "header=n", "-E", "separator=\\t"];
    const { stdout } = await execFileAsync(tsharkCommand, args, { maxBuffer: 20 * 1024 * 1024 });
    const entries: Array<{ frameNumber: number; srcIp: string; dstIp: string; srcPort: number; dstPort: number; flags: string[] }> = [];
    for (const line of stdout.trim().split("\n")) {
      if (!line.trim()) continue;
      const parts = line.split("\t");
      if (parts.length < 12) continue;
      const flags: string[] = [];
      if (parts[5] === "1" || parts[5]?.toLowerCase() === "true") flags.push("retransmission");
      if (parts[6] === "1" || parts[6]?.toLowerCase() === "true") flags.push("fast_retransmission");
      if (parts[7] === "1" || parts[7]?.toLowerCase() === "true") flags.push("out_of_order");
      if (parts[8] === "1" || parts[8]?.toLowerCase() === "true") flags.push("duplicate_ack");
      if (parts[9] === "1" || parts[9]?.toLowerCase() === "true") flags.push("zero_window");
      if (parts[10] === "1" || parts[10]?.toLowerCase() === "true") flags.push("keep_alive");
      if (parts[11] === "1" || parts[11]?.toLowerCase() === "true") flags.push("window_full");
      if (parts[12] === "1" || parts[12]?.toLowerCase() === "true") flags.push("lost_segment");
      if (!flags.length) continue;
      entries.push({
        frameNumber: parseInt(parts[0], 10) || 0,
        srcIp: parts[1], dstIp: parts[2],
        srcPort: parseInt(parts[3], 10) || 0, dstPort: parseInt(parts[4], 10) || 0,
        flags
      });
    }
    return { content: [{ type: "text", text: JSON.stringify({ expertInfo: entries, totalEntries: entries.length }) }] };
  }
);

if (process.env.NODE_ENV !== "test") {
  await server.connect(new StdioServerTransport());
}
