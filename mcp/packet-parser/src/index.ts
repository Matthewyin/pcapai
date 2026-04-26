import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { parserConfig } from "./config.js";

const server = new McpServer({ name: "packet-parser-mcp", version: "0.1.0" });
const execFileAsync = promisify(execFile);

type PacketSummary = {
  packetId: string;
  nodeId: string;
  pcapFilename: string;
  frameNumber: number;
  timestamp: number;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol: string;
  tcpFlags: string[];
  tcpSeq?: number;
  tcpAck?: number;
  length?: number;
  summary: string;
  raw: Record<string, unknown>;
};

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
  "frame.len",
  "_ws.col.Info"
];

function numberOrUndefined(value: string) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function parseFlag(value: string, label: string) {
  return value === "1" || value.toLowerCase() === "true" ? [label] : [];
}

function parseTsharkRows(output: string, nodeId: string, pcapFilename: string): PacketSummary[] {
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
      frameLength,
      info
    ] = columns;

    const parsedFrameNumber = Number(frameNumber);
    const packetId = `${nodeId}:${parsedFrameNumber}`;

    return {
      packetId,
      nodeId,
      pcapFilename,
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
      length: numberOrUndefined(frameLength),
      summary: info || "",
      raw: Object.fromEntries(tsharkFields.map((field, index) => [field, columns[index] || ""]))
    };
  });
}

async function parsePcap(input: { caseId: string; nodeId: string; pcapPath: string; pcapFilename?: string }) {
  const args = [
    "-r",
    input.pcapPath,
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
  const { stdout } = await execFileAsync(parserConfig.tsharkCommand, args, { maxBuffer: parserConfig.maxBufferBytes });
  const pcapFilename = input.pcapFilename || path.basename(input.pcapPath);
  return {
    caseId: input.caseId,
    nodeId: input.nodeId,
    pcapPath: input.pcapPath,
    pcapFilename,
    packets: parseTsharkRows(stdout, input.nodeId, pcapFilename)
  };
}

server.registerTool(
  "parse_pcap",
  {
    title: "Parse pcap",
    description: "Parse a pcap or pcapng file into packet summaries using tshark.",
    inputSchema: {
      caseId: z.string(),
      nodeId: z.string(),
      pcapPath: z.string(),
      pcapFilename: z.string().optional()
    }
  },
  async (input) => ({
    content: [
      {
        type: "text",
        text: JSON.stringify(await parsePcap(input))
      }
    ]
  })
);

server.registerTool(
  "get_packet_detail",
  {
    title: "Get packet detail",
    description: "Return packet detail by packetId.",
    inputSchema: {
      caseId: z.string(),
      packetId: z.string()
    }
  },
  async ({ caseId, packetId }) => ({
    content: [{ type: "text", text: JSON.stringify({ caseId, packetId, detail: null }) }]
  })
);

await server.connect(new StdioServerTransport());
