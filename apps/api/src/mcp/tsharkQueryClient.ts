import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import { ConversationSchema, PacketSummarySchema } from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";

const BuildDisplayFilterResultSchema = z.object({ displayFilter: z.string() });
const CaptureTimeRangeResultSchema = z.object({
  nodeId: z.string(),
  pcapFilename: z.string(),
  packetCount: z.number().int(),
  firstPacketTime: z.number().optional(),
  lastPacketTime: z.number().optional()
});
const ListConversationsResultSchema = z.object({
  conversations: z.array(ConversationSchema),
  packetCount: z.number().int()
});
const QueryPacketsResultSchema = z.object({ packets: z.array(PacketSummarySchema) });
const ListProtocolsResultSchema = z.object({
  protocolCount: z.number().int(),
  packetCount: z.number().int(),
  protocols: z.array(z.object({
    protocol: z.string(),
    packetCount: z.number().int()
  })),
  captures: z.array(z.object({
    nodeId: z.string(),
    pcapFilename: z.string(),
    packetCount: z.number().int(),
    protocols: z.array(z.object({
      protocol: z.string(),
      packetCount: z.number().int()
    }))
  }))
});
const PortDistributionSchema = z.object({
  protocol: z.string(),
  port: z.number().int(),
  packetCount: z.number().int()
});
const IpDistributionSchema = z.object({
  ip: z.string(),
  packetCount: z.number().int()
});
const NetworkStatisticsResultSchema = z.object({
  packetCount: z.number().int(),
  ipCount: z.number().int(),
  sourceIpCount: z.number().int(),
  destinationIpCount: z.number().int(),
  ips: z.array(IpDistributionSchema),
  sourceIps: z.array(IpDistributionSchema),
  destinationIps: z.array(IpDistributionSchema),
  ports: z.array(PortDistributionSchema),
  sourcePorts: z.array(PortDistributionSchema),
  destinationPorts: z.array(PortDistributionSchema),
  tcpRstCount: z.number().int(),
  tcpRetransmissionCount: z.number().int(),
  httpStatusCodes: z.array(z.object({
    code: z.number().int(),
    packetCount: z.number().int()
  })),
  dnsRcodes: z.array(z.object({
    rcode: z.number().int(),
    packetCount: z.number().int()
  })),
  captures: z.array(z.object({
    nodeId: z.string(),
    pcapFilename: z.string(),
    packetCount: z.number().int(),
    ipCount: z.number().int(),
    sourceIpCount: z.number().int(),
    destinationIpCount: z.number().int(),
    tcpRstCount: z.number().int(),
    tcpRetransmissionCount: z.number().int()
  }).passthrough())
});
const PacketEvidenceResultSchema = z.object({
  packets: z.array(z.object({
	    packetId: z.string(),
	    nodeId: z.string(),
	    pcapFilename: z.string(),
	    frameNumber: z.number().int(),
	    timestamp: z.number(),
	    protocol: z.string().optional(),
	    srcIp: z.string().optional(),
	    srcPort: z.number().int().optional(),
	    dstIp: z.string().optional(),
    dstPort: z.number().int().optional(),
    tcpFlags: z.array(z.string()).default([]),
    summary: z.string(),
    displayFilter: z.string()
  }))
});
const PacketDetailResultSchema = z.object({
  frameNumber: z.number().int(),
  detail: z.string()
});

export type CaptureQueryInput = {
  nodeId: string;
  name: string;
  pcapFilename?: string;
  pcapPath?: string;
};

function firstTextContent(result: unknown) {
  const content = typeof result === "object" && result !== null && "content" in result && Array.isArray(result.content)
    ? result.content
    : [];
  const firstText = content.find((item) => typeof item === "object" && item !== null && "type" in item && item.type === "text");
  if (!firstText || !("text" in firstText) || typeof firstText.text !== "string") {
    throw new Error("tshark-query MCP returned no text content");
  }
  return firstText.text;
}

async function callTsharkQueryTool<T>(toolName: string, args: Record<string, unknown>, schema: z.ZodType<T>) {
  const client = new Client({ name: "pcapai-api", version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: apiConfig.tsharkQueryMcp.command,
    args: apiConfig.tsharkQueryMcp.args,
    cwd: apiConfig.tsharkQueryMcp.cwd,
    stderr: "pipe"
  });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: toolName, arguments: args });
    const text = firstTextContent(result);
    try {
      return schema.parse(JSON.parse(text));
    } catch (error) {
      throw new Error(`tshark-query MCP ${toolName} returned invalid JSON: ${text.slice(0, 1000)}${error instanceof Error ? `; ${error.message}` : ""}`);
    }
  } finally {
    await transport.close();
  }
}

export async function buildDisplayFilterWithMcp(input: { start?: number; end?: number; srcIp?: string; dstIp?: string; port?: number; protocol?: string }) {
  return callTsharkQueryTool("build_display_filter", input, BuildDisplayFilterResultSchema);
}

export async function getCaptureTimeRangeWithMcp(input: { capture: CaptureQueryInput }) {
  return callTsharkQueryTool("get_capture_time_range", { captureJson: JSON.stringify(input.capture) }, CaptureTimeRangeResultSchema);
}

export async function listTcpConversationsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string }) {
  return callTsharkQueryTool("list_tcp_conversations", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter
  }, ListConversationsResultSchema);
}

export async function queryPacketsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("query_packets", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, QueryPacketsResultSchema);
}

export async function listProtocolsWithMcp(input: { captures: CaptureQueryInput[] }) {
  return callTsharkQueryTool("list_protocols", {
    capturesJson: JSON.stringify(input.captures)
  }, ListProtocolsResultSchema);
}

export async function getNetworkStatisticsWithMcp(input: { captures: CaptureQueryInput[] }) {
  return callTsharkQueryTool("get_network_statistics", {
    capturesJson: JSON.stringify(input.captures)
  }, NetworkStatisticsResultSchema);
}

export async function getConversationPacketsWithMcp(input: { capture: CaptureQueryInput; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("get_conversation_packets", {
    captureJson: JSON.stringify(input.capture),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, QueryPacketsResultSchema);
}

export async function getPacketDetailWithMcp(input: { pcapPath: string; frameNumber: number }) {
  return callTsharkQueryTool("get_tshark_packet_detail", input, PacketDetailResultSchema);
}

export async function listTcpResetsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_tcp_resets", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, PacketEvidenceResultSchema);
}

export async function listTcpRetransmissionsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_tcp_retransmissions", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, PacketEvidenceResultSchema);
}

export async function listTcpZeroWindowWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_tcp_zero_window", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, PacketEvidenceResultSchema);
}

export async function listIcmpEventsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_icmp_events", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, QueryPacketsResultSchema);
}

export async function listDnsPacketsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_dns_packets", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, QueryPacketsResultSchema);
}

export async function listUdpPacketsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_udp_packets", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, QueryPacketsResultSchema);
}

export async function listTlsPacketsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_tls_packets", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, QueryPacketsResultSchema);
}

export async function listHttpPacketsWithMcp(input: { captures: CaptureQueryInput[]; displayFilter: string; limit?: number }) {
  return callTsharkQueryTool("list_http_packets", {
    capturesJson: JSON.stringify(input.captures),
    displayFilter: input.displayFilter,
    limit: input.limit
  }, QueryPacketsResultSchema);
}
