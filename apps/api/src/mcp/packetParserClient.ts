import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import { PacketSummarySchema } from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";

const ParsePcapResultSchema = z.object({
  caseId: z.string(),
  nodeId: z.string(),
  pcapPath: z.string(),
  pcapFilename: z.string(),
  packets: z.array(PacketSummarySchema)
});

export type ParsePcapResult = z.infer<typeof ParsePcapResultSchema>;

function firstTextContent(result: unknown) {
  const content = typeof result === "object" && result !== null && "content" in result && Array.isArray(result.content)
    ? result.content
    : [];
  const firstText = content.find((item) => {
    return typeof item === "object" && item !== null && "type" in item && item.type === "text";
  });

  if (!firstText || !("text" in firstText) || typeof firstText.text !== "string") {
    throw new Error("packet-parser MCP returned no text content");
  }

  return firstText.text;
}

export async function parsePcapWithMcp(input: {
  caseId: string;
  nodeId: string;
  pcapPath: string;
  pcapFilename?: string;
}): Promise<ParsePcapResult> {
  const client = new Client({ name: "pcapai-api", version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: apiConfig.packetParserMcp.command,
    args: apiConfig.packetParserMcp.args,
    cwd: apiConfig.packetParserMcp.cwd,
    stderr: "pipe"
  });

  try {
    await client.connect(transport);
    const result = await client.callTool({
      name: "parse_pcap",
      arguments: input
    });
    return ParsePcapResultSchema.parse(JSON.parse(firstTextContent(result)));
  } finally {
    await transport.close();
  }
}
