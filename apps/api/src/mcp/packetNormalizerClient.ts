import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import {
  EvidenceEventSchema,
  FindingSchema,
  PathGraphSchema,
  SessionSegmentSchema,
  type CaseGraph
} from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";

const NormalizePacketsResultSchema = z.object({
  caseId: z.string(),
  sessions: z.array(SessionSegmentSchema),
  evidence: z.array(EvidenceEventSchema),
  path: PathGraphSchema,
  findings: z.array(FindingSchema)
});

export type NormalizePacketsResult = z.infer<typeof NormalizePacketsResultSchema>;

function firstTextContent(result: unknown) {
  const content = typeof result === "object" && result !== null && "content" in result && Array.isArray(result.content)
    ? result.content
    : [];
  const firstText = content.find((item) => {
    return typeof item === "object" && item !== null && "type" in item && item.type === "text";
  });

  if (!firstText || !("text" in firstText) || typeof firstText.text !== "string") {
    throw new Error("packet-normalizer MCP returned no text content");
  }

  return firstText.text;
}

export async function normalizePacketsWithMcp(graph: CaseGraph): Promise<NormalizePacketsResult> {
  const client = new Client({ name: "pcapai-api", version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: apiConfig.packetNormalizerMcp.command,
    args: apiConfig.packetNormalizerMcp.args,
    cwd: apiConfig.packetNormalizerMcp.cwd,
    stderr: "pipe"
  });

  try {
    await client.connect(transport);
    const result = await client.callTool({
      name: "normalize_packets",
      arguments: { caseGraphJson: JSON.stringify(graph) }
    });
    return NormalizePacketsResultSchema.parse(JSON.parse(firstTextContent(result)));
  } finally {
    await transport.close();
  }
}
