import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import {
  PathGraphSchema,
  SessionLinkSchema,
  type CaseGraph,
  type SessionLink
} from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";

const MatchCrossNodeSessionsResultSchema = z.object({
  links: z.array(SessionLinkSchema)
});
const BuildPathGraphResultSchema = PathGraphSchema;

function firstTextContent(result: unknown) {
  const content = typeof result === "object" && result !== null && "content" in result && Array.isArray(result.content)
    ? result.content
    : [];
  const firstText = content.find((item) => {
    return typeof item === "object" && item !== null && "type" in item && item.type === "text";
  });

  if (!firstText || !("text" in firstText) || typeof firstText.text !== "string") {
    throw new Error("chain-builder MCP returned no text content");
  }

  return firstText.text;
}

async function withChainBuilderClient<T>(callback: (client: Client) => Promise<T>) {
  const client = new Client({ name: "pcapai-api", version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: apiConfig.chainBuilderMcp.command,
    args: apiConfig.chainBuilderMcp.args,
    cwd: apiConfig.chainBuilderMcp.cwd,
    stderr: "pipe"
  });

  try {
    await client.connect(transport);
    return await callback(client);
  } finally {
    await transport.close();
  }
}

export async function matchCrossNodeSessionsWithMcp(graph: CaseGraph) {
  return withChainBuilderClient(async (client) => {
    const result = await client.callTool({
      name: "match_cross_node_sessions",
      arguments: { caseGraphJson: JSON.stringify(graph) }
    });
    return MatchCrossNodeSessionsResultSchema.parse(JSON.parse(firstTextContent(result)));
  });
}

export async function buildPathGraphWithMcp(graph: CaseGraph, sessionLinks: SessionLink[]) {
  return withChainBuilderClient(async (client) => {
    const result = await client.callTool({
      name: "build_path_graph",
      arguments: {
        caseGraphJson: JSON.stringify(graph),
        sessionLinksJson: JSON.stringify(sessionLinks)
      }
    });
    return BuildPathGraphResultSchema.parse(JSON.parse(firstTextContent(result)));
  });
}
