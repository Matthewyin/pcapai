import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { z } from "zod";
import { apiConfig } from "../config.js";

const OpenWiresharkResultSchema = z.object({
  opened: z.boolean(),
  pcapPath: z.string(),
  displayFilter: z.string(),
  frameNumber: z.number().int().optional(),
  launch: z.object({
    launcher: z.string(),
    args: z.array(z.string())
  }).optional()
});

function firstTextContent(result: unknown) {
  const content = typeof result === "object" && result !== null && "content" in result && Array.isArray(result.content)
    ? result.content
    : [];
  const firstText = content.find((item) => typeof item === "object" && item !== null && "type" in item && item.type === "text");
  if (!firstText || !("text" in firstText) || typeof firstText.text !== "string") {
    throw new Error("evidence-opener MCP returned no text content");
  }
  return firstText.text;
}

export async function openInWiresharkWithMcp(input: { pcapPath: string; displayFilter: string; frameNumber?: number }) {
  const client = new Client({ name: "pcapai-api", version: "0.1.0" });
  const transport = new StdioClientTransport({
    command: apiConfig.evidenceOpenerMcp.command,
    args: apiConfig.evidenceOpenerMcp.args,
    cwd: apiConfig.evidenceOpenerMcp.cwd,
    stderr: "pipe",
    // 同 tsharkQueryClient：传 ELECTRON_RUN_AS_NODE 让 MCP server 以 node 模式运行
    env: {
      ...process.env,
      ELECTRON_RUN_AS_NODE: process.env.ELECTRON_RUN_AS_NODE || "1"
    }
  });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: "open_in_wireshark", arguments: input });
    const text = firstTextContent(result);
    try {
      return OpenWiresharkResultSchema.parse(JSON.parse(text));
    } catch {
      throw new Error(text);
    }
  } finally {
    await transport.close();
  }
}
