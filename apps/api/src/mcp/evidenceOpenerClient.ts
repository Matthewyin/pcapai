import { z } from "zod";
import { createClient, resetClient } from "./mcpRegistry.js";

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
  // 从注册表获取 client（替代硬编码 transport）
  const client = await createClient("evidence-opener");
  let result: Awaited<ReturnType<typeof client.callTool>>;
  try {
    result = await client.callTool({ name: "open_in_wireshark", arguments: input });
  } catch (error) {
    await resetClient("evidence-opener");
    throw error;
  }
  const text = firstTextContent(result);
  try {
    return OpenWiresharkResultSchema.parse(JSON.parse(text));
  } catch {
    throw new Error(text);
  }
}
