import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const server = new McpServer({ name: "diagnosis-report-mcp", version: "0.1.0" });

server.registerTool(
  "detect_breakpoints",
  {
    title: "Detect breakpoints",
    description: "Detect likely network breakpoints from a case graph.",
    inputSchema: {
      caseGraphJson: z.string()
    }
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify({ findings: [] }) }]
  })
);

server.registerTool(
  "export_report",
  {
    title: "Export report",
    description: "Generate a Chinese troubleshooting report from case graph evidence.",
    inputSchema: {
      caseGraphJson: z.string()
    }
  },
  async () => ({
    content: [{ type: "text", text: JSON.stringify({ reportMarkdown: "" }) }]
  })
);

await server.connect(new StdioServerTransport());
