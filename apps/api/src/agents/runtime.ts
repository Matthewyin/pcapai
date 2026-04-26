import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { Agent, MCPServerStdio, OpenAIProvider, run, setDefaultModelProvider } from "@openai/agents";
import { z } from "zod";
import type { AgentAnswer, CaseGraph } from "../../../../packages/shared/src/index.js";
import { apiConfig } from "../config.js";

type RuntimeInput = {
  graph: CaseGraph;
  question: string;
};

const answerSchema = z.object({
  answer: z.string(),
  evidenceIds: z.array(z.string()),
  packetIds: z.array(z.string()),
  sessionLinkIds: z.array(z.string()),
  findingIds: z.array(z.string()),
  missingContext: z.array(z.string()),
  confidence: z.enum(["certain", "high", "low", "needs_context"]).nullable(),
  suggestedActions: z.array(z.string()),
  handoffAgent: z.string().nullable()
});

const jsonOutputInstruction = [
  "最终只能输出一个 JSON 对象，不要使用 Markdown。",
  "JSON 字段固定为 answer、evidenceIds、packetIds、sessionLinkIds、findingIds、missingContext、confidence、suggestedActions、handoffAgent。",
  "没有内容的数组填 []，没有 confidence 或 handoffAgent 时填 null。"
].join("\n");

function parseAgentOutput(output: unknown): AgentAnswer {
  const text = typeof output === "string" ? output : JSON.stringify(output);
  const jsonText = text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1);
  if (jsonText) {
    try {
      const parsed = answerSchema.parse(JSON.parse(jsonText));
      return {
        ...parsed,
        confidence: parsed.confidence || undefined,
        handoffAgent: parsed.handoffAgent || undefined
      };
    } catch {
      // Fall through to plain text. The LLM boundary is allowed to be messy.
    }
  }
  return {
    answer: text,
    evidenceIds: [],
    packetIds: [],
    sessionLinkIds: [],
    findingIds: [],
    missingContext: [],
    suggestedActions: []
  };
}

function processEnv() {
  return Object.fromEntries(Object.entries(process.env).filter((entry): entry is [string, string] => entry[1] !== undefined));
}

export async function runPcapTroubleshootingAgent(input: RuntimeInput): Promise<AgentAnswer> {
  setDefaultModelProvider(new OpenAIProvider({
    apiKey: apiConfig.llm.apiKey,
    baseURL: apiConfig.llm.baseURL,
    useResponses: apiConfig.llm.useResponses
  }));

  const tempDirectory = mkdtempSync(path.join(tmpdir(), "pcapai-case-graph-"));
  const caseGraphPath = path.join(tempDirectory, "case.json");
  writeFileSync(caseGraphPath, JSON.stringify(input.graph));
  const caseGraphMcp = new MCPServerStdio({
    name: "case-graph-mcp",
    command: apiConfig.caseGraphMcp.command,
    args: apiConfig.caseGraphMcp.args,
    cwd: apiConfig.caseGraphMcp.cwd,
    env: { ...processEnv(), PCAPAI_CASE_GRAPH_PATH: caseGraphPath },
    cacheToolsList: true
  });

  await caseGraphMcp.connect();

  const triageAgent = new Agent({
    name: "TriageAgent",
    instructions: [
      "你是 pcapAI 的上下文检查专家。",
      "先调用 load_case_graph，只基于工具返回内容判断缺什么信息。",
      "重点检查抓包节点、接口方向、NAT/SLB/代理线索、时间窗口。",
      "缺少上下文时写入 missingContext 和 suggestedActions。",
      "回答必须是中文，并引用相关 evidenceIds、findingIds 或 sessionLinkIds。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    mcpServers: [caseGraphMcp]
  });

  const evidenceAgent = new Agent({
    name: "EvidenceAgent",
    instructions: [
      "你是 pcapAI 的证据解释专家。",
      "必须先调用 load_case_graph，再按需要调用 get_finding、get_evidence、get_session_link、get_packet_detail。",
      "不允许编造未出现在 case graph 中的包、节点或故障原因。",
      "回答必须包含 evidenceIds、packetIds、findingIds 或 sessionLinkIds。低置信度不能说成确定结论。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    mcpServers: [caseGraphMcp]
  });

  const reportAgent = new Agent({
    name: "ReportAgent",
    instructions: [
      "你是 pcapAI 的中文排障报告专家。",
      "必须调用 export_report 获取报告草稿，再按用户问题压缩或解释。",
      "只整理已有 case graph，不新增证据判断。",
      "报告包含：问题现象、路径还原、关键证据、判断结论、下一步动作。",
      "所有结论必须引用 evidenceIds、packetIds、findingIds 或 sessionLinkIds。",
      jsonOutputInstruction
    ].join("\n"),
    model: apiConfig.llm.model,
    mcpServers: [caseGraphMcp]
  });

  const leaderAgent = new Agent({
    name: "PcapTroubleshootingLeaderAgent",
    instructions: [
      "你是 pcapAI 的 leader agent。",
      "根据用户问题选择合适的专家：缺少什么数据交给 TriageAgent，解释证据交给 EvidenceAgent，生成报告交给 ReportAgent。",
      "不要直接读取本地文件，不要执行 shell，不要绕过工具。",
      "你只能通过工具读取 case graph，不允许基于常识补造包、节点、转换线索或结论。",
      "输出必须绑定 evidenceIds、packetIds、findingIds 或 sessionLinkIds；没有证据就追问缺失上下文。",
      jsonOutputInstruction
    ].join("\n"),
    handoffs: [triageAgent, evidenceAgent, reportAgent],
    model: apiConfig.llm.model,
    mcpServers: [caseGraphMcp]
  });

  try {
    const result = await run(leaderAgent, input.question, { maxTurns: 8 });
    return parseAgentOutput(result.finalOutput);
  } finally {
    await caseGraphMcp.close();
    rmSync(tempDirectory, { recursive: true, force: true });
  }
}
