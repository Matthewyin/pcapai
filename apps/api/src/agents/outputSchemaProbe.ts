// outputSchema 兼容性探针：检测当前 LLM provider 是否支持 SDK 的 outputSchema（structured output）。
// SDK 的 outputSchema 底层走 response_format: { type: "json_schema" }，第三方模型（MiniMax 等）支持不一。
// 探针结果缓存（进程级），避免每次 Agent 运行都测。
// 探针失败则 runtime 保留手写 JSON 解析 fallback（见 parseAgentOutput）。
import { Agent, Runner } from "@openai/agents";
import { z } from "zod";
import { OpenAIProvider } from "@openai/agents";
import { apiConfig } from "../config.js";

const ProbeSchema = z.object({
  verdict: z.enum(["ok", "fail"]),
  detail: z.string()
});

let cachedResult: boolean | null = null;

// 测试当前配置的 LLM 是否支持 outputSchema。返回 true 表示支持。
// 用一个最小 Agent + 固定 schema 跑一次，能产出符合 schema 的对象即视为支持。
export async function probeOutputSchemaSupport(): Promise<boolean> {
  if (cachedResult !== null) return cachedResult;
  if (!apiConfig.llm.apiKey) {
    cachedResult = false;
    return false;
  }
  try {
    const runner = new Runner({
      modelProvider: new OpenAIProvider({
        apiKey: apiConfig.llm.apiKey,
        baseURL: apiConfig.llm.baseURL,
        useResponses: apiConfig.llm.useResponses
      })
    });
    const probeAgent = new Agent({
      name: "OutputSchemaProbe",
      instructions: "输出一个 JSON 对象，verdict 为 \"ok\"，detail 简述你正在响应探针测试。",
      model: apiConfig.llm.model,
      outputType: ProbeSchema
    });
    const result = await runner.run(probeAgent, "执行 outputSchema 兼容性探针。", { maxTurns: 1 });
    // finalOutput 若符合 schema（SDK 已校验），视为支持
    cachedResult = Boolean(result.finalOutput && typeof result.finalOutput === "object" && "verdict" in result.finalOutput);
    return cachedResult;
  } catch {
    cachedResult = false;
    return false;
  }
}

export function getCachedOutputSchemaSupport(): boolean | null {
  return cachedResult;
}

// 重置缓存（配置变更后重新探测用）
export function resetOutputSchemaCache(): void {
  cachedResult = null;
}
