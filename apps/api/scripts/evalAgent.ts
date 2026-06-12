// Agent 行为评测：用黄金用例集对运行中的 API 做端到端断言（确定性路由、RFC 引用、守门、无 think 泄漏）。
// 前置：npm run dev -w apps/api 已启动且配置了 LLM Key。
// 用法：npm run eval [-- --case dns-http-chain]
import { readFileSync } from "node:fs";
import path from "node:path";
import { apiConfig } from "../src/config.js";

type AgentExpect = {
  answerMatch?: string[];
  answerNotMatch?: string[];
  eventMatch?: string[];
  eventNotMatch?: string[];
};

type InsightsExpect = {
  minInsights?: number;
  coverageRequired?: boolean;
  minProtocolKinds?: number;
};

type EvalCase = {
  id: string;
  kind: "agent" | "insights";
  describe: string;
  question?: string;
  expect: AgentExpect & InsightsExpect;
};

type EvalSpec = { fixture: string; cases: EvalCase[] };

const baseURL = `http://${apiConfig.host}:${apiConfig.port}/api`;
const specPath = path.join(import.meta.dirname, "evalCases.json");
const spec = JSON.parse(readFileSync(specPath, "utf8")) as EvalSpec;
const onlyCase = (() => {
  const index = process.argv.indexOf("--case");
  return index >= 0 ? process.argv[index + 1] : undefined;
})();

type CheckResult = { label: string; pass: boolean; detail?: string };

function checkRegexes(text: string, patterns: string[] | undefined, mustMatch: boolean, label: string): CheckResult[] {
  return (patterns || []).map((pattern) => {
    const matched = new RegExp(pattern, "i").test(text);
    const pass = mustMatch ? matched : !matched;
    return { label: `${label} ${mustMatch ? "匹配" : "排除"} /${pattern}/`, pass, detail: pass ? undefined : `文本${mustMatch ? "未命中" : "意外命中"}` };
  });
}

async function api(pathname: string, init?: RequestInit) {
  const response = await fetch(`${baseURL}${pathname}`, init);
  if (!response.ok) throw new Error(`${pathname} -> HTTP ${response.status}: ${(await response.text()).slice(0, 300)}`);
  return response;
}

async function runAgentCase(caseId: string, evalCase: EvalCase): Promise<CheckResult[]> {
  const response = await api(`/cases/${caseId}/agent/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question: evalCase.question })
  });
  const sseText = await response.text();
  const doneData = [...sseText.matchAll(/event: done\ndata: (.*)/g)].at(-1)?.[1];
  const errorData = [...sseText.matchAll(/event: error\ndata: (.*)/g)].at(-1)?.[1];
  if (!doneData) return [{ label: "完成事件", pass: false, detail: `没有 done 事件${errorData ? `；error=${errorData.slice(0, 200)}` : ""}` }];
  const answer = String(JSON.parse(doneData).answer || "");
  return [
    { label: "完成事件", pass: true },
    ...checkRegexes(answer, evalCase.expect.answerMatch, true, "答案"),
    ...checkRegexes(answer, evalCase.expect.answerNotMatch, false, "答案"),
    ...checkRegexes(sseText, evalCase.expect.eventMatch, true, "事件流"),
    ...checkRegexes(sseText, evalCase.expect.eventNotMatch, false, "事件流")
  ];
}

async function runInsightsCase(caseId: string, evalCase: EvalCase): Promise<CheckResult[]> {
  const graph = await (await api(`/cases/${caseId}`)).json() as {
    insights?: Array<{ type: string }>;
    insightCoverage?: { note: string };
    packets?: Array<{ protocol?: string }>;
  };
  const results: CheckResult[] = [];
  const insightCount = graph.insights?.length || 0;
  if (evalCase.expect.minInsights !== undefined) {
    results.push({ label: `洞察数 >= ${evalCase.expect.minInsights}`, pass: insightCount >= evalCase.expect.minInsights, detail: `实际 ${insightCount}` });
  }
  if (evalCase.expect.coverageRequired) {
    results.push({ label: "insightCoverage 存在", pass: Boolean(graph.insightCoverage?.note) });
  }
  if (evalCase.expect.minProtocolKinds !== undefined) {
    const kinds = new Set((graph.packets || []).map((packet) => (packet.protocol || "").toLowerCase()).filter(Boolean));
    results.push({ label: `提取包协议种类 >= ${evalCase.expect.minProtocolKinds}`, pass: kinds.size >= evalCase.expect.minProtocolKinds, detail: `实际 ${[...kinds].join("/")}` });
  }
  return results;
}

async function main() {
  try {
    await api("/health");
  } catch {
    console.error(`API 不可达（${baseURL}）。请先运行 npm run dev -w apps/api 并配置 LLM Key。`);
    process.exit(1);
  }

  const caseId = ((await (await api("/cases/new-chat", { method: "POST" })).json()) as { spec: { caseId: string } }).spec.caseId;
  const fixturePath = path.resolve(path.join(import.meta.dirname, "../../.."), spec.fixture);
  const form = new FormData();
  form.append(apiConfig.uploadFieldName, new Blob([readFileSync(fixturePath)]), path.basename(fixturePath));
  await api(`/cases/${caseId}/attachments`, { method: "POST", body: form });
  console.log(`评测 case：${caseId}，fixture：${spec.fixture}\n`);

  let failed = 0;
  const startedAt = Date.now();
  for (const evalCase of spec.cases) {
    if (onlyCase && evalCase.id !== onlyCase) continue;
    const caseStartedAt = Date.now();
    let checks: CheckResult[];
    try {
      checks = evalCase.kind === "insights" ? await runInsightsCase(caseId, evalCase) : await runAgentCase(caseId, evalCase);
    } catch (error) {
      checks = [{ label: "执行", pass: false, detail: error instanceof Error ? error.message : String(error) }];
    }
    const casePass = checks.every((check) => check.pass);
    if (!casePass) failed += 1;
    const seconds = ((Date.now() - caseStartedAt) / 1000).toFixed(1);
    console.log(`${casePass ? "✅" : "❌"} ${evalCase.id} — ${evalCase.describe}（${seconds}s）`);
    for (const check of checks) {
      if (!check.pass) console.log(`   ✗ ${check.label}${check.detail ? ` — ${check.detail}` : ""}`);
    }
  }

  await api("/cases", { method: "DELETE", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ caseIds: [caseId] }) });
  const total = ((Date.now() - startedAt) / 1000).toFixed(0);
  console.log(`\n总计：${failed ? `${failed} 个用例失败` : "全部通过"}，耗时 ${total}s。评测 case 已清理。`);
  process.exit(failed ? 1 : 0);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
