import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { apiConfig } from "../config.js";

export interface LearnedPattern {
  regex: string;
  adapterId: string;
  createdAt: string;
  exampleQuestions: string[];
  hitCount: number;
}

interface PatternStore {
  patterns: LearnedPattern[];
}

const PATTERNS_FILE = apiConfig.learnedPatternsPath;

// 学习是 fire-and-forget 的异步任务，串行化读改写避免并发互相覆盖
let writeLock: Promise<void> = Promise.resolve();

function withWriteLock(task: () => void | Promise<void>): Promise<void> {
  const next = writeLock.then(task);
  writeLock = next.catch(() => {});
  return next;
}

function readStore(): PatternStore {
  try {
    return JSON.parse(readFileSync(PATTERNS_FILE, "utf-8"));
  } catch {
    return { patterns: [] };
  }
}

function writeStore(store: PatternStore) {
  mkdirSync(dirname(PATTERNS_FILE), { recursive: true });
  writeFileSync(PATTERNS_FILE, JSON.stringify(store, null, 2));
}

export function loadLearnedPatterns(): { regex: RegExp; adapterId: string }[] {
  const store = readStore();
  return store.patterns
    .map((p) => {
      try {
        return { regex: new RegExp(p.regex, "i"), adapterId: p.adapterId };
      } catch {
        return null;
      }
    })
    .filter((p): p is { regex: RegExp; adapterId: string } => p !== null);
}

export function listLearnedPatterns(): LearnedPattern[] {
  return readStore().patterns;
}

// 直通车选择：命中次数达到阈值的学习模式可绕过 Chain Planner 直接走确定性路径
export function selectBypassPattern(patterns: LearnedPattern[], question: string, minHits: number): LearnedPattern | null {
  for (const pattern of patterns) {
    if (pattern.hitCount < minHits) continue;
    try {
      if (new RegExp(pattern.regex, "i").test(question)) return pattern;
    } catch {
      continue;
    }
  }
  return null;
}

export function findBypassPattern(question: string, minHits: number): LearnedPattern | null {
  return selectBypassPattern(readStore().patterns, question, minHits);
}

export function deleteLearnedPattern(regex: string, adapterId: string): boolean {
  const store = readStore();
  const remaining = store.patterns.filter((p) => !(p.regex === regex && p.adapterId === adapterId));
  if (remaining.length === store.patterns.length) return false;
  writeStore({ patterns: remaining });
  return true;
}

export function incrementHitCount(adapterId: string, regexSource: string) {
  void withWriteLock(() => {
    const store = readStore();
    const pattern = store.patterns.find((p) => p.adapterId === adapterId && p.regex === regexSource);
    if (pattern) {
      pattern.hitCount += 1;
      writeStore(store);
    }
  });
}

export async function learnFromAgentRun(
  question: string,
  toolCalls: string[],
  adapterIds: string[]
): Promise<void> {
  if (!apiConfig.llm.apiKey) return;
  if (!toolCalls.length) return;

  const store = readStore();
  const existingPatterns = store.patterns.map((p) => `${p.adapterId}: ${p.regex}`).join("\n");

  const prompt = `你是 pcapAI 的 pattern 学习器。分析以下 agent 查询场景，生成一个正则表达式用于未来确定性路由。

用户问题：${question}
Agent 调用的 MCP tools：${toolCalls.join(", ")}

可用 adapter 列表：
${adapterIds.map((id) => `- ${id}`).join("\n")}

要求：
1. 返回 JSON：{"regex": "...", "adapterId": "..."}
2. regex 必须匹配原始问题
3. regex 不应太宽泛，不应匹配其他 protocol 的问题
4. adapterId 从上面的可用列表中选择最匹配的
${existingPatterns ? `5. 已有的 learned patterns（不要重复或冲突）：\n${existingPatterns}` : ""}`;

  try {
    const response = await fetch(`${apiConfig.llm.baseURL}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiConfig.llm.apiKey}`
      },
      body: JSON.stringify({
        model: apiConfig.llm.model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0,
        max_tokens: 200
      })
    });
    if (!response.ok) return;

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content?.trim();
    if (!content) return;

    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return;

    const parsed = JSON.parse(jsonMatch[0]);
    if (!parsed.regex || !parsed.adapterId) return;
    if (!adapterIds.includes(parsed.adapterId)) return;

    const regex = new RegExp(parsed.regex, "i");
    if (!regex.test(question)) return;

    await withWriteLock(() => {
      const freshStore = readStore();
      if (freshStore.patterns.some((p) => p.regex === parsed.regex && p.adapterId === parsed.adapterId)) return;
      freshStore.patterns.push({
        regex: parsed.regex,
        adapterId: parsed.adapterId,
        createdAt: new Date().toISOString(),
        exampleQuestions: [question],
        hitCount: 0
      });
      writeStore(freshStore);
    });
  } catch {
    // 学习失败不影响主流程
  }
}
