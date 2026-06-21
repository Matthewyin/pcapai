/*
 * Markdown 渲染工具（从 main.tsx 抽出）。
 * 用 marked 解析 + DOMPurify XSS 过滤；白名单与原 main.tsx 一致。
 */
import { marked } from "marked";
import DOMPurify from "dompurify";
import type { ChatMessage } from "../types";

// 全局 marked 配置（与原 main.tsx 一致：单换行 = <br>，启用 GFM）
marked.setOptions({ breaks: true, gfm: true });

export function renderMarkdown(text: string): string {
  const html = marked.parse(text) as string;
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ["h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr", "strong", "em", "del", "ul", "ol", "li", "a", "code", "pre", "blockquote", "table", "thead", "tbody", "tr", "th", "td"],
    ALLOWED_ATTR: ["href", "target", "rel"]
  });
}

/** Agent 内部名 → 中文友好名（与原 main.tsx 一致）。 */
export function friendlyAgentName(name?: string): string {
  if (!name) return "";
  if (name === "EvidenceAgent") return "假设验证 Agent";
  if (name === "HypothesisAgent") return "假设验证 Agent";
  if (name === "TriageAgent") return "诊断访谈 Agent";
  if (name === "DiagnosticInterviewAgent") return "诊断访谈 Agent";
  if (name === "PathAgent") return "路径还原 Agent";
  if (name === "ProtocolAgent") return "协议诊断 Agent";
  if (name === "ReportAgent") return "报告 Agent";
  return name;
}

/**
 * 把原始 thought 文本规范化为可展示文本（去噪、转中文术语）。
 * 返回 null 表示该 thought 不展示。
 */
export function normalizeThoughtForDisplay(text: string): string | null {
  if (!text.trim()) return null;
  const displayText = text
    .replace(/Leader Intent Planner/g, "规划")
    .replace(/Chain Planner/g, "规划");
  const cleanedText = displayText.replace(/^▸\s*/, "").trim();
  if (displayText.includes("使用模型：")) return null;
  if (displayText === "规划 正在规划分析步骤。") return "规划：正在识别问题并选择分析路径。";
  if (displayText.startsWith("规划 输出：")) return null;
  if (displayText.startsWith("规划 识别：")) {
    const planKind = displayText.match(/^规划 识别：(chain|single)（([^）]+)）/);
    return planKind ? `规划：已生成${planKind[1] === "chain" ? "多步" : "单步"}分析计划，置信度 ${planKind[2]}。` : "规划：已生成分析计划。";
  }
  if (displayText.startsWith("规划 正在判断用户意图。")) return "规划：正在识别问题意图。";
  if (cleanedText.startsWith("开始分析链")) return `规划：${cleanedText}`;
  if (/^步骤 \d+\/\d+/.test(cleanedText)) return `工具查询：${cleanedText}`;
  if (/^✗ 步骤/.test(cleanedText)) return `执行失败：${cleanedText.replace(/^✗\s*/, "")}`;
  if (cleanedText.startsWith("分析链完成")) return "综合解读：分析链完成。";
  if (cleanedText.startsWith("调用 tshark-query MCP")) return `工具查询：${cleanedText.replace(/^调用 tshark-query MCP 的?/, "").trim()}`;
  if (cleanedText.startsWith("已保存") || cleanedText.includes("EvidenceCard") || cleanedText.includes("证据卡")) return `证据生成：${cleanedText}`;
  if (cleanedText.startsWith("综合解读")) return "综合解读：正在基于证据生成结论。";
  return cleanedText;
}

/** 追加一条 thought 到消息（去重 + 规范化）。返回新 message（不可变）。 */
export function appendThought(message: ChatMessage, text: string): ChatMessage {
  const thought = normalizeThoughtForDisplay(text);
  if (!thought) return message;
  const thoughts = message.thoughts || [];
  if (thoughts[thoughts.length - 1] === thought || thoughts.includes(thought)) return message;
  return { ...message, thoughts: [...thoughts, thought] };
}

/** 当前消息应展示的 thought 列表（去重 + 规范化）。 */
export function displayThoughts(message: ChatMessage): string[] {
  return (message.thoughts || []).reduce<string[]>((items, text) => {
    const thought = normalizeThoughtForDisplay(text);
    if (thought && !items.includes(thought)) items.push(thought);
    return items;
  }, []);
}
