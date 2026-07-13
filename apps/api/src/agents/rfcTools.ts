import { tool, type Tool } from "@openai/agents";
import { z } from "zod";
import { getRfcSection, searchRfc } from "../services/rfcRagService.js";

function errorText(error: unknown) {
  return JSON.stringify({ error: error instanceof Error ? error.message : String(error) });
}

// LLM 边界防御：部分模型会把 null 序列化成字符串 "null"
function cleanOptionalString(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed === "null" || trimmed === "undefined") return undefined;
  return trimmed;
}

export type RfcSectionAuditRecord = {
  rfcDocId: number;
  requestedSection?: string;
  returnedSection?: string;
  success: boolean;
};

type RfcToolsOptions = {
  onSectionRead?: (record: RfcSectionAuditRecord) => void;
};

// RFC 知识库工具：search_rfc 定位条文，get_rfc_section 精读原文。
// 设计原则：每次调用一击命中（BM25 排序 + 摘要），不要求模型迭代检索。
export function createRfcTools(options: RfcToolsOptions = {}): Tool[] {
  return [
    tool({
      name: "search_rfc",
      description: "在本地 RFC 全文知识库中按关键词检索协议规范条文。query 必须用英文关键词（RFC 原文为英文），如 \"TCP zero window probe\"、\"DNS SERVFAIL resolver\"。返回命中的 RFC 编号、章节、摘要片段和文档状态（含被废弃标注）。定位后用 get_rfc_section 精读原文。",
      parameters: z.object({
        query: z.string(),
        topK: z.number().int().min(1).max(12).nullable().optional()
      }),
      execute: ({ query, topK }) => {
        try {
          const hits = searchRfc(query, topK || undefined);
          if (!hits.length) return JSON.stringify({ hits: [], note: "没有命中；尝试更通用的英文关键词，或确认协议名/字段名拼写。" });
          return JSON.stringify({
            hits: hits.map((hit) => ({
              rfc: hit.docId,
              title: hit.title,
              section: hit.section,
              sectionTitle: hit.sectionTitle,
              status: hit.status,
              obsoletedBy: hit.obsoletedBy.length ? hit.obsoletedBy : undefined,
              snippet: hit.snippet
            }))
          });
        } catch (error) {
          return errorText(error);
        }
      }
    }),
    tool({
      name: "get_rfc_section",
      description: "精读指定 RFC 的章节原文（结论中的规范依据必须经此工具取回原文，不凭记忆引用）。不带 section 时返回该 RFC 的章节目录与状态；带 section（如 \"3.5\"）时返回该章节及其子章节全文。",
      parameters: z.object({
        rfcNumber: z.number().int(),
        section: z.string().nullable().optional()
      }),
      execute: ({ rfcNumber, section }) => {
        const requestedSection = cleanOptionalString(section);
        try {
          const result = getRfcSection(rfcNumber, requestedSection);
          options.onSectionRead?.({
            rfcDocId: result.docId,
            requestedSection,
            returnedSection: result.section,
            success: Boolean(result.section && result.body)
          });
          return JSON.stringify(result);
        } catch (error) {
          options.onSectionRead?.({ rfcDocId: rfcNumber, requestedSection, success: false });
          return errorText(error);
        }
      }
    })
  ];
}
