// RFC txt 语料解析：rfc-index.txt 元数据 + 正文章节切分。纯函数，供构建脚本与测试使用。

export type RfcIndexEntry = {
  docId: number;
  title: string;
  status: string;
  obsoletedBy: number[];
  updatedBy: number[];
};

export type RfcSection = {
  section: string;
  sectionTitle: string;
  body: string;
};

function rfcNumbersFrom(text: string): number[] {
  return [...text.matchAll(/RFC0*(\d+)/g)].map((match) => Number(match[1]));
}

// rfc-index.txt 条目格式：行首编号开头，续行缩进 5 空格
export function parseRfcIndex(raw: string): RfcIndexEntry[] {
  const entries: RfcIndexEntry[] = [];
  let current: string[] = [];
  const flush = () => {
    if (!current.length) return;
    const joined = current.join(" ").replace(/\s+/g, " ").trim();
    current = [];
    const head = joined.match(/^(\d{1,5}) (.+)$/);
    if (!head) return;
    const docId = Number(head[1]);
    const rest = head[2];
    if (/^Not Issued\.?$/i.test(rest.trim())) return;
    // 标题取第一个「. 」之前的部分；标题内含「. 」的情况极少，可接受
    const dotIndex = rest.indexOf(". ");
    const title = (dotIndex > 0 ? rest.slice(0, dotIndex) : rest).trim();
    const status = rest.match(/\(Status:\s*([^)]+)\)/)?.[1].trim() || "UNKNOWN";
    const obsoletedBy = rfcNumbersFrom(rest.match(/\(Obsoleted by ([^)]+)\)/)?.[1] || "");
    const updatedBy = rfcNumbersFrom(rest.match(/\(Updated by ([^)]+)\)/)?.[1] || "");
    entries.push({ docId, title, status, obsoletedBy, updatedBy });
  };
  for (const line of raw.split(/\r?\n/)) {
    if (/^\d{1,5} /.test(line)) {
      flush();
      current = [line];
    } else if (current.length && /^\s{3,}\S/.test(line)) {
      current.push(line.trim());
    } else if (current.length && !line.trim()) {
      flush();
    }
  }
  flush();
  return entries;
}

const pageFooterPattern = /^\s*\[Page \w+\]\s*$/;
// 翻页后的页眉行，如 "RFC 9293                         TCP                          August 2022"
const pageHeaderPattern = /^RFC \d+\s{2,}.*\s{2,}\S+ \d{4}\s*$/;
// 行首章节标题，如 "3.5.  Establishing a Connection"；ToC 行带点引线或行尾页码
const headingPattern = /^(\d+(?:\.\d+)*)\.?\s{1,3}(\S.*)$/;
const namedHeadingPattern = /^(Abstract|Appendix [A-Z](?:\.\d+)*\.?)(?:\s{1,3}(\S.*))?$/;

function isTocLine(titleText: string) {
  return /\.{4,}/.test(titleText) || /\s\d{1,4}$/.test(titleText.trimEnd());
}

export function parseRfcSections(raw: string): RfcSection[] {
  const lines = raw.replace(/^﻿/, "").replace(/\f/g, "\n").split(/\r?\n/);
  type Draft = { section: string; sectionTitle: string; bodyLines: string[] };
  const drafts: Draft[] = [{ section: "_front", sectionTitle: "Front Matter", bodyLines: [] }];
  for (const line of lines) {
    if (pageFooterPattern.test(line) || pageHeaderPattern.test(line)) continue;
    const named = line.match(namedHeadingPattern);
    const numbered = line.match(headingPattern);
    if (named) {
      const id = named[1].toLowerCase().startsWith("appendix")
        ? named[1].replace(/^Appendix\s+/i, "appendix-").replace(/\.$/, "").toLowerCase()
        : "abstract";
      drafts.push({ section: id, sectionTitle: named[2] ? `${named[1]} ${named[2]}` : named[1], bodyLines: [] });
      continue;
    }
    if (numbered && !isTocLine(numbered[2])) {
      drafts.push({ section: numbered[1], sectionTitle: numbered[2].trim(), bodyLines: [] });
      continue;
    }
    drafts[drafts.length - 1].bodyLines.push(line);
  }
  // 压缩空白、丢弃 ToC 残片（正文过短的编号章节）；同号章节保留正文更长的一个
  const bySection = new Map<string, RfcSection>();
  for (const draft of drafts) {
    const body = draft.bodyLines.join("\n").replace(/\n{3,}/g, "\n\n").trim();
    if (draft.section !== "_front" && body.length < 40) continue;
    if (draft.section === "_front" && body.length < 40) continue;
    const existing = bySection.get(draft.section);
    if (!existing || body.length > existing.body.length) {
      bySection.set(draft.section, { section: draft.section, sectionTitle: draft.sectionTitle, body });
    }
  }
  return [...bySection.values()];
}

// 检索词构造：抽取 ASCII 词元（语料为英文）；全 CJK 查询返回 null 让调用方提示换英文关键词
export function buildFtsMatchQuery(query: string): { and: string; or: string } | null {
  const tokens = [...query.matchAll(/[A-Za-z][A-Za-z0-9_.-]*|\d{2,5}/g)]
    .map((match) => match[0].replace(/^[.-]+|[.-]+$/g, ""))
    .filter((token) => token.length > 1);
  if (!tokens.length) return null;
  const quoted = [...new Set(tokens)].map((token) => `"${token.replace(/"/g, "")}"`);
  return { and: quoted.join(" AND "), or: quoted.join(" OR ") };
}
