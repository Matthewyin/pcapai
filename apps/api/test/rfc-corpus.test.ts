import assert from "node:assert/strict";
import { test } from "node:test";
import { buildFtsMatchQuery, parseRfcIndex, parseRfcSections } from "../src/services/rfcCorpus.js";

const indexSample = [
  "0001 Host Software. S. Crocker. April 1969. (Format: TXT, HTML) (Status:",
  "     UNKNOWN) (DOI: 10.17487/RFC0001)",
  "",
  "0793 Transmission Control Protocol. J. Postel. September 1981. (Format:",
  "     TXT, HTML) (Obsoletes RFC761) (Obsoleted by RFC9293) (Updated by",
  "     RFC1122, RFC3168, RFC6093, RFC6528) (Status: INTERNET STANDARD)",
  "     (DOI: 10.17487/RFC0793)",
  "",
  "3300 Not Issued.",
  "",
  "9293 Transmission Control Protocol (TCP). W. Eddy, Ed.. August 2022.",
  "     (Format: HTML, TXT, PDF, XML) (Obsoletes RFC793, RFC879) (Status:",
  "     INTERNET STANDARD) (DOI: 10.17487/RFC9293)"
].join("\n");

test("parseRfcIndex 提取编号、标题、状态与废弃关系", () => {
  const entries = parseRfcIndex(indexSample);
  assert.equal(entries.length, 3);
  const rfc793 = entries.find((entry) => entry.docId === 793)!;
  assert.equal(rfc793.title, "Transmission Control Protocol");
  assert.equal(rfc793.status, "INTERNET STANDARD");
  assert.deepEqual(rfc793.obsoletedBy, [9293]);
  assert.deepEqual(rfc793.updatedBy, [1122, 3168, 6093, 6528]);
  const rfc9293 = entries.find((entry) => entry.docId === 9293)!;
  assert.equal(rfc9293.title, "Transmission Control Protocol (TCP)");
  assert.deepEqual(rfc9293.obsoletedBy, []);
});

test("parseRfcIndex 跳过 Not Issued 条目", () => {
  const entries = parseRfcIndex(indexSample);
  assert.equal(entries.find((entry) => entry.docId === 3300), undefined);
});

const rfcBody = [
  "",
  "Internet Engineering Task Force (IETF)                      W. Eddy, Ed.",
  "Request for Comments: 9293                                   August 2022",
  "",
  "Abstract",
  "",
  "   This document specifies the Transmission Control Protocol and is the",
  "   primary reference for TCP behavior across implementations today.",
  "",
  "Table of Contents",
  "",
  "1.  Purpose and Scope ............................................. 2",
  "3.5.  Establishing a Connection ................................... 9",
  "",
  "1.  Purpose and Scope",
  "",
  "   In 1981, RFC 793 was released, documenting the Transmission Control",
  "   Protocol and replacing earlier specifications of its behavior.",
  "",
  "RFC 9293                          TCP                        August 2022",
  "",
  "3.5.  Establishing a Connection",
  "",
  "   The three-way handshake is the procedure used to establish a",
  "   connection between two endpoints exchanging initial sequence numbers.",
  "",
  "                                                                [Page 9]"
].join("\n");

test("parseRfcSections 切分章节、保留 Abstract、过滤 ToC 与页脚", () => {
  const sections = parseRfcSections(rfcBody);
  const ids = sections.map((section) => section.section);
  assert.ok(ids.includes("abstract"));
  assert.ok(ids.includes("1"));
  assert.ok(ids.includes("3.5"));
  const section35 = sections.find((section) => section.section === "3.5")!;
  assert.equal(section35.sectionTitle, "Establishing a Connection");
  assert.ok(section35.body.includes("three-way handshake"));
  assert.ok(!section35.body.includes("[Page"));
  // ToC 行不应产生独立空章节
  assert.ok(!sections.some((section) => section.body.length < 40));
});

test("buildFtsMatchQuery 抽取英文词元并生成 AND/OR 两种查询", () => {
  const match = buildFtsMatchQuery("TCP zero window probe 的规范行为")!;
  assert.ok(match.and.includes('"TCP" AND "zero" AND "window" AND "probe"'));
  assert.ok(match.or.includes('"TCP" OR "zero"'));
});

test("buildFtsMatchQuery 纯中文查询返回 null", () => {
  assert.equal(buildFtsMatchQuery("零窗口探测规范"), null);
});
