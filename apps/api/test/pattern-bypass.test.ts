import assert from "node:assert/strict";
import { test } from "node:test";
import { selectBypassPattern, type LearnedPattern } from "../src/services/patternLearner.js";

function pattern(regex: string, adapterId: string, hitCount: number): LearnedPattern {
  return { regex, adapterId, hitCount, createdAt: "2026-01-01T00:00:00Z", exampleQuestions: [] };
}

test("selectBypassPattern 只选择命中次数达标且正则匹配的模式", () => {
  const patterns = [
    pattern("dns.*解析失败", "dns_failures", 5),
    pattern("rst.*通信对", "tcp_rst_pairs", 1)
  ];
  const hit = selectBypassPattern(patterns, "查询 DNS 解析失败事件", 3);
  assert.equal(hit?.adapterId, "dns_failures");
  // hitCount 不达标的不直通
  assert.equal(selectBypassPattern(patterns, "给出 RST 通信对", 3), null);
  // 不匹配的问题不直通
  assert.equal(selectBypassPattern(patterns, "协议分布是什么", 3), null);
});

test("selectBypassPattern 跳过非法正则不抛错", () => {
  const patterns = [pattern("([invalid", "dns_failures", 9), pattern("http.*4xx", "http_transactions", 4)];
  const hit = selectBypassPattern(patterns, "查 HTTP 4xx 错误", 3);
  assert.equal(hit?.adapterId, "http_transactions");
});
