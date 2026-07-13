import assert from "node:assert/strict";
import test from "node:test";
import type { AgentAnswer, CaseGraph } from "../../../packages/shared/src/index.js";
import {
  collectPacketIdsFromToolOutput,
  validateAgentAnswerGrounding
} from "../src/agents/agentAnswerGrounding.js";
import type { RfcSectionAuditRecord } from "../src/agents/rfcTools.js";

function graph(): CaseGraph {
  return {
    spec: { caseId: "grounding-test", title: "test", createdAt: new Date().toISOString() },
    captures: [], mappingHints: [], timeOffsetHints: [], rawPackets: [], analysisFilter: {},
    packets: [{
      packetId: "pkt-valid", nodeId: "node-1", pcapFilename: "test.pcap", frameNumber: 1,
      timestamp: 1, protocol: "tcp", tcpFlags: [], summary: "", raw: {}
    }],
    sessions: [], sessionLinks: [], diagnosticTags: [], evidence: [], findings: [],
    path: { nodes: [], edges: [] }, queryRuns: [], analysisRuns: [], toolRuns: [],
    insights: [], connectionLinks: [], memory: { topology: "", findings: [], userNotes: [] }
  };
}

function answer(patch: Partial<NonNullable<AgentAnswer["rootCauses"]>[number]> = {}): AgentAnswer {
  return {
    answer: "结论",
    evidenceIds: [], packetIds: [], sessionLinkIds: [], findingIds: [], missingContext: [], suggestedActions: [],
    rootCauses: [{
      cause: "服务端未按规范响应",
      rfcDocId: 9293,
      rfcSection: "3.10.7.4",
      rfcVerified: true,
      confidence: "high",
      evidencePacketIds: ["pkt-valid"],
      skillIds: [],
      ...patch
    }]
  };
}

const validAudit: RfcSectionAuditRecord[] = [{
  rfcDocId: 9293,
  requestedSection: "3.10.7.4",
  returnedSection: "3.10.7.4",
  success: true
}];

test("真实读取 RFC 章节且证据包存在时保留 verified", () => {
  const validated = validateAgentAnswerGrounding(answer(), graph(), validAudit);
  assert.equal(validated.rootCauses?.[0].rfcVerified, true);
  assert.equal(validated.rootCauses?.[0].confidence, "high");
});

test("模型伪造 rfcVerified=true 时降级为经验推测", () => {
  const validated = validateAgentAnswerGrounding(answer(), graph(), []);
  assert.equal(validated.rootCauses?.[0].rfcVerified, false);
  assert.equal(validated.rootCauses?.[0].confidence, "low");
  assert.match(validated.rootCauses?.[0].cause || "", /经验推测，无已验证 RFC 依据/);
});

test("RFC 章节不匹配或读取失败时不能通过硬校验", () => {
  const mismatch = validateAgentAnswerGrounding(answer(), graph(), [{ ...validAudit[0], returnedSection: "3.10.7.3" }]);
  const failed = validateAgentAnswerGrounding(answer(), graph(), [{ ...validAudit[0], success: false }]);
  assert.equal(mismatch.rootCauses?.[0].rfcVerified, false);
  assert.equal(failed.rootCauses?.[0].rfcVerified, false);
});

test("证据包不存在或根因没有证据包时不能通过硬校验", () => {
  const forged = validateAgentAnswerGrounding(answer({ evidencePacketIds: ["pkt-forged"] }), graph(), validAudit);
  const empty = validateAgentAnswerGrounding(answer({ evidencePacketIds: [] }), graph(), validAudit);
  assert.equal(forged.rootCauses?.[0].rfcVerified, false);
  assert.equal(empty.rootCauses?.[0].rfcVerified, false);
});

test("本轮确定性工具结果中的包 ID 可以作为有效证据", () => {
  const toolPacketIds = new Set<string>();
  collectPacketIdsFromToolOutput(JSON.stringify({ status: "success", answer: { packetIds: ["pkt-tool"] } }), toolPacketIds);
  const validated = validateAgentAnswerGrounding(answer({ evidencePacketIds: ["pkt-tool"] }), graph(), validAudit, toolPacketIds);
  assert.equal(validated.rootCauses?.[0].rfcVerified, true);
});
