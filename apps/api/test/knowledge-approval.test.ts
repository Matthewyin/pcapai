import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { apiConfig } from "../src/config.js";
import { createSkill } from "../src/services/skillsService.js";
import {
  approveSkillProposal,
  createSkillProposal,
  listSkillProposals,
  rejectSkillProposal
} from "../src/services/skillProposalsService.js";
import {
  approveLearnedPattern,
  deleteLearnedPattern,
  learnFromAgentRun,
  listLearnedPatterns,
  loadLearnedPatterns,
  rejectLearnedPattern,
  setLearnedPatternEnabled
} from "../src/services/patternLearner.js";

function isolatedKnowledgeStore() {
  const root = mkdtempSync(path.join(tmpdir(), "pcapai-knowledge-approval-"));
  process.env.PCAPAI_SKILLS_DIR = path.join(root, "skills");
  process.env.PCAPAI_SKILL_PROPOSALS_PATH = path.join(root, "skill-proposals.json");
  process.env.PCAPAI_LEARNED_PATTERNS_PATH = path.join(root, "learned-patterns.json");
  return root;
}

function cleanup(root: string) {
  delete process.env.PCAPAI_SKILLS_DIR;
  delete process.env.PCAPAI_SKILL_PROPOSALS_PATH;
  delete process.env.PCAPAI_LEARNED_PATTERNS_PATH;
  rmSync(root, { recursive: true, force: true });
}

test("Agent Skill 提案在人工批准前不会写入全局 Skill", () => {
  const root = isolatedKnowledgeStore();
  try {
    const result = createSkillProposal({
      name: "verify-agent-proposal",
      description: "验证 Agent 提案审批",
      body: "## 步骤\n\n1. 检查证据。"
    });
    assert.equal(result.created, true);
    assert.equal(listSkillProposals("pending").length, 1);
    assert.throws(() => readFileSync(path.join(root, "skills", "verify-agent-proposal.md"), "utf8"));

    const approved = approveSkillProposal(result.proposal!.proposalId);
    assert.equal(approved.approved, true);
    assert.match(readFileSync(path.join(root, "skills", "verify-agent-proposal.md"), "utf8"), /检查证据/);
  } finally {
    cleanup(root);
  }
});

test("覆盖已有 Skill 必须经过第二次显式确认", () => {
  const root = isolatedKnowledgeStore();
  try {
    assert.equal(createSkill({
      name: "verify-overwrite-approval",
      description: "旧版本",
      body: "旧正文"
    }).created, true);
    const proposal = createSkillProposal({
      name: "verify-overwrite-approval",
      description: "新版本",
      body: "新正文"
    }).proposal!;

    const first = approveSkillProposal(proposal.proposalId, true);
    assert.equal(first.approved, false);
    assert.equal(first.requiresOverwriteConfirmation, true);
    assert.equal(first.proposal?.status, "overwrite_confirmation");
    assert.match(readFileSync(path.join(root, "skills", "verify-overwrite-approval.md"), "utf8"), /旧正文/);

    const second = approveSkillProposal(proposal.proposalId, true);
    assert.equal(second.approved, true);
    assert.match(readFileSync(path.join(root, "skills", "verify-overwrite-approval.md"), "utf8"), /新正文/);
  } finally {
    cleanup(root);
  }
});

test("拒绝 Skill 提案后不会写入 Skill 文件", () => {
  const root = isolatedKnowledgeStore();
  try {
    const proposal = createSkillProposal({
      name: "verify-rejected-proposal",
      description: "拒绝测试",
      body: "不应生效"
    }).proposal!;
    assert.equal(rejectSkillProposal(proposal.proposalId, "证据不足").rejected, true);
    assert.equal(approveSkillProposal(proposal.proposalId).approved, false);
    assert.throws(() => readFileSync(path.join(root, "skills", "verify-rejected-proposal.md"), "utf8"));
  } finally {
    cleanup(root);
  }
});

test("自动学习的 pattern 先进入候选态，批准后才生效，并可禁用、拒绝和删除", async () => {
  const root = isolatedKnowledgeStore();
  const originalFetch = globalThis.fetch;
  const originalKey = apiConfig.llm.apiKey;
  try {
    apiConfig.llm.apiKey = "test-key";
    globalThis.fetch = async () => new Response(JSON.stringify({
      choices: [{ message: { content: '{"regex":"重传.*问题","adapterId":"tcp_issues"}' } }]
    }), { status: 200, headers: { "Content-Type": "application/json" } });

    await learnFromAgentRun("重传有什么问题", ["query_tcp_retransmissions"], ["tcp_issues"]);
    const pending = listLearnedPatterns()[0];
    assert.equal(pending.status, "pending");
    assert.equal(loadLearnedPatterns().length, 0);

    assert.equal(approveLearnedPattern(pending.regex, pending.adapterId)?.status, "approved");
    assert.equal(loadLearnedPatterns().length, 1);
    assert.equal(setLearnedPatternEnabled(pending.regex, pending.adapterId, false)?.status, "disabled");
    assert.equal(loadLearnedPatterns().length, 0);
    assert.equal(rejectLearnedPattern(pending.regex, pending.adapterId)?.status, "rejected");
    assert.equal(deleteLearnedPattern(pending.regex, pending.adapterId), true);
    assert.equal(listLearnedPatterns().length, 0);
  } finally {
    globalThis.fetch = originalFetch;
    apiConfig.llm.apiKey = originalKey;
    cleanup(root);
  }
});
