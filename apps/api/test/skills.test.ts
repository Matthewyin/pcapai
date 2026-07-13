import assert from "node:assert/strict";
import test, { after } from "node:test";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { listSkills, getSkill, createSkill, deleteSkill, isValidSkillName, skillsIndexStatus } from "../src/services/skillsService.js";
import { apiConfig } from "../src/config.js";

const skillsTestDir = mkdtempSync(path.join(tmpdir(), "pcapai-skills-test-"));
cpSync(apiConfig.skills.dir, skillsTestDir, { recursive: true });
process.env.PCAPAI_SKILLS_DIR = skillsTestDir;
after(() => {
  delete process.env.PCAPAI_SKILLS_DIR;
  rmSync(skillsTestDir, { recursive: true, force: true });
});

const createdNames: string[] = [];
function registerForCleanup(name: string) { createdNames.push(name); }
// 套件开始前先清理上次可能的残留，保证幂等
for (const n of ["test-skill-roundtrip", "test-skill-overwrite", "test-skill-alpha", "test-skill-beta"]) {
  deleteSkill(n);
}

test("isValidSkillName: 合法/非法判定", () => {
  assert.equal(isValidSkillName("verify-tcp-options"), true);
  assert.equal(isValidSkillName("analyze-retransmission-pattern"), true);
  assert.equal(isValidSkillName("a1"), true);
  assert.equal(isValidSkillName("UPPER"), false);
  assert.equal(isValidSkillName("../etc/passwd"), false);
  assert.equal(isValidSkillName(""), false);
  assert.equal(isValidSkillName("-leading-dash"), false);
});

test("createSkill + getSkill: 写入并读回，frontmatter 解析正确", () => {
  const result = createSkill({
    name: "test-skill-roundtrip",
    description: "测试技能",
    triggers: ["场景A", "场景B"],
    toolsRequired: ["get_packet_detail", "get_rfc_section"],
    body: "# 标题\n\n## 步骤\n1. 第一步\n2. 第二步"
  });
  assert.equal(result.created, true);
  registerForCleanup("test-skill-roundtrip");

  const skill = getSkill("test-skill-roundtrip");
  assert.ok(skill);
  assert.equal(skill!.description, "测试技能");
  assert.deepEqual(skill!.triggers, ["场景A", "场景B"]);
  assert.deepEqual(skill!.toolsRequired, ["get_packet_detail", "get_rfc_section"]);
  assert.ok(skill!.body.includes("# 标题"));
  assert.ok(skill!.body.includes("第一步"));
});

test("createSkill: 已存在且不覆盖时拒绝", () => {
  createSkill({ name: "test-skill-overwrite", description: "原版", body: "v1" });
  registerForCleanup("test-skill-overwrite");
  const result = createSkill({ name: "test-skill-overwrite", description: "新版", body: "v2" });
  assert.equal(result.created, false);
  assert.ok(result.reason?.includes("已存在"));

  const overwriteResult = createSkill({ name: "test-skill-overwrite", description: "新版", body: "v2", overwrite: true });
  assert.equal(overwriteResult.created, true);
  const skill = getSkill("test-skill-overwrite");
  assert.equal(skill!.description, "新版");
});

test("createSkill: 非法名拒绝", () => {
  const result = createSkill({ name: "../evil", description: "x", body: "x" });
  assert.equal(result.created, false);
  assert.ok(result.reason?.includes("非法"));
});

test("listSkills: 列出所有 skill 的摘要", () => {
  createSkill({ name: "test-skill-alpha", description: "阿尔法", body: "x" });
  createSkill({ name: "test-skill-beta", description: "贝塔", body: "x" });
  registerForCleanup("test-skill-alpha");
  registerForCleanup("test-skill-beta");
  const list = listSkills();
  // 至少含复制到临时目录的种子 + 测试创建项
  const names = list.map((s) => s.name);
  assert.ok(names.includes("test-skill-alpha"));
  assert.ok(names.includes("test-skill-beta"));
  assert.ok(names.includes("verify-tcp-options"), "应含种子 skill");
  // 排序检查
  for (let i = 1; i < list.length; i++) {
    assert.ok(list[i - 1].name <= list[i].name);
  }
});

test("getSkill: 不存在返回 null", () => {
  const skill = getSkill("nonexistent-skill-999");
  assert.equal(skill, null);
});

test("getSkill: 非法名返回 null（防路径穿越）", () => {
  const skill = getSkill("../../etc/passwd");
  assert.equal(skill, null);
});

test("getSkill: 能读取 Claude 格式种子（带 frontmatter + 列表）", () => {
  // 种子 verify-tcp-options 是 Claude 风格格式
  const skill = getSkill("verify-tcp-options");
  assert.ok(skill);
  assert.equal(skill!.name, "verify-tcp-options");
  assert.ok(skill!.description.includes("options"));
  assert.ok(skill!.triggers?.length, "种子应有 triggers");
  assert.ok(skill!.toolsRequired?.length, "种子应有 tools_required");
  assert.ok(skill!.body.includes("# 验证 TCP Options"));
});

test("skillsIndexStatus: 返回技能数量", () => {
  const status = skillsIndexStatus();
  assert.equal(status.built, true);
  assert.ok(status.skillCount >= 2, "至少含 2 个种子");
});

test("deleteSkill: 删除已存在 skill", () => {
  createSkill({ name: "test-skill-to-delete", description: "x", body: "x" });
  assert.ok(getSkill("test-skill-to-delete"));
  const result = deleteSkill("test-skill-to-delete");
  assert.equal(result.deleted, true);
  assert.equal(getSkill("test-skill-to-delete"), null);
});

test("deleteSkill: 不存在幂等返回 deleted=true", () => {
  const result = deleteSkill("never-existed-skill-xyz");
  assert.equal(result.deleted, true);
});

test("deleteSkill: 非法名拒绝", () => {
  const result = deleteSkill("../etc/passwd");
  assert.equal(result.deleted, false);
});

test("清理测试创建的 skill", () => {
  // 用 deleteSkill 彻底删除，保证测试幂等
  for (const name of createdNames) {
    const result = deleteSkill(name);
    assert.equal(result.deleted, true);
  }
});
