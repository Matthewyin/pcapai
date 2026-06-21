// Skills 服务：可复用排障 SOP（方法论层），比实战知识库更抽象。
// 格式借鉴 Claude skills：markdown + frontmatter（name/description/triggers/tools_required）+ 正文步骤。
// 一个 Skill 可被多个实战库条目引用（通过 skillIds）。SDK 无原生 skills 支持，自实现。
// 设计见 docs/design-full-roadmap.md A7。
import { existsSync, mkdirSync, readFileSync, readdirSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { apiConfig } from "../config.js";

export type Skill = {
  name: string;                 // 文件名（不含 .md），kebab-case
  description: string;          // 一句话说明用途
  triggers?: string[];          // 触发场景描述
  toolsRequired?: string[];     // 依赖的工具
  body: string;                 // 正文（步骤、判定标准等）
  filePath: string;             // 源文件绝对路径
};

// skill 名只允许小写字母、数字、横杠，防路径穿越
const SKILL_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

export function isValidSkillName(name: string): boolean {
  return SKILL_NAME_PATTERN.test(name);
}

function parseFrontmatter(raw: string): { frontmatter: Record<string, unknown>; body: string } {
  const match = raw.match(/^---\s*\n([\s\S]*?)\n---\s*\n?([\s\S]*)$/);
  if (!match) return { frontmatter: {}, body: raw };
  const frontmatterText = match[1];
  const body = match[2];
  // 简单 YAML 解析（只支持 key: value 和 key: 后跟列表项 - item），不引第三方库
  const frontmatter: Record<string, unknown> = {};
  let currentKey = "";
  for (const line of frontmatterText.split("\n")) {
    const listMatch = line.match(/^\s+-\s+(.+)$/);
    if (listMatch && currentKey) {
      const existing = frontmatter[currentKey];
      const value = listMatch[1].replace(/^["']|["']$/g, "");
      if (Array.isArray(existing)) {
        existing.push(value);
      } else {
        frontmatter[currentKey] = [value];
      }
      continue;
    }
    const kvMatch = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/);
    if (kvMatch) {
      currentKey = kvMatch[1];
      const value = kvMatch[2].replace(/^["']|["']$/g, "").trim();
      frontmatter[currentKey] = value;
    }
  }
  return { frontmatter, body };
}

function asStringArray(value: unknown): string[] | undefined {
  if (Array.isArray(value)) return value.map((v) => String(v)).filter(Boolean);
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return undefined;
}

function ensureSkillsDir(): string {
  const dir = apiConfig.skills.dir;
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

// 列出所有 skill（只读 frontmatter，不读正文，省内存）
export function listSkills(): Array<Pick<Skill, "name" | "description" | "triggers">> {
  const dir = apiConfig.skills.dir;
  if (!existsSync(dir)) return [];
  const result: Array<Pick<Skill, "name" | "description" | "triggers">> = [];
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".md")) continue;
    const name = file.replace(/\.md$/, "");
    if (!isValidSkillName(name)) continue;
    try {
      const raw = readFileSync(path.join(dir, file), "utf8");
      const { frontmatter } = parseFrontmatter(raw);
      result.push({
        name,
        description: typeof frontmatter.description === "string" ? frontmatter.description : "",
        triggers: asStringArray(frontmatter.triggers)
      });
    } catch {
      // 单个文件解析失败跳过，不影响其他
    }
  }
  return result.sort((a, b) => a.name.localeCompare(b.name));
}

// 读取单个 skill 全文
export function getSkill(name: string): Skill | null {
  if (!isValidSkillName(name)) return null;
  const filePath = path.join(apiConfig.skills.dir, `${name}.md`);
  if (!existsSync(filePath)) return null;
  const raw = readFileSync(filePath, "utf8");
  const { frontmatter, body } = parseFrontmatter(raw);
  return {
    name,
    description: typeof frontmatter.description === "string" ? frontmatter.description : "",
    triggers: asStringArray(frontmatter.triggers),
    toolsRequired: asStringArray(frontmatter.tools_required),
    body: body.trim(),
    filePath
  };
}

// 创建 skill（Agent 自我进化用）。已存在则覆盖（带 overwrite 控制）。
export function createSkill(input: {
  name: string;
  description: string;
  triggers?: string[];
  toolsRequired?: string[];
  body: string;
  overwrite?: boolean;
}): { created: boolean; filePath: string; reason?: string } {
  if (!isValidSkillName(input.name)) {
    return { created: false, filePath: "", reason: `skill 名非法（只允许小写字母、数字、横杠）：${input.name}` };
  }
  const dir = ensureSkillsDir();
  const filePath = path.join(dir, `${input.name}.md`);
  if (existsSync(filePath) && !input.overwrite) {
    return { created: false, filePath, reason: `skill 已存在：${input.name}（要覆盖请显式 overwrite=true）` };
  }
  const frontmatterLines: string[] = ["---", `name: ${input.name}`, `description: ${input.description}`];
  if (input.triggers?.length) {
    frontmatterLines.push("triggers:");
    for (const t of input.triggers) frontmatterLines.push(`  - ${t}`);
  }
  if (input.toolsRequired?.length) {
    frontmatterLines.push("tools_required:");
    for (const t of input.toolsRequired) frontmatterLines.push(`  - ${t}`);
  }
  frontmatterLines.push("---", "");
  const content = frontmatterLines.join("\n") + input.body.trim() + "\n";
  writeFileSync(filePath, content, "utf8");
  return { created: true, filePath };
}

// 删除 skill。不存在视为已删除（幂等）。P8 沉淀闭环 + 测试清理用。
export function deleteSkill(name: string): { deleted: boolean; filePath: string } {
  if (!isValidSkillName(name)) return { deleted: false, filePath: "" };
  const filePath = path.join(apiConfig.skills.dir, `${name}.md`);
  if (!existsSync(filePath)) return { deleted: true, filePath };
  unlinkSync(filePath);
  return { deleted: true, filePath };
}

export function skillsIndexStatus(): { built: boolean; skillCount: number; dir: string } {
  const dir = apiConfig.skills.dir;
  if (!existsSync(dir)) return { built: false, skillCount: 0, dir };
  const count = readdirSync(dir).filter((f) => f.endsWith(".md")).length;
  return { built: true, skillCount: count, dir };
}
