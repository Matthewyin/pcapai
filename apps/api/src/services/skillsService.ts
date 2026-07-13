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

export type CreateSkillInput = {
  name: string;
  description: string;
  triggers?: string[];
  toolsRequired?: string[];
  body: string;
  overwrite?: boolean;
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
  const dir = skillsDir();
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  return dir;
}

export function skillsDir(): string {
  return process.env.PCAPAI_SKILLS_DIR
    ? path.resolve(process.env.PCAPAI_SKILLS_DIR)
    : apiConfig.skills.dir;
}

/** 所有 skills 目录（主目录 + extraDirs），后者优先级更高（用户可覆盖内置） */
function allSkillDirs(): string[] {
  return [skillsDir(), ...apiConfig.skills.extraDirs].filter((d) => existsSync(d));
}

// 列出所有 skill（扫描所有目录，同名 skill 后面的目录覆盖前面的）
export function listSkills(): Array<Pick<Skill, "name" | "description" | "triggers">> {
  const dirs = allSkillDirs();
  const byName = new Map<string, Pick<Skill, "name" | "description" | "triggers">>();
  for (const dir of dirs) {
    let files: string[];
    try { files = readdirSync(dir); } catch { continue; }
    for (const file of files) {
      if (!file.endsWith(".md")) continue;
      const name = file.replace(/\.md$/, "");
      if (!isValidSkillName(name)) continue;
      try {
        const raw = readFileSync(path.join(dir, file), "utf8");
        const { frontmatter } = parseFrontmatter(raw);
        byName.set(name, {
          name,
          description: typeof frontmatter.description === "string" ? frontmatter.description : "",
          triggers: asStringArray(frontmatter.triggers)
        });
      } catch {
        // 单个文件解析失败跳过
      }
    }
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// 读取单个 skill 全文（从优先级最高的目录找）
export function getSkill(name: string): Skill | null {
  if (!isValidSkillName(name)) return null;
  for (const dir of [...allSkillDirs()].reverse()) {
    const filePath = path.join(dir, `${name}.md`);
    if (existsSync(filePath)) {
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
  }
  return null;
}

// 创建正式 skill。仅供人工 API 或审批服务调用，Agent 只能提交提案。
export function createSkill(input: CreateSkillInput): { created: boolean; filePath: string; reason?: string } {
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
  const filePath = path.join(skillsDir(), `${name}.md`);
  if (!existsSync(filePath)) return { deleted: true, filePath };
  unlinkSync(filePath);
  return { deleted: true, filePath };
}

export function skillsIndexStatus(): { built: boolean; skillCount: number; dir: string } {
  const dirs = allSkillDirs();
  let count = 0;
  for (const dir of dirs) {
    try { count += readdirSync(dir).filter((f) => f.endsWith(".md")).length; } catch { /* ignore */ }
  }
  return { built: dirs.length > 0, skillCount: count, dir: dirs.join(", ") };
}

// ===== Skill 开关（禁用列表，持久化到 userData/skills-config.json） =====

function skillsConfigPath(): string {
  const userDataDir = process.env.PCAPAI_USERDATA_DIR;
  return userDataDir ? path.join(userDataDir, "skills-config.json") : "";
}

function loadDisabledSkills(): Set<string> {
  const cfgPath = skillsConfigPath();
  if (!cfgPath || !existsSync(cfgPath)) return new Set();
  try {
    const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    return new Set(Array.isArray(cfg.disabledSkills) ? cfg.disabledSkills : []);
  } catch { return new Set(); }
}

function saveDisabledSkills(disabled: Set<string>): void {
  const cfgPath = skillsConfigPath();
  if (!cfgPath) return;
  try {
    // 读已有配置（保留 directories）
    let cfg: { directories?: string[]; disabledSkills?: string[] } = {};
    if (existsSync(cfgPath)) cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
    cfg.disabledSkills = [...disabled];
    writeFileSync(cfgPath, JSON.stringify(cfg, null, 2), "utf8");
  } catch { /* ignore */ }
}

/** 列出所有 skill（含启用/禁用状态） */
export function listSkillsWithStatus(): Array<Pick<Skill, "name" | "description" | "triggers"> & { enabled: boolean }> {
  const disabled = loadDisabledSkills();
  return listSkills().map((s) => ({ ...s, enabled: !disabled.has(s.name) }));
}

/** 切换 skill 启用/禁用 */
export function toggleSkill(name: string): boolean {
  const disabled = loadDisabledSkills();
  if (disabled.has(name)) {
    disabled.delete(name);
  } else {
    disabled.add(name);
  }
  saveDisabledSkills(disabled);
  return !disabled.has(name); // 返回新状态（true=启用）
}
