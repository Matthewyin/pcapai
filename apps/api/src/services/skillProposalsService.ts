import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { createSkill, getSkill, isValidSkillName, skillsDir, type CreateSkillInput } from "./skillsService.js";

export type SkillProposalStatus = "pending" | "overwrite_confirmation" | "approved" | "rejected";

export type SkillProposal = Omit<CreateSkillInput, "overwrite"> & {
  proposalId: string;
  status: SkillProposalStatus;
  source: "agent" | "user";
  createdAt: string;
  reviewedAt?: string;
  rejectionReason?: string;
};

type SkillProposalStore = { proposals: SkillProposal[] };

function proposalStorePath(): string {
  if (process.env.PCAPAI_SKILL_PROPOSALS_PATH) {
    return path.resolve(process.env.PCAPAI_SKILL_PROPOSALS_PATH);
  }
  const baseDir = process.env.PCAPAI_USERDATA_DIR
    ? path.resolve(process.env.PCAPAI_USERDATA_DIR)
    : path.dirname(skillsDir());
  return path.join(baseDir, "skill-proposals.json");
}

function readStore(): SkillProposalStore {
  try {
    const parsed = JSON.parse(readFileSync(proposalStorePath(), "utf8")) as SkillProposalStore;
    return { proposals: Array.isArray(parsed.proposals) ? parsed.proposals : [] };
  } catch {
    return { proposals: [] };
  }
}

function writeStore(store: SkillProposalStore): void {
  const target = proposalStorePath();
  mkdirSync(path.dirname(target), { recursive: true });
  const temporary = `${target}.${process.pid}.${randomUUID()}.tmp`;
  writeFileSync(temporary, JSON.stringify(store, null, 2), "utf8");
  renameSync(temporary, target);
}

export function listSkillProposals(status?: SkillProposalStatus): SkillProposal[] {
  const proposals = readStore().proposals;
  return status ? proposals.filter((proposal) => proposal.status === status) : proposals;
}

export function createSkillProposal(
  input: Omit<CreateSkillInput, "overwrite">,
  source: SkillProposal["source"] = "agent"
): { created: boolean; proposal?: SkillProposal; reason?: string } {
  if (!isValidSkillName(input.name)) {
    return { created: false, reason: `skill 名非法（只允许小写字母、数字、横杠）：${input.name}` };
  }
  if (!input.description.trim() || !input.body.trim()) {
    return { created: false, reason: "description 和 body 不能为空" };
  }
  const store = readStore();
  const duplicate = store.proposals.find((proposal) => (
    (proposal.status === "pending" || proposal.status === "overwrite_confirmation")
    && proposal.name === input.name
  ));
  if (duplicate) {
    return { created: false, proposal: duplicate, reason: `skill ${input.name} 已有待审批提案` };
  }
  const proposal: SkillProposal = {
    ...input,
    description: input.description.trim(),
    body: input.body.trim(),
    proposalId: randomUUID(),
    status: "pending",
    source,
    createdAt: new Date().toISOString()
  };
  store.proposals.push(proposal);
  writeStore(store);
  return { created: true, proposal };
}

export function approveSkillProposal(
  proposalId: string,
  confirmOverwrite = false
): { approved: boolean; proposal?: SkillProposal; requiresOverwriteConfirmation?: boolean; reason?: string } {
  const store = readStore();
  const proposal = store.proposals.find((item) => item.proposalId === proposalId);
  if (!proposal) return { approved: false, reason: "提案不存在" };
  if (proposal.status === "approved") return { approved: true, proposal };
  if (proposal.status === "rejected") return { approved: false, proposal, reason: "已拒绝的提案不能批准" };

  const existing = getSkill(proposal.name);
  if (existing && proposal.status !== "overwrite_confirmation") {
    proposal.status = "overwrite_confirmation";
    proposal.reviewedAt = new Date().toISOString();
    writeStore(store);
    return {
      approved: false,
      proposal,
      requiresOverwriteConfirmation: true,
      reason: `skill ${proposal.name} 已存在，需要再次确认覆盖`
    };
  }
  if (existing && !confirmOverwrite) {
    return {
      approved: false,
      proposal,
      requiresOverwriteConfirmation: true,
      reason: `skill ${proposal.name} 已存在，需要显式确认覆盖`
    };
  }
  if (existing && path.dirname(existing.filePath) !== skillsDir()) {
    return { approved: false, proposal, reason: "同名 skill 来自更高优先级的外部目录，不能在主目录覆盖" };
  }

  const result = createSkill({
    name: proposal.name,
    description: proposal.description,
    triggers: proposal.triggers,
    toolsRequired: proposal.toolsRequired,
    body: proposal.body,
    overwrite: Boolean(existing)
  });
  if (!result.created) return { approved: false, proposal, reason: result.reason };

  proposal.status = "approved";
  proposal.reviewedAt = new Date().toISOString();
  writeStore(store);
  return { approved: true, proposal };
}

export function rejectSkillProposal(
  proposalId: string,
  reason?: string
): { rejected: boolean; proposal?: SkillProposal; reason?: string } {
  const store = readStore();
  const proposal = store.proposals.find((item) => item.proposalId === proposalId);
  if (!proposal) return { rejected: false, reason: "提案不存在" };
  if (proposal.status === "approved") return { rejected: false, proposal, reason: "已批准的提案不能拒绝" };
  proposal.status = "rejected";
  proposal.reviewedAt = new Date().toISOString();
  proposal.rejectionReason = reason?.trim() || undefined;
  writeStore(store);
  return { rejected: true, proposal };
}
