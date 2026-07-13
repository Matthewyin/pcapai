import type { AgentAnswer, CaseGraph } from "../../../../packages/shared/src/index.js";
import type { RfcSectionAuditRecord } from "./rfcTools.js";

const SPECULATION_MARK = "经验推测，无已验证 RFC 依据";

function normalizeSection(section?: string): string {
  return (section || "").replace(/^§\s*/, "").replace(/\.$/, "").trim();
}
function addPacketIds(target: Set<string>, values?: string[]) {
  for (const value of values || []) {
    if (value) target.add(value);
  }
}

export function casePacketIds(graph: CaseGraph): Set<string> {
  const ids = new Set<string>();
  for (const packet of [...(graph.rawPackets || []), ...(graph.packets || [])]) ids.add(packet.packetId);
  for (const session of graph.sessions || []) addPacketIds(ids, session.packetIds);
  for (const evidence of graph.evidence || []) addPacketIds(ids, evidence.packetIds);
  for (const finding of graph.findings || []) addPacketIds(ids, finding.packetIds);
  for (const tag of graph.diagnosticTags || []) addPacketIds(ids, tag.packetIds);
  for (const insight of graph.insights || []) addPacketIds(ids, insight.packetIds);
  for (const run of graph.queryRuns || []) {
    for (const correlation of run.protocolCorrelations || []) ids.add(correlation.sourcePacketId);
    for (const check of run.selectedDiagnosis?.checks || []) addPacketIds(ids, check.packetIds);
    for (const evidence of run.selectedDiagnosis?.evidence || []) addPacketIds(ids, evidence.packetIds);
    for (const finding of run.selectedDiagnosis?.findings || []) addPacketIds(ids, finding.packetIds);
    for (const tag of run.selectedDiagnosis?.diagnosticTags || []) addPacketIds(ids, tag.packetIds);
  }
  return ids;
}

function parseJsonText(value: string): unknown {
  const text = value.trim();
  if (!text.startsWith("{") && !text.startsWith("[")) return value;
  try {
    return JSON.parse(text);
  } catch {
    return value;
  }
}

export function collectPacketIdsFromToolOutput(output: unknown, target: Set<string>): void {
  const visit = (value: unknown, key = "") => {
    if (typeof value === "string") {
      const parsed = parseJsonText(value);
      if (parsed !== value) visit(parsed, key);
      else if (key === "packetId" || key === "sourcePacketId") target.add(value);
      return;
    }
    if (Array.isArray(value)) {
      if (key === "packetIds" || key === "evidencePacketIds") {
        for (const item of value) if (typeof item === "string" && item) target.add(item);
      } else {
        for (const item of value) visit(item);
      }
      return;
    }
    if (!value || typeof value !== "object") return;
    for (const [childKey, child] of Object.entries(value as Record<string, unknown>)) visit(child, childKey);
  };
  visit(output);
}

function markSpeculative(cause: string): string {
  return cause.includes(SPECULATION_MARK) ? cause : `${cause}（${SPECULATION_MARK}）`;
}

export function validateAgentAnswerGrounding(
  answer: AgentAnswer,
  graph: CaseGraph,
  rfcAudit: RfcSectionAuditRecord[],
  toolPacketIds: Set<string> = new Set()
): AgentAnswer {
  if (!answer.rootCauses?.length) return answer;
  const validPacketIds = casePacketIds(graph);
  for (const packetId of toolPacketIds) validPacketIds.add(packetId);

  return {
    ...answer,
    rootCauses: answer.rootCauses.map((rootCause) => {
      const section = normalizeSection(rootCause.rfcSection);
      const hasVerifiedRfcRead = rootCause.rfcVerified === true
        && rootCause.rfcDocId !== undefined
        && section.length > 0
        && rfcAudit.some((record) => record.success
          && record.rfcDocId === rootCause.rfcDocId
          && normalizeSection(record.returnedSection) === section);
      const hasValidEvidence = rootCause.evidencePacketIds.length > 0
        && rootCause.evidencePacketIds.every((packetId) => validPacketIds.has(packetId));

      if (hasVerifiedRfcRead && hasValidEvidence) return rootCause;
      return {
        ...rootCause,
        cause: markSpeculative(rootCause.cause),
        rfcVerified: false,
        confidence: rootCause.confidence === "needs_context" ? "needs_context" : "low"
      };
    })
  };
}
