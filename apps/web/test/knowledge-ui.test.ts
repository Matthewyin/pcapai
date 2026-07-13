import assert from "node:assert/strict";
import test from "node:test";
import { rfcDownloadView, skillProposalApproval } from "../src/components/shared/knowledgeUiState.js";

test("Skill 提案普通批准与覆盖二次确认使用不同动作", () => {
  assert.deepEqual(skillProposalApproval("pending"), {
    visible: true,
    label: "批准",
    confirmOverwrite: false
  });
  assert.deepEqual(skillProposalApproval("overwrite_confirmation"), {
    visible: true,
    label: "确认覆盖",
    confirmOverwrite: true
  });
  assert.equal(skillProposalApproval("approved").visible, false);
  assert.equal(skillProposalApproval("rejected").visible, false);
});

test("RFC 下载中和校验中持续轮询，暂停和失败提供恢复动作", () => {
  assert.deepEqual(rfcDownloadView("downloading"), {
    shouldPoll: true,
    canCancel: true,
    primaryAction: null
  });
  assert.equal(rfcDownloadView("validating").shouldPoll, true);
  assert.equal(rfcDownloadView("validating").canCancel, false);
  assert.equal(rfcDownloadView("paused").primaryAction, "resume");
  assert.equal(rfcDownloadView("failed").primaryAction, "retry");
  assert.equal(rfcDownloadView("idle").primaryAction, "start");
  assert.equal(rfcDownloadView("completed").primaryAction, null);
});
