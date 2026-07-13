export type SkillProposalStatus = "pending" | "overwrite_confirmation" | "approved" | "rejected";

export function skillProposalApproval(status: SkillProposalStatus): {
  visible: boolean;
  label: string;
  confirmOverwrite: boolean;
} {
  if (status === "pending") return { visible: true, label: "批准", confirmOverwrite: false };
  if (status === "overwrite_confirmation") return { visible: true, label: "确认覆盖", confirmOverwrite: true };
  return { visible: false, label: "", confirmOverwrite: false };
}

export type RfcDownloadState = "idle" | "downloading" | "validating" | "paused" | "completed" | "failed";

export function rfcDownloadView(state: RfcDownloadState) {
  return {
    shouldPoll: state === "downloading" || state === "validating",
    canCancel: state === "downloading",
    primaryAction: state === "paused" ? "resume" as const
      : state === "failed" ? "retry" as const
        : state === "idle" ? "start" as const
          : null
  };
}
