import type { TFunction } from "i18next";

import type { PreflightIssue, PreflightReport } from "../gen/postern/panel/v1/deploy_pb";
import { formatBytes } from "./format";

// What the preflight of an install over SSH means for the wizard
// (internal/panel/deploy): the issues in the words of the page, and whether
// the install can go.

/** An issue in the words of the page; one that this version does not know, from a newer panel, in the words of the panel. */
export function issueText(t: TFunction, issue: PreflightIssue): string {
  const p = issue.params;
  switch (issue.code) {
    case "not_root":
      return t("deploy.issues.not_root", { uid: p.uid ?? "" });
    case "arch_unsupported":
      return t("deploy.issues.arch_unsupported", { machine: p.machine ?? "" });
    case "kit_missing":
      return t("deploy.issues.kit_missing", { arch: p.arch ?? "" });
    case "bash_missing":
      return t("deploy.issues.bash_missing");
    case "docker_missing":
      return t("deploy.issues.docker_missing");
    case "docker_not_running":
      // The problem of a daemon that does not run is the panel's own words, which the page has: what Docker says is shown as it said it.
      return p.stopped === "true"
        ? t("deploy.issues.docker_stopped")
        : t("deploy.issues.docker_not_running", { problem: p.problem ?? "" });
    case "compose_missing": {
      if (issue.fixedByDockerInstall) {
        return t("deploy.issues.compose_missing");
      }
      const origin = p.origin ?? "";
      return t("deploy.issues.compose_manual", { origin: origin !== "" ? origin : t("deploy.issues.originUnknown") });
    }
    case "userns_remap":
      return t("deploy.issues.userns_remap");
    case "https_port_taken":
      return t("deploy.issues.https_port_taken", { port: p.port ?? "443", owner: p.owner ?? "" });
    case "mgmt_port_taken":
      return t("deploy.issues.mgmt_port_taken", { port: p.port ?? "", owner: p.owner ?? "" });
    case "ports_unknown":
      return t("deploy.issues.ports_unknown");
    case "clock_skew": {
      const seconds = Number(p.seconds ?? "0");
      return t(seconds >= 0 ? "deploy.issues.clock_ahead" : "deploy.issues.clock_behind", { seconds: Math.abs(seconds) });
    }
    case "low_disk":
      return t("deploy.issues.low_disk", { free: formatBytes(Number(p.free_bytes ?? "0")), path: p.path ?? "" });
    default:
      return issue.message;
  }
}

/** The error of every cancelled job, which the panel follows with "; " and what the admin still has to do, when there is something. */
const CANCELLED = "the job was cancelled";

/** What the admin still has to do after a job that was cancelled, such as a bundle to remove by hand, in the words of the panel; "" for nothing. */
export function cancelledNotice(error: string): string {
  return error.startsWith(`${CANCELLED}; `) ? error.slice(CANCELLED.length + 2) : "";
}

/** Whether the install can go: no blockers, or only those that installing Docker mends when it is asked for. */
export function canInstall(report: PreflightReport, installDocker: boolean): boolean {
  return report.issues.every((issue) => issue.severity !== "blocker" || (installDocker && issue.fixedByDockerInstall));
}
