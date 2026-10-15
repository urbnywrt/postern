import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { PreflightIssueSchema } from "../gen/postern/panel/v1/deploy_pb";
import i18n from "../i18n";
import { cancelledNotice, issueText } from "./deploy";

describe("issueText", () => {
  const stopped = create(PreflightIssueSchema, {
    code: "docker_not_running",
    severity: "blocker",
    message: "Docker does not answer: the Docker daemon does not run",
    params: { problem: "the Docker daemon does not run", stopped: "true" },
    fixedByDockerInstall: true,
  });

  it("says that the Docker daemon does not run in the language of the page, with no English in Russian", () => {
    const ru = issueText(i18n.getFixedT("ru"), stopped);
    expect(ru).toBe(i18n.getFixedT("ru")("deploy.issues.docker_stopped"));
    expect(ru.replaceAll("Docker", "")).not.toMatch(/[A-Za-z]/);
    expect(issueText(i18n.getFixedT("en"), stopped)).toBe("Docker does not answer: the Docker daemon does not run.");
  });

  it("shows what Docker said when it did not answer", () => {
    const said = create(PreflightIssueSchema, {
      code: "docker_not_running",
      severity: "blocker",
      params: { problem: "permission denied" },
    });
    expect(issueText(i18n.getFixedT("ru"), said)).toBe("Docker не отвечает: permission denied");
  });
});

describe("cancelledNotice", () => {
  it.each([
    ["the job was cancelled", ""],
    ["", ""],
    ["install.sh failed with exit code 1", ""],
    [
      "the job was cancelled; the bundle /root/postern-install/postern-node-bundle.tar may still be on the server: remove it by hand",
      "the bundle /root/postern-install/postern-node-bundle.tar may still be on the server: remove it by hand",
    ],
  ])("of %j is %j", (error, notice) => {
    expect(cancelledNotice(error)).toBe(notice);
  });
});
