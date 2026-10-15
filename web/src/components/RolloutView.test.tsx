import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { RolloutSchema } from "../gen/postern/panel/v1/versions_pb";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { RolloutView } from "./RolloutView";

const BUTTONS = ["continue", "pause", "retry", "abort"] as const;
const label = (action: (typeof BUTTONS)[number]) => t(`versions.rolloutView.${action}`);

function show(status: string, extra: Record<string, unknown> = {}) {
  const init = {
    id: "rollout-1",
    kind: "version",
    component: "telemt",
    channel: "stable",
    fromVersion: "3.5.12",
    toVersion: "3.5.13",
    mode: "manual",
    status,
    steps: [
      { index: 0, nodeName: "Frankfurt", proxyId: "proxy-1", status: "done", items: 1, itemsDone: 1 },
      { index: 1, nodeName: "Helsinki", status: status === "failed" ? "reverted" : "pending", items: 4, itemsDone: 2, itemsDeferred: 1, error: status === "failed" ? "proxy Beta did not come up" : "" },
    ],
    ...extra,
  };
  const panel = createFakePanel({ signedIn: true, rollouts: [init] });
  renderWithProviders(<RolloutView rollout={create(RolloutSchema, init)} />, { transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

const shown = () => BUTTONS.filter((action) => screen.queryByRole("button", { name: label(action) }) !== null);

describe("RolloutView", () => {
  it.each([
    ["running", ["pause", "abort"]],
    ["paused", ["continue", "abort"]],
    ["failed", ["retry", "abort"]],
    ["preparing", ["abort"]],
    ["completed", []],
    ["aborted", []],
  ])("a %s rollout offers %j", (status, actions) => {
    show(status);
    expect(shown()).toEqual(actions);
  });

  it("shows the steps: items done and deferred, and the error of a failed step", () => {
    show("failed");
    expect(screen.getByText("Helsinki")).toBeInTheDocument();
    expect(screen.getByText(`${t("versions.rolloutView.itemsDone", { done: "2", total: "4" })} · ${t("versions.rolloutView.itemsDeferred", { count: 1 })}`)).toBeInTheDocument();
    expect(screen.getByText("proxy Beta did not come up")).toBeInTheDocument();
    expect(screen.getByText(t("versions.rolloutView.canary"))).toBeInTheDocument();
  });

  it("continues a paused rollout and shows its new status", async () => {
    const { panel, user } = show("paused");
    await user.click(screen.getByRole("button", { name: label("continue") }));
    await waitFor(() => {
      expect(panel.rpc.continueRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.continueRollout.mock.calls[0]?.[0]).toMatchObject({ id: "rollout-1" });
    expect(await screen.findByRole("button", { name: label("pause") })).toBeInTheDocument();
  });

  it("links each step's checks before and after it, with the regression badge", () => {
    show("failed", {
      steps: [
        { index: 0, nodeId: "node-1", nodeName: "Frankfurt", status: "reverted", items: 1, beforeRunId: "run-b", beforeRunState: "done", afterRunId: "run-a", afterRunState: "done", afterRegressed: true },
        { index: 1, nodeId: "node-2", nodeName: "Helsinki", status: "pending", items: 1 },
      ],
    });
    const [, firstRow, secondRow] = screen.getAllByRole("row");
    if (firstRow === undefined || secondRow === undefined) throw new Error("two steps");
    const first = within(firstRow);
    expect(first.getByRole("link", { name: t("insights.stepChecks.openBefore") })).toHaveAttribute("href", "/nodes/node-1/diagnostics?run=run-b");
    expect(first.getByRole("link", { name: t("insights.stepChecks.openAfter") })).toHaveAttribute("href", "/nodes/node-1/diagnostics?run=run-a");
    expect(first.getByText(t("insights.diagnostics.run.regressed"))).toBeInTheDocument();
    const second = within(secondRow);
    expect(second.getByText(t("insights.stepChecks.none"))).toBeInTheDocument();
    expect(second.queryByRole("link")).toBeNull();
  });

  it("shows a step's check before it while there is none after it, without a regression", () => {
    show("running", {
      steps: [{ index: 0, nodeId: "node-1", nodeName: "Frankfurt", status: "applying", items: 1, beforeRunId: "run-b", beforeRunState: "partial" }],
    });
    expect(screen.getByRole("link", { name: t("insights.stepChecks.openBefore") })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: t("insights.stepChecks.openAfter") })).toBeNull();
    expect(screen.queryByText(t("insights.diagnostics.run.regressed"))).toBeNull();
  });

  it("shows the reason when the panel refuses an action", async () => {
    const { panel, user } = show("running");
    panel.rpc.abortRollout.mockImplementation(() => {
      throw new ConnectError("the step of node Helsinki is being reverted; try again in a moment", Code.FailedPrecondition);
    });
    await user.click(screen.getByRole("button", { name: label("abort") }));
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("the step of node Helsinki is being reverted; try again in a moment")).toBeInTheDocument();
  });
});
