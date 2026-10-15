import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { RolloutTarget } from "../app/versions";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { RolloutDialog } from "./RolloutDialog";

const NODES = [
  { id: "node-a", name: "Frankfurt" },
  { id: "node-b", name: "Helsinki" },
];
const PROXIES = [
  { id: "proxy-1", name: "Alpha", nodeId: "node-a", engine: "telemt" },
  { id: "proxy-2", name: "Beta", nodeId: "node-b", engine: "telemt" },
];
const FIELD = { selector: "input" };

function open(target: RolloutTarget, options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: NODES, proxies: PROXIES, ...options });
  const onClose = vi.fn();
  renderWithProviders(<RolloutDialog opened target={target} onClose={onClose} />, { transport: panel.transport });
  return { panel, onClose, user: userEvent.setup() };
}

describe("RolloutDialog", () => {
  it("starts an engine version rollout in auto mode with a canary proxy", async () => {
    const { panel, user, onClose } = open({ kind: "version", component: "telemt", componentKind: "engine", channel: "stable", toVersion: "3.5.13" });
    await user.click(screen.getByRole("radio", { name: t("versions.rollout.modeAuto") }));
    const pause = screen.getByLabelText(t("versions.rollout.pause"));
    await user.clear(pause);
    await user.type(pause, "60");
    await user.click(screen.getByLabelText(t("versions.rollout.canaryProxy"), FIELD));
    await user.click(await screen.findByRole("option", { name: "Beta" }));
    await user.click(screen.getByRole("button", { name: t("versions.rollout.start") }));

    await waitFor(() => {
      expect(panel.rpc.startRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({
      kind: "version",
      component: "telemt",
      channel: "stable",
      toVersion: "3.5.13",
      mode: "auto",
      pauseSeconds: 60,
      canaryProxyId: "proxy-2",
      canaryNodeId: "",
      skipOffline: false,
    });
    await waitFor(() => {
      expect(onClose).toHaveBeenCalled();
    });
  });

  it("starts a node rollout of the edge only, skipping offline nodes", async () => {
    const { panel, user } = open({ kind: "node" });
    await user.click(screen.getByRole("checkbox", { name: t("versions.rollout.agent") }));
    await user.click(screen.getByRole("checkbox", { name: t("versions.rollout.skipOffline") }));
    await user.click(screen.getByRole("button", { name: t("versions.rollout.start") }));
    await waitFor(() => {
      expect(panel.rpc.startRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({
      kind: "node",
      nodeIds: [],
      agent: false,
      edge: true,
      mode: "manual",
      pauseSeconds: 0,
      skipOffline: true,
      canaryProxyId: "",
    });
  });

  it("refuses a node rollout of nothing", async () => {
    const { user } = open({ kind: "node" });
    await user.click(screen.getByRole("checkbox", { name: t("versions.rollout.agent") }));
    await user.click(screen.getByRole("checkbox", { name: t("versions.rollout.edge") }));
    expect(screen.getByRole("button", { name: t("versions.rollout.start") })).toBeDisabled();
  });

  it("a switch to mtg notes that mtg fronts from the node, and sends the chosen proxies", async () => {
    const { panel, user } = open({ kind: "switch", engine: "mtg" });
    expect(screen.getByText(t("versions.rollout.mtgNote"))).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("versions.rollout.start") })).toBeDisabled();
    await user.click(screen.getByLabelText(t("versions.rollout.proxies"), FIELD));
    await user.click(await screen.findByRole("option", { name: "Alpha" }));
    await user.click(screen.getByRole("button", { name: t("versions.rollout.start") }));
    await waitFor(() => {
      expect(panel.rpc.startRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({ kind: "switch", component: "mtg", proxyIds: ["proxy-1"], toVersion: "" });
  });

  it("shows the conflict that names the rollout holding the channel", async () => {
    const { user, onClose } = open(
      { kind: "version", component: "telemt", componentKind: "engine", channel: "stable", toVersion: "3.5.13" },
      { rollouts: [{ id: "rollout-held", kind: "version", component: "telemt", channel: "stable", status: "paused" }] },
    );
    await user.click(screen.getByRole("button", { name: t("versions.rollout.start") }));
    expect(await screen.findByText("rollout rollout-held is active for telemt on stable")).toBeInTheDocument();
    expect(onClose).not.toHaveBeenCalled();
  });
});
