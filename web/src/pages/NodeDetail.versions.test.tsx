import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const NODE = {
  id: "node-a",
  name: "Frankfurt",
  agentVersion: "v0.5.0",
  edgeVersion: "v0.5.0",
  previousAgentVersion: "v0.4.2",
  healthy: true,
  engineChannel: "stable",
  engineChannelDefault: true,
  capabilities: ["rollout-status", "update-self", "update-edge"],
  warnings: ["edge-handoff-unsafe", "test-release-keys", "something-new"],
};
const AFFECTED = [{ proxyId: "proxy-1", name: "Alpha", nodeId: "node-a", fromVersion: "3.5.12", toVersion: "3.5.13" }];
const FIELD = { selector: "input" };

function openNode(options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], ...options });
  renderApp({ route: "/nodes/node-a/settings", transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

const section = () => screen.findByRole("region", { name: t("versions.node.title") });

describe("NodeDetail: versions", () => {
  it("shows the warnings of the node in words, and an unknown one by its code", async () => {
    openNode();
    const versions = await section();
    expect(within(versions).getByText(t("versions.warning.edge-handoff-unsafe"))).toBeInTheDocument();
    expect(within(versions).getByText(t("versions.warning.test-release-keys"))).toBeInTheDocument();
    expect(within(versions).getByText("something-new")).toBeInTheDocument();
    expect(within(versions).getByText("v0.4.2")).toBeInTheDocument();
  });

  it("lists the affected proxies before changing the channel of the node", async () => {
    const { panel, user } = openNode({ affected: { "node:node-a:latest": AFFECTED } });
    const versions = await section();
    await user.click(within(versions).getByLabelText(t("versions.nodes.channel"), FIELD));
    await user.click(await screen.findByRole("option", { name: t("versions.channels.latest") }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(t("versions.channel.affectedProxy", { name: "Alpha", from: "3.5.12", to: "3.5.13" }))).toBeInTheDocument();
    expect(panel.rpc.setNodeChannel).toHaveBeenCalledTimes(1);
    await user.click(within(dialog).getByRole("button", { name: t("versions.channel.confirm") }));
    await waitFor(() => {
      expect(panel.rpc.setNodeChannel).toHaveBeenCalledTimes(2);
    });
    expect(panel.rpc.setNodeChannel.mock.calls[1]?.[0]).toMatchObject({ nodeId: "node-a", channel: "latest", confirm: true });
  });

  it("updates the agent of this node alone", async () => {
    const { panel, user } = openNode();
    const versions = await section();
    await user.click(within(versions).getByRole("button", { name: t("versions.node.updateAgent") }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: t("versions.rollout.start") }));
    await waitFor(() => {
      expect(panel.rpc.startRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({ kind: "node", nodeIds: ["node-a"], agent: true, edge: false });
  });

  it("rolls the edge of this node alone", async () => {
    const { panel, user } = openNode();
    const versions = await section();
    await user.click(within(versions).getByRole("button", { name: t("versions.node.rollEdge") }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: t("versions.rollout.start") }));
    await waitFor(() => {
      expect(panel.rpc.startRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({ kind: "node", nodeIds: ["node-a"], agent: false, edge: true });
  });
});
