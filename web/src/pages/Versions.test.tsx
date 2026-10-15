import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const NODES = [{ id: "node-a", name: "Frankfurt", agentVersion: "0.5.0", engineChannel: "stable", engineChannelDefault: true, healthy: true, previousAgentVersion: "v0.4.2", capabilities: ["rollout-status", "engine-mtg"] }];
const COMPONENTS: { name: string; kind: string; channelVersions: Record<string, string>; newest: Record<string, string>; followedChannels?: string[] }[] = [
  { name: "telemt", kind: "engine", channelVersions: { stable: "3.5.12", latest: "3.5.13" }, newest: { stable: "3.5.13", latest: "3.5.13" }, followedChannels: ["stable"] },
  { name: "xray", kind: "provider", channelVersions: { stable: "v26.3.27" }, newest: { stable: "v26.3.27" } },
];
const AFFECTED = [
  { proxyId: "proxy-1", name: "Alpha", nodeId: "node-a", fromVersion: "3.5.12", toVersion: "3.5.13" },
  { proxyId: "proxy-2", name: "Beta", nodeId: "node-a", fromVersion: "3.5.12", toVersion: "3.5.13" },
];
const FIELD = { selector: "input" };

function openVersions(options: Parameters<typeof createFakePanel>[0] = {}, route = "/versions") {
  const panel = createFakePanel({ signedIn: true, nodes: NODES, components: COMPONENTS, ...options });
  const view = renderApp({ route, transport: panel.transport });
  return { panel, user: userEvent.setup(), router: view.router };
}

describe("Versions", () => {
  it("is reached from the navigation", async () => {
    const panel = createFakePanel({ signedIn: true });
    renderApp({ route: "/", transport: panel.transport });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("link", { name: t("nav.versions") }));
    expect(await screen.findByRole("heading", { level: 1, name: t("versions.title") })).toBeInTheDocument();
  });

  it("offers to update a channel whose newest release differs, and only that one", async () => {
    const { user } = openVersions();
    const telemt = await screen.findByRole("region", { name: "telemt" });
    const update = within(telemt).getByRole("button", { name: t("versions.updateChannel", { channel: "stable", version: "3.5.13" }) });
    expect(within(telemt).queryByRole("button", { name: t("versions.updateChannel", { channel: "latest", version: "3.5.13" }) })).not.toBeInTheDocument();
    expect(within(screen.getByRole("region", { name: "xray" })).queryByRole("button", { name: /3\.5|v26/ })).not.toBeInTheDocument();
    await user.click(update);
    expect(await screen.findByRole("dialog", { name: t("versions.rollout.titleVersion", { component: "telemt", channel: "stable", version: "3.5.13" }) })).toBeInTheDocument();
  });

  it("moves a channel that no proxy follows at once, and shows it at the new version", async () => {
    const { panel, user } = openVersions({
      components: [
        { name: "telemt", kind: "engine", channelVersions: { stable: "3.5.13", latest: "3.5.13" }, newest: { stable: "3.5.13", latest: "3.5.14" }, followedChannels: ["stable"] },
      ],
    });
    const telemt = await screen.findByRole("region", { name: "telemt" });
    expect(within(telemt).queryByRole("button", { name: t("versions.updateChannel", { channel: "latest", version: "3.5.14" }) })).not.toBeInTheDocument();
    await user.click(within(telemt).getByRole("button", { name: t("versions.moveChannel", { channel: "latest", version: "3.5.14" }) }));
    const dialog = await screen.findByRole("dialog", { name: t("versions.rollout.titleVersion", { component: "telemt", channel: "latest", version: "3.5.14" }) });
    expect(within(dialog).getByText(t("versions.rollout.moveNote"))).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: t("versions.rollout.start") }));
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({ kind: "version", component: "telemt", channel: "latest", toVersion: "3.5.14" });
    // The channel is at 3.5.14 now: the button is gone, and no error shows.
    await waitFor(() => {
      expect(within(screen.getByRole("region", { name: "telemt" })).queryByRole("button", { name: /3\.5\.14/ })).not.toBeInTheDocument();
    });
    expect(screen.queryByText(t("versions.rollout.refused"))).not.toBeInTheDocument();
  });

  it("lists the affected proxies before changing the default channel, and changes it only on confirm", async () => {
    const { panel, user } = openVersions({ affected: { latest: AFFECTED } }, "/versions/settings");
    await user.click(await screen.findByLabelText(t("versions.defaultChannel"), FIELD));
    await user.click(await screen.findByRole("option", { name: t("versions.channels.latest") }));

    const dialog = await screen.findByRole("dialog");
    const list = within(dialog).getByRole("list", { name: t("versions.channel.affected") });
    expect(within(list).getByText(t("versions.channel.affectedProxy", { name: "Alpha", from: "3.5.12", to: "3.5.13" }))).toBeInTheDocument();
    expect(within(list).getByText(t("versions.channel.affectedProxy", { name: "Beta", from: "3.5.12", to: "3.5.13" }))).toBeInTheDocument();
    expect(panel.rpc.setDefaultChannel).toHaveBeenCalledTimes(1);
    expect(panel.rpc.setDefaultChannel.mock.calls[0]?.[0]).toMatchObject({ channel: "latest", confirm: false });
    expect(panel.versions.defaultChannel).toBe("stable");

    await user.click(within(dialog).getByRole("button", { name: t("versions.channel.confirm") }));
    await waitFor(() => {
      expect(panel.rpc.setDefaultChannel).toHaveBeenCalledTimes(2);
    });
    expect(panel.rpc.setDefaultChannel.mock.calls[1]?.[0]).toMatchObject({ channel: "latest", confirm: true });
    expect(panel.versions.defaultChannel).toBe("latest");
  });

  it("changes a node's channel at once when no proxy changes version", async () => {
    const { panel, user } = openVersions({}, "/versions/nodes");
    await user.click(await screen.findByLabelText(t("versions.nodes.channelOf", { name: "Frankfurt" }), FIELD));
    await user.click(await screen.findByRole("option", { name: t("versions.channels.latest") }));
    await waitFor(() => {
      expect(panel.rpc.setNodeChannel).toHaveBeenCalledTimes(2);
    });
    expect(panel.rpc.setNodeChannel.mock.calls.map((call) => call[0])).toMatchObject([
      { nodeId: "node-a", channel: "latest", confirm: false },
      { nodeId: "node-a", channel: "latest", confirm: true },
    ]);
  });

  it("shows why a refresh was refused, such as too soon", async () => {
    const { panel, user } = openVersions();
    panel.rpc.refreshReleases.mockImplementation(() => {
      throw new ConnectError("telemt: releases: the release list was refreshed less than a minute ago", Code.Unavailable);
    });
    await user.click(await screen.findByRole("button", { name: t("versions.refreshAll") }));
    expect(await screen.findByText("telemt: releases: the release list was refreshed less than a minute ago")).toBeInTheDocument();
  });

  it("shows the builds of the nodes and opens a node rollout", async () => {
    const { user } = openVersions({}, "/versions/nodes");
    const nodes = await screen.findByRole("region", { name: t("versions.nodes.title") });
    expect(await within(nodes).findByText("v0.4.2")).toBeInTheDocument();
    expect(within(nodes).getByText("rollout-status, engine-mtg")).toBeInTheDocument();
    await user.click(within(nodes).getByRole("button", { name: t("versions.nodes.update") }));
    expect(await screen.findByRole("dialog", { name: t("versions.rollout.titleNode") })).toBeInTheDocument();
  });
});
