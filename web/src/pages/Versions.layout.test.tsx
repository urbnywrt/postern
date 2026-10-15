import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { create } from "@bufbuild/protobuf";
import { Code, ConnectError } from "@connectrpc/connect";

import { versionKeys } from "../api/hooks/versions";
import { ReleaseSchema } from "../gen/postern/panel/v1/versions_pb";
import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const CURRENT = [
  { id: "node-a", name: "Frankfurt", agentVersion: "0.5.0" },
  { id: "node-b", name: "Helsinki", agentVersion: "v0.5.0" },
];
const UP_TO_DATE = [{ name: "telemt", kind: "engine", channelVersions: { stable: "3.5.13" }, newest: { stable: "3.5.13" }, followedChannels: ["stable"] }];
const BEHIND = [{ name: "telemt", kind: "engine", channelVersions: { stable: "3.5.13", latest: "3.5.13" }, newest: { stable: "3.5.14", latest: "3.5.15" }, followedChannels: ["stable"] }];

function open(options: Parameters<typeof createFakePanel>[0] = {}, route = "/versions") {
  const panel = createFakePanel({ signedIn: true, nodes: CURRENT, components: UP_TO_DATE, ...options });
  const view = renderApp({ route, transport: panel.transport });
  return { panel, router: view.router, queryClient: view.queryClient, user: userEvent.setup() };
}

const updates = () => screen.findByRole("region", { name: t("versions.updates.title") });
const line = async (name: string) => within(await updates()).findByRole("group", { name });

describe("Versions: the tabs", () => {
  it.each([
    ["/versions", "region", "telemt"],
    ["/versions/nodes", "region", t("versions.nodes.title")],
    ["/versions/history", "region", t("versions.rollouts.title")],
    ["/versions/settings", "region", t("versions.panel.title")],
    ["/versions/settings", "region", t("versions.source.title")],
  ] as const)("%s shows %s %s, below the updates", async (route, role, name) => {
    open({}, route);
    expect(await screen.findByRole(role, { name })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: t("versions.updates.title") })).toBeInTheDocument();
  });

  it("keeps the default channel and the bundle upload in the settings", async () => {
    open({}, "/versions/settings");
    expect(await screen.findByLabelText(t("versions.defaultChannel"), { selector: "input" })).toBeInTheDocument();
    expect(await screen.findByRole("group", { name: t("versions.upload.title") })).toBeInTheDocument();
  });

  it("moves between the tabs by the address, back and forward too", async () => {
    const { router, user } = open();
    await screen.findByRole("region", { name: "telemt" });
    await user.click(screen.getByRole("tab", { name: t("versions.tabs.history") }));
    expect(await screen.findByRole("region", { name: t("versions.rollouts.title") })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/versions/history");
    await act(() => router.navigate(-1));
    expect(await screen.findByRole("region", { name: "telemt" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: t("versions.tabs.engines") })).toHaveAttribute("aria-selected", "true");
  });

  it("sends a tab that does not exist to the first one", async () => {
    const { router } = open({}, "/versions/nope");
    expect(await screen.findByRole("region", { name: "telemt" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/versions");
  });

  it("names the prerelease switch as an offer, with what it covers", async () => {
    open({}, "/versions/settings");
    // Mantine puts the description inside the label of a switch.
    expect(await screen.findByRole("switch", { name: (name) => name.startsWith(t("versions.source.prereleases")) })).not.toBeChecked();
    expect(t("versions.source.prereleases")).toBe("Offer prereleases (rc)");
    expect(screen.getByText(t("versions.source.prereleasesHint"))).toBeInTheDocument();
  });
});

describe("Versions: what can be updated", () => {
  it("says all is up to date when nothing can be updated", async () => {
    open();
    expect(await within(await updates()).findByText(t("versions.updates.allUpToDate"))).toBeInTheDocument();
    expect(within(await updates()).queryByRole("button", { name: t("versions.updates.update") })).not.toBeInTheDocument();
  });

  it("updates the panel after the confirmation, and marks a prerelease", async () => {
    const { panel, user } = open({
      panelVersion: { version: "v0.5.0", canUpdate: true, cannotUpdateReason: "", releases: [{ component: "postern", version: "v1.0.0-rc6", prerelease: true }] },
    });
    const panelLine = await line(t("versions.updates.panel", { from: "v0.5.0", to: "v1.0.0-rc6" }));
    expect(within(panelLine).getByText(t("versions.updates.prerelease"))).toBeInTheDocument();
    expect(within(await updates()).queryByText(t("versions.updates.allUpToDate"))).not.toBeInTheDocument();
    await user.click(within(panelLine).getByRole("button", { name: t("versions.updates.updatePanel") }));
    const dialog = await screen.findByRole("dialog", { name: t("versions.panel.confirmTitle", { version: "v1.0.0-rc6" }) });
    expect(panel.rpc.updatePanel).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: t("versions.panel.update", { version: "v1.0.0-rc6" }) }));
    expect(await screen.findByText(t("versions.panel.restarting", { version: "v1.0.0-rc6" }))).toBeInTheDocument();
    expect(panel.rpc.updatePanel.mock.calls[0]?.[0]).toMatchObject({ version: "v1.0.0-rc6" });
  });

  it("shows why the panel cannot update in place of its button", async () => {
    open({ panelVersion: { canUpdate: false, cannotUpdateReason: "these nodes run an agent older than v0.6.0: Helsinki", releases: [{ component: "postern", version: "v0.6.0" }] } });
    const panelLine = await line(t("versions.updates.panel", { from: "v0.5.0", to: "v0.6.0" }));
    expect(within(panelLine).getByText("these nodes run an agent older than v0.6.0: Helsinki")).toBeInTheDocument();
    expect(within(panelLine).queryByRole("button")).not.toBeInTheDocument();
  });

  it("offers a node rollout for the nodes older than the panel", async () => {
    const { user } = open({ nodes: [...CURRENT, { id: "node-c", name: "Riga", agentVersion: "0.4.2" }] });
    const nodesLine = await line(t("versions.updates.nodes", { behind: "1", total: "3", versions: "0.4.2", panel: "v0.5.0" }));
    await user.click(within(nodesLine).getByRole("button", { name: t("versions.updates.updateNodes") }));
    expect(await screen.findByRole("dialog", { name: t("versions.rollout.titleNode") })).toBeInTheDocument();
  });

  it("offers a version rollout for a followed engine channel with a newer release, and not for one that nothing follows", async () => {
    const { user } = open({ components: BEHIND });
    const channelLine = await line(t("versions.updates.channel", { component: "telemt", channel: t("versions.channels.stable"), from: "3.5.13", to: "3.5.14" }));
    expect(within(await updates()).queryByRole("group", { name: /3\.5\.15/ })).not.toBeInTheDocument();
    await user.click(within(channelLine).getByRole("button", { name: t("versions.updates.update") }));
    expect(await screen.findByRole("dialog", { name: t("versions.rollout.titleVersion", { component: "telemt", channel: "stable", version: "3.5.14" }) })).toBeInTheDocument();
  });

  it("shows an active rollout with its step and its controls, in place of its channel", async () => {
    const { panel, user } = open({
      components: BEHIND,
      rollouts: [
        {
          id: "r1",
          kind: "version",
          component: "telemt",
          channel: "stable",
          fromVersion: "3.5.13",
          toVersion: "3.5.14",
          mode: "manual",
          status: "paused",
          currentStep: 1,
          steps: [{ index: 0 }, { index: 1 }, { index: 2 }],
        },
        { id: "r0", kind: "version", component: "telemt", channel: "latest", fromVersion: "3.5.12", toVersion: "3.5.13", status: "completed" },
      ],
    });
    const summary = t("versions.rolloutView.summaryVersion", { component: "telemt", channel: "stable", from: "3.5.13", to: "3.5.14" });
    const rolloutLine = await line(summary);
    expect(within(rolloutLine).getByText(t("versions.updates.step", { step: "2", total: "3" }))).toBeInTheDocument();
    expect(within(rolloutLine).getByText(t("versions.status.paused"))).toBeInTheDocument();
    expect(within(rolloutLine).getByRole("link", { name: t("versions.updates.details") })).toHaveAttribute("href", "/versions/history");
    expect(within(await updates()).queryByRole("group", { name: /3\.5\.13 → 3\.5\.14$/ })).toBe(rolloutLine);
    // The completed one is history only.
    expect(within(await updates()).queryByRole("group", { name: /3\.5\.12/ })).not.toBeInTheDocument();

    await user.click(within(rolloutLine).getByRole("button", { name: t("versions.rolloutView.continue") }));
    await waitFor(() => {
      expect(panel.rpc.continueRollout).toHaveBeenCalledTimes(1);
    });
    await user.click(await within(await line(summary)).findByRole("button", { name: t("versions.rolloutView.pause") }));
    await waitFor(() => {
      expect(panel.rpc.pauseRollout).toHaveBeenCalledTimes(1);
    });
    await user.click(await within(await line(summary)).findByRole("button", { name: t("versions.rolloutView.abort") }));
    await waitFor(() => {
      expect(panel.rpc.abortRollout).toHaveBeenCalledTimes(1);
    });
    await waitFor(() => {
      expect(within(screen.getByRole("region", { name: t("versions.updates.title") })).queryByRole("group", { name: summary })).not.toBeInTheDocument();
    });
  });

  it("allows prereleases from the top while they are off and the panel is up to date, keeping the source and its tokens", async () => {
    const { panel, user } = open();
    const offLine = await line(t("versions.updates.prereleasesOff"));
    const asked = panel.rpc.getPanelVersion.mock.calls.length;
    // The panel reads its source again on the save, and lists the prerelease.
    panel.versions.panel.canUpdate = true;
    panel.versions.panel.releases = [create(ReleaseSchema, { component: "postern", version: "v1.0.0-rc6", prerelease: true })];
    await user.click(within(offLine).getByRole("button", { name: t("versions.updates.allowPrereleases") }));
    await waitFor(() => {
      expect(panel.rpc.setReleaseSource).toHaveBeenCalledTimes(1);
    });
    const sent = panel.rpc.setReleaseSource.mock.calls[0]?.[0];
    expect(sent?.source).toMatchObject({ kind: "github", repo: "urbnywrt/postern", includePrereleases: true });
    expect(sent?.token).toBeUndefined();
    expect(sent?.githubToken).toBeUndefined();
    await waitFor(() => {
      expect(panel.rpc.getPanelVersion.mock.calls.length).toBeGreaterThan(asked);
    });
    await waitFor(() => {
      expect(screen.queryByRole("group", { name: t("versions.updates.prereleasesOff") })).not.toBeInTheDocument();
    });
    expect(await line(t("versions.updates.panel", { from: "v0.5.0", to: "v1.0.0-rc6" }))).toBeInTheDocument();
  });

  it("does not say prereleases are off while the version of the panel failed to load", async () => {
    const { panel, queryClient } = open();
    await line(t("versions.updates.prereleasesOff"));
    // A refetch fails: the old answer stays in the cache, but it is no longer the panel's word.
    panel.rpc.getPanelVersion.mockImplementation(() => {
      throw new ConnectError("down", Code.Unavailable);
    });
    await act(() => queryClient.invalidateQueries({ queryKey: versionKeys.panel }));
    await waitFor(() => {
      expect(queryClient.getQueryState(versionKeys.panel)?.status).toBe("error");
    });
    await waitFor(() => {
      expect(screen.queryByRole("group", { name: t("versions.updates.prereleasesOff") })).not.toBeInTheDocument();
    });
  });

  it("never shows a release of the panel without a button or a reason", async () => {
    open({ panelVersion: { canUpdate: false, cannotUpdateReason: "", releases: [{ component: "postern", version: "v0.6.0" }] } });
    const panelLine = await line(t("versions.updates.panel", { from: "v0.5.0", to: "v0.6.0" }));
    expect(within(panelLine).getByText(t("versions.panel.cannotUpdate"))).toBeInTheDocument();
  });

  it("shows why the panel cannot update in its details, with no newer release too", async () => {
    open({ panelVersion: { canUpdate: false, cannotUpdateReason: "the panel was not started by its launcher" } }, "/versions/settings");
    const details = await screen.findByRole("region", { name: t("versions.panel.title") });
    expect(await within(details).findByText("the panel was not started by its launcher")).toBeInTheDocument();
    expect(within(await updates()).queryByText("the panel was not started by its launcher")).not.toBeInTheDocument();
  });

  it("does not offer prereleases while a release of Postern can be installed", async () => {
    const { queryClient } = open({ panelVersion: { canUpdate: true, releases: [{ component: "postern", version: "v0.6.0" }] } });
    await line(t("versions.updates.panel", { from: "v0.5.0", to: "v0.6.0" }));
    await waitFor(() => {
      expect(queryClient.getQueryData(versionKeys.source)).toBeDefined();
    });
    expect(screen.queryByRole("group", { name: t("versions.updates.prereleasesOff") })).not.toBeInTheDocument();
  });
});
