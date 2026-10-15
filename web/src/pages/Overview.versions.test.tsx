import { screen, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { versionKeys } from "../api/hooks/versions";
import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

describe("Overview: updates", () => {
  it("shows an update-available badge for each followed channel that could move, linking to the versions", async () => {
    const panel = createFakePanel({
      signedIn: true,
      nodes: [{ id: "node-a", name: "Frankfurt" }],
      components: [
        {
          name: "telemt",
          kind: "engine",
          channelVersions: { stable: "3.5.12", latest: "3.5.13" },
          newest: { stable: "3.5.13", latest: "3.5.13" },
          followedChannels: ["stable"],
        },
      ],
    });
    renderApp({ route: "/", transport: panel.transport });
    const badge = await screen.findByRole("link", { name: t("overview.updateAvailable", { channel: t("versions.channels.stable"), components: "telemt" }) });
    expect(badge).toHaveAttribute("href", "/versions");
    expect(screen.queryByRole("link", { name: new RegExp(t("versions.channels.latest")) })).not.toBeInTheDocument();
  });

  it("shows no badge for a channel that no proxy follows, however new its release", async () => {
    const panel = createFakePanel({
      signedIn: true,
      nodes: [{ id: "node-a", name: "Frankfurt" }],
      components: [
        {
          name: "telemt",
          kind: "engine",
          channelVersions: { stable: "3.5.12", latest: "3.5.13" },
          newest: { stable: "3.5.13", latest: "3.5.14" },
          followedChannels: [],
        },
        { name: "mtg", kind: "engine", channelVersions: { stable: "2.1.0" }, newest: { stable: "2.2.0" }, followedChannels: ["stable"] },
      ],
    });
    renderApp({ route: "/", transport: panel.transport });
    // The badge of mtg shows once the components are in; telemt is in none.
    expect(await screen.findByRole("link", { name: t("overview.updateAvailable", { channel: t("versions.channels.stable"), components: "mtg" }) })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: new RegExp(t("versions.channels.latest")) })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /telemt/ })).not.toBeInTheDocument();
  });

  it("shows a Postern badge when the panel can be updated, linking to the versions", async () => {
    const panel = createFakePanel({
      signedIn: true,
      nodes: [{ id: "node-a", name: "Frankfurt", agentVersion: "0.5.0" }],
      panelVersion: { version: "v0.5.0", canUpdate: true, releases: [{ component: "postern", version: "v0.6.0" }] },
    });
    renderApp({ route: "/", transport: panel.transport });
    expect(await screen.findByRole("link", { name: t("overview.posternUpdate") })).toHaveAttribute("href", "/versions");
  });

  it("shows a Postern badge when a node runs an agent older than the panel", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [{ id: "node-a", name: "Frankfurt", agentVersion: "0.4.2" }] });
    renderApp({ route: "/", transport: panel.transport });
    expect(await screen.findByRole("link", { name: t("overview.posternUpdate") })).toHaveAttribute("href", "/versions");
  });

  it("shows no Postern badge when the panel and the nodes are up to date", async () => {
    const panel = createFakePanel({ signedIn: true, nodes: [{ id: "node-a", name: "Frankfurt", agentVersion: "0.5.0" }] });
    const { queryClient } = renderApp({ route: "/", transport: panel.transport });
    await screen.findByText("Frankfurt");
    // The answer of the panel is in before looking for what it must not show.
    await waitFor(() => {
      expect(queryClient.getQueryData(versionKeys.panel)).toBeDefined();
    });
    expect(screen.queryByRole("link", { name: t("overview.posternUpdate") })).not.toBeInTheDocument();
  });
});
