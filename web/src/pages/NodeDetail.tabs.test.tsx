import { act, configure, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { formatBytes } from "../app/format";
import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";
import type { NodeTab } from "./node/nodeTabs";

// As in NodeDetail.test.tsx: the page is large, and its first render can be slow under the whole suite.
configure({ asyncUtilTimeout: 10_000 });
vi.setConfig({ testTimeout: 30_000 });

const now = () => Math.floor(Date.now() / 1000);
const main = () => within(screen.getByRole("main"));

const BOTH = ["update-self", "update-edge"];
const NODE = {
  id: "node-a",
  name: "Frankfurt",
  mgmtHost: "203.0.113.7",
  mgmtPort: 8443,
  status: "online",
  agentVersion: "0.5.0",
  edgeVersion: "0.5.0",
  capabilities: BOTH,
  appliedGeneration: 3n,
  desiredGeneration: 3n,
  lastSeenUnix: BigInt(now() - 60),
};

function openNode(options: Parameters<typeof createFakePanel>[0] = {}, path = "/nodes/node-a") {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [NODE],
    listeners: [{ id: "listener-1", nodeId: "node-a", bindIp: "0.0.0.0", port: 443 }],
    proxies: [{ id: "proxy-1", nodeId: "node-a", listenerId: "listener-1", name: "Family", domain: "fam.example.com" }],
    ...options,
  });
  const view = renderApp({ route: path, transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

const ready = () => screen.findByRole("heading", { name: "Frankfurt", level: 1 });
const heading = (name: string) => screen.findByRole("heading", { name, level: 2 });
const tab = (name: string) => screen.getByRole("tab", { name: new RegExp(`^${name}`) });
const banner = () => screen.queryByRole("status", { name: t("nodes.banner.label") });

describe("NodeDetail: the tabs", () => {
  it.each([
    ["", [t("nodes.detail.proxies"), t("insights.node.title")]],
    ["proxies", [t("nodes.detail.proxies"), t("listeners.title"), t("nodes.detail.ports")]],
    ["egress", [t("nodes.detail.egress"), t("egressHealth.title"), t("insights.egressHistory.title")]],
    ["diagnostics", [t("insights.diagnostics.title")]],
    [
      "settings",
      [
        t("nodes.detail.state"),
        t("nodes.detail.management"),
        t("versions.node.title"),
        t("nodes.artifacts.title"),
        t("nodes.detail.reinstall"),
        t("nodes.detail.danger"),
      ],
    ],
  ] satisfies [string, string[]][])("the tab %j shows its sections", async (path, titles) => {
    openNode({}, path === "" ? "/nodes/node-a" : `/nodes/node-a/${path}`);
    await ready();
    for (const title of titles) {
      expect(await heading(title)).toBeInTheDocument();
    }
    const selected = screen.getByRole("tab", { selected: true });
    expect(selected).toHaveTextContent(t(`nodes.tabs.${(path === "" ? "overview" : path) as NodeTab}`));
  });

  it("keeps the other tabs' sections off the overview", async () => {
    openNode();
    await ready();
    await heading(t("nodes.detail.proxies"));
    expect(screen.queryByRole("heading", { name: t("listeners.title") })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: t("nodes.detail.state") })).not.toBeInTheDocument();
    // The proxies of the overview are a list: the form of a new one is on its own tab.
    expect(screen.queryByRole("button", { name: t("proxies.add") })).not.toBeInTheDocument();
  });

  it("is in the address: a tab moves to its route, and back returns", async () => {
    const { user, router } = openNode();
    await ready();

    await user.click(tab(t("nodes.tabs.egress")));
    expect(await heading(t("egressHealth.title"))).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/nodes/node-a/egress");

    await user.click(tab(t("nodes.tabs.settings")));
    await heading(t("nodes.detail.state"));
    expect(router.state.location.pathname).toBe("/nodes/node-a/settings");

    await router.navigate(-1);
    expect(await heading(t("egressHealth.title"))).toBeInTheDocument();
    expect(tab(t("nodes.tabs.egress"))).toHaveAttribute("aria-selected", "true");
  });

  it("takes an address under the node that is no tab to its overview", async () => {
    const { router } = openNode({}, "/nodes/node-a/no-such-tab");
    await ready();
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/nodes/node-a");
    });
    expect(screen.getByRole("tab", { selected: true })).toHaveTextContent(t("nodes.tabs.overview"));
  });

  it("shows the traffic of 24 hours on the overview, and the rest of the statistics on request", async () => {
    const { panel, user } = openNode();
    panel.insights.nodeSeries.set("node-a", [
      { tsUnix: BigInt(now() - 120), up: 1000n, down: 3000n, devicesSum: 4, cpu: 20 },
      { tsUnix: BigInt(now() - 60), up: 2000n, down: 4000n, devicesSum: 7, cpu: 30 },
    ]);
    await ready();

    expect(await screen.findByRole("region", { name: t("insights.node.traffic") })).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: t("insights.node.cpu") })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: t("insights.node.devices") })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: t("nodes.detail.moreStats") }));
    expect(await screen.findByRole("region", { name: t("insights.node.cpu") })).toBeInTheDocument();
    expect(screen.getByRole("region", { name: t("insights.node.devices") })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: t("nodes.detail.moreStats") })).not.toBeInTheDocument();
    // The same query: the range of the overview is that of the section, 24 hours.
    expect(panel.rpc.nodeSeries.mock.calls.every(([request]) => request.range === "24h")).toBe(true);
  });

  it("opens a run named in the address on the diagnostics", async () => {
    const { router } = openNode({}, "/nodes/node-a/egress?run=run-9");
    await ready();
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/nodes/node-a/diagnostics");
    });
    expect(router.state.location.search).toBe("?run=run-9");
  });

  it("counts the warnings and errors of the node on the diagnostics tab", async () => {
    const { panel } = openNode();
    panel.diagnostics.problems = [
      { severity: "error", kind: "node.offline", nodeId: "node-a", nodeName: "Frankfurt", summary: "offline" },
      { severity: "warning", kind: "edge.outdated", nodeId: "node-a", nodeName: "Frankfurt", summary: "old edge" },
    ];
    await ready();
    expect(await within(tab(t("nodes.tabs.diagnostics"))).findByText("2")).toBeInTheDocument();
  });

  it("shows no count on the diagnostics tab when nothing is wrong", async () => {
    const { panel, queryClient } = openNode();
    await ready();
    await heading(t("nodes.detail.proxies"));
    // The problems are asked and answered before the tab is looked at.
    await waitFor(() => {
      expect(panel.rpc.listProblems).toHaveBeenCalled();
    });
    await waitFor(() => {
      expect(queryClient.isFetching()).toBe(0);
    });
    expect(tab(t("nodes.tabs.diagnostics"))).toHaveTextContent(new RegExp(`^${t("nodes.tabs.diagnostics")}$`));
  });
});

describe("NodeDetail: the overview tiles", () => {
  it("shows the proxies, the devices now, the traffic of 24 hours and the last contact", async () => {
    const { panel } = openNode();
    panel.insights.nodeSeries.set("node-a", [
      { tsUnix: BigInt(now() - 120), up: 1000n, down: 3000n, devicesSum: 4 },
      { tsUnix: BigInt(now() - 60), up: 2000n, down: 4000n, devicesSum: 7 },
    ]);
    await ready();

    const tile = (name: string) => within(screen.getByRole("group", { name }));
    await waitFor(() => {
      expect(tile(t("nodes.tiles.devices")).getByText("7")).toBeInTheDocument();
    });
    expect(tile(t("nodes.tiles.traffic")).getByText(formatBytes(10_000))).toBeInTheDocument();
    expect(await screen.findByRole("group", { name: t("nodes.tiles.proxies") })).toHaveTextContent("1");
    expect(tile(t("node.lastSeen")).getByText("1 minute ago")).toBeInTheDocument();
  });

  it("shows a dash in a tile that has no data", async () => {
    openNode();
    await ready();
    await screen.findByText("fam.example.com");
    await waitFor(() => {
      expect(within(screen.getByRole("group", { name: t("nodes.tiles.devices") })).getByText("—")).toBeInTheDocument();
    });
    expect(within(screen.getByRole("group", { name: t("nodes.tiles.traffic") })).getByText("—")).toBeInTheDocument();
  });
});

describe("NodeDetail: the banner", () => {
  it("asks to install a node that was never seen", async () => {
    openNode({ nodes: [{ ...NODE, lastSeenUnix: 0n, status: "provisioning", agentVersion: "", edgeVersion: "", capabilities: [] }] });
    await ready();
    const shown = await screen.findByRole("status", { name: t("nodes.banner.label") });
    expect(within(shown).getByText(t("nodes.banner.provisioning"))).toBeInTheDocument();
    // The install is the page itself, right below: the banner has no button for it.
    expect(within(shown).queryByRole("button", { name: t("nodes.banner.install") })).not.toBeInTheDocument();
    expect(within(shown).queryByRole("link", { name: t("nodes.banner.install") })).not.toBeInTheDocument();
  });

  it("sends a node that was never seen but is past provisioning to the reinstall", async () => {
    openNode({ nodes: [{ ...NODE, lastSeenUnix: 0n, status: "offline" }] });
    await ready();
    const shown = await screen.findByRole("status", { name: t("nodes.banner.label") });
    expect(within(shown).getByRole("link", { name: t("nodes.banner.install") })).toHaveAttribute("href", "/nodes/node-a/settings");
  });

  it("offers nothing to an agent that is newer than the panel", async () => {
    const { panel } = openNode({ nodes: [{ ...NODE, agentVersion: "0.6.0", edgeVersion: "0.6.0" }] });
    await ready();
    await waitFor(() => {
      expect(panel.rpc.getPanelVersion).toHaveBeenCalled();
    });
    await heading(t("nodes.detail.proxies"));
    expect(screen.queryByText(t("nodes.banner.agentUpdate", { agent: "v0.6.0", panel: "v0.5.0" }))).not.toBeInTheDocument();
    expect(banner()).not.toBeInTheDocument();
  });

  it("offers the panel's agent to a node whose agent is older, and starts its rollout", async () => {
    const { user } = openNode({ nodes: [{ ...NODE, agentVersion: "0.4.0", edgeVersion: "0.4.0" }] });
    await ready();
    const shown = await screen.findByRole("status", { name: t("nodes.banner.label") });
    expect(await within(shown).findByText(t("nodes.banner.agentUpdate", { agent: "v0.4.0", panel: "v0.5.0" }))).toBeInTheDocument();

    await user.click(within(shown).getByRole("button", { name: t("nodes.banner.updateNode") }));
    expect(await screen.findByRole("dialog", { name: t("versions.rollout.titleNode") })).toBeInTheDocument();
  });

  it("asks to roll an edge that is behind its agent, through the rollout of the edge", async () => {
    const { user } = openNode({ nodes: [{ ...NODE, edgeVersion: "0.4.0" }] });
    await ready();
    const shown = await screen.findByRole("status", { name: t("nodes.banner.label") });
    expect(await within(shown).findByText(t("nodes.banner.edgeOutdated"))).toBeInTheDocument();

    await user.click(within(shown).getByRole("button", { name: t("versions.node.rollEdge") }));
    expect(await screen.findByRole("dialog", { name: t("versions.rollout.titleNode") })).toBeInTheDocument();
  });

  it("says that a node that cannot update itself needs a new build", async () => {
    openNode({ nodes: [{ ...NODE, capabilities: ["update-edge"] }] });
    await ready();
    const shown = await screen.findByRole("status", { name: t("nodes.banner.label") });
    expect(within(shown).getByText(t("versions.node.needsInstall"))).toBeInTheDocument();
  });

  it("shows nothing when the node needs nothing", async () => {
    const { panel } = openNode();
    await ready();
    await waitFor(() => {
      expect(panel.rpc.getPanelVersion).toHaveBeenCalled();
    });
    await heading(t("nodes.detail.proxies"));
    expect(banner()).not.toBeInTheDocument();
  });
});

describe("NodeDetail: a node that is not connected yet", () => {
  const WAITING = { ...NODE, lastSeenUnix: 0n, status: "provisioning", agentVersion: "", edgeVersion: "", capabilities: [] };

  it("opens on the install, with the other tabs disabled until it connects", async () => {
    const { panel, user, queryClient } = openNode({ nodes: [WAITING] });
    await ready();

    const install = await heading(t("nodes.detail.install"));
    const docker = await main().findByRole("heading", { name: t("nodes.docker.title") });
    const ssh = main().getByRole("link", { name: t("deploy.open") });
    const kit = main().getByRole("button", { name: t("nodes.install.manualBlock") });
    expect(install.compareDocumentPosition(docker) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(docker.compareDocumentPosition(ssh) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(ssh.compareDocumentPosition(kit) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

    expect(tab(t("nodes.tabs.overview"))).toBeEnabled();
    for (const name of ["proxies", "egress", "diagnostics", "settings"] as const) {
      expect(tab(t(`nodes.tabs.${name}`))).toBeDisabled();
    }
    const wrapper = tab(t("nodes.tabs.settings")).parentElement;
    if (wrapper === null) throw new Error("no tooltip target");
    await user.hover(wrapper);
    expect(await screen.findByText(t("nodes.tabs.waiting"))).toBeInTheDocument();
    await user.unhover(wrapper);
    await waitFor(() => {
      expect(screen.queryByText(t("nodes.tabs.waiting"))).not.toBeInTheDocument();
    });
    // The keyboard reaches it too: the wrapper takes the focus, and the reason shows.
    act(() => {
      wrapper.focus();
    });
    expect(wrapper).toHaveFocus();
    expect(await screen.findByText(t("nodes.tabs.waiting"))).toBeInTheDocument();

    // It connects: the page becomes the usual one without a reload.
    const node = panel.inventory.nodes.find((n) => n.id === "node-a");
    if (node === undefined) throw new Error("no node");
    node.status = "online";
    node.lastSeenUnix = BigInt(now());
    await queryClient.invalidateQueries();
    await waitFor(() => {
      expect(tab(t("nodes.tabs.settings"))).toBeEnabled();
    });
    expect(await screen.findByRole("group", { name: t("nodes.tiles.proxies") })).toBeInTheDocument();
  });

  it("keeps a waiting node on the install when a tab is opened by its address", async () => {
    const { router } = openNode({ nodes: [WAITING] }, "/nodes/node-a/settings");
    await ready();
    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/nodes/node-a");
    });
    expect(await heading(t("nodes.detail.install"))).toBeInTheDocument();
  });
});

describe("NodeDetail: deleting", () => {
  it("deletes from the danger zone of the settings, through the confirmation", async () => {
    const { panel, user, router } = openNode({}, "/nodes/node-a/settings");
    await ready();
    const zone = within(await screen.findByRole("region", { name: t("nodes.detail.danger") }));

    await user.click(zone.getByRole("button", { name: t("nodes.delete.action") }));
    const dialog = await screen.findByRole("dialog", { name: t("nodes.delete.title") });
    expect(panel.rpc.deleteNode).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: t("nodes.delete.confirm") }));

    await waitFor(() => {
      expect(router.state.location.pathname).toBe("/nodes");
    });
    expect(panel.rpc.deleteNode.mock.calls[0]?.[0]).toMatchObject({ id: "node-a" });
  });
});
