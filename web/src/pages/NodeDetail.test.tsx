import { Code, ConnectError } from "@connectrpc/connect";
import { configure, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ROLL_EDGE_COMMAND } from "../app/bundle";
import { INSTALL_COMMAND } from "../test/fakeInventory";
import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

// The page is large: under the load of the whole suite its first render can
// take longer than the defaults (1 s for a findBy, 5 s for a test), which made
// these tests time out now and then. Each test file runs in its own context,
// so this loosens the waits of this file only.
configure({ asyncUtilTimeout: 10_000 });
vi.setConfig({ testTimeout: 30_000 });

const now = () => Math.floor(Date.now() / 1000);
// A Select or a Modal can repeat a label, so a field is asked for by its input.
const FIELD = { selector: "input, textarea" };

// The navigation of the app has links of its own, with the same names as the page.
const main = () => within(screen.getByRole("main"));

const NODE = {
  id: "node-a",
  name: "Frankfurt",
  mgmtHost: "203.0.113.7",
  mgmtPort: 8443,
  linkHost: "links.example.com",
  status: "online",
  agentVersion: "0.1.0",
  edgeVersion: "0.1.1",
  arch: "arm64",
  os: "linux",
  publicIps: ["203.0.113.7", "2001:db8::7"],
  desiredGeneration: 9n,
  appliedGeneration: 8n,
  lastSeenUnix: BigInt(now() - 150),
  note: "rack 4",
};
const LISTENERS = [
  { id: "listener-1", nodeId: "node-a", bindIp: "0.0.0.0", port: 443, strangerAction: "mask", maskTarget: "www.example.com" },
  {
    id: "listener-2",
    nodeId: "node-a",
    bindIp: "203.0.113.7",
    port: 8443,
    linkHostOverride: "other.example.com",
    strangerAction: "reject",
    nonTlsAction: "http400",
  },
  { id: "listener-other", nodeId: "node-b", port: 9999 },
];
const PROXIES = [
  { id: "proxy-1", nodeId: "node-a", listenerId: "listener-1", name: "Family", domain: "fam.example.com" },
  { id: "proxy-other", nodeId: "node-b", listenerId: "listener-other", name: "Elsewhere", domain: "else.example.com" },
];

/** Opens the page of a node, on a tab ("" is the overview). */
function openNode(options: Parameters<typeof createFakePanel>[0] = {}, { id = "node-a", tab = "" }: { id?: string; tab?: string } = {}) {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [NODE, { id: "node-b", name: "Amsterdam" }],
    listeners: LISTENERS,
    proxies: PROXIES,
    ...options,
  });
  const view = renderApp({ route: tab === "" ? `/nodes/${id}` : `/nodes/${id}/${tab}`, transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

/** Deletes through the «⋯» menu of the header, which opens the confirmation. */
async function openDeleteFromMenu(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: t("nodes.detail.more") }));
  await user.click(await screen.findByRole("menuitem", { name: t("nodes.delete.action") }));
}

const section = (name: string) => within(screen.getByRole("region", { name }));

/** The page has its node, and from then on its sections. */
const ready = () => screen.findByRole("heading", { name: "Frankfurt", level: 1 });

describe("NodeDetail: the node", () => {
  it("shows what the panel knows of the node", async () => {
    openNode({}, { tab: "settings" });

    expect(await ready()).toBeInTheDocument();
    const state = section(t("nodes.detail.state"));
    expect(state.getByText(t("status.node.online"))).toBeInTheDocument();
    expect(state.getByText("203.0.113.7:8443")).toBeInTheDocument();
    expect(state.getByText("links.example.com")).toBeInTheDocument();
    expect(state.getByText("0.1.0")).toBeInTheDocument();
    expect(state.getByText("0.1.1")).toBeInTheDocument();
    expect(state.getByText("linux / arm64")).toBeInTheDocument();
    expect(state.getByText("203.0.113.7, 2001:db8::7")).toBeInTheDocument();
    expect(state.getByText("8 / 9")).toBeInTheDocument();
    expect(state.getByText(t("node.applying"))).toBeInTheDocument();
    expect(state.getByText("2 minutes ago")).toBeInTheDocument();
    expect(state.getByText("rack 4")).toBeInTheDocument();
  });

  it("says why the node does not run its state, in the words of the node, instead of applying", async () => {
    const why = "edge g1 does not answer: dial unix /opt/postern/data/run/edge-g1.sock: connect: no such file or directory";
    openNode({ nodes: [{ ...NODE, lastError: why }] }, { tab: "settings" });

    await ready();
    const state = section(t("nodes.detail.state"));
    expect(state.getByText(t("node.failing"))).toBeInTheDocument();
    expect(state.queryByText(t("node.applying"))).not.toBeInTheDocument();
    expect(state.getByText(t("node.lastError"))).toBeInTheDocument();
    expect(state.getByText(why)).toBeInTheDocument();
  });

  it("shows the error of a pass that failed on a node that has its state", async () => {
    openNode({ nodes: [{ ...NODE, appliedGeneration: 9n, lastError: "docker: the daemon does not answer" }] }, { tab: "settings" });

    await ready();
    const state = section(t("nodes.detail.state"));
    expect(state.getByText("9 / 9")).toBeInTheDocument();
    expect(state.getByText(t("node.failing"))).toBeInTheDocument();
    expect(state.getByText("docker: the daemon does not answer")).toBeInTheDocument();
  });

  it("has no line for an error when there is none", async () => {
    openNode({}, { tab: "settings" });

    await ready();
    const state = section(t("nodes.detail.state"));
    expect(state.queryByText(t("node.lastError"))).not.toBeInTheDocument();
    expect(state.queryByText(t("node.failing"))).not.toBeInTheDocument();
  });

  it("says that the edge runs another version than the agent, and how to roll it", async () => {
    openNode({ nodes: [{ ...NODE, agentVersion: "0.1.1", edgeVersion: "0.1.0" }] }, { tab: "settings" });

    await ready();
    const state = section(t("nodes.detail.state"));
    expect(state.getByText(t("node.edgeOutdated"))).toBeInTheDocument();
    expect(state.getByText(t("node.edgeBehind", { edge: "0.1.0", agent: "0.1.1" }))).toBeInTheDocument();
    expect(state.getByText(t("node.edgeRoll"))).toBeInTheDocument();
    expect(state.getByText(ROLL_EDGE_COMMAND)).toBeInTheDocument();
    expect(state.getByRole("button", { name: t("node.copyRollEdge") })).toBeInTheDocument();
  });

  it("takes an edge that does not say its version, on a node that has a state, for an outdated one", async () => {
    openNode({ nodes: [{ ...NODE, agentVersion: "0.1.1", edgeVersion: "" }] }, { tab: "settings" });

    await ready();
    const state = section(t("nodes.detail.state"));
    expect(state.getByText(t("node.edgeOutdated"))).toBeInTheDocument();
    expect(state.getByText(t("node.edgeUnknown", { agent: "0.1.1" }))).toBeInTheDocument();
    expect(state.getByText(ROLL_EDGE_COMMAND)).toBeInTheDocument();
  });

  it.each([
    ["an edge of the version of the agent", { agentVersion: "0.1.1", edgeVersion: "0.1.1" }],
    ["a node that has not applied a state yet, and has no edge", { agentVersion: "0.1.1", edgeVersion: "", appliedGeneration: 0n }],
    ["a node that has not said its versions", { agentVersion: "", edgeVersion: "" }],
  ])("does not call the edge outdated for %s", async (_name, versions) => {
    openNode({ nodes: [{ ...NODE, ...versions }] }, { tab: "settings" });

    await ready();
    const state = section(t("nodes.detail.state"));
    expect(state.queryByText(t("node.edgeOutdated"))).not.toBeInTheDocument();
    expect(state.queryByText(ROLL_EDGE_COMMAND)).not.toBeInTheDocument();
  });

  it("has a way back to the list of nodes", async () => {
    openNode();

    await screen.findByRole("heading", { name: "Frankfurt", level: 1 });
    expect(main().getByRole("link", { name: t("nodes.title") })).toHaveAttribute("href", "/nodes");
  });

  it("offers the one Docker command first, then SSH, then the kit and the bundle folded away", async () => {
    const { panel } = openNode({}, { tab: "settings" });
    await ready();

    const install = section(t("nodes.detail.reinstall"));
    const heading = await install.findByRole("heading", { name: t("nodes.docker.title") });
    const button = await install.findByRole("button", { name: t("nodes.docker.get") });
    const ssh = install.getByRole("link", { name: t("deploy.open") });
    const folded = install.getByRole("button", { name: t("nodes.install.manualBlock") });
    expect(heading.compareDocumentPosition(ssh) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(button.compareDocumentPosition(ssh) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(ssh.compareDocumentPosition(folded) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(folded).toHaveAttribute("aria-expanded", "false");
    expect(install.queryByRole("link", { name: t("nodes.install.downloadBundle") })).not.toBeInTheDocument();
    // A command is a join token: none is made until the admin asks.
    expect(panel.rpc.createJoinToken).not.toHaveBeenCalled();
  });

  it("says that the panel has no node image, and keeps the other ways", async () => {
    const { panel, user } = openNode({ nodeImage: "" }, { tab: "settings" });
    await ready();

    const install = section(t("nodes.detail.reinstall"));
    expect(await install.findByText(t("nodes.docker.noImage"))).toBeInTheDocument();
    expect(install.queryByRole("button", { name: t("nodes.docker.get") })).not.toBeInTheDocument();
    expect(install.getByRole("link", { name: t("deploy.open") })).toBeInTheDocument();
    await user.click(install.getByRole("button", { name: t("nodes.install.manualBlock") }));
    expect(await install.findByRole("link", { name: t("nodes.install.downloadBundle") })).toBeInTheDocument();
    expect(panel.rpc.createJoinToken).not.toHaveBeenCalled();
  });

  it("says that a node without an address gets it from its first connection", async () => {
    openNode({ nodes: [{ ...NODE, mgmtHost: "", linkHost: "", status: "provisioning" }] });
    await ready();

    expect(main().getByText(t("nodes.detail.noHost"))).toBeInTheDocument();
  });

  it("says nothing of the address of a node that has one", async () => {
    openNode();
    await ready();

    expect(main().queryByText(t("nodes.detail.noHost"))).not.toBeInTheDocument();
  });

  it("offers the install steps at any time: the bundle, the node kit and the command", async () => {
    const { panel, user } = openNode({}, { tab: "settings" });
    await ready();

    const install = section(t("nodes.detail.reinstall"));
    await user.click(install.getByRole("button", { name: t("nodes.install.manualBlock") }));
    expect(await install.findByRole("link", { name: t("nodes.install.downloadBundle") })).toHaveAttribute(
      "href",
      "/api/nodes/node-a/bundle.tar",
    );
    expect(install.getByRole("link", { name: t("nodes.install.downloadKit", { arch: "amd64" }) })).toHaveAttribute(
      "href",
      "/api/node-kit/amd64",
    );
    expect(install.getByText(INSTALL_COMMAND.replace("<ARCH>", "amd64"))).toBeInTheDocument();
    expect(panel.rpc.getNodeInstall.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a" });
  });

  it("keeps the management host required when the node is edited", async () => {
    const { panel, user } = openNode();
    await ready();

    await user.click(screen.getByRole("button", { name: t("nodes.detail.edit") }));
    const dialog = await screen.findByRole("dialog", { name: t("nodes.edit.title") });
    expect(within(dialog).getByLabelText(t("nodes.form.mgmtHost"), FIELD)).toHaveAccessibleDescription(
      t("nodes.form.mgmtHostHint"),
    );
    await user.clear(within(dialog).getByLabelText(t("nodes.form.mgmtHost"), FIELD));
    await user.click(within(dialog).getByRole("button", { name: t("nodes.form.save") }));

    expect(await within(dialog).findByText(t("validation.required"))).toBeInTheDocument();
    expect(panel.rpc.updateNode).not.toHaveBeenCalled();
  });

  it("edits the node, and sends only what was changed", async () => {
    const { panel, user } = openNode();
    await screen.findByRole("heading", { name: "Frankfurt", level: 1 });

    await user.click(screen.getByRole("button", { name: t("nodes.detail.edit") }));
    const dialog = await screen.findByRole("dialog", { name: t("nodes.edit.title") });
    expect(within(dialog).getByLabelText(t("nodes.form.mgmtPort"), FIELD)).toHaveValue("8443");
    await user.clear(within(dialog).getByLabelText(t("nodes.form.name"), FIELD));
    await user.type(within(dialog).getByLabelText(t("nodes.form.name"), FIELD), "Frankfurt 2");
    await user.click(within(dialog).getByRole("button", { name: t("nodes.form.save") }));

    expect(await screen.findByRole("heading", { name: "Frankfurt 2", level: 1 })).toBeInTheDocument();
    const request = panel.rpc.updateNode.mock.calls[0]?.[0];
    expect(request).toMatchObject({ id: "node-a", name: "Frankfurt 2" });
    expect(request?.mgmtHost).toBeUndefined();
    expect(request?.mgmtPort).toBeUndefined();
    expect(request?.linkHost).toBeUndefined();
    expect(request?.note).toBeUndefined();
  });

  it("refuses a management port that is out of range, before it calls the panel", async () => {
    const { panel, user } = openNode();
    await screen.findByRole("heading", { name: "Frankfurt", level: 1 });

    await user.click(screen.getByRole("button", { name: t("nodes.detail.edit") }));
    const dialog = await screen.findByRole("dialog", { name: t("nodes.edit.title") });
    await user.clear(within(dialog).getByLabelText(t("nodes.form.mgmtPort"), FIELD));
    await user.type(within(dialog).getByLabelText(t("nodes.form.mgmtPort"), FIELD), "70000");
    await user.click(within(dialog).getByRole("button", { name: t("nodes.form.save") }));

    expect(await within(dialog).findByText(t("validation.port"))).toBeInTheDocument();
    expect(panel.rpc.updateNode).not.toHaveBeenCalled();
  });

  it("deletes the node after a confirmation, and goes back to the list", async () => {
    const { panel, user, router } = openNode();
    await screen.findByRole("heading", { name: "Frankfurt", level: 1 });

    await openDeleteFromMenu(user);
    const dialog = await screen.findByRole("dialog", { name: t("nodes.delete.title") });
    expect(panel.rpc.deleteNode).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: t("nodes.delete.confirm") }));

    await waitFor(() => {
      expect(panel.rpc.deleteNode).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.deleteNode.mock.calls[0]?.[0]).toMatchObject({ id: "node-a" });
    expect(await screen.findByRole("heading", { name: t("nodes.title"), level: 1 })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/nodes");
    expect(await screen.findByText(t("nodes.delete.done"))).toBeInTheDocument();
  });

  it("does not delete the node when the admin cancels", async () => {
    const { panel, user } = openNode();
    await screen.findByRole("heading", { name: "Frankfurt", level: 1 });

    await openDeleteFromMenu(user);
    const dialog = await screen.findByRole("dialog", { name: t("nodes.delete.title") });
    await user.click(within(dialog).getByRole("button", { name: t("common.cancel") }));

    expect(panel.rpc.deleteNode).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "Frankfurt", level: 1 })).toBeInTheDocument();
  });

  it("shows the message of the panel when it refuses to delete the node, and stays", async () => {
    const { panel, user } = openNode();
    panel.rpc.deleteNode.mockImplementation(() => {
      throw new ConnectError("the egress chain is still used by another node", Code.FailedPrecondition);
    });
    await screen.findByRole("heading", { name: "Frankfurt", level: 1 });

    await openDeleteFromMenu(user);
    const dialog = await screen.findByRole("dialog", { name: t("nodes.delete.title") });
    await user.click(within(dialog).getByRole("button", { name: t("nodes.delete.confirm") }));

    expect(await screen.findByText("the egress chain is still used by another node")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Frankfurt", level: 1 })).toBeInTheDocument();
  });

  it("says that there is no such node, with a way back", async () => {
    openNode({}, { id: "no-such-node" });

    expect(await screen.findByText(t("errors.notFoundTitle"))).toBeInTheDocument();
    expect(main().getByRole("link", { name: t("nodes.title") })).toHaveAttribute("href", "/nodes");
  });

  it("switches where the node gets its binaries, and shows it after the save", async () => {
    const { panel, user } = openNode({
      nodes: [{ ...NODE, capabilities: ["artifact-direct"], artifactSource: "panel" }],
    }, { tab: "settings" });
    await ready();
    const artifacts = section(t("nodes.artifacts.title"));
    // The section is made again with the saved value, so it is looked up anew.
    const source = () => section(t("nodes.artifacts.title")).getByLabelText(t("nodes.artifacts.source"), FIELD);
    expect(source()).toHaveValue(t("nodes.artifacts.sourcePanel"));

    await user.click(source());
    await user.click(await screen.findByRole("option", { name: t("nodes.artifacts.sourceDirect") }));
    await user.click(artifacts.getByRole("button", { name: t("nodes.artifacts.save") }));

    await waitFor(() => {
      expect(panel.rpc.updateNode).toHaveBeenCalledTimes(1);
    });
    const request = panel.rpc.updateNode.mock.calls[0]?.[0];
    expect(request).toMatchObject({ id: "node-a", artifactSource: "direct" });
    expect(request?.name).toBeUndefined();
    expect(await screen.findByText(t("nodes.artifacts.saved"))).toBeInTheDocument();
    expect(source()).toHaveValue(t("nodes.artifacts.sourceDirect"));
  });

  it("offers no direct download on a node whose agent cannot do it", async () => {
    const { user } = openNode({}, { tab: "settings" });
    await ready();
    const artifacts = section(t("nodes.artifacts.title"));
    expect(artifacts.getByText(t("nodes.artifacts.directUnsupported"))).toBeInTheDocument();
    await user.click(artifacts.getByLabelText(t("nodes.artifacts.source"), FIELD));
    expect(await screen.findByRole("option", { name: t("nodes.artifacts.sourceDirect") })).toHaveAttribute(
      "data-combobox-disabled",
      "true",
    );
  });
});

describe("NodeDetail: the listeners", () => {
  it("lists the listeners of this node and no others", async () => {
    openNode({}, { tab: "proxies" });
    await ready();

    const listeners = section(t("listeners.title"));
    const first = within(await listeners.findByRole("row", { name: /0\.0\.0\.0:443/ }));
    expect(first.getByText(t("listeners.strangerShort.mask"))).toBeInTheDocument();
    expect(first.getByText("www.example.com")).toBeInTheDocument();
    const second = within(listeners.getByRole("row", { name: /203\.0\.113\.7:8443/ }));
    expect(second.getByText("other.example.com")).toBeInTheDocument();
    expect(second.getByText(t("listeners.strangerShort.reject"))).toBeInTheDocument();
    expect(second.getByText(t("listeners.nonTlsShort.http400"))).toBeInTheDocument();
    expect(listeners.queryByText(/9999/)).not.toBeInTheDocument();
  });

  it("says that a node has no listeners yet", async () => {
    openNode({ listeners: [], proxies: [] }, { tab: "proxies" });
    await ready();

    expect(await section(t("listeners.title")).findByText(t("listeners.empty"))).toBeInTheDocument();
  });

  it("adds a listener", async () => {
    const { panel, user } = openNode({}, { tab: "proxies" });
    await ready();
    await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:443/ });

    await user.click(screen.getByRole("button", { name: t("listeners.add") }));
    const dialog = await screen.findByRole("dialog", { name: t("listeners.addTitle") });
    await user.type(within(dialog).getByLabelText(t("listener.form.port"), FIELD), "8080");
    await user.click(within(dialog).getByRole("button", { name: t("listener.form.create") }));

    expect(await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:8080/ })).toBeInTheDocument();
    expect(panel.rpc.createListener.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a", port: 8080 });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("edits a listener, and the table shows the change", async () => {
    const { panel, user } = openNode({}, { tab: "proxies" });
    await ready();
    const row = await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:443/ });

    await user.click(within(row).getByRole("button", { name: t("listeners.edit", { address: "0.0.0.0:443" }) }));
    const dialog = await screen.findByRole("dialog", { name: t("listeners.editTitle") });
    await user.clear(within(dialog).getByLabelText(t("listener.form.port"), FIELD));
    await user.type(within(dialog).getByLabelText(t("listener.form.port"), FIELD), "4443");
    await user.click(within(dialog).getByRole("button", { name: t("listener.form.save") }));

    expect(await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:4443/ })).toBeInTheDocument();
    expect(panel.rpc.updateListener.mock.calls[0]?.[0]).toMatchObject({ id: "listener-1", port: 4443 });
  });

  it("deletes a listener only after a confirmation", async () => {
    const { panel, user } = openNode({}, { tab: "proxies" });
    await ready();
    const row = await section(t("listeners.title")).findByRole("row", { name: /203\.0\.113\.7:8443/ });

    await user.click(within(row).getByRole("button", { name: t("listeners.delete.action", { address: "203.0.113.7:8443" }) }));
    const dialog = await screen.findByRole("dialog", { name: t("listeners.delete.title") });
    expect(panel.rpc.deleteListener).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: t("common.cancel") }));
    expect(panel.rpc.deleteListener).not.toHaveBeenCalled();

    await user.click(within(row).getByRole("button", { name: t("listeners.delete.action", { address: "203.0.113.7:8443" }) }));
    await user.click(
      within(await screen.findByRole("dialog", { name: t("listeners.delete.title") })).getByRole("button", {
        name: t("listeners.delete.confirm"),
      }),
    );

    await waitFor(() => {
      expect(panel.rpc.deleteListener).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.deleteListener.mock.calls[0]?.[0]).toMatchObject({ id: "listener-2" });
    await waitFor(() => {
      expect(section(t("listeners.title")).queryByRole("row", { name: /203\.0\.113\.7:8443/ })).not.toBeInTheDocument();
    });
  });

  it("adds a listener on a port that another process holds, and warns that the node cannot take it yet", async () => {
    const { panel, user } = openNode({
      nodes: [{ ...NODE, portOwners: [{ bind: "0.0.0.0", port: 80, owner: "nginx (pid 812)", postern: false }] }],
    }, { tab: "proxies" });
    await ready();
    await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:443/ });

    await user.click(screen.getByRole("button", { name: t("listeners.add") }));
    const dialog = await screen.findByRole("dialog", { name: t("listeners.addTitle") });
    await user.type(within(dialog).getByLabelText(t("listener.form.port"), FIELD), "80");
    await user.click(within(dialog).getByRole("button", { name: t("listener.form.create") }));

    expect(await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:80/ })).toBeInTheDocument();
    expect(panel.rpc.createListener).toHaveBeenCalledTimes(1);
    expect(await screen.findByText(t("listener.portTaken.title", { address: "0.0.0.0:80" }))).toBeInTheDocument();
    expect(screen.getByText(t("listener.portTaken.message", { owners: "nginx (pid 812)" }))).toBeInTheDocument();
  });

  it("does not warn about a port that Postern itself holds", async () => {
    const { user } = openNode({
      listeners: [],
      proxies: [],
      nodes: [{ ...NODE, portOwners: [{ bind: "0.0.0.0", port: 443, owner: "postern-edge-g1", postern: true }] }],
    }, { tab: "proxies" });
    await ready();

    await user.click(screen.getByRole("button", { name: t("listeners.add") }));
    const dialog = await screen.findByRole("dialog", { name: t("listeners.addTitle") });
    await user.type(within(dialog).getByLabelText(t("listener.form.port"), FIELD), "443");
    await user.click(within(dialog).getByRole("button", { name: t("listener.form.create") }));

    expect(await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:443/ })).toBeInTheDocument();
    expect(screen.queryByText(t("listener.portTaken.title", { address: "0.0.0.0:443" }))).not.toBeInTheDocument();
  });

  it("shows the message of the panel when a listener is still in use", async () => {
    const { user } = openNode({}, { tab: "proxies" });
    await ready();
    const row = await section(t("listeners.title")).findByRole("row", { name: /0\.0\.0\.0:443/ });

    await user.click(within(row).getByRole("button", { name: t("listeners.delete.action", { address: "0.0.0.0:443" }) }));
    await user.click(
      within(await screen.findByRole("dialog", { name: t("listeners.delete.title") })).getByRole("button", {
        name: t("listeners.delete.confirm"),
      }),
    );

    // The fake panel, like the real one, refuses a listener that proxies still use.
    expect(await screen.findByText("the listener is still used by proxies")).toBeInTheDocument();
    expect(section(t("listeners.title")).getByRole("row", { name: /0\.0\.0\.0:443/ })).toBeInTheDocument();
  });
});

describe("NodeDetail: the ports in use", () => {
  it("lists what listens on the ports of the node, and marks what is Postern", async () => {
    openNode({
      nodes: [
        {
          ...NODE,
          portOwners: [
            { bind: "0.0.0.0", port: 80, owner: "nginx (pid 812)", postern: false },
            { bind: "0.0.0.0", port: 443, owner: "postern-edge-g1", postern: true },
            { bind: "::", port: 8080, owner: "unknown", postern: false },
          ],
        },
      ],
    }, { tab: "proxies" });
    await ready();

    const ports = section(t("nodes.detail.ports"));
    const nginx = within(ports.getByRole("row", { name: /nginx/ }));
    expect(nginx.getByText("0.0.0.0:80")).toBeInTheDocument();
    expect(nginx.queryByText(t("nodes.ports.postern"))).not.toBeInTheDocument();
    const edge = within(ports.getByRole("row", { name: /postern-edge-g1/ }));
    expect(edge.getByText("0.0.0.0:443")).toBeInTheDocument();
    expect(edge.getByText(t("nodes.ports.postern"))).toBeInTheDocument();
    expect(ports.getByText("[::]:8080")).toBeInTheDocument();
  });

  it("says that the node has not said which ports are in use", async () => {
    openNode({ nodes: [{ ...NODE, portOwners: [] }] }, { tab: "proxies" });
    await ready();

    expect(section(t("nodes.detail.ports")).getByText(t("nodes.ports.none"))).toBeInTheDocument();
  });
});

describe("NodeDetail: the proxies", () => {
  it("lists the proxies of this node and no others", async () => {
    openNode({}, { tab: "proxies" });
    await ready();

    const proxies = section(t("nodes.detail.proxies"));
    expect(await proxies.findByText("fam.example.com")).toBeInTheDocument();
    expect(proxies.queryByText("else.example.com")).not.toBeInTheDocument();
    expect(proxies.getByRole("link", { name: "Family" })).toHaveAttribute("href", "/proxies/proxy-1");
  });

  it("says that the node has no proxies yet", async () => {
    openNode({ proxies: [] }, { tab: "proxies" });
    await ready();

    expect(await section(t("nodes.detail.proxies")).findByText(t("nodes.detail.noProxies"))).toBeInTheDocument();
  });

  it("opens the form of a new proxy on this node, without asking which node", async () => {
    const { user } = openNode({}, { tab: "proxies" });
    await ready();
    await section(t("nodes.detail.proxies")).findByText("fam.example.com");

    await user.click(screen.getByRole("button", { name: t("proxies.add") }));
    const dialog = await screen.findByRole("dialog", { name: t("proxies.addTitle") });

    expect(within(dialog).getByLabelText(t("proxy.form.listener"), FIELD)).toBeInTheDocument();
    expect(within(dialog).queryByLabelText(t("proxy.form.node"), FIELD)).not.toBeInTheDocument();
  });
});
