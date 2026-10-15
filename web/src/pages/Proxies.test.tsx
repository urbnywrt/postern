import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

// A Select has a list of options with the same label as its input: ask for the field.
const FIELD = { selector: "input, textarea" };

const NODES = [
  { id: "node-a", name: "Frankfurt" },
  { id: "node-b", name: "Amsterdam" },
];
const LISTENERS = [
  { id: "listener-a", nodeId: "node-a", port: 443 },
  { id: "listener-b", nodeId: "node-b", port: 8443 },
];
const PROXIES = [
  { id: "proxy-1", nodeId: "node-a", listenerId: "listener-a", name: "Family", domain: "fam.example.com" },
  {
    id: "proxy-2",
    nodeId: "node-b",
    listenerId: "listener-b",
    name: "Friends",
    domain: "friends.example.com",
    enabled: false,
    status: { phase: "paused", reason: "", runningVersion: "", instanceGeneration: 5n, reportedUnix: 0n },
  },
  {
    id: "proxy-3",
    nodeId: "node-a",
    listenerId: "listener-a",
    name: "",
    domain: "unnamed.example.com",
    status: { phase: "failed", reason: "artifact missing", runningVersion: "", instanceGeneration: 5n, reportedUnix: 0n },
  },
];

function openProxies(route = "/proxies", options: Parameters<typeof createFakePanel>[0] = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: NODES, listeners: LISTENERS, proxies: PROXIES, ...options });
  const view = renderApp({ route, transport: panel.transport });
  return { panel, user: userEvent.setup(), ...view };
}

const row = (name: RegExp | string) => screen.getByRole("row", { name });

async function loaded() {
  await screen.findByText("fam.example.com");
}

afterEach(() => {
  Reflect.deleteProperty(window, "isSecureContext");
});

describe("Proxies", () => {
  it("lists the proxies of every node, with their node, domain and status", async () => {
    openProxies();
    await loaded();

    const family = within(row(/Family/));
    expect(family.getByText("fam.example.com")).toBeInTheDocument();
    expect(family.getByText("Frankfurt")).toBeInTheDocument();
    expect(family.getByText(t("status.proxy.serving"))).toBeInTheDocument();

    const friends = within(row(/Friends/));
    expect(friends.getByText("Amsterdam")).toBeInTheDocument();
    expect(friends.getByText(t("status.proxy.paused"))).toBeInTheDocument();
  });

  it("names a proxy that has no name by its domain, once", async () => {
    openProxies();
    await loaded();

    const unnamed = within(row(/unnamed\.example\.com/));
    expect(unnamed.getAllByText("unnamed.example.com")).toHaveLength(1);
    expect(unnamed.getByText(t("status.proxy.failed"))).toBeInTheDocument();
  });

  it("links each proxy to its page", async () => {
    openProxies();
    await loaded();

    expect(within(row(/Family/)).getByRole("link", { name: "Family" })).toHaveAttribute("href", "/proxies/proxy-1");
  });

  describe("the enable switch", () => {
    it("pauses an enabled proxy: it calls SetProxyEnabled, and the switch follows the answer", async () => {
      const { panel, user } = openProxies();
      await loaded();

      const toggle = within(row(/Family/)).getByRole("switch");
      expect(toggle).toBeChecked();
      await user.click(toggle);

      await waitFor(() => {
        expect(panel.rpc.setProxyEnabled).toHaveBeenCalledTimes(1);
      });
      expect(panel.rpc.setProxyEnabled.mock.calls[0]?.[0]).toMatchObject({ id: "proxy-1", enabled: false });
      await waitFor(() => {
        expect(within(row(/Family/)).getByRole("switch")).not.toBeChecked();
      });
      expect(panel.inventory.proxies.find((p) => p.id === "proxy-1")?.enabled).toBe(false);
    });

    it("resumes a paused proxy", async () => {
      const { panel, user } = openProxies();
      await loaded();

      const toggle = within(row(/Friends/)).getByRole("switch");
      expect(toggle).not.toBeChecked();
      await user.click(toggle);

      await waitFor(() => {
        expect(panel.rpc.setProxyEnabled).toHaveBeenCalledTimes(1);
      });
      expect(panel.rpc.setProxyEnabled.mock.calls[0]?.[0]).toMatchObject({ id: "proxy-2", enabled: true });
      await waitFor(() => {
        expect(within(row(/Friends/)).getByRole("switch")).toBeChecked();
      });
    });

    it("names each switch for its proxy, so that a screen reader can tell them apart", async () => {
      openProxies();
      await loaded();

      expect(screen.getByRole("switch", { name: t("proxies.table.enabledFor", { name: "Family" }) })).toBeChecked();
      expect(screen.getByRole("switch", { name: t("proxies.table.enabledFor", { name: "Friends" }) })).not.toBeChecked();
    });

    it("shows the message of the panel when it refuses, and leaves the switch as it was", async () => {
      const { panel, user } = openProxies();
      panel.rpc.setProxyEnabled.mockImplementation(() => {
        throw new ConnectError("the node would refuse its state: no listener", Code.FailedPrecondition);
      });
      await loaded();

      await user.click(within(row(/Family/)).getByRole("switch"));

      expect(await screen.findByText("the node would refuse its state: no listener")).toBeInTheDocument();
      await waitFor(() => {
        expect(within(row(/Family/)).getByRole("switch")).toBeEnabled();
      });
      expect(within(row(/Family/)).getByRole("switch")).toBeChecked();
    });

    it("cannot be pressed again while its call is on its way", async () => {
      const { panel, user } = openProxies();
      let finish: () => void = () => undefined;
      panel.rpc.setProxyEnabled.mockImplementation(
        (req) =>
          new Promise((resolve) => {
            finish = () => {
              const proxy = panel.inventory.proxies.find((p) => p.id === req.id);
              if (proxy === undefined) {
                throw new Error("no such proxy");
              }
              proxy.enabled = req.enabled;
              resolve({ proxy });
            };
          }),
      );
      await loaded();

      await user.click(within(row(/Family/)).getByRole("switch"));
      await waitFor(() => {
        expect(within(row(/Family/)).getByRole("switch")).toBeDisabled();
      });
      finish();
      await waitFor(() => {
        expect(within(row(/Family/)).getByRole("switch")).toBeEnabled();
      });
      expect(panel.rpc.setProxyEnabled).toHaveBeenCalledTimes(1);
    });
  });

  describe("copying the link", () => {
    it("fetches the tg link of that proxy and puts it on the clipboard", async () => {
      Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
      const { panel, user } = openProxies();
      await loaded();

      await user.click(within(row(/Family/)).getByRole("button", { name: t("proxies.table.copyLink", { name: "Family" }) }));

      expect(await screen.findByText(t("common.copied"))).toBeInTheDocument();
      expect(panel.rpc.getProxyLinks).toHaveBeenCalledTimes(1);
      expect(panel.rpc.getProxyLinks.mock.calls[0]?.[0]).toMatchObject({ id: "proxy-1" });
      const copied = await navigator.clipboard.readText();
      expect(copied).toMatch(/^tg:\/\/proxy\?server=203\.0\.113\.7&port=443&secret=ee/);
      // Nothing is kept of it in the page.
      expect(screen.queryByText(copied)).not.toBeInTheDocument();
    });

    it("says why when the panel cannot give the link, and does not claim a copy", async () => {
      Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
      const { panel, user } = openProxies();
      panel.rpc.getProxyLinks.mockImplementation(() => {
        throw new ConnectError("the node has no host for links", Code.FailedPrecondition);
      });
      await loaded();

      await user.click(within(row(/Family/)).getByRole("button", { name: t("proxies.table.copyLink", { name: "Family" }) }));

      expect(await screen.findByText("the node has no host for links")).toBeInTheDocument();
      expect(screen.queryByText(t("common.copied"))).not.toBeInTheDocument();
    });
  });

  describe("filtering", () => {
    it("by node: asks the panel for the proxies of that node, and keeps the choice in the address", async () => {
      const { panel, user, router } = openProxies();
      await loaded();

      await user.click(screen.getByLabelText(t("proxies.filter.node"), FIELD));
      await user.click(await screen.findByRole("option", { name: "Amsterdam" }));

      await waitFor(() => {
        expect(screen.queryByText("fam.example.com")).not.toBeInTheDocument();
      });
      expect(screen.getByText("friends.example.com")).toBeInTheDocument();
      expect(panel.rpc.listProxies).toHaveBeenLastCalledWith(expect.objectContaining({ nodeId: "node-b" }), expect.anything());
      expect(router.state.location.search).toBe("?node=node-b");
    });

    it("starts filtered when the address names a node", async () => {
      const { panel } = openProxies("/proxies?node=node-b");

      expect(await screen.findByText("friends.example.com")).toBeInTheDocument();
      expect(screen.queryByText("fam.example.com")).not.toBeInTheDocument();
      expect(screen.getByLabelText(t("proxies.filter.node"), FIELD)).toHaveValue("Amsterdam");
      expect(panel.rpc.listProxies.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-b" });
    });

    it("shows every node again when the choice is cleared", async () => {
      const { user, router } = openProxies("/proxies?node=node-b");
      await screen.findByText("friends.example.com");

      await user.click(screen.getByRole("button", { name: t("proxies.filter.clear") }));

      expect(await screen.findByText("fam.example.com")).toBeInTheDocument();
      expect(router.state.location.search).toBe("");
    });

    it("by text: asks the panel to search once the admin has stopped typing", async () => {
      const { panel, user } = openProxies();
      await loaded();

      await user.type(screen.getByLabelText(t("proxies.filter.search"), FIELD), "friends");

      await waitFor(() => {
        expect(panel.rpc.listProxies).toHaveBeenLastCalledWith(expect.objectContaining({ query: "friends" }), expect.anything());
      });
      // One question for the whole word, not one for each letter.
      const queries = panel.rpc.listProxies.mock.calls.map((call) => call[0].query);
      expect(queries).not.toContain("f");
      expect(queries).not.toContain("fr");
      await waitFor(() => {
        expect(screen.queryByText("fam.example.com")).not.toBeInTheDocument();
      });
      expect(screen.getByText("friends.example.com")).toBeInTheDocument();
    });
  });

  describe("when there is nothing to show", () => {
    it("says that there are no proxies yet, and offers to add one", async () => {
      openProxies("/proxies", { proxies: [] });

      expect(await screen.findByText(t("proxies.empty"))).toBeInTheDocument();
      expect(screen.getAllByRole("button", { name: t("proxies.add") }).length).toBeGreaterThan(0);
    });

    it("says that nothing matches when a filter is on", async () => {
      const { user } = openProxies();
      await loaded();

      await user.type(screen.getByLabelText(t("proxies.filter.search"), FIELD), "no such proxy");

      expect(await screen.findByText(t("proxies.noMatch"))).toBeInTheDocument();
    });

    it("sends the admin to add a node first, when there is none", async () => {
      openProxies("/proxies", { nodes: [], listeners: [], proxies: [] });

      expect(await screen.findByText(t("proxies.noNodes"))).toBeInTheDocument();
      expect(screen.getByRole("link", { name: t("nodes.add") })).toHaveAttribute("href", "/nodes");
      expect(screen.queryByRole("button", { name: t("proxies.add") })).not.toBeInTheDocument();
    });
  });

  describe("when the panel does not answer", () => {
    it("says so, and tries again on request", async () => {
      const { panel, user } = openProxies();
      panel.rpc.listProxies.mockImplementationOnce(() => {
        throw new ConnectError("the database is locked", Code.Internal);
      });

      expect(await screen.findByText("the database is locked")).toBeInTheDocument();
      await user.click(screen.getByRole("button", { name: t("common.retry") }));

      expect(await screen.findByText("fam.example.com")).toBeInTheDocument();
    });
  });
});
