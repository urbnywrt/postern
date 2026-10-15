import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const NODE = { id: "node-a", name: "Frankfurt", capabilities: ["rollout-status", "engine-mtg"] };
const PROXIES = [
  { id: "proxy-1", name: "Alpha", nodeId: "node-a", engine: "telemt", engineVersion: "3.5.13", status: { phase: "serving", runningEngine: "telemt", runningVersion: "3.5.12" } },
  { id: "proxy-2", name: "Beta", nodeId: "node-a", engine: "telemt", engineVersion: "3.5.13", status: { phase: "serving", runningEngine: "telemt", runningVersion: "3.5.13" } },
  { id: "proxy-3", name: "Gamma", nodeId: "node-a", engine: "mtg", engineVersion: "v2.2.8", status: { phase: "serving", runningEngine: "mtg", runningVersion: "v2.2.8" } },
  // Runs what it should, but a newer release is on its channel: the panel marks it outdated.
  { id: "proxy-4", name: "Delta", nodeId: "node-a", engine: "telemt", engineVersion: "3.5.12", outdated: true, status: { phase: "serving", runningEngine: "telemt", runningVersion: "3.5.12" } },
];
const FIELD = { selector: "input" };

function openProxies() {
  const panel = createFakePanel({ signedIn: true, nodes: [NODE], proxies: PROXIES });
  renderApp({ route: "/proxies", transport: panel.transport });
  return { panel, user: userEvent.setup() };
}

const lastList = (panel: ReturnType<typeof createFakePanel>) => panel.rpc.listProxies.mock.calls.at(-1)?.[0];

describe("Proxies: engines and versions", () => {
  it("shows the engine and what runs against what should", async () => {
    openProxies();
    const row = (await screen.findByRole("link", { name: "Alpha" })).closest("tr");
    if (row === null) throw new Error("no row");
    expect(within(row).getByText("telemt")).toBeInTheDocument();
    expect(within(row).getByText(t("proxies.table.runningVersion", { engine: "telemt", version: "3.5.12" }))).toBeInTheDocument();
    expect(within(row).getByText(t("proxies.table.desiredVersion", { version: "3.5.13" }))).toBeInTheDocument();
  });

  it("marks the rows that the outdated filter lists, and only those", async () => {
    openProxies();
    const rowOf = async (name: string) => {
      const row = (await screen.findByRole("link", { name })).closest("tr");
      if (row === null) throw new Error("no row");
      return row;
    };
    const marked = (row: HTMLElement) => within(row).queryByTitle(t("proxies.table.outdated")) !== null;
    expect(marked(await rowOf("Alpha"))).toBe(true); // runs another version than it should
    expect(marked(await rowOf("Delta"))).toBe(true); // a newer release is on its channel
    expect(marked(await rowOf("Beta"))).toBe(false);
    expect(marked(await rowOf("Gamma"))).toBe(false);
  });

  it("asks the panel for the outdated proxies only", async () => {
    const { panel, user } = openProxies();
    await screen.findByRole("link", { name: "Alpha" });
    await user.click(screen.getByRole("checkbox", { name: t("proxies.filter.outdated") }));
    await waitFor(() => {
      expect(lastList(panel)).toMatchObject({ outdated: true });
    });
    expect(await screen.findByRole("link", { name: "Alpha" })).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.queryByRole("link", { name: "Beta" })).not.toBeInTheDocument();
    });
  });

  it("asks the panel for the proxies of one engine", async () => {
    const { panel, user } = openProxies();
    await screen.findByRole("link", { name: "Alpha" });
    await user.click(screen.getByLabelText(t("proxies.filter.engine"), FIELD));
    await user.click(await screen.findByRole("option", { name: "mtg" }));
    await waitFor(() => {
      expect(lastList(panel)).toMatchObject({ engine: "mtg", outdated: false });
    });
  });

  it("switches the selected proxies in one rollout", async () => {
    const { panel, user } = openProxies();
    await screen.findByRole("link", { name: "Alpha" });
    const bulk = screen.getByRole("button", { name: t("proxies.bulkSwitch", { count: 0 }) });
    expect(bulk).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: t("proxies.table.select", { name: "Alpha" }) }));
    await user.click(screen.getByRole("checkbox", { name: t("proxies.table.select", { name: "Beta" }) }));
    await user.click(screen.getByRole("button", { name: t("proxies.bulkSwitch", { count: 2 }) }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("button", { name: t("versions.rollout.start") }));
    await waitFor(() => {
      expect(panel.rpc.startRollout).toHaveBeenCalledTimes(1);
    });
    expect(panel.rpc.startRollout.mock.calls[0]?.[0]).toMatchObject({ kind: "switch", proxyIds: ["proxy-1", "proxy-2"] });
  });
});
