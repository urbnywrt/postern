import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { EgressOptions } from "../test/fakeEgress";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { EgressHealth } from "./EgressHealth";

const NODE = { id: "node-a", name: "Frankfurt" };
const now = () => BigInt(Math.floor(Date.now() / 1000));
const DAY = 86_400n;

function open(health: EgressOptions["health"], { status = "online", egresses = [] }: { status?: string; egresses?: EgressOptions["egresses"] } = {}) {
  const panel = createFakePanel({ signedIn: true, nodes: [{ ...NODE, status }], health, egresses });
  renderWithProviders(<EgressHealth nodeId={NODE.id} />, { transport: panel.transport });
  return panel;
}

/** The rows of the members, without the header: `row(i)` asks within the i-th of them. */
async function memberRows() {
  const rows = (await screen.findAllByRole("row")).slice(1);
  const row = (i: number) => {
    const found = rows[i];
    if (found === undefined) {
      throw new Error(`no row ${String(i)}`);
    }
    return within(found);
  };
  return { count: rows.length, row };
}

type Row = ReturnType<Awaited<ReturnType<typeof memberRows>>["row"]>;

/** The cell of a row that holds a text. */
const cellOf = (row: Row, text: string) => row.getByText(text).closest("td");

describe("EgressHealth", () => {
  it("shows every member with its status, latency, exit IP and the time of its check", async () => {
    open({
      [NODE.id]: {
        reportedUnix: now() - 20n,
        members: [
          { chainId: "chain-1", chainName: "Main", egressId: "eg-sub", egressName: "Subscription", member: "0123456789ab", status: "up", latencyMs: 87, exitIp: "198.51.100.20", checkedUnix: now() - 30n },
          { chainId: "chain-1", chainName: "Main", egressId: "eg-warp", egressName: "WARP", member: "warp", status: "down", exitIp: "203.0.113.44", checkedUnix: now() - 30n },
          { chainId: "default", egressId: "direct", status: "unknown" },
        ],
      },
    });

    const { count, row } = await memberRows();
    expect(count).toBe(3);
    const [sub, warp, direct] = [row(0), row(1), row(2)];
    expect(sub.getByText("Main")).toBeInTheDocument();
    expect(sub.getByText("Subscription")).toBeInTheDocument();
    expect(sub.getByText("0123456789ab")).toBeInTheDocument();
    expect(sub.getByText(t("egressHealth.status.up"))).toBeInTheDocument();
    expect(sub.getByText(t("egressHealth.latency", { ms: 87 }))).toBeInTheDocument();
    expect(sub.getByText("198.51.100.20")).toBeInTheDocument();
    // The exit IP of a WARP egress.
    expect(warp.getByText("203.0.113.44")).toBeInTheDocument();
    expect(warp.getByText(t("egressHealth.status.down"))).toBeInTheDocument();
    // The implicit chain of a node without a default chain goes out directly.
    expect(direct.getAllByText(t("egressHealth.direct"))).toHaveLength(2);
    expect(direct.getByText(t("egressHealth.status.unknown"))).toBeInTheDocument();
    // Fresh: nothing is marked stale.
    expect(screen.queryByText(t("egressHealth.stale"))).not.toBeInTheDocument();
  });

  it("marks a member that was checked long ago as stale, in words, and dims what it says", async () => {
    open({
      [NODE.id]: {
        reportedUnix: now() - 20n,
        members: [
          { chainId: "chain-1", chainName: "Main", egressId: "eg-old", egressName: "Old", status: "up", latencyMs: 87, exitIp: "198.51.100.20", checkedUnix: now() - 3n * DAY },
          { chainId: "chain-1", chainName: "Main", egressId: "eg-new", egressName: "New", status: "up", latencyMs: 40, exitIp: "203.0.113.44", checkedUnix: now() - 10n },
        ],
      },
    });

    const { row } = await memberRows();
    const [old, fresh] = [row(0), row(1)];
    expect(old.getByText(t("egressHealth.stale"))).toBeInTheDocument();
    for (const text of [t("egressHealth.status.up"), t("egressHealth.latency", { ms: 87 }), "198.51.100.20"]) {
      expect(cellOf(old, text), text).toHaveStyle({ opacity: "0.5" });
    }
    expect(fresh.queryByText(t("egressHealth.stale"))).not.toBeInTheDocument();
    for (const text of [t("egressHealth.status.up"), t("egressHealth.latency", { ms: 40 }), "203.0.113.44"]) {
      expect(cellOf(fresh, text), text).not.toHaveStyle({ opacity: "0.5" });
    }
    // The report itself is recent.
    expect(screen.queryByText(t("egressHealth.nodeOffline"))).not.toBeInTheDocument();
  });

  it("marks everything stale when the node is offline, and says why", async () => {
    open(
      {
        [NODE.id]: {
          reportedUnix: now() - 20n,
          members: [{ chainId: "chain-1", chainName: "Main", egressId: "eg-a", egressName: "Alpha", status: "up", latencyMs: 87, exitIp: "198.51.100.20", checkedUnix: now() - 30n }],
        },
      },
      { status: "offline" },
    );

    const alpha = (await memberRows()).row(0);
    expect(alpha.getByText(t("egressHealth.stale"))).toBeInTheDocument();
    expect(cellOf(alpha, t("egressHealth.status.up"))).toHaveStyle({ opacity: "0.5" });
    expect(screen.getByText(t("egressHealth.nodeOffline"))).toBeInTheDocument();
  });

  it("says when the whole report is old", async () => {
    open({
      [NODE.id]: {
        reportedUnix: now() - DAY,
        members: [{ chainId: "chain-1", chainName: "Main", egressId: "eg-a", egressName: "Alpha", status: "up", checkedUnix: now() - DAY }],
      },
    });

    const alpha = (await memberRows()).row(0);
    expect(alpha.getByText(t("egressHealth.stale"))).toBeInTheDocument();
    expect(screen.getByText(t("egressHealth.staleReport"))).toBeInTheDocument();
  });

  it("labels a psiphon member experimental, in words", async () => {
    open(
      {
        [NODE.id]: {
          reportedUnix: now() - 20n,
          members: [
            { chainId: "chain-1", chainName: "Main", egressId: "eg-psiphon", egressName: "Psiphon DE", status: "up", checkedUnix: now() - 10n },
            { chainId: "chain-1", chainName: "Main", egressId: "eg-warp", egressName: "WARP", status: "up", checkedUnix: now() - 10n },
          ],
        },
      },
      { egresses: [{ id: "eg-psiphon", name: "Psiphon DE", kind: "psiphon" }, { id: "eg-warp", name: "WARP", kind: "warp" }] },
    );

    const { row } = await memberRows();
    const [psiphon, warp] = [row(0), row(1)];
    expect(psiphon.getByText(t("egress.experimental"))).toBeInTheDocument();
    expect(warp.queryByText(t("egress.experimental"))).not.toBeInTheDocument();
  });

  it("judges the age by the interval of the checks of the node: of its default chain, or else of the first chain it uses that has one", async () => {
    // The default chain has no check; the chain of a proxy of the node checks every 100 seconds: stale after 300.
    const panel = createFakePanel({
      signedIn: true,
      nodes: [{ ...NODE, defaultChainId: "chain-b" }],
      chains: [
        { id: "chain-a", name: "Checked", check: { intervalSeconds: 100 } },
        { id: "chain-b", name: "Default" },
        // First by id, but the node does not use it.
        { id: "chain-0", name: "Of nobody", check: { intervalSeconds: 5 } },
      ],
      listeners: [{ id: "listener-a", nodeId: NODE.id }],
      proxies: [{ id: "proxy-a", nodeId: NODE.id, listenerId: "listener-a", egressChainId: "chain-a" }],
      health: {
        [NODE.id]: {
          reportedUnix: now() - 20n,
          members: [
            { chainId: "chain-a", chainName: "Checked", egressId: "eg-a", egressName: "Recent", status: "up", checkedUnix: now() - 200n },
            { chainId: "chain-a", chainName: "Checked", egressId: "eg-b", egressName: "Old", status: "up", checkedUnix: now() - 400n },
          ],
        },
      },
    });
    renderWithProviders(<EgressHealth nodeId={NODE.id} />, { transport: panel.transport });

    const { row } = await memberRows();
    expect(row(0).queryByText(t("egressHealth.stale"))).not.toBeInTheDocument();
    expect(row(1).getByText(t("egressHealth.stale"))).toBeInTheDocument();
  });

  it("says when the node has reported nothing", async () => {
    open({});
    expect(await screen.findByText(t("egressHealth.empty"))).toBeInTheDocument();
  });
});
