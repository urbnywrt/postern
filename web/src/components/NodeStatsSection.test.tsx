import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { EgressHistory } from "./EgressHistory";
import { NodeStatsSection } from "./NodeStatsSection";

const now = () => Math.floor(Date.now() / 1000);
const region = (name: string) => screen.findByRole("region", { name }).then((element) => within(element));

function open() {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [{ id: "node-a", name: "Frankfurt" }],
    chains: [{ id: "chain-1", name: "Via WARP", nodeId: "node-a" }],
  });
  return { panel, user: userEvent.setup() };
}

const minute = (at: number, init: Record<string, unknown> = {}) => ({
  tsUnix: BigInt(now() - (now() % 60) - at),
  cpu: 25,
  memUsed: 1_000_000_000n,
  memTotal: 4_000_000_000n,
  load1: 0.5,
  diskUsed: 10_000_000_000n,
  diskTotal: 40_000_000_000n,
  netRx: 1_000n,
  netTx: 2_000n,
  conns: 12,
  up: 3_000n,
  down: 4_000n,
  devicesSum: 6,
  ...init,
});

const NODE_CHARTS = [
  "insights.node.cpu",
  "insights.node.memory",
  "insights.node.load",
  "insights.node.disk",
  "insights.node.network",
  "insights.node.connections",
  "insights.node.traffic",
  "insights.node.devices",
] as const;

describe("NodeStatsSection", () => {
  it("draws the load, the network, the connections, the traffic and the unique IPs of the node", async () => {
    const { panel } = open();
    panel.insights.nodeSeries.set("node-a", [minute(120), minute(60)]);
    renderWithProviders(<NodeStatsSection nodeId="node-a" />, { transport: panel.transport });

    for (const key of NODE_CHARTS) {
      expect(await screen.findByRole("region", { name: t(key) })).toBeInTheDocument();
    }
    // "Unique IPs, sum of proxies", as the spec words it.
    expect(t("insights.node.devices")).toBe("Unique IPs, sum of proxies");
    // The edge refused nothing: there is no chart of refusals.
    expect(screen.queryByRole("region", { name: t("insights.node.refusals") })).not.toBeInTheDocument();
    const memory = await region(t("insights.node.memory"));
    expect(memory.getByText(t("insights.node.memTotal"))).toBeInTheDocument();
  });

  it("draws only the traffic over 24 hours when compact, without a choice of range", async () => {
    const { panel } = open();
    panel.insights.nodeSeries.set("node-a", [minute(120, { refusedTotal: 3n }), minute(60)]);
    renderWithProviders(<NodeStatsSection nodeId="node-a" compact />, { transport: panel.transport });

    expect(await screen.findByRole("region", { name: t("insights.node.traffic") })).toBeInTheDocument();
    for (const key of NODE_CHARTS.filter((key) => key !== "insights.node.traffic")) {
      expect(screen.queryByRole("region", { name: t(key) })).not.toBeInTheDocument();
    }
    expect(screen.queryByRole("region", { name: t("insights.node.refusals") })).not.toBeInTheDocument();
    expect(screen.queryByRole("radio")).not.toBeInTheDocument();
    expect(panel.rpc.nodeSeries.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a", range: "24h" });
  });

  it("shows the refusals of the edge when there were any", async () => {
    const { panel } = open();
    panel.insights.nodeSeries.set("node-a", [minute(60, { refusedTotal: 3n, refusedPrehello: 2n })]);
    renderWithProviders(<NodeStatsSection nodeId="node-a" />, { transport: panel.transport });

    const refusals = await region(t("insights.node.refusals"));
    expect(refusals.getByText(t("insights.node.refusedPrehello"))).toBeInTheDocument();
  });

  it("says that the node reported nothing in the range", async () => {
    const { panel } = open();
    renderWithProviders(<NodeStatsSection nodeId="node-a" />, { transport: panel.transport });

    expect(await screen.findByText(t("insights.node.empty"))).toBeInTheDocument();
  });

  it("asks again for another range", async () => {
    const { panel, user } = open();
    renderWithProviders(<NodeStatsSection nodeId="node-a" />, { transport: panel.transport });
    await screen.findByText(t("insights.node.empty"));

    await user.click(screen.getByRole("radio", { name: t("insights.ranges.1y") }));

    await waitFor(() => {
      expect(panel.rpc.nodeSeries.mock.calls.at(-1)?.[0]).toMatchObject({ nodeId: "node-a", range: "1y" });
    });
  });
});

describe("EgressHistory", () => {
  const hour = (at: number, exitIp: string, up = 60) => ({
    tsUnix: BigInt(now() - (now() % 3600) - at * 3600),
    upMinutes: up,
    downMinutes: 60 - up,
    unknownMinutes: 0,
    latencyAvgMs: 80,
    latencyMaxMs: 140,
    exitIp,
  });

  it("names each member by its chain, draws its minutes and latency, and lists the changes of its exit IP", async () => {
    const { panel } = open();
    panel.insights.egressHistory.set("node-a", [
      { chainId: "chain-1", memberKey: "warp-1", hours: [hour(3, "203.0.113.10"), hour(2, "203.0.113.10", 40), hour(1, "203.0.113.20")] },
    ]);
    renderWithProviders(<EgressHistory nodeId="node-a" />, { transport: panel.transport });

    const member = await region("Via WARP / warp-1");
    expect(member.getByText(t("insights.egressHistory.down"))).toBeInTheDocument();
    expect(member.getByText(t("insights.egressHistory.latencyMax"))).toBeInTheDocument();
    expect(member.getByText("203.0.113.10")).toBeInTheDocument();
    expect(member.getByText("203.0.113.20")).toBeInTheDocument();
  });

  it("says when the exit IP stayed the same", async () => {
    const { panel } = open();
    panel.insights.egressHistory.set("node-a", [
      { chainId: "chain-1", memberKey: "warp-1", hours: [hour(2, "203.0.113.10"), hour(1, "203.0.113.10")] },
    ]);
    renderWithProviders(<EgressHistory nodeId="node-a" />, { transport: panel.transport });

    const member = await region("Via WARP / warp-1");
    expect(member.getByText(t("insights.egressHistory.exitSteady", { ip: "203.0.113.10" }))).toBeInTheDocument();
  });

  it("says that no member was checked, and offers ranges up to 30 days", async () => {
    const { panel, user } = open();
    renderWithProviders(<EgressHistory nodeId="node-a" />, { transport: panel.transport });

    expect(await screen.findByText(t("insights.egressHistory.empty"))).toBeInTheDocument();
    expect(screen.queryByRole("radio", { name: t("insights.ranges.90d") })).not.toBeInTheDocument();
    await user.click(screen.getByRole("radio", { name: t("insights.ranges.30d") }));
    await waitFor(() => {
      expect(panel.rpc.egressHistory.mock.calls.at(-1)?.[0]).toMatchObject({ nodeId: "node-a", range: "30d" });
    });
  });
});
