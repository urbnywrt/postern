import { Code, ConnectError } from "@connectrpc/connect";
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { PROBE_PAUSED } from "../test/fakeInsights";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { AvailabilitySection } from "./AvailabilitySection";

const now = () => Math.floor(Date.now() / 1000);
const region = (name: string) => screen.findByRole("region", { name }).then((element) => within(element));

function open({ enabled = true }: { enabled?: boolean } = {}) {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [{ id: "node-a", name: "Frankfurt" }],
    proxies: [{ id: "proxy-1", nodeId: "node-a", name: "Family", enabled }],
  });
  return { panel, user: userEvent.setup() };
}

function show(panel: ReturnType<typeof open>["panel"]) {
  const proxy = panel.inventory.proxies[0];
  if (proxy === undefined) throw new Error("no proxy");
  return renderWithProviders(<AvailabilitySection proxy={proxy} />, { transport: panel.transport, route: "/proxies/proxy-1" });
}

describe("AvailabilitySection: probes", () => {
  it("shows the uptime of each vantage over 24 hours and 7 days, the latest failure and the last probe's class", async () => {
    const { panel } = open();
    panel.insights.probes.set("proxy-1", [
      { ts: BigInt(now() - 600), vantage: "panel", kind: "l2", ok: true, latencyMs: 90, error: "" },
      // The panel says that the proxy took the secret; the class does not depend on the words of the error.
      { ts: BigInt(now() - 300), vantage: "panel", kind: "l2", ok: false, latencyMs: 0, error: "no datacenter answered", l1Ok: true },
      { ts: BigInt(now() - 300), vantage: "node", kind: "l2", ok: true, latencyMs: 20, error: "" },
    ]);
    show(panel);

    const probes = await region(t("insights.probes.title"));
    const uptime = within(await probes.findByRole("table", { name: t("insights.availability.uptime") }));
    expect(uptime.getAllByText(t("insights.probes.uptime", { percent: "50%", ok: "1", total: "2" }))).toHaveLength(2);
    expect(uptime.getAllByText(t("insights.probes.uptime", { percent: "100%", ok: "1", total: "1" }))).toHaveLength(2);
    expect(uptime.getByText(t("insights.availability.uptime7d"))).toBeInTheDocument();
    expect(probes.getByText(t("insights.availability.class.l1"))).toBeInTheDocument();
    expect(probes.getByText(t("insights.availability.last", { when: "5 minutes ago" }))).toBeInTheDocument();
    expect(probes.getAllByText("no datacenter answered").length).toBeGreaterThan(0);
    expect(panel.rpc.probeHistory.mock.calls.map((call) => call[0].range).sort()).toEqual(["24h", "7d"]);
  });

  it("probes now and shows the result with its class", async () => {
    const { panel, user } = open();
    show(panel);

    const probes = await region(t("insights.probes.title"));
    await user.click(probes.getByRole("button", { name: t("insights.probes.probeNow") }));

    expect(await probes.findByText(t("insights.probes.ok", { latency: "120 ms" }))).toBeInTheDocument();
    expect(probes.getAllByText(t("insights.availability.class.ok")).length).toBeGreaterThan(0);
    expect(panel.rpc.probeNow.mock.calls[0]?.[0]).toMatchObject({ proxyId: "proxy-1" });
  });

  it("classes a probe that reached the proxy but no datacenter as L1 only", async () => {
    const { panel, user } = open();
    panel.rpc.probeNow.mockImplementationOnce(() => ({ kind: "l2", ok: false, latencyMs: 0, error: "no datacenter answered through the proxy (L1 ok)", l1Ok: true }));
    show(panel);

    const probes = await region(t("insights.probes.title"));
    await user.click(probes.getByRole("button", { name: t("insights.probes.probeNow") }));

    expect(await probes.findByText(t("insights.probes.failed", { error: "no datacenter answered through the proxy (L1 ok)" }))).toBeInTheDocument();
    expect(probes.getByText(t("insights.availability.class.l1"))).toBeInTheDocument();
  });

  it("shows why the panel did not probe a proxy that is paused", async () => {
    const { panel, user } = open({ enabled: false });
    show(panel);

    const probes = await region(t("insights.probes.title"));
    await user.click(probes.getByRole("button", { name: t("insights.probes.probeNow") }));

    expect(await probes.findByText(t("insights.probes.refused", { reason: PROBE_PAUSED }))).toBeInTheDocument();
  });

  it("checks this proxy: a run of the scope of the proxy", async () => {
    const { panel, user } = open();
    show(panel);

    const check = await region(t("insights.diagnostics.proxyTitle"));
    await user.click(check.getByRole("button", { name: t("insights.diagnostics.runProxy") }));
    await waitFor(() => {
      expect(panel.rpc.startRun.mock.calls[0]?.[0]).toMatchObject({ nodeId: "node-a", scope: "proxy:proxy-1" });
    });
  });

  it("says why a run did not start", async () => {
    const { panel, user } = open();
    panel.rpc.startRun.mockImplementationOnce(() => {
      throw new ConnectError("the node is offline", Code.FailedPrecondition);
    });
    show(panel);

    const check = await region(t("insights.diagnostics.proxyTitle"));
    await user.click(check.getByRole("button", { name: t("insights.diagnostics.runProxy") }));
    expect(await check.findByText(t("insights.diagnostics.startFailed", { reason: "the node is offline" }))).toBeInTheDocument();
  });
});
