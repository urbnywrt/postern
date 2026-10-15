import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { localMidnightUnix } from "../app/midnight";
import { ATTRIBUTION, ATTRIBUTION_URL } from "../test/fakeInsights";
import { createFakePanel, type FakePanelOptions } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

const tile = (name: string) => screen.findByRole("article", { name }).then((element) => within(element));
const region = (name: string) => screen.findByRole("region", { name }).then((element) => within(element));

function open(options: Omit<FakePanelOptions, "signedIn"> = {}) {
  const panel = createFakePanel({
    signedIn: true,
    nodes: [
      { id: "node-a", name: "Frankfurt" },
      { id: "node-b", name: "Helsinki" },
    ],
    proxies: [
      { id: "proxy-1", nodeId: "node-a", name: "Family" },
      { id: "proxy-2", nodeId: "node-b", name: "Work" },
    ],
    ...options,
  });
  return panel;
}

describe("Overview: the tiles of the nodes", () => {
  it("shows CPU, RAM, connections and the traffic since local midnight", async () => {
    const panel = open();
    panel.insights.overview.set("node-a", {
      minuteUnix: BigInt(Math.floor(Date.now() / 1000) - 60),
      cpu: 25,
      memUsed: 1_000_000_000n,
      memTotal: 4_000_000_000n,
      conns: 12,
      up: 3_000_000n,
      down: 50_000_000n,
    });
    renderApp({ route: "/", transport: panel.transport });

    const frankfurt = await tile("Frankfurt");
    expect(await frankfurt.findByText("25%")).toBeInTheDocument();
    expect(frankfurt.getByText("1 GB / 4 GB")).toBeInTheDocument();
    expect(frankfurt.getByText("12")).toBeInTheDocument();
    expect(frankfurt.getByText(t("insights.overview.trafficValue", { down: "50 MB", up: "3 MB" }))).toBeInTheDocument();
    // The day starts at the midnight of the browser, which the panel cannot know.
    expect(panel.rpc.overview.mock.calls[0]?.[0].sinceUnix).toBe(BigInt(localMidnightUnix(new Date())));
  });

  it("says that a node reported no minute lately, and still shows its traffic", async () => {
    const panel = open();
    panel.insights.overview.set("node-b", { minuteUnix: 0n, up: 0n, down: 2_000n });
    renderApp({ route: "/", transport: panel.transport });

    const helsinki = await tile("Helsinki");
    expect(await helsinki.findByText(t("insights.overview.noMinute"))).toBeInTheDocument();
    expect(helsinki.getByText(t("insights.overview.trafficValue", { down: "2 kB", up: "0 byte" }))).toBeInTheDocument();
  });
});

describe("Overview: the cards", () => {
  it("lists the busiest proxies of the last 24 hours, with their nodes", async () => {
    const panel = open();
    panel.insights.top = [
      { proxyId: "proxy-2", name: "Work", nodeId: "node-b", up: 1_000_000n, down: 9_000_000n, connsNew: 40n, devicesPeak: 6 },
      { proxyId: "proxy-1", name: "Family", nodeId: "node-a", up: 0n, down: 1_000n, connsNew: 2n, devicesPeak: 1 },
    ];
    renderApp({ route: "/", transport: panel.transport });

    const card = await region(t("insights.overview.topProxies.title"));
    const [, busiest] = await card.findAllByRole("row");
    if (busiest === undefined) throw new Error("no rows");
    const first = within(busiest);
    expect(first.getByRole("link", { name: "Work" })).toHaveAttribute("href", "/proxies/proxy-2");
    expect(first.getByText("Helsinki")).toBeInTheDocument();
    expect(first.getByText("40")).toBeInTheDocument();
    expect(panel.rpc.topProxies.mock.calls[0]?.[0]).toMatchObject({ nodeId: "", range: "24h" });
  });

  it("says when no proxy carried anything", async () => {
    const panel = open();
    panel.insights.top = [];
    renderApp({ route: "/", transport: panel.transport });

    const card = await region(t("insights.overview.topProxies.title"));
    expect(await card.findByText(t("insights.overview.topProxies.empty"))).toBeInTheDocument();
  });

  it("lists the countries of the last 24 hours of every proxy, with the DB-IP attribution", async () => {
    const panel = open();
    panel.insights.countries.set("", [
      { country: "NL", bytes: 7_000_000n, ipsPeak: 3 },
      { country: "", bytes: 1_000n, ipsPeak: 1 },
    ]);
    renderApp({ route: "/", transport: panel.transport });

    const card = await region(t("insights.overview.countries.title"));
    expect(await card.findByRole("row", { name: /Netherlands/ })).toBeInTheDocument();
    expect(card.getByRole("row", { name: new RegExp(t("insights.countries.unknown")) })).toBeInTheDocument();
    expect(card.getByRole("link", { name: ATTRIBUTION })).toHaveAttribute("href", ATTRIBUTION_URL);
    expect(panel.rpc.countries.mock.calls[0]?.[0]).toMatchObject({ proxyId: "", nodeId: "", range: "24h" });
  });

  it("says that nothing about countries is kept under the policy off", async () => {
    const panel = open({ ipPolicy: "off" });
    renderApp({ route: "/", transport: panel.transport });

    const card = await region(t("insights.overview.countries.title"));
    expect(await card.findByText(t("insights.countries.off"))).toBeInTheDocument();
  });
});
