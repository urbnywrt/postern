import { Code, ConnectError } from "@connectrpc/connect";
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import i18n from "../i18n";
import { ATTRIBUTION, ATTRIBUTION_URL, NOT_FULL, type IpPolicy } from "../test/fakeInsights";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { IP_PAGE_SIZE } from "./IpHistoryTable";
import { StatsSection } from "./StatsSection";

const now = () => Math.floor(Date.now() / 1000);
const FIELD = { selector: "input, textarea" };
const region = (name: string) => screen.findByRole("region", { name }).then((element) => within(element));

function open({ policy = "countries", enabled = true }: { policy?: IpPolicy; enabled?: boolean } = {}) {
  const panel = createFakePanel({
    signedIn: true,
    ipPolicy: policy,
    nodes: [{ id: "node-a", name: "Frankfurt" }],
    proxies: [{ id: "proxy-1", nodeId: "node-a", name: "Family", enabled }],
  });
  return { panel, user: userEvent.setup() };
}

function show(panel: ReturnType<typeof open>["panel"]) {
  return renderWithProviders(<StatsSection proxyId="proxy-1" />, { transport: panel.transport });
}

function setSeries(panel: ReturnType<typeof open>["panel"], points: { at: number; up: bigint; down: bigint; connsNew: number; connsPeak: number; devices: number }[]) {
  const end = now() - (now() % 60);
  panel.inventory.series.set("proxy-1", {
    stepSeconds: 60,
    fromUnix: BigInt(end - 86_400),
    toUnix: BigInt(end),
    points: points.map(({ at, ...rest }) => ({ tsUnix: BigInt(end - at), ...rest })),
  });
}

const SERIES = [
  { at: 180, up: 1_000_000n, down: 20_000_000n, connsNew: 4, connsPeak: 2, devices: 3 },
  { at: 120, up: 2_000_000n, down: 30_000_000n, connsNew: 6, connsPeak: 7, devices: 5 },
];

describe("StatsSection: traffic, connections and unique IPs", () => {
  it("shows the totals of the range and draws each chart", async () => {
    const { panel } = open();
    setSeries(panel, SERIES);
    show(panel);

    const traffic = await region(t("insights.stats.traffic.title"));
    expect(await traffic.findByText("50 MB")).toBeInTheDocument();
    expect(traffic.getByText("3 MB")).toBeInTheDocument();
    expect(traffic.getByText(t("insights.stats.traffic.down"))).toBeInTheDocument();
    // A day of minutes is 1,440 periods, more than a chart is given: a point is 3 minutes.
    expect(traffic.getByText(t("insights.chart.thinned", { period: "3 minutes" }))).toBeInTheDocument();

    const connections = await region(t("insights.stats.connections.title"));
    expect(connections.getByText("10")).toBeInTheDocument(); // opened: 4 + 6
    expect(connections.getByText("7")).toBeInTheDocument(); // most open at once

    const devices = await region(t("insights.stats.devices.title"));
    expect(devices.getByText("5")).toBeInTheDocument();
    expect(devices.getByText(t("insights.stats.devices.hint"))).toBeInTheDocument();
  });

  it("says that nothing was reported, in each panel", async () => {
    const { panel } = open();
    setSeries(panel, []);
    show(panel);

    expect(await (await region(t("insights.stats.traffic.title"))).findByText(t("insights.stats.traffic.empty"))).toBeInTheDocument();
    expect((await region(t("insights.stats.connections.title"))).getByText(t("insights.stats.connections.empty"))).toBeInTheDocument();
    expect((await region(t("insights.stats.devices.title"))).getByText(t("insights.stats.devices.empty"))).toBeInTheDocument();
  });

  it("asks for the series and the countries again when the range changes", async () => {
    const { panel, user } = open();
    show(panel);
    await region(t("insights.stats.traffic.title"));
    expect(panel.rpc.proxySeries.mock.calls.at(-1)?.[0]).toMatchObject({ proxyId: "proxy-1", range: "24h" });

    await user.click(screen.getByRole("radio", { name: t("insights.ranges.7d") }));

    await waitFor(() => {
      expect(panel.rpc.proxySeries.mock.calls.at(-1)?.[0]).toMatchObject({ proxyId: "proxy-1", range: "7d" });
    });
    await waitFor(() => {
      expect(panel.rpc.countries.mock.calls.at(-1)?.[0]).toMatchObject({ proxyId: "proxy-1", range: "7d" });
    });
  });

  it("says why when the panel cannot give the series", async () => {
    const { panel } = open();
    panel.rpc.proxySeries.mockImplementation(() => {
      throw new Error("boom");
    });
    show(panel);
    expect(await screen.findByText(t("errors.loadTitle"))).toBeInTheDocument();
  });
});

describe("StatsSection: countries", () => {
  const COUNTRIES = [
    { country: "DE", bytes: 5_000_000n, ipsPeak: 4 },
    { country: "", bytes: 1_000_000n, ipsPeak: 1 },
  ];

  it("names the countries in English, with their bytes, peak unique IPs and the DB-IP attribution", async () => {
    const { panel } = open();
    panel.insights.countries.set("proxy-1", COUNTRIES);
    show(panel);

    const countries = await region(t("insights.countries.title"));
    const table = within(await countries.findByRole("table"));
    expect(table.getByRole("columnheader", { name: t("insights.countries.ipsPeak") })).toBeInTheDocument();
    const germany = table.getByRole("row", { name: /Germany/ });
    expect(within(germany).getByText("5 MB")).toBeInTheDocument();
    expect(within(germany).getByText("4")).toBeInTheDocument();
    expect(table.getByRole("row", { name: new RegExp(t("insights.countries.unknown")) })).toBeInTheDocument();

    const link = countries.getByRole("link", { name: ATTRIBUTION });
    expect(link).toHaveAttribute("href", ATTRIBUTION_URL);
  });

  it("names the countries in Russian on a Russian page", async () => {
    await act(() => i18n.changeLanguage("ru"));
    const { panel } = open();
    panel.insights.countries.set("proxy-1", COUNTRIES);
    show(panel);

    const countries = await region(i18n.t("insights.countries.title"));
    const table = within(await countries.findByRole("table"));
    expect(table.getByRole("row", { name: /Германия/ })).toBeInTheDocument();
    expect(table.getByRole("row", { name: /Неизвестно/ })).toBeInTheDocument();
  });

  it("says that no country was recorded, with the attribution still there", async () => {
    const { panel } = open();
    show(panel);

    const countries = await region(t("insights.countries.title"));
    expect(await countries.findByText(t("insights.countries.empty"))).toBeInTheDocument();
    expect(countries.getByRole("link", { name: ATTRIBUTION })).toBeInTheDocument();
  });

  it("says that the policy keeps no countries under \"off\"", async () => {
    const { panel } = open({ policy: "off" });
    show(panel);

    const countries = await region(t("insights.countries.title"));
    expect(await countries.findByText(t("insights.countries.off"))).toBeInTheDocument();
  });
});

describe("StatsSection: IP history", () => {
  const sightings = (count: number) =>
    Array.from({ length: count }, (_, i) => ({
      ip: `198.51.100.${String(i + 1)}`,
      country: i % 2 === 0 ? "DE" : "NL",
      firstSeenUnix: BigInt(now() - 7200),
      lastSeenUnix: BigInt(now() - 60),
      bytes: 1_000_000n,
    }));

  it("is not asked for under another policy, and a note names the policy", async () => {
    const { panel } = open({ policy: "countries" });
    show(panel);

    const history = await region(t("insights.ipHistory.title"));
    expect(
      await history.findByText(
        t("insights.ipHistory.policyNote", { policy: "countries", meaning: t("insights.ipHistory.meaning.countries") }),
      ),
    ).toBeInTheDocument();
    expect(panel.rpc.listIpSightings).not.toHaveBeenCalled();
  });

  it("shows a page of addresses under \"full\", and the next page on request", async () => {
    const { panel, user } = open({ policy: "full" });
    panel.insights.sightings.set("proxy-1", sightings(60));
    show(panel);

    const history = await region(t("insights.ipHistory.title"));
    expect(await history.findByText("198.51.100.1")).toBeInTheDocument();
    expect(history.getByRole("columnheader", { name: t("insights.ipHistory.bytes") })).toBeInTheDocument();
    expect(history.queryByText("198.51.100.51")).not.toBeInTheDocument();
    expect(history.getByText(t("insights.ipHistory.shown", { from: "1", to: "50", total: "60" }))).toBeInTheDocument();

    await user.click(history.getByRole("button", { name: "2" }));

    expect(await history.findByText("198.51.100.51")).toBeInTheDocument();
    expect(panel.rpc.listIpSightings.mock.calls.at(-1)?.[0]).toMatchObject({ offset: IP_PAGE_SIZE, limit: IP_PAGE_SIZE });
  });

  it("narrows the list to a country, from the first page", async () => {
    const { panel, user } = open({ policy: "full" });
    panel.insights.sightings.set("proxy-1", sightings(60));
    panel.insights.countries.set("proxy-1", [
      { country: "DE", bytes: 30n, ipsPeak: 3 },
      { country: "NL", bytes: 20n, ipsPeak: 2 },
    ]);
    show(panel);

    const history = await region(t("insights.ipHistory.title"));
    await history.findByText("198.51.100.1");
    await user.click(history.getByRole("button", { name: "2" }));
    await history.findByText("198.51.100.51");

    await user.click(history.getByLabelText(t("insights.ipHistory.filter"), FIELD));
    await user.click(await screen.findByRole("option", { name: "Netherlands" }));

    expect(await history.findByText("198.51.100.2")).toBeInTheDocument();
    expect(history.queryByText("198.51.100.1")).not.toBeInTheDocument();
    expect(panel.rpc.listIpSightings.mock.calls.at(-1)?.[0]).toMatchObject({ country: "NL", offset: 0 });
  });

  it("offers every country of the year in its filter, not only those of the range", async () => {
    const { panel, user } = open({ policy: "full" });
    panel.insights.sightings.set("proxy-1", sightings(4));
    panel.insights.countries.set("proxy-1", [{ country: "DE", bytes: 30n, ipsPeak: 3 }]);
    const countries = panel.rpc.countries.getMockImplementation();
    if (countries === undefined) throw new Error("no countries");
    // Over the year the proxy had clients in the Netherlands too; the 24 hours of the range had none.
    panel.rpc.countries.mockImplementation(async (req) => {
      const answer = await countries(req);
      return req.range === "1y" ? { ...answer, countries: [...answer.countries, { country: "NL", bytes: 5n, ipsPeak: 1 }] } : answer;
    });
    show(panel);

    const history = await region(t("insights.ipHistory.title"));
    await history.findByText("198.51.100.1");
    await user.click(history.getByLabelText(t("insights.ipHistory.filter"), FIELD));
    expect(await screen.findByRole("option", { name: "Netherlands" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Germany" })).toBeInTheDocument();
  });

  it("says that the policy changed when the panel refuses the history (FAILED_PRECONDITION)", async () => {
    const { panel } = open({ policy: "full" });
    // The countries said "full", and the policy changed before the history was asked for.
    panel.rpc.listIpSightings.mockImplementation(() => {
      throw new ConnectError(NOT_FULL, Code.FailedPrecondition);
    });
    show(panel);

    const history = await region(t("insights.ipHistory.title"));
    expect(await history.findByText(t("insights.ipHistory.policyChanged", { reason: NOT_FULL }))).toBeInTheDocument();
    expect(history.queryByRole("table")).not.toBeInTheDocument();
  });
});
