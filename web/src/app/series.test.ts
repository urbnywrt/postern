import { create } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";

import { ProxySeriesResponseSchema } from "../gen/postern/panel/v1/proxies_pb";
import { proxyChart } from "./series";

describe("proxyChart", () => {
  it("has a point for every period, sums the bytes and keeps the peaks of a thinned series", () => {
    const from = 1_800_000_000; // a minute boundary
    const minutes = 7 * 24 * 60; // a week of minutes, more than a chart is given
    const points = Array.from({ length: minutes }, (_, i) => ({
      tsUnix: BigInt(from + i * 60),
      up: 10n,
      down: 100n,
      connsNew: 1,
      connsPeak: i === 7000 ? 50 : 2,
      devices: i === 9000 ? 9 : 1,
    }));
    const chart = proxyChart(
      create(ProxySeriesResponseSchema, { stepSeconds: 60, fromUnix: BigInt(from), toUnix: BigInt(from + minutes * 60), points }),
    );

    expect(chart.thinned).toBe(true);
    expect(chart.points.length).toBeLessThanOrEqual(500);
    const sum = (key: "up" | "down" | "connsNew") => chart.points.reduce((total, p) => total + (p[key] ?? 0), 0);
    expect(sum("down")).toBe(minutes * 100);
    expect(sum("up")).toBe(minutes * 10);
    expect(sum("connsNew")).toBe(minutes);
    expect(Math.max(...chart.points.map((p) => p.connsPeak ?? 0))).toBe(50);
    expect(Math.max(...chart.points.map((p) => p.devices ?? 0))).toBe(9);
  });
});
