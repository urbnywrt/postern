import { describe, expect, it } from "vitest";

import { bucketSeries } from "./buckets";

const T0 = 1_800_003_600; // a multiple of 3600, so an hour boundary
const frame = (from: number, to: number, stepSeconds: number) => ({
  fromUnix: BigInt(from),
  toUnix: BigInt(to),
  stepSeconds,
});
const row = (ts: number, bytes: number, peak: number, cpu: number) => ({ tsUnix: BigInt(ts), bytes, peak, cpu });
const AGG = { bytes: "sum", peak: "max", cpu: "avg" } as const;

describe("bucketSeries", () => {
  it("has a point for every period of the range, with zeros for the periods without statistics", () => {
    const { points, bucketSeconds, thinned } = bucketSeries(
      [row(T0 + 60, 10, 1, 5), row(T0 + 240, 20, 2, 7)],
      frame(T0, T0 + 300, 60),
      AGG,
    );

    expect(points.map((p) => p.ts)).toEqual([0, 60, 120, 180, 240].map((s) => (T0 + s) * 1000));
    expect(points.map((p) => p.bytes)).toEqual([0, 10, 0, 0, 20]);
    expect(points.map((p) => p.peak)).toEqual([0, 1, 0, 0, 2]);
    expect(bucketSeconds).toBe(60);
    expect(thinned).toBe(false);
  });

  it("leaves the gaps empty when asked, so that a line does not show a load that nobody measured", () => {
    const { points } = bucketSeries([row(T0 + 60, 10, 1, 5)], frame(T0, T0 + 180, 60), AGG, { gaps: "null" });

    expect(points.map((p) => p.cpu)).toEqual([null, 5, null]);
    expect(points.map((p) => p.bytes)).toEqual([null, 10, null]);
  });

  it("thins a year of hours to at most the points asked for: sums are summed, peaks kept, averages averaged", () => {
    const hours = 8760;
    const rows = Array.from({ length: hours }, (_, i) => row(T0 + i * 3600, 1000, i === 5000 ? 99 : 1, i % 2 === 0 ? 10 : 20));
    const { points, bucketSeconds, thinned } = bucketSeries(rows, frame(T0, T0 + hours * 3600, 3600), AGG, {
      maxPoints: 500,
    });

    expect(thinned).toBe(true);
    expect(points.length).toBeLessThanOrEqual(500);
    // 8760 / 500 rounds up to 18 hours a point.
    expect(bucketSeconds).toBe(18 * 3600);
    // Nothing is lost from a sum, and the highest of the minutes stays the highest.
    expect(points.reduce((total, p) => total + (p.bytes ?? 0), 0)).toBe(hours * 1000);
    expect(Math.max(...points.map((p) => p.peak ?? 0))).toBe(99);
    // The average of 10 and 20, nine times each.
    expect(points[0]?.cpu).toBe(15);
    // The points start on the boundaries of the thinned periods.
    expect(points[1]?.ts).toBe((T0 + 18 * 3600) * 1000);
  });

  it("averages over the periods that have statistics, not over the gaps", () => {
    const { points } = bucketSeries([row(T0, 0, 0, 40)], frame(T0, T0 + 4 * 60, 60), AGG, { maxPoints: 1 });

    expect(points).toHaveLength(1);
    expect(points[0]?.cpu).toBe(40);
  });

  it("leaves out what is outside the range", () => {
    const { points } = bucketSeries(
      [row(T0 - 60, 5, 5, 5), row(T0, 1, 1, 1), row(T0 + 120, 7, 7, 7)],
      frame(T0, T0 + 120, 60),
      AGG,
    );

    expect(points.map((p) => p.bytes)).toEqual([1, 0]);
  });

  it("shows the points as they are when the range makes no sense", () => {
    const { points } = bucketSeries([row(T0 + 60, 2, 2, 2), row(T0, 1, 1, 1)], frame(T0, T0, 0), AGG);

    expect(points.map((p) => p.bytes)).toEqual([1, 2]);
  });
});
