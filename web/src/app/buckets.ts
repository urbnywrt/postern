import { formatTick } from "./format";

/**
 * How the periods that one point of a chart stands for are taken together when
 * there are too many to draw: bytes and counts of things that happened are
 * summed (nothing is lost from a total), the highest of the periods is kept for
 * a peak (a spike stays visible), and a level such as the CPU is averaged over
 * the periods that have statistics.
 */
export type Aggregate = "sum" | "max" | "avg";

export interface Frame {
  fromUnix: bigint;
  toUnix: bigint;
  stepSeconds: number;
}

export type BucketPoint<K extends string> = { ts: number; time: string } & Record<K, number | null>;

export interface Bucketed<K extends string> {
  points: BucketPoint<K>[];
  /** The length of the period of a point, in seconds: the step of the series, or a multiple of it when thinned. */
  bucketSeconds: number;
  /** Whether a point stands for more than one period of the series. */
  thinned: boolean;
}

/** What a chart is given at most: a year of hours is 8,760 points, more than a chart is wide in pixels. */
export const MAX_CHART_POINTS = 500;

/**
 * The points of a series as the points of a chart. The panel leaves out a period
 * without statistics; a chart that joined its neighbours would show what did not
 * happen, so every period of the range gets a point: zero for traffic (none was
 * reported), or empty (`gaps: "null"`) for a level such as the CPU, which was
 * not measured. A range of more than `maxPoints` periods is thinned: a point
 * then stands for a whole number of periods, taken together as `aggregates` says.
 */
export function bucketSeries<K extends string>(
  rows: readonly ({ tsUnix: bigint } & Record<NoInfer<K>, number>)[],
  frame: Frame,
  aggregates: Record<K, Aggregate>,
  { maxPoints = MAX_CHART_POINTS, gaps = "zero" }: { maxPoints?: number; gaps?: "zero" | "null" } = {},
): Bucketed<K> {
  const keys = Object.keys(aggregates) as K[];
  const step = frame.stepSeconds;
  const from = Number(frame.fromUnix);
  const to = Number(frame.toUnix);
  const span = to - from;

  if (step <= 0 || to <= from) {
    const sorted = [...rows].sort((a, b) => Number(a.tsUnix - b.tsUnix));
    return {
      points: sorted.map((row) => {
        const ts = Number(row.tsUnix);
        const point = { ts: ts * 1000, time: formatTick(ts, 0, step) } as BucketPoint<K>;
        for (const key of keys) {
          (point as Record<K, number | null>)[key] = row[key];
        }
        return point;
      }),
      bucketSeconds: step,
      thinned: false,
    };
  }

  // The periods start on multiples of their length, and the first one that starts inside the range is the first point.
  const first = Math.ceil(from / step) * step;
  const periods = Math.max(0, Math.ceil((to - first) / step));
  const factor = Math.max(1, Math.ceil(periods / Math.max(1, maxPoints)));
  const bucket = step * factor;
  const count = Math.ceil(periods / factor);

  const columns = keys.map((key) => ({ key, aggregate: aggregates[key], values: new Array<number>(count).fill(0) }));
  const counts = new Array<number>(count).fill(0);
  for (const row of rows) {
    const ts = Number(row.tsUnix);
    if (ts < first || ts >= to) {
      continue;
    }
    const at = Math.floor((ts - first) / bucket);
    if (at >= count) {
      continue;
    }
    counts[at] = (counts[at] ?? 0) + 1;
    for (const column of columns) {
      const value = row[column.key];
      const held = column.values[at] ?? 0;
      column.values[at] = column.aggregate === "max" ? Math.max(held, value) : held + value;
    }
  }

  const points: BucketPoint<K>[] = [];
  for (let at = 0; at < count; at++) {
    const start = first + at * bucket;
    const point = { ts: start * 1000, time: formatTick(start, span, bucket) } as BucketPoint<K>;
    const seen = counts[at] ?? 0;
    for (const column of columns) {
      const value = column.values[at] ?? 0;
      (point as Record<K, number | null>)[column.key] =
        seen === 0 ? (gaps === "null" ? null : 0) : column.aggregate === "avg" ? value / seen : value;
    }
    points.push(point);
  }
  return { points, bucketSeconds: bucket, thinned: factor > 1 };
}
