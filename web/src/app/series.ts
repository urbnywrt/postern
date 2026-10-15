import type { ProxySeriesResponse } from "../gen/postern/panel/v1/proxies_pb";
import { bucketSeries } from "./buckets";

/**
 * The series of a proxy as the points of its charts, thinned to what a chart can
 * show (see bucketSeries): bytes and new connections are summed over a point, the
 * peaks are the highest of its periods. Gaps are zeros: nothing was reported.
 */
export function proxyChart(series: ProxySeriesResponse) {
  return bucketSeries(
    series.points.map((point) => ({
      tsUnix: point.tsUnix,
      up: Number(point.up),
      down: Number(point.down),
      connsNew: point.connsNew,
      connsPeak: point.connsPeak,
      devices: point.devices,
    })),
    series,
    { up: "sum", down: "sum", connsNew: "sum", connsPeak: "max", devices: "max" },
  );
}
