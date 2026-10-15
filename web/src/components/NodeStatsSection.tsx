import "@mantine/charts/styles.css";

import { AreaChart, BarChart, LineChart } from "@mantine/charts";
import { Group, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useNodeSeries } from "../api/hooks/metrics";
import { type BucketPoint, bucketSeries } from "../app/buckets";
import { formatBytes, formatNumber, formatPercent } from "../app/format";
import { DEFAULT_RANGE, type StatsRange } from "../app/ranges";
import type { NodeSeriesResponse } from "../gen/postern/panel/v1/metrics_pb";
import { QueryView } from "./QueryView";
import { RangeSelect } from "./RangeSelect";
import { ChartCaption, StatsCard } from "./StatsCard";

/**
 * How the minutes of a node are taken together on a thinned chart: levels
 * (CPU, memory, load, disk) are averaged, sizes and open connections keep their
 * highest, bytes and refusals are summed, as the panel does for hours and days.
 */
const NODE_AGGREGATES = {
  cpu: "avg",
  memUsed: "avg",
  memTotal: "max",
  load1: "avg",
  diskUsed: "avg",
  diskTotal: "max",
  netRx: "sum",
  netTx: "sum",
  conns: "max",
  refusedPrehello: "sum",
  refusedTotal: "sum",
  evictedPrehello: "sum",
  up: "sum",
  down: "sum",
  devicesSum: "max",
} as const;

type NodeKey = keyof typeof NODE_AGGREGATES;

/** The points of the charts of a node. A period without statistics stays empty: the node did not measure it. */
function nodeChart(series: NodeSeriesResponse) {
  return bucketSeries(
    series.points.map((point) => ({
      tsUnix: point.tsUnix,
      cpu: point.cpu,
      memUsed: Number(point.memUsed),
      memTotal: Number(point.memTotal),
      load1: point.load1,
      diskUsed: Number(point.diskUsed),
      diskTotal: Number(point.diskTotal),
      netRx: Number(point.netRx),
      netTx: Number(point.netTx),
      conns: point.conns,
      refusedPrehello: Number(point.refusedPrehello),
      refusedTotal: Number(point.refusedTotal),
      evictedPrehello: Number(point.evictedPrehello),
      up: Number(point.up),
      down: Number(point.down),
      devicesSum: point.devicesSum,
    })),
    series,
    NODE_AGGREGATES,
    { gaps: "null" },
  );
}

/**
 * The statistics of a node over a range: CPU, memory, load, disk, network, open
 * connections, the traffic and the unique IPs of its proxies, and the refusals of
 * its edge when it refused anything. It draws charts, so the page of a node loads
 * it on demand. `compact` is for the overview of the node: only the traffic of its
 * proxies over the default range (24 h), without the choice of a range.
 */
export function NodeStatsSection({ nodeId, compact = false }: { nodeId: string; compact?: boolean }) {
  const { t } = useTranslation();
  const titleId = useId();
  const [range, setRange] = useState<StatsRange>(DEFAULT_RANGE);
  const series = useNodeSeries(nodeId, range);

  return (
    <Stack component="section" aria-labelledby={titleId} gap="md">
      <Group justify="space-between" align="center" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("insights.node.title")}
        </Title>
        {compact ? null : <RangeSelect value={range} onChange={setRange} />}
      </Group>
      <QueryView query={series}>{(data) => <NodeCharts series={data} compact={compact} />}</QueryView>
    </Stack>
  );
}

interface ChartSpec {
  title: string;
  kind: "line" | "area" | "bar";
  series: { name: NodeKey; label: string; color: string }[];
  format: (value: number) => string;
}

function NodeCharts({ series, compact }: { series: NodeSeriesResponse; compact: boolean }) {
  const { t } = useTranslation();
  if (series.points.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        {t("insights.node.empty")}
      </Text>
    );
  }
  const chart = nodeChart(series);
  const refused = series.points.some(
    (point) => point.refusedPrehello > 0n || point.refusedTotal > 0n || point.evictedPrehello > 0n,
  );
  const bytes = (value: number) => formatBytes(value);
  const all: ChartSpec[] = [
    { title: t("insights.node.cpu"), kind: "line", series: [{ name: "cpu", label: t("insights.node.cpuSeries"), color: "blue.6" }], format: (v) => formatPercent(v / 100) },
    {
      title: t("insights.node.memory"),
      kind: "line",
      series: [
        { name: "memUsed", label: t("insights.node.memUsed"), color: "violet.6" },
        { name: "memTotal", label: t("insights.node.memTotal"), color: "gray.5" },
      ],
      format: bytes,
    },
    { title: t("insights.node.load"), kind: "line", series: [{ name: "load1", label: t("insights.node.load1"), color: "orange.6" }], format: (v) => formatNumber(Math.round(v * 100) / 100) },
    {
      title: t("insights.node.disk"),
      kind: "line",
      series: [
        { name: "diskUsed", label: t("insights.node.diskUsed"), color: "cyan.6" },
        { name: "diskTotal", label: t("insights.node.diskTotal"), color: "gray.5" },
      ],
      format: bytes,
    },
    {
      title: t("insights.node.network"),
      kind: "area",
      series: [
        { name: "netRx", label: t("insights.node.rx"), color: "indigo.6" },
        { name: "netTx", label: t("insights.node.tx"), color: "teal.6" },
      ],
      format: bytes,
    },
    { title: t("insights.node.connections"), kind: "line", series: [{ name: "conns", label: t("insights.node.conns"), color: "blue.6" }], format: (v) => formatNumber(v) },
    {
      title: t("insights.node.traffic"),
      kind: "area",
      series: [
        { name: "down", label: t("insights.node.down"), color: "indigo.6" },
        { name: "up", label: t("insights.node.up"), color: "teal.6" },
      ],
      format: bytes,
    },
    { title: t("insights.node.devices"), kind: "line", series: [{ name: "devicesSum", label: t("insights.node.devices"), color: "grape.6" }], format: (v) => formatNumber(v) },
  ];
  const traffic = t("insights.node.traffic");
  const specs = compact ? all.filter((spec) => spec.title === traffic) : all;
  if (refused && !compact) {
    specs.push({
      title: t("insights.node.refusals"),
      kind: "bar",
      series: [
        { name: "refusedPrehello", label: t("insights.node.refusedPrehello"), color: "orange.6" },
        { name: "refusedTotal", label: t("insights.node.refusedTotal"), color: "red.6" },
        { name: "evictedPrehello", label: t("insights.node.evictedPrehello"), color: "yellow.6" },
      ],
      format: (v) => formatNumber(v),
    });
  }

  return (
    <Stack gap="md">
      <ChartCaption bucketSeconds={chart.bucketSeconds} thinned={chart.thinned} />
      <SimpleGrid cols={compact ? 1 : { base: 1, md: 2 }} spacing="md">
        {specs.map((spec) => (
          <StatsCard key={spec.title} title={spec.title}>
            <NodeChart spec={spec} data={chart.points} />
          </StatsCard>
        ))}
      </SimpleGrid>
    </Stack>
  );
}

function NodeChart({ spec, data }: { spec: ChartSpec; data: BucketPoint<NodeKey>[] }) {
  const common = {
    h: 180,
    data,
    dataKey: "time",
    series: spec.series,
    withLegend: spec.series.length > 1,
    tickLine: "x" as const,
    valueFormatter: spec.format,
    yAxisProps: { width: 72 },
    xAxisProps: { interval: "preserveStartEnd" as const, minTickGap: 48 },
  };
  if (spec.kind === "bar") {
    return <BarChart {...common} barProps={{ isAnimationActive: false }} />;
  }
  if (spec.kind === "area") {
    return <AreaChart {...common} withDots={false} connectNulls={false} areaProps={{ isAnimationActive: false }} />;
  }
  return <LineChart {...common} withDots={false} connectNulls={false} lineProps={{ isAnimationActive: false }} />;
}
