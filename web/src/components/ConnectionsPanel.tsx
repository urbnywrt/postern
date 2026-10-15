import "@mantine/charts/styles.css";

import { LineChart } from "@mantine/charts";
import { Group, Stack, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { formatNumber } from "../app/format";
import { proxyChart } from "../app/series";
import type { ProxySeriesResponse } from "../gen/postern/panel/v1/proxies_pb";
import { ChartCaption, Figure, StatsCard } from "./StatsCard";

/** The connections of a proxy over the range: opened in each period, and the most that were open at once. */
export function ConnectionsPanel({ series }: { series: ProxySeriesResponse }) {
  const { t } = useTranslation();
  let opened = 0;
  let peak = 0;
  for (const point of series.points) {
    opened += point.connsNew;
    peak = Math.max(peak, point.connsPeak);
  }
  const chart = proxyChart(series);

  return (
    <StatsCard title={t("insights.stats.connections.title")}>
      {series.points.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.stats.connections.empty")}
        </Text>
      ) : (
        <Stack gap="sm">
          <Group gap="xl" wrap="wrap">
            <Figure label={t("insights.stats.connections.totalNew")} value={formatNumber(opened)} />
            <Figure label={t("insights.stats.connections.maxPeak")} value={formatNumber(peak)} />
          </Group>
          <ChartCaption bucketSeconds={chart.bucketSeconds} thinned={chart.thinned} />
          <LineChart
            h={200}
            data={chart.points}
            dataKey="time"
            series={[
              { name: "connsNew", label: t("insights.stats.connections.new"), color: "blue.6" },
              { name: "connsPeak", label: t("insights.stats.connections.peak"), color: "orange.6" },
            ]}
            curveType="linear"
            withDots={false}
            withLegend
            tickLine="x"
            valueFormatter={(value) => formatNumber(value)}
            xAxisProps={{ interval: "preserveStartEnd", minTickGap: 48 }}
            lineProps={{ isAnimationActive: false }}
          />
        </Stack>
      )}
    </StatsCard>
  );
}
