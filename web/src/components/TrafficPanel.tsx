import "@mantine/charts/styles.css";

import { AreaChart } from "@mantine/charts";
import { Group, Stack, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { formatBytes } from "../app/format";
import { proxyChart } from "../app/series";
import type { ProxySeriesResponse } from "../gen/postern/panel/v1/proxies_pb";
import { ChartCaption, Figure, StatsCard } from "./StatsCard";

/** What a proxy sent and received over the range: the totals, exact, and a chart of down and up. */
export function TrafficPanel({ series }: { series: ProxySeriesResponse }) {
  const { t } = useTranslation();
  let totalUp = 0n;
  let totalDown = 0n;
  for (const point of series.points) {
    totalUp += point.up;
    totalDown += point.down;
  }
  const chart = proxyChart(series);

  return (
    <StatsCard title={t("insights.stats.traffic.title")}>
      {series.points.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.stats.traffic.empty")}
        </Text>
      ) : (
        <Stack gap="sm">
          <Group gap="xl" wrap="wrap">
            <Figure label={t("insights.stats.traffic.totalDown")} value={formatBytes(totalDown)} />
            <Figure label={t("insights.stats.traffic.totalUp")} value={formatBytes(totalUp)} />
          </Group>
          <ChartCaption bucketSeconds={chart.bucketSeconds} thinned={chart.thinned} />
          <AreaChart
            h={240}
            data={chart.points}
            dataKey="time"
            series={[
              { name: "down", label: t("insights.stats.traffic.down"), color: "indigo.6" },
              { name: "up", label: t("insights.stats.traffic.up"), color: "teal.6" },
            ]}
            curveType="monotone"
            withDots={false}
            withLegend
            tickLine="x"
            valueFormatter={(value) => formatBytes(value)}
            yAxisProps={{ width: 80 }}
            xAxisProps={{ interval: "preserveStartEnd", minTickGap: 48 }}
            areaProps={{ isAnimationActive: false }}
          />
        </Stack>
      )}
    </StatsCard>
  );
}
