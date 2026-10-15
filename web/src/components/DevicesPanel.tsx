import "@mantine/charts/styles.css";

import { AreaChart } from "@mantine/charts";
import { Stack, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { formatNumber } from "../app/format";
import { proxyChart } from "../app/series";
import type { ProxySeriesResponse } from "../gen/postern/panel/v1/proxies_pb";
import { ChartCaption, Figure, StatsCard } from "./StatsCard";

/** The unique client IPs of a proxy: the most of one minute in each period, and the highest of the range. */
export function DevicesPanel({ series }: { series: ProxySeriesResponse }) {
  const { t } = useTranslation();
  const peak = series.points.reduce((most, point) => Math.max(most, point.devices), 0);
  const chart = proxyChart(series);

  return (
    <StatsCard title={t("insights.stats.devices.title")}>
      {series.points.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.stats.devices.empty")}
        </Text>
      ) : (
        <Stack gap="sm">
          <Figure label={t("insights.stats.devices.max")} value={formatNumber(peak)} />
          <Text size="xs" c="dimmed">
            {t("insights.stats.devices.hint")}
          </Text>
          <ChartCaption bucketSeconds={chart.bucketSeconds} thinned={chart.thinned} />
          <AreaChart
            h={180}
            data={chart.points}
            dataKey="time"
            series={[{ name: "devices", label: t("insights.stats.devices.series"), color: "grape.6" }]}
            curveType="step"
            withDots={false}
            tickLine="x"
            valueFormatter={(value) => formatNumber(value)}
            xAxisProps={{ interval: "preserveStartEnd", minTickGap: 48 }}
            areaProps={{ isAnimationActive: false }}
          />
        </Stack>
      )}
    </StatsCard>
  );
}
