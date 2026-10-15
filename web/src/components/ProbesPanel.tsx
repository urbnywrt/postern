import { LineChart } from "@mantine/charts";
import { Alert, Badge, Button, Group, SegmentedControl, Stack, Table, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useProbeHistory, useProbeNow } from "../api/hooks/probes";
import { type ProbeClass, probeClass } from "../app/diagnostics";
import { formatClock, formatDateTime, formatMilliseconds, formatNumber, formatPercent, formatRelative } from "../app/format";
import type { ProbeHistoryResponse, ProbePoint } from "../gen/postern/panel/v1/probes_pb";
import { QueryView } from "./QueryView";
import { StatsCard } from "./StatsCard";

/** The failures listed, the newest first. */
const FAILURES_SHOWN = 10;

const VANTAGE_LABEL = { panel: "insights.probes.vantage.panel", node: "insights.probes.vantage.node" } as const;
const CLASS_COLORS: Record<ProbeClass, string> = { ok: "teal", l1: "yellow", failed: "red" };
const VANTAGE_COLORS: Record<string, string> = { panel: "blue.6", node: "grape.6" };

type ProbeRange = "24h" | "7d";

/**
 * The probes of a proxy: the last one from the panel and its class (through to
 * a datacenter, only to the proxy, or not at all), the uptime from the panel and
 * from the node over 24 hours and 7 days, the latency, the latest failures, and a
 * probe from the panel on request. When the panel refuses to probe (a paused
 * proxy, an offline node, a WEB proxy, a probe asked for less than 5 seconds
 * ago) its reason is shown here. It draws a chart, so it is only on the page of a
 * proxy, which is loaded on demand.
 */
export function ProbesPanel({ proxyId }: { proxyId: string }) {
  const { t } = useTranslation();
  const [range, setRange] = useState<ProbeRange>("24h");
  const day = useProbeHistory(proxyId, "24h");
  const week = useProbeHistory(proxyId, "7d");
  const shown = range === "24h" ? day : week;
  const probe = useProbeNow();
  const result = probe.data;

  return (
    <StatsCard
      title={t("insights.probes.title")}
      aside={
        <Button
          size="xs"
          variant="light"
          loading={probe.isPending}
          onClick={() => {
            probe.mutate(proxyId);
          }}
        >
          {t("insights.probes.probeNow")}
        </Button>
      }
    >
      <Stack gap="sm">
        <Text size="sm" c="dimmed">
          {t("insights.probes.intro")}
        </Text>
        {probe.isError ? (
          <Alert color="orange" role="status">
            {t("insights.probes.refused", { reason: errorMessage(probe.error) })}
          </Alert>
        ) : null}
        {result !== undefined ? (
          <Alert color={CLASS_COLORS[probeClass(result)]} role="status">
            <Stack gap={4}>
              <ClassBadge value={probeClass(result)} />
              <Text size="sm">
                {result.ok
                  ? t("insights.probes.ok", { latency: formatMilliseconds(result.latencyMs) })
                  : t("insights.probes.failed", { error: result.error })}
              </Text>
            </Stack>
          </Alert>
        ) : day.data !== undefined ? (
          <LastProbe points={day.data.points} />
        ) : null}
        <Uptimes day={day.data} week={week.data} />
        <SegmentedControl
          size="xs"
          value={range}
          onChange={(value) => {
            setRange(value === "7d" ? "7d" : "24h");
          }}
          data={[
            { value: "24h", label: t("insights.ranges.24h") },
            { value: "7d", label: t("insights.ranges.7d") },
          ]}
          style={{ alignSelf: "flex-start" }}
        />
        <Text size="xs" c="dimmed">
          {range === "24h" ? t("insights.probes.range24h") : t("insights.probes.range7d")}
        </Text>
        <QueryView query={shown}>{(data) => <ProbesBody data={data} />}</QueryView>
      </Stack>
    </StatsCard>
  );
}

function ClassBadge({ value }: { value: ProbeClass }) {
  const { t } = useTranslation();
  return (
    <Badge variant="light" color={CLASS_COLORS[value]} style={{ alignSelf: "flex-start" }}>
      {t(`insights.availability.class.${value}`)}
    </Badge>
  );
}

/**
 * The newest probe from the panel. History keeps no L1 result, so a failure is
 * classed by its error text, which names the class the panel gave it.
 */
function LastProbe({ points }: { points: ProbePoint[] }) {
  const { t } = useTranslation();
  const last = points.filter((point) => point.vantage === "panel").reduce<ProbePoint | undefined>(
    (newest, point) => (newest === undefined || point.ts >= newest.ts ? point : newest),
    undefined,
  );
  if (last === undefined) {
    return (
      <Text size="sm" c="dimmed">
        {t("insights.availability.lastNone")}
      </Text>
    );
  }
  const cls = probeClass(last);
  return (
    <Stack gap={4}>
      <Text size="xs" c="dimmed">
        {t("insights.availability.last", { when: formatRelative(last.ts) })}
      </Text>
      <Group gap="xs" wrap="wrap">
        <ClassBadge value={cls} />
        <Text size="sm">{last.ok ? formatMilliseconds(last.latencyMs) : last.error}</Text>
      </Group>
    </Stack>
  );
}

function Uptimes({ day, week }: { day?: ProbeHistoryResponse; week?: ProbeHistoryResponse }) {
  const { t } = useTranslation();
  const vantage = (name: string) => (name === "panel" || name === "node" ? t(VANTAGE_LABEL[name]) : name);
  const vantages = [...new Set([...(day?.uptimes ?? []), ...(week?.uptimes ?? [])].map((uptime) => uptime.vantage))].sort();
  if (vantages.length === 0) {
    return null;
  }
  const cell = (data: ProbeHistoryResponse | undefined, name: string) => {
    const uptime = data?.uptimes.find((entry) => entry.vantage === name);
    return uptime === undefined || uptime.total === 0
      ? "—"
      : t("insights.probes.uptime", {
          percent: formatPercent(uptime.uptime),
          ok: formatNumber(uptime.ok),
          total: formatNumber(uptime.total),
        });
  };
  return (
    <Table verticalSpacing={4} aria-label={t("insights.availability.uptime")}>
      <Table.Thead>
        <Table.Tr>
          <Table.Th>{t("insights.probes.from")}</Table.Th>
          <Table.Th>{t("insights.availability.uptime24h")}</Table.Th>
          <Table.Th>{t("insights.availability.uptime7d")}</Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {vantages.map((name) => (
          <Table.Tr key={name}>
            <Table.Td>{vantage(name)}</Table.Td>
            <Table.Td>{cell(day, name)}</Table.Td>
            <Table.Td>{cell(week, name)}</Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}

/** The latency of the probes that got through, a line per vantage. */
function latencyPoints(points: ProbePoint[]) {
  const byTs = new Map<bigint, Record<string, number | string>>();
  for (const point of [...points].sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0))) {
    if (!point.ok) continue;
    const row = byTs.get(point.ts) ?? { time: formatClock(point.ts) };
    row[point.vantage] = point.latencyMs;
    byTs.set(point.ts, row);
  }
  return [...byTs.values()];
}

function ProbesBody({ data }: { data: ProbeHistoryResponse }) {
  const { t } = useTranslation();
  const vantage = (name: string) => (name === "panel" || name === "node" ? t(VANTAGE_LABEL[name]) : name);
  if (data.points.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        {t("insights.probes.none")}
      </Text>
    );
  }
  const failures = data.points
    .filter((point) => !point.ok)
    .slice(-FAILURES_SHOWN)
    .reverse();
  const chart = latencyPoints(data.points);
  const vantages = [...new Set(data.points.filter((point) => point.ok).map((point) => point.vantage))].sort();

  return (
    <Stack gap="sm">
      <Text size="sm" fw={500}>
        {t("insights.availability.latency")}
      </Text>
      {chart.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.availability.latencyNone")}
        </Text>
      ) : (
        <LineChart
          h={160}
          data={chart}
          dataKey="time"
          series={vantages.map((name) => ({ name, label: vantage(name), color: VANTAGE_COLORS[name] ?? "gray.6" }))}
          withLegend
          withDots={false}
          connectNulls
          tickLine="x"
          valueFormatter={(value) => formatMilliseconds(value)}
          xAxisProps={{ interval: "preserveStartEnd", minTickGap: 48 }}
          lineProps={{ isAnimationActive: false }}
        />
      )}
      <Text size="sm" fw={500}>
        {t("insights.probes.failures")}
      </Text>
      {failures.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.probes.noFailures")}
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={480}>
          <Table verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("insights.probes.time")}</Table.Th>
                <Table.Th>{t("insights.probes.from")}</Table.Th>
                <Table.Th>{t("insights.probes.error")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {failures.map((point) => (
                <Table.Tr key={`${String(point.ts)} ${point.vantage} ${point.kind}`}>
                  <Table.Td>{formatDateTime(point.ts)}</Table.Td>
                  <Table.Td>{vantage(point.vantage)}</Table.Td>
                  <Table.Td>{point.error}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Stack>
  );
}
