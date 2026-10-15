import "@mantine/charts/styles.css";

import { BarChart, LineChart } from "@mantine/charts";
import { Group, List, Paper, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useChains } from "../api/hooks/egress";
import { useEgressHistory } from "../api/hooks/metrics";
import { bucketSeries } from "../app/buckets";
import { formatDateTime, formatMilliseconds, formatNumber } from "../app/format";
import { EGRESS_RANGES } from "../app/ranges";
import type { EgressHistoryResponse, MemberHistory } from "../gen/postern/panel/v1/metrics_pb";
import { QueryView } from "./QueryView";
import { RangeSelect } from "./RangeSelect";
import { ChartCaption, StatsCard } from "./StatsCard";

type EgressRange = (typeof EGRESS_RANGES)[number];

/** A member's hours over 30 days are 720 bars; fewer fit in a card. */
const MAX_BARS = 240;

/** When the exit address of a member changed: the hours whose known exit IP differs from the one before. */
function exitChanges(member: MemberHistory): { ts: bigint; ip: string }[] {
  const changes: { ts: bigint; ip: string }[] = [];
  let last = "";
  for (const hour of member.hours) {
    if (hour.exitIp !== "" && hour.exitIp !== last) {
      changes.push({ ts: hour.tsUnix, ip: hour.exitIp });
      last = hour.exitIp;
    }
  }
  return changes;
}

/**
 * The health of the members of the chains of a node, hour by hour, over up to 30
 * days: the minutes each was up, down or unknown as stacked bars, its latency,
 * and when its exit IP changed. It sits beside the latest health of the members
 * (EgressHealth), and it draws charts, so the page of a node loads it on demand.
 */
export function EgressHistory({ nodeId }: { nodeId: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const [range, setRange] = useState<EgressRange>("24h");
  const history = useEgressHistory(nodeId, range);

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="center" mb="xs" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("insights.egressHistory.title")}
        </Title>
        <RangeSelect value={range} onChange={setRange} ranges={EGRESS_RANGES} />
      </Group>
      <Text size="sm" c="dimmed" mb="md">
        {t("insights.egressHistory.intro")}
      </Text>
      <QueryView query={history}>{(data) => <Members nodeId={nodeId} data={data} />}</QueryView>
    </Paper>
  );
}

function Members({ nodeId, data }: { nodeId: string; data: EgressHistoryResponse }) {
  const { t } = useTranslation();
  const chains = useChains(nodeId);
  if (data.members.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        {t("insights.egressHistory.empty")}
      </Text>
    );
  }
  const chainName = (id: string) => chains.data?.find((chain) => chain.id === id)?.name ?? id;
  return (
    <Stack gap="md">
      {data.members.map((member) => (
        <MemberCard
          key={`${member.chainId} ${member.memberKey}`}
          title={`${chainName(member.chainId)} / ${member.memberKey}`}
          member={member}
          frame={data}
        />
      ))}
    </Stack>
  );
}

function MemberCard({ title, member, frame }: { title: string; member: MemberHistory; frame: EgressHistoryResponse }) {
  const { t } = useTranslation();
  // Minutes are summed over a thinned bar; the latency keeps the average of the hourly averages and the highest of the highest.
  const chart = bucketSeries(
    member.hours.map((hour) => ({
      tsUnix: hour.tsUnix,
      up: hour.upMinutes,
      down: hour.downMinutes,
      unknown: hour.unknownMinutes,
      latencyAvg: hour.latencyAvgMs,
      latencyMax: hour.latencyMaxMs,
    })),
    { fromUnix: frame.fromUnix, toUnix: frame.toUnix, stepSeconds: 3600 },
    { up: "sum", down: "sum", unknown: "sum", latencyAvg: "avg", latencyMax: "max" },
    { maxPoints: MAX_BARS, gaps: "null" },
  );
  const changes = exitChanges(member);

  return (
    <StatsCard title={title}>
      <Stack gap="sm">
        <ChartCaption bucketSeconds={chart.bucketSeconds} thinned={chart.thinned} />
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
          <div>
            <Text size="xs" c="dimmed">
              {t("insights.egressHistory.uptime")}
            </Text>
            <BarChart
              h={160}
              data={chart.points}
              dataKey="time"
              type="stacked"
              series={[
                { name: "up", label: t("insights.egressHistory.up"), color: "teal.6" },
                { name: "down", label: t("insights.egressHistory.down"), color: "red.6" },
                { name: "unknown", label: t("insights.egressHistory.unknown"), color: "gray.5" },
              ]}
              withLegend
              tickLine="x"
              valueFormatter={(value) => formatNumber(value)}
              xAxisProps={{ interval: "preserveStartEnd", minTickGap: 48 }}
              barProps={{ isAnimationActive: false }}
            />
          </div>
          <div>
            <Text size="xs" c="dimmed">
              {t("insights.egressHistory.latency")}
            </Text>
            <LineChart
              h={160}
              data={chart.points}
              dataKey="time"
              series={[
                { name: "latencyAvg", label: t("insights.egressHistory.latencyAvg"), color: "blue.6" },
                { name: "latencyMax", label: t("insights.egressHistory.latencyMax"), color: "orange.6" },
              ]}
              withLegend
              withDots={false}
              connectNulls={false}
              tickLine="x"
              valueFormatter={(value) => formatMilliseconds(value)}
              xAxisProps={{ interval: "preserveStartEnd", minTickGap: 48 }}
              lineProps={{ isAnimationActive: false }}
            />
          </div>
        </SimpleGrid>
        <Text size="sm" fw={500}>
          {t("insights.egressHistory.exitChanges")}
        </Text>
        {changes.length === 0 ? (
          <Text size="sm" c="dimmed">
            {t("insights.egressHistory.exitUnknown")}
          </Text>
        ) : changes.length === 1 ? (
          <Text size="sm">{t("insights.egressHistory.exitSteady", { ip: changes[0]?.ip ?? "" })}</Text>
        ) : (
          <List size="sm" spacing={2}>
            {changes.map((change) => (
              <List.Item key={`${String(change.ts)} ${change.ip}`}>
                {formatDateTime(change.ts)}:{" "}
                <Text span ff="monospace">
                  {change.ip}
                </Text>
              </List.Item>
            ))}
          </List>
        )}
      </Stack>
    </StatsCard>
  );
}
