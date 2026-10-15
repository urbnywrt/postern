import { Group, Paper, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { useProxyLive } from "../api/hooks/stats";
import { formatBytes, formatDateTime, formatNumber, formatRelative } from "../app/format";
import type { LiveMinute, ProxyLiveResponse } from "../gen/postern/panel/v1/proxies_pb";
import { QueryView } from "./QueryView";
import { StatusBadge } from "./StatusBadge";

/** What the node reports about a proxy right now. The panel is asked again every 10 seconds. */
export function LiveStats({ proxyId }: { proxyId: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const live = useProxyLive(proxyId);

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="md">
        {t("proxy.detail.live")}
      </Title>
      <QueryView query={live}>{(data) => <LiveBody live={data} />}</QueryView>
    </Paper>
  );
}

function LiveBody({ live }: { live: ProxyLiveResponse }) {
  const { t } = useTranslation();
  const { status, minute } = live;
  return (
    <Stack gap="md">
      <Group gap="sm" align="center" wrap="wrap">
        <StatusBadge kind="proxy" value={status?.phase ?? "unknown"} />
        {status !== undefined && status.runningVersion !== "" ? (
          <Text size="sm" c="dimmed">
            {t("proxy.live.version")}: {status.runningVersion}
          </Text>
        ) : null}
      </Group>
      {status !== undefined && status.reason !== "" ? (
        <Text size="sm" c="red">
          {status.reason}
        </Text>
      ) : null}

      {minute === undefined ? (
        <Text size="sm" c="dimmed">
          {t("proxy.live.empty")}
        </Text>
      ) : (
        <MinuteStats minute={minute} />
      )}
    </Stack>
  );
}

function MinuteStats({ minute }: { minute: LiveMinute }) {
  const { t } = useTranslation();
  return (
    <Stack gap="xs">
      <Text size="xs" c="dimmed">
        {t("proxy.live.caption")}: <span title={formatDateTime(minute.minuteUnix)}>{formatRelative(minute.minuteUnix)}</span>
      </Text>
      <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="md">
        <Stat label={t("proxy.live.down")} value={formatBytes(minute.down)} />
        <Stat label={t("proxy.live.up")} value={formatBytes(minute.up)} />
        <Stat label={t("proxy.live.active")} value={formatNumber(minute.connsActive)} />
        <Stat label={t("proxy.live.peak")} value={formatNumber(minute.connsPeak)} />
        <Stat label={t("proxy.live.new")} value={formatNumber(minute.connsNew)} />
        <Stat label={t("proxy.live.devices")} value={formatNumber(minute.devices)} />
      </SimpleGrid>
    </Stack>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <Stack gap={0}>
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text fw={600} size="lg">
        {value}
      </Text>
    </Stack>
  );
}
