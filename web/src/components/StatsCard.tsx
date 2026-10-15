import { Group, Paper, Text, Title } from "@mantine/core";
import { type ReactNode, useId } from "react";
import { useTranslation } from "react-i18next";

import { formatDuration } from "../app/format";

/** A part of the statistics: a section with a title, and what it shows. */
export function StatsCard({ title, aside, children }: { title: string; aside?: ReactNode; children: ReactNode }) {
  const titleId = useId();
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="md" radius="md">
      <Group justify="space-between" align="center" mb="sm" wrap="wrap">
        <Title order={3} size="h4" id={titleId}>
          {title}
        </Title>
        {aside}
      </Group>
      {children}
    </Paper>
  );
}

/** A figure with its label: "Downloaded / 50 MB". */
export function Figure({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text fw={600} size="lg">
        {value}
      </Text>
    </div>
  );
}

/** What a point of a chart stands for, and how it was taken together when the series was thinned. */
export function ChartCaption({ bucketSeconds, thinned }: { bucketSeconds: number; thinned: boolean }) {
  const { t } = useTranslation();
  if (bucketSeconds <= 0) {
    return null;
  }
  const period = formatDuration(bucketSeconds);
  return (
    <Text size="xs" c="dimmed">
      {thinned ? t("insights.chart.thinned", { period }) : t("insights.chart.step", { period })}
    </Text>
  );
}
