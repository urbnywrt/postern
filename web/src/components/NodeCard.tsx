import { Anchor, Card, Group } from "@mantine/core";
import type { TFunction } from "i18next";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { formatBytes, formatNumber, formatPercent, orDash } from "../app/format";
import type { NodeOverview } from "../gen/postern/panel/v1/metrics_pb";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { DefinitionList } from "./DefinitionList";
import { EdgeVersion, Generation, LastError, LastSeen } from "./NodeFacts";
import { StatusBadge } from "./StatusBadge";

/**
 * A node on the overview: how it is doing, what it runs and how far it has come
 * with the state of the panel; with `stats`, also its CPU, memory and open
 * connections of its latest minute, and what its proxies carried since local
 * midnight.
 */
export function NodeCard({ node, stats }: { node: Node; stats?: NodeOverview }) {
  const { t } = useTranslation();
  const titleId = useId();
  return (
    <Card component="article" aria-labelledby={titleId} withBorder padding="md" radius="md">
      <Group justify="space-between" wrap="nowrap" mb="sm" gap="xs">
        <Anchor component={Link} to={`/nodes/${node.id}`} id={titleId} fw={600} size="lg" truncate>
          {node.name}
        </Anchor>
        <StatusBadge kind="node" value={node.status} />
      </Group>
      <DefinitionList
        items={[
          { label: t("node.agent"), value: orDash(node.agentVersion) },
          { label: t("node.edge"), value: <EdgeVersion node={node} /> },
          { label: t("node.generation"), value: <Generation node={node} /> },
          ...(node.lastError === "" ? [] : [{ label: t("node.lastError"), value: <LastError node={node} lines={3} /> }]),
          { label: t("node.lastSeen"), value: <LastSeen unix={node.lastSeenUnix} /> },
          ...(stats === undefined ? [] : statsItems(stats, t)),
        ]}
      />
    </Card>
  );
}

/** The figures of the tile. Without a minute in the last 3 minutes the load is unknown, and said so; the traffic is still known. */
function statsItems(stats: NodeOverview, t: TFunction) {
  const traffic = {
    label: t("insights.overview.traffic"),
    value: t("insights.overview.trafficValue", { down: formatBytes(stats.down), up: formatBytes(stats.up) }),
  };
  if (stats.minuteUnix === 0n) {
    return [{ label: t("insights.overview.cpu"), value: t("insights.overview.noMinute") }, traffic];
  }
  return [
    { label: t("insights.overview.cpu"), value: formatPercent(stats.cpu / 100) },
    {
      label: t("insights.overview.ram"),
      value: stats.memTotal > 0n ? `${formatBytes(stats.memUsed)} / ${formatBytes(stats.memTotal)}` : formatBytes(stats.memUsed),
    },
    { label: t("insights.overview.conns"), value: formatNumber(stats.conns) },
    traffic,
  ];
}
