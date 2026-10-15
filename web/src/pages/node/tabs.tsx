import { Button, Group, Paper, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { lazy, type ReactNode, Suspense, useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useOutletContext } from "react-router";

import { useNodeSeries } from "../../api/hooks/metrics";
import { useProxies } from "../../api/hooks/proxies";
import { formatBytes, formatNumber } from "../../app/format";
import type { ChangeCheck } from "../../components/ChangeCheckNotice";
import { DiagnosticsSection } from "../../components/DiagnosticsSection";
import { EgressHealth } from "../../components/EgressHealth";
import { TrashIcon } from "../../components/icons";
import { ListenersTable } from "../../components/ListenersTable";
import { NodeEgressSettings } from "../../components/NodeEgressSettings";
import { LastSeen } from "../../components/NodeFacts";
import { NodeManagement } from "../../components/NodeManagement";
import { NodeVersionsCard } from "../../components/NodeVersionsCard";
import { PageLoader } from "../../components/PageLoader";
import type { Node } from "../../gen/postern/panel/v1/nodes_pb";
import { NodeArtifactSource, NodeInstall, NodePorts, NodeProxies, NodeState } from "./sections";

// The statistics and the egress history draw charts, and the chart library is the
// biggest part of the app: they are loaded when the page of a node is first opened,
// as the page of a proxy is, and every other page is not made to wait for them.
const NodeStatsSection = lazy(() =>
  import("../../components/NodeStatsSection").then((module) => ({ default: module.NodeStatsSection })),
);
const EgressHistory = lazy(() => import("../../components/EgressHistory").then((module) => ({ default: module.EgressHistory })));

/** What the page of a node gives its tabs. */
export interface NodeOutlet {
  node: Node;
  /** The node was never seen: the page is its install. */
  provisioning: boolean;
  /** Asks to delete the node, through the confirmation of the page. */
  onDelete: () => void;
}

const useNodeOutlet = () => useOutletContext<NodeOutlet>();

/**
 * The overview: the node at a glance, its proxies and the traffic of the last 24 hours, with
 * the rest of its statistics on request; or, before it connects, its install.
 */
export function NodeOverviewTab() {
  const { t } = useTranslation();
  const { node, provisioning } = useNodeOutlet();
  const [fullStats, setFullStats] = useState(false);
  if (provisioning) {
    return <NodeInstall node={node} title={t("nodes.detail.install")} />;
  }
  return (
    <Stack gap="lg">
      <NodeTiles node={node} />
      <NodeProxies node={node} canAdd={false} />
      <Suspense fallback={<PageLoader />}>
        <NodeStatsSection nodeId={node.id} compact={!fullStats} />
      </Suspense>
      {fullStats ? null : (
        <Group>
          <Button
            variant="default"
            size="xs"
            onClick={() => {
              setFullStats(true);
            }}
          >
            {t("nodes.detail.moreStats")}
          </Button>
        </Group>
      )}
    </Stack>
  );
}

function Tile({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Paper withBorder p="md" radius="md" role="group" aria-label={label}>
      <Text size="xs" c="dimmed">
        {label}
      </Text>
      <Text size="lg" fw={600} component="div">
        {children}
      </Text>
    </Paper>
  );
}

const DASH = "—";

/** The tiles of the overview, from what the page asks anyway; a tile without data shows a dash. */
function NodeTiles({ node }: { node: Node }) {
  const { t } = useTranslation();
  const proxies = useProxies({ nodeId: node.id });
  const series = useNodeSeries(node.id, "24h");
  const points = series.data?.points ?? [];
  const last = points.at(-1);
  const traffic = points.reduce((sum, point) => sum + point.up + point.down, 0n);
  return (
    <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
      <Tile label={t("nodes.tiles.proxies")}>{proxies.data === undefined ? DASH : formatNumber(proxies.data.length)}</Tile>
      <Tile label={t("nodes.tiles.devices")}>{last === undefined ? DASH : formatNumber(last.devicesSum)}</Tile>
      <Tile label={t("nodes.tiles.traffic")}>{points.length === 0 ? DASH : formatBytes(traffic)}</Tile>
      <Tile label={t("node.lastSeen")}>
        <LastSeen unix={node.lastSeenUnix} />
      </Tile>
    </SimpleGrid>
  );
}

/** The proxies of the node, with the form of a new one, its listeners and the ports in use. */
export function NodeProxiesTab() {
  const { node } = useNodeOutlet();
  return (
    <Stack gap="lg">
      <NodeProxies node={node} />
      <ListenersTable nodeId={node.id} />
      <NodePorts node={node} />
    </Stack>
  );
}

/** How the node goes out: its default chain and DNS, and the health of its egresses. */
export function NodeEgressTab() {
  const { node } = useNodeOutlet();
  const [check, setCheck] = useState<ChangeCheck>(null);
  return (
    <Stack gap="lg">
      <NodeEgressSettings key={`${node.defaultChainId} ${node.dnsMode}`} node={node} check={check} onCheck={setCheck} />
      <EgressHealth nodeId={node.id} />
      <Suspense fallback={<PageLoader />}>
        <EgressHistory nodeId={node.id} />
      </Suspense>
    </Stack>
  );
}

/** The diagnostics of the node: its problems, a full run and the runs before. */
export function NodeDiagnosticsTab() {
  const { node } = useNodeOutlet();
  return <DiagnosticsSection nodeId={node.id} />;
}

/** The facts of the node, its management, versions and artifacts, the reinstall, and its deletion last. */
export function NodeSettingsTab() {
  const { t } = useTranslation();
  const { node, onDelete } = useNodeOutlet();
  const dangerId = useId();
  return (
    <Stack gap="lg">
      <NodeState node={node} />
      <NodeManagement node={node} />
      <NodeVersionsCard node={node} />
      <NodeArtifactSource key={node.artifactSource} node={node} />
      <NodeInstall node={node} title={t("nodes.detail.reinstall")} />
      <Paper
        component="section"
        aria-labelledby={dangerId}
        withBorder
        p="lg"
        radius="md"
        style={{ borderColor: "var(--mantine-color-red-filled)" }}
      >
        <Title order={2} size="h3" id={dangerId} mb="xs">
          {t("nodes.detail.danger")}
        </Title>
        <Group justify="space-between" align="center" wrap="wrap" gap="sm">
          <Text size="sm" c="dimmed" style={{ flex: "1 1 16rem" }}>
            {t("nodes.detail.dangerHint")}
          </Text>
          <Button variant="light" color="red" leftSection={<TrashIcon />} onClick={onDelete}>
            {t("nodes.delete.action")}
          </Button>
        </Group>
      </Paper>
    </Stack>
  );
}

/** An address under a node that is no tab of it: the overview of the node. */
export function NodeTabNotFound() {
  const { node } = useNodeOutlet();
  return <Navigate to={`/nodes/${node.id}`} replace />;
}
