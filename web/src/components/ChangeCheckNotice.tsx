import { Alert, Anchor, Group, Loader, Stack, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useRuns } from "../api/hooks/diagnostics";
import { useNodes } from "../api/hooks/nodes";
import { findChangeRuns, runLink } from "../app/diagnostics";
import type { DiagnosticRun } from "../gen/postern/panel/v1/diagnostics_pb";
import { RegressedBadge, RunStateBadge } from "./RunHistory";

/** How often the runs are asked for until the after-run of a change is there. */
const CHANGE_POLL_MS = 5_000;

export type ChangeCheck =
  /** Nothing saved that runs a check. */
  | null
  /**
   * A save that runs a check of `nodeId` (or of the scope of `proxyId`). Once the
   * panel has answered, `beforeRunId` is the run that it made before the change
   * ("" when it made none).
   */
  | { nodeId: string; proxyId?: string; beforeRunId?: string }
  /** A save that runs a check of every node that uses an egress; once answered, the before-runs by node. */
  | { nodes: true; beforeRuns?: Record<string, string> };

/**
 * What a save that changes the egress of a node or a proxy says. The panel runs a
 * full check of the affected scope before such a change and waits for it for up
 * to 90 seconds, so while it saves the notice says that the node is being checked;
 * afterwards it links the check before the change, whose id the panel answered
 * the save with, and, once the panel has made it (about a minute after the node
 * has applied the change), the check after it.
 */
export function ChangeCheckNotice({ saving, check }: { saving: boolean; check: ChangeCheck }) {
  const { t } = useTranslation();
  if (check === null) {
    return null;
  }
  if (saving) {
    return (
      <Alert color="blue" role="status">
        <Group gap="xs" wrap="nowrap">
          <Loader size="xs" />
          <Text size="sm">{"nodes" in check ? t("insights.changeCheck.checkingNodes") : t("insights.changeCheck.checking")}</Text>
        </Group>
      </Alert>
    );
  }
  if ("nodes" in check) {
    return <NodesRuns runs={check.beforeRuns ?? {}} />;
  }
  if (check.beforeRunId === undefined || check.beforeRunId === "") {
    return (
      <Alert color="gray" role="status">
        <Text size="sm">{t("insights.changeCheck.beforeMissing")}</Text>
      </Alert>
    );
  }
  return <ChangeRuns nodeId={check.nodeId} proxyId={check.proxyId} beforeRunId={check.beforeRunId} />;
}

function ChangeRuns({ nodeId, proxyId, beforeRunId }: { nodeId: string; proxyId?: string; beforeRunId: string }) {
  const { t } = useTranslation();
  const runs = useRuns({ nodeId, proxyId }, (data) =>
    data === undefined || findChangeRuns(data.runs, beforeRunId).after === undefined ? CHANGE_POLL_MS : false,
  );
  const { before, after } = findChangeRuns(runs.data?.runs ?? [], beforeRunId);

  return (
    <Alert color="gray" role="status">
      <Stack gap={4}>
        <RunLink label={t("insights.changeCheck.before")} runId={beforeRunId} run={before} />
        {after === undefined ? (
          <Text size="sm" c="dimmed">
            {t("insights.changeCheck.afterPending")}
          </Text>
        ) : (
          <RunLink label={t("insights.changeCheck.after")} runId={after.id} run={after} />
        )}
      </Stack>
    </Alert>
  );
}

/** A run on the page that is open: the diagnostics of the page open it from the address. */
function RunLink({ label, runId, run }: { label: string; runId: string; run?: DiagnosticRun }) {
  const { t } = useTranslation();
  return (
    <Group gap="xs" wrap="wrap">
      <Text size="sm">{label}</Text>
      {run === undefined ? null : <RunStateBadge state={run.state} />}
      {run?.regressed === true ? <RegressedBadge /> : null}
      <Anchor component={Link} to={{ search: `?run=${encodeURIComponent(runId)}` }} preventScrollReset size="sm">
        {t("insights.changeCheck.open", { what: label })}
      </Anchor>
    </Group>
  );
}

/** The checks before a change of an egress, one of each node that it changed, on the pages of the nodes. */
function NodesRuns({ runs }: { runs: Record<string, string> }) {
  const { t } = useTranslation();
  const nodes = useNodes();
  const entries = Object.entries(runs);
  if (entries.length === 0) {
    return (
      <Alert color="gray" role="status">
        {t("insights.changeCheck.eachNode")}
      </Alert>
    );
  }
  const name = (nodeId: string) => nodes.data?.find((node) => node.id === nodeId)?.name ?? nodeId;
  return (
    <Alert color="gray" role="status">
      <Stack gap={4}>
        <Text size="sm">{t("insights.changeCheck.eachNode")}</Text>
        {entries.map(([nodeId, runId]) => (
          <Anchor key={nodeId} component={Link} to={runLink(nodeId, runId)} size="sm">
            {t("insights.changeCheck.beforeOn", { node: name(nodeId) })}
          </Anchor>
        ))}
      </Stack>
    </Alert>
  );
}
