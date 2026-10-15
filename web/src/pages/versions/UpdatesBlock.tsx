import { Alert, Anchor, Badge, Button, Group, Paper, Stack, Text, Title } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { errorMessage } from "../../api/errors";
import { useNodes } from "../../api/hooks/nodes";
import {
  isActiveRollout,
  type RolloutAction,
  useComponents,
  usePanelVersion,
  useReleaseSource,
  useRolloutAction,
  useRollouts,
  useSetReleaseSource,
  versionKeys,
} from "../../api/hooks/versions";
import { compareVersions } from "../../app/node";
import { notifySuccess } from "../../app/notify";
import { channelUpdateLines, outdatedNodes, rolloutActions, rolloutSummary, type RolloutTarget, statusColor, term } from "../../app/versions";
import { PanelUpdateAction } from "../../components/PanelUpdateCard";
import type { ReleaseSource, Rollout } from "../../gen/postern/panel/v1/versions_pb";
import { versionsTabPath } from "./versionsTabs";

/**
 * What can be updated now, on top of the page, one line each with its one
 * action: the panel, the nodes whose agent is older than the panel, the
 * engine and provider channels with a newer release (as channelUpdates), and
 * each active rollout with its controls. With nothing, "all up to date".
 *
 * The panel does not list a release of Postern that the prerelease setting
 * hides (the release source drops it, and nothing stores it), so the page
 * cannot tell such a release: while the setting is off and the panel is up to
 * date, a line says that prereleases are off, with the button that allows them.
 */
export function UpdatesBlock({ onRollout }: { onRollout: (target: RolloutTarget) => void }) {
  const { t } = useTranslation();
  const panel = usePanelVersion();
  const components = useComponents();
  const nodes = useNodes();
  const rollouts = useRollouts();
  const source = useReleaseSource();

  const active = (rollouts.data ?? []).filter((r) => isActiveRollout(r.status));
  const lines: ReactNode[] = [];

  const info = panel.data;
  const newest = info?.releases[0];
  if (info !== undefined && newest !== undefined) {
    lines.push(
      <UpdateLine
        key="panel"
        label={t("versions.updates.panel", { from: info.version, to: newest.version })}
        badges={
          newest.prerelease ? (
            <Badge size="sm" color="orange" variant="light">
              {t("versions.updates.prerelease")}
            </Badge>
          ) : null
        }
      >
        <PanelUpdateAction info={info} />
      </UpdateLine>,
    );
  }

  const behind = info !== undefined ? outdatedNodes(nodes.data ?? [], info.version) : [];
  if (info !== undefined && behind.length > 0 && !active.some((r) => r.kind === "node")) {
    const versions = [...new Set(behind.map((n) => n.agentVersion))].sort(compareVersions).join(", ");
    lines.push(
      <UpdateLine
        key="nodes"
        label={t("versions.updates.nodes", { behind: String(behind.length), total: String(nodes.data?.length ?? 0), versions, panel: info.version })}
      >
        <Button
          size="xs"
          onClick={() => {
            onRollout({ kind: "node" });
          }}
        >
          {t("versions.updates.updateNodes")}
        </Button>
      </UpdateLine>,
    );
  }

  for (const line of channelUpdateLines(components.data?.components ?? [])) {
    // A channel that a rollout holds shows as that rollout.
    if (active.some((r) => r.kind === "version" && r.component === line.component.name && r.channel === line.channel)) continue;
    lines.push(
      <UpdateLine
        key={`channel:${line.component.name}:${line.channel}`}
        label={t("versions.updates.channel", {
          component: line.component.name,
          channel: term(t, "versions.channels", line.channel),
          from: line.from !== "" ? line.from : "—",
          to: line.to,
        })}
      >
        <Button
          size="xs"
          onClick={() => {
            onRollout({ kind: "version", component: line.component.name, componentKind: line.component.kind, channel: line.channel, toVersion: line.to, followed: true });
          }}
        >
          {t("versions.updates.update")}
        </Button>
      </UpdateLine>,
    );
  }

  for (const rollout of active) {
    lines.push(<RolloutLine key={`rollout:${rollout.id}`} rollout={rollout} />);
  }

  const loaded = panel.isSuccess && components.isSuccess && nodes.isSuccess && rollouts.isSuccess;
  // Only once the panel has answered that it has no newer release.
  const prereleasesOff = panel.isSuccess && info?.releases.length === 0 && source.data?.includePrereleases === false ? source.data : undefined;

  return (
    <Stack gap="xs" role="region" aria-label={t("versions.updates.title")}>
      <Title order={2}>{t("versions.updates.title")}</Title>
      {lines}
      {loaded && lines.length === 0 ? (
        <Text size="sm" c="teal">
          {t("versions.updates.allUpToDate")}
        </Text>
      ) : null}
      {prereleasesOff !== undefined ? <PrereleasesOffLine source={prereleasesOff} /> : null}
    </Stack>
  );
}

/** One line of the block: what can be updated, and its action; the two wrap on a narrow screen. */
function UpdateLine({ label, badges, children }: { label: string; badges?: ReactNode; children: ReactNode }) {
  return (
    <Paper withBorder p="sm" radius="md" role="group" aria-label={label}>
      <Group justify="space-between" align="center" gap="xs" wrap="wrap">
        <Group gap="xs" wrap="wrap" style={{ minWidth: 0 }}>
          <Text size="sm" fw={600} style={{ overflowWrap: "anywhere" }}>
            {label}
          </Text>
          {badges}
        </Group>
        {children}
      </Group>
    </Paper>
  );
}

/** An active rollout: what it does, its step and status, its controls as on its card, and a link to it. */
function RolloutLine({ rollout }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const act = useRolloutAction();
  const labels: Record<RolloutAction, string> = {
    continue: t("versions.rolloutView.continue"),
    pause: t("versions.rolloutView.pause"),
    retry: t("versions.rolloutView.retry"),
    abort: t("versions.rolloutView.abort"),
  };
  const summary = rolloutSummary(rollout, t);
  return (
    <UpdateLine
      label={summary}
      badges={
        <>
          {rollout.steps.length > 0 ? (
            <Text size="sm" c="dimmed">
              {t("versions.updates.step", { step: String(Math.min(rollout.currentStep + 1, rollout.steps.length)), total: String(rollout.steps.length) })}
            </Text>
          ) : null}
          <Badge size="sm" color={statusColor(rollout.status)} variant="light">
            {term(t, "versions.status", rollout.status)}
          </Badge>
        </>
      }
    >
      <Stack gap="xs" style={{ minWidth: 0 }}>
        <Group gap="xs" wrap="wrap">
          {rolloutActions(rollout.status).map((action) => (
            <Button
              key={action}
              size="xs"
              variant={action === "abort" ? "light" : "filled"}
              color={action === "abort" ? "red" : undefined}
              loading={act.isPending && act.variables.action === action}
              disabled={act.isPending}
              onClick={() => {
                act.mutate({ id: rollout.id, action });
              }}
            >
              {labels[action]}
            </Button>
          ))}
          <Anchor component={Link} to={versionsTabPath("history")} size="sm">
            {t("versions.updates.details")}
          </Anchor>
        </Group>
        {act.isError ? (
          <Alert color="red" role="alert" title={t("versions.rolloutView.refused")}>
            {errorMessage(act.error)}
          </Alert>
        ) : null}
      </Stack>
    </UpdateLine>
  );
}

/**
 * Prereleases are off and the panel is up to date: it says so, and allows
 * them with one click, keeping the source and its tokens as they are.
 */
function PrereleasesOffLine({ source }: { source: ReleaseSource }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const save = useSetReleaseSource();

  async function allow() {
    try {
      // No token field: the stored tokens stay.
      await save.mutateAsync({ source: { kind: source.kind, baseUrl: source.baseUrl, repo: source.repo, includePrereleases: true } });
    } catch {
      return; // the query client has shown why
    }
    // The panel reads its release source again on a save: the version of the panel shows a prerelease at once.
    await queryClient.invalidateQueries({ queryKey: versionKeys.all });
    notifySuccess(t("versions.updates.prereleasesAllowed"));
  }

  return (
    <UpdateLine label={t("versions.updates.prereleasesOff")}>
      <Button
        size="xs"
        variant="light"
        loading={save.isPending}
        onClick={() => {
          void allow();
        }}
      >
        {t("versions.updates.allowPrereleases")}
      </Button>
    </UpdateLine>
  );
}
