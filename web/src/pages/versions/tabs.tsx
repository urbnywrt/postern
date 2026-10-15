import { Group, Stack, Text, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { Navigate, useOutletContext } from "react-router";

import { useNodes } from "../../api/hooks/nodes";
import { isActiveRollout, useComponents, useRollouts, useSetDefaultChannel } from "../../api/hooks/versions";
import type { RolloutTarget } from "../../app/versions";
import { ChannelSelect } from "../../components/ChannelSelect";
import { ComponentCard } from "../../components/ComponentCard";
import { NodeVersionsTable } from "../../components/NodeVersionsTable";
import { PanelDetails } from "../../components/PanelUpdateCard";
import { QueryView } from "../../components/QueryView";
import { ReleaseSourceForm } from "../../components/ReleaseSourceForm";
import { RolloutView } from "../../components/RolloutView";

/** What the page of versions gives its tabs. */
export interface VersionsOutlet {
  /** Opens the rollout dialog for a target. */
  onRollout: (target: RolloutTarget) => void;
}

const useVersionsOutlet = () => useOutletContext<VersionsOutlet>();

/** The engines and the egress providers, each with its channels, its releases and its rollouts. */
export function VersionsEnginesTab() {
  const { t } = useTranslation();
  const { onRollout } = useVersionsOutlet();
  const components = useComponents();
  return (
    <QueryView query={components}>
      {(data) => (
        <Stack gap="md">
          {data.includePrereleases ? (
            <Text size="xs" c="dimmed">
              {t("versions.prereleasesOn")}
            </Text>
          ) : null}
          {data.components.map((component) => (
            <ComponentCard key={component.name} component={component} onRollout={onRollout} />
          ))}
        </Stack>
      )}
    </QueryView>
  );
}

/** The builds of the nodes and their channels. */
export function VersionsNodesTab() {
  const { onRollout } = useVersionsOutlet();
  const components = useComponents();
  const nodes = useNodes();
  return (
    <QueryView query={nodes}>
      {(list) => (
        <NodeVersionsTable
          nodes={list}
          defaultChannel={components.data?.defaultChannel ?? "stable"}
          onUpdateNodes={() => {
            onRollout({ kind: "node" });
          }}
        />
      )}
    </QueryView>
  );
}

/** The rollouts, the active ones first (polled), then the recent ones. */
export function VersionsHistoryTab() {
  const { t } = useTranslation();
  const rollouts = useRollouts();
  return (
    <Stack gap="sm" role="region" aria-label={t("versions.rollouts.title")}>
      <Title order={2}>{t("versions.rollouts.title")}</Title>
      <QueryView query={rollouts}>
        {(list) => {
          const active = list.filter((r) => isActiveRollout(r.status));
          const recent = list.filter((r) => !isActiveRollout(r.status));
          if (list.length === 0) {
            return (
              <Text size="sm" c="dimmed">
                {t("versions.rollouts.none")}
              </Text>
            );
          }
          return (
            <Stack gap="sm">
              {active.length > 0 ? <Title order={3}>{t("versions.rollouts.active")}</Title> : null}
              {active.map((rollout) => (
                <RolloutView key={rollout.id} rollout={rollout} />
              ))}
              {recent.length > 0 ? <Title order={3}>{t("versions.rollouts.recent")}</Title> : null}
              {recent.map((rollout) => (
                <RolloutView key={rollout.id} rollout={rollout} />
              ))}
            </Stack>
          );
        }}
      </QueryView>
    </Stack>
  );
}

/** The default channel, the panel's own details with the bundle upload, and where the releases of Postern come from. */
export function VersionsSettingsTab() {
  const { t } = useTranslation();
  const components = useComponents();
  const setDefault = useSetDefaultChannel();
  return (
    <Stack gap="lg">
      {components.data !== undefined ? (
        <Group>
          <ChannelSelect
            label={t("versions.defaultChannel")}
            value={components.data.defaultChannel}
            options={[
              { value: "stable", label: t("versions.channels.stable") },
              { value: "latest", label: t("versions.channels.latest") },
            ]}
            ask={(channel, confirm) => setDefault.mutateAsync({ channel, confirm })}
          />
        </Group>
      ) : null}
      <PanelDetails />
      <ReleaseSourceForm />
    </Stack>
  );
}

/** A tab that does not exist is the first one. */
export function VersionsTabNotFound() {
  return <Navigate to="/versions" replace />;
}
