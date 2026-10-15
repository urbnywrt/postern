import { Alert, Button, Checkbox, Group, Modal, MultiSelect, NumberInput, Radio, Select, Stack, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useNodes } from "../api/hooks/nodes";
import { useProxies } from "../api/hooks/proxies";
import { useReleases, useStartRollout } from "../api/hooks/versions";
import { buildStartRollout, canaryIsProxy, DEFAULT_CHOICES, hasPin, type RolloutChoices, type RolloutTarget } from "../app/versions";
import type { Rollout } from "../gen/postern/panel/v1/versions_pb";

interface RolloutDialogProps {
  opened: boolean;
  /** Kept while the dialog closes. */
  target: RolloutTarget | undefined;
  onClose: () => void;
  onStarted?: (rollout: Rollout) => void;
}

/** Asks how a rollout is to go (mode, pause, canary, offline nodes) and starts it. */
export function RolloutDialog({ opened, target, onClose, onStarted }: RolloutDialogProps) {
  const { t } = useTranslation();
  const title =
    target === undefined
      ? ""
      : target.kind === "version"
        ? t("versions.rollout.titleVersion", { component: target.component, channel: target.channel, version: target.toVersion })
        : target.kind === "switch"
          ? t("versions.rollout.titleSwitch", { engine: target.engine })
          : t("versions.rollout.titleNode");
  return (
    <Modal opened={opened} onClose={onClose} title={title} centered size="lg">
      {target !== undefined && opened ? (
        <RolloutForm
          key={JSON.stringify(target)}
          target={target}
          onCancel={onClose}
          onStarted={(rollout) => {
            onStarted?.(rollout);
            onClose();
          }}
        />
      ) : null}
    </Modal>
  );
}

/** The choices of a rollout of a target, and its start; the dialogs put it in a modal. */
export function RolloutForm({ target, onCancel, onStarted }: { target: RolloutTarget; onCancel: () => void; onStarted: (r: Rollout) => void }) {
  const { t } = useTranslation();
  const [choices, setChoices] = useState<RolloutChoices>({
    ...DEFAULT_CHOICES,
    proxyIds: target.kind === "switch" ? (target.proxyIds ?? []) : [],
    ...(target.kind === "node"
      ? { nodeIds: target.nodeIds ?? [], agent: target.agent ?? true, edge: target.edge ?? true }
      : {}),
  });
  const set = (patch: Partial<RolloutChoices>) => {
    setChoices((current) => ({ ...current, ...patch }));
  };
  const start = useStartRollout();
  const nodes = useNodes();
  const wantsProxies = canaryIsProxy(target);
  const proxies = useProxies();
  const engine = target.kind === "switch" ? target.engine : "";
  const releases = useReleases(engine, { enabled: target.kind === "switch" });

  const proxyName = (id: string) => proxies.data?.find((p) => p.id === id)?.name ?? id;
  const proxyOptions = (proxies.data ?? [])
    .filter((p) => (target.kind === "version" ? p.engine === target.component : true))
    .filter((p) => (target.kind === "switch" ? p.engine !== target.engine || choices.proxyIds.includes(p.id) : true))
    .map((p) => ({ value: p.id, label: p.name }));
  const canaryProxyOptions =
    target.kind === "switch" ? choices.proxyIds.map((id) => ({ value: id, label: proxyName(id) })) : proxyOptions;
  const nodeOptions = (nodes.data ?? []).map((n) => ({ value: n.id, label: n.name }));
  const canaryNodeOptions =
    target.kind === "node" && choices.nodeIds.length > 0 ? nodeOptions.filter((o) => choices.nodeIds.includes(o.value)) : nodeOptions;

  const invalid =
    (target.kind === "switch" && choices.proxyIds.length === 0) || (target.kind === "node" && !choices.agent && !choices.edge);

  async function submit() {
    try {
      onStarted(await start.mutateAsync(buildStartRollout(target, choices)));
    } catch {
      // shown below: another rollout holds the channel or a node, a node lacks a capability
    }
  }

  return (
    <Stack gap="md">
      {target.kind === "version" && target.followed === false ? <Alert color="blue">{t("versions.rollout.moveNote")}</Alert> : null}
      {target.kind === "switch" ? (
        <>
          <MultiSelect
            label={t("versions.rollout.proxies")}
            data={proxyOptions}
            value={choices.proxyIds}
            onChange={(proxyIds) => {
              set({ proxyIds, canaryProxyId: proxyIds.includes(choices.canaryProxyId) ? choices.canaryProxyId : "" });
            }}
            searchable
          />
          <Select
            label={t("versions.rollout.pinVersion")}
            description={t("versions.rollout.pinVersionHint")}
            data={[
              { value: "", label: t("versions.rollout.followChannel") },
              // Only a version with a pinned SHA-256 can be named in a desired state.
              ...(releases.data ?? []).filter((r) => hasPin(r)).map((r) => ({ value: r.version, label: r.version })),
            ]}
            value={choices.pinVersion}
            onChange={(value) => {
              set({ pinVersion: value ?? "" });
            }}
            allowDeselect={false}
          />
          {target.engine === "mtg" ? (
            <Alert color="yellow" title={t("versions.rollout.mtgNoteTitle")}>
              {t("versions.rollout.mtgNote")}
            </Alert>
          ) : null}
        </>
      ) : null}

      {target.kind === "node" ? (
        <>
          <MultiSelect
            label={t("versions.rollout.nodes")}
            description={t("versions.rollout.nodesHint")}
            data={nodeOptions}
            value={choices.nodeIds}
            onChange={(nodeIds) => {
              set({ nodeIds, canaryNodeId: nodeIds.length === 0 || nodeIds.includes(choices.canaryNodeId) ? choices.canaryNodeId : "" });
            }}
            searchable
          />
          <Group gap="lg">
            <Checkbox
              label={t("versions.rollout.agent")}
              checked={choices.agent}
              onChange={(event) => {
                set({ agent: event.currentTarget.checked });
              }}
            />
            <Checkbox
              label={t("versions.rollout.edge")}
              checked={choices.edge}
              onChange={(event) => {
                set({ edge: event.currentTarget.checked });
              }}
            />
          </Group>
        </>
      ) : null}

      <Radio.Group
        label={t("versions.rollout.mode")}
        value={choices.mode}
        onChange={(mode) => {
          set({ mode: mode === "auto" ? "auto" : "manual" });
        }}
      >
        <Stack gap={6} mt={6}>
          <Radio value="manual" label={t("versions.rollout.modeManual")} />
          <Radio value="auto" label={t("versions.rollout.modeAuto")} />
        </Stack>
      </Radio.Group>
      {choices.mode === "auto" ? (
        <NumberInput
          label={t("versions.rollout.pause")}
          min={0}
          max={86_400}
          value={choices.pauseSeconds}
          onChange={(value) => {
            set({ pauseSeconds: typeof value === "number" ? value : Number(value) || 0 });
          }}
        />
      ) : null}

      {wantsProxies ? (
        <Select
          label={t("versions.rollout.canaryProxy")}
          data={[{ value: "", label: t("versions.rollout.canaryAuto") }, ...canaryProxyOptions]}
          value={choices.canaryProxyId}
          onChange={(value) => {
            set({ canaryProxyId: value ?? "" });
          }}
          allowDeselect={false}
          searchable
        />
      ) : (
        <Select
          label={t("versions.rollout.canaryNode")}
          data={[{ value: "", label: t("versions.rollout.canaryAuto") }, ...canaryNodeOptions]}
          value={choices.canaryNodeId}
          onChange={(value) => {
            set({ canaryNodeId: value ?? "" });
          }}
          allowDeselect={false}
          searchable
        />
      )}

      <Checkbox
        label={t("versions.rollout.skipOffline")}
        description={t("versions.rollout.skipOfflineHint")}
        checked={choices.skipOffline}
        onChange={(event) => {
          set({ skipOffline: event.currentTarget.checked });
        }}
      />

      <Text size="xs" c="dimmed">
        {t("versions.rollout.canaryHint")}
      </Text>

      {start.isError ? (
        <Alert color="red" role="alert" title={t("versions.rollout.refused")}>
          {errorMessage(start.error)}
        </Alert>
      ) : null}

      <Group justify="flex-end" gap="sm">
        <Button variant="default" onClick={onCancel} disabled={start.isPending}>
          {t("common.cancel")}
        </Button>
        <Button
          loading={start.isPending}
          disabled={invalid}
          onClick={() => {
            void submit();
          }}
        >
          {t("versions.rollout.start")}
        </Button>
      </Group>
    </Stack>
  );
}
