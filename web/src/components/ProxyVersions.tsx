import { Alert, Button, Group, Paper, Select, Stack, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useNode } from "../api/hooks/nodes";
import { useUpdateProxy } from "../api/hooks/proxies";
import { useReleases } from "../api/hooks/versions";
import { notifySuccess } from "../app/notify";
import { hasPin } from "../app/versions";
import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import { DefinitionList } from "./DefinitionList";
import { SwitchEngineDialog } from "./SwitchEngineDialog";

/**
 * The engine of a proxy: what runs («работает», as the node reports it) and
 * what should («должна быть», with the rule that gives it), the version the
 * node could not bring up, the pin, and the switch to another engine.
 */
export function ProxyVersions({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const titleId = useId();
  const node = useNode(proxy.nodeId);
  const releases = useReleases(proxy.engine);
  const update = useUpdateProxy();
  const [switching, setSwitching] = useState(false);

  const runningEngine = proxy.status?.runningEngine ?? "";
  const runningVersion = proxy.status?.runningVersion ?? "";
  const failedVersion = proxy.status?.failedVersion ?? "";
  const running = runningVersion === "" ? "—" : `${runningEngine === "" ? proxy.engine : runningEngine} ${runningVersion}`;
  const source =
    proxy.versionSource === "pinned"
      ? t("proxy.versions.source.pinned")
      : proxy.versionSource === "rollout"
        ? t("proxy.versions.source.rollout")
        : t("proxy.versions.source.channel", { channel: proxy.channel === "" ? "—" : proxy.channel });
  const desired = `${proxy.engine} ${proxy.engineVersion === "" ? "—" : proxy.engineVersion} · ${source}`;
  const arch = node.data?.arch ?? "";
  const pinned = (releases.data ?? []).filter((r) => hasPin(r, arch));
  const current = proxy.versionSource === "pinned" ? proxy.engineVersion : "";
  const options = [
    { value: "", label: t("versions.rollout.followChannel") },
    ...pinned.map((r) => ({ value: r.version, label: r.version })),
    // The pin in force stays offered even when the list does not have it.
    ...(current !== "" && !pinned.some((r) => r.version === current) ? [{ value: current, label: current }] : []),
  ];

  async function pin(version: string) {
    if (version === current) return;
    try {
      await update.mutateAsync({ id: proxy.id, engineVersion: version });
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(version === "" ? t("proxy.versions.followed") : t("proxy.versions.pinned", { version }));
  }

  return (
    <Paper component="section" role="region" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Stack gap="md">
        <Group justify="space-between">
          <Title order={2} size="h3" id={titleId}>
            {t("proxy.versions.title")}
          </Title>
          <Button
            variant="light"
            onClick={() => {
              setSwitching(true);
            }}
          >
            {t("proxy.versions.switch")}
          </Button>
        </Group>
        <DefinitionList
          items={[
            { label: t("proxy.versions.running"), value: running },
            { label: t("proxy.versions.desired"), value: desired },
          ]}
        />
        {failedVersion !== "" ? (
          <Alert color="red" role="status">
            {t("proxy.versions.failed", { version: failedVersion })}
          </Alert>
        ) : null}
        <Select
          label={t("proxy.versions.pin")}
          description={proxy.versionSource === "rollout" ? t("proxy.versions.heldByRollout") : t("proxy.versions.pinHint")}
          data={options}
          value={current}
          disabled={proxy.versionSource === "rollout" || update.isPending}
          allowDeselect={false}
          onChange={(value) => {
            void pin(value ?? "");
          }}
          maw={320}
        />
        <Text size="xs" c="dimmed">
          {t("proxy.versions.pinRestart")}
        </Text>
      </Stack>
      <SwitchEngineDialog
        opened={switching}
        proxyIds={[proxy.id]}
        onClose={() => {
          setSwitching(false);
        }}
      />
    </Paper>
  );
}
