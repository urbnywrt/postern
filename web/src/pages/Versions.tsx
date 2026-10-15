import { Alert, Button, Group, Stack, Tabs, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Outlet, useMatches, useNavigate } from "react-router";

import { errorMessage } from "../api/errors";
import { useRefreshReleases } from "../api/hooks/versions";
import type { RolloutTarget } from "../app/versions";
import { RefreshIcon } from "../components/icons";
import { RolloutDialog } from "../components/RolloutDialog";
import type { VersionsOutlet } from "./versions/tabs";
import { UpdatesBlock } from "./versions/UpdatesBlock";
import { VERSIONS_TABS, type VersionsTab, type VersionsTabHandle, versionsTabPath } from "./versions/versionsTabs";

function useCurrentTab(): VersionsTab {
  for (const match of useMatches()) {
    const handle = match.handle as Partial<VersionsTabHandle> | undefined;
    if (handle?.versionsTab !== undefined) {
      return handle.versionsTab;
    }
  }
  return "engines";
}

/**
 * Versions and updates: what can be updated now on top (UpdatesBlock), and
 * the rest in tabs, one route each, so that the address is the tab and back
 * and forward move between them: the engines and providers, the builds of the
 * nodes, the rollouts, and the settings (the default channel, the panel
 * itself, where the releases of Postern come from).
 */
export function Versions() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const tab = useCurrentTab();
  const refresh = useRefreshReleases();
  // The dialog keeps its target while it closes.
  const [dialog, setDialog] = useState<{ opened: boolean; target?: RolloutTarget }>({ opened: false });
  const outlet: VersionsOutlet = {
    onRollout: (target) => {
      setDialog({ opened: true, target });
    },
  };
  const labels: Record<VersionsTab, string> = {
    engines: t("versions.tabs.engines"),
    nodes: t("versions.tabs.nodes"),
    history: t("versions.tabs.history"),
    settings: t("versions.tabs.settings"),
  };

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-end" wrap="wrap">
        <Stack gap={4}>
          <Title order={1}>{t("versions.title")}</Title>
          <Text size="sm" c="dimmed" maw={760}>
            {t("versions.intro")}
          </Text>
        </Stack>
        <Button
          variant="default"
          leftSection={<RefreshIcon />}
          loading={refresh.isPending}
          onClick={() => {
            refresh.mutate("");
          }}
        >
          {t("versions.refreshAll")}
        </Button>
      </Group>
      {refresh.isError && refresh.variables === "" ? (
        <Alert color="yellow" role="alert">
          {errorMessage(refresh.error)}
        </Alert>
      ) : null}

      <UpdatesBlock onRollout={outlet.onRollout} />

      <Tabs
        value={tab}
        keepMounted={false}
        onChange={(value) => {
          const next = VERSIONS_TABS.find((name) => name === value);
          if (next !== undefined && next !== tab) {
            void navigate(versionsTabPath(next));
          }
        }}
      >
        <Tabs.List aria-label={t("versions.tabs.label")} style={{ flexWrap: "nowrap", overflowX: "auto", overflowY: "hidden" }} mb="lg">
          {VERSIONS_TABS.map((name) => (
            <Tabs.Tab key={name} value={name} style={{ flexShrink: 0 }}>
              {labels[name]}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel value={tab}>
          <Outlet context={outlet} />
        </Tabs.Panel>
      </Tabs>

      <RolloutDialog
        opened={dialog.opened}
        target={dialog.target}
        onClose={() => {
          setDialog((current) => ({ ...current, opened: false }));
        }}
      />
    </Stack>
  );
}
