import { Alert, Badge, Button, Collapse, Group, Paper, Stack, Table, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useRefreshReleases, useReleases } from "../api/hooks/versions";
import { formatRelative, orDash } from "../app/format";
import { channelsOf, followsChannel, type RolloutTarget, term, updatableTo } from "../app/versions";
import type { Component } from "../gen/postern/panel/v1/versions_pb";
import { RefreshIcon } from "./icons";
import { PageLoader } from "./PageLoader";
import { ReleaseList } from "./ReleaseList";


interface ComponentCardProps {
  component: Component;
  onRollout: (target: RolloutTarget) => void;
}

/**
 * One component: the version of each channel and the newest release it could
 * move to, with "Update <channel> to <version>", a switch of proxies to an
 * engine, a refresh of its release list, and the list itself.
 */
export function ComponentCard({ component, onRollout }: ComponentCardProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const releases = useReleases(component.name, { enabled: open });
  const refresh = useRefreshReleases();

  return (
    <Paper withBorder p="md" radius="md" role="region" aria-label={component.name}>
      <Stack gap="sm">
        <Group justify="space-between" wrap="wrap">
          <Group gap="xs">
            <Title order={3}>{component.name}</Title>
            <Badge variant="light" color="gray">
              {term(t, "versions.kind", component.kind)}
            </Badge>
          </Group>
          <Group gap="xs">
            <Text size="xs" c="dimmed">
              {component.checkedUnix > 0n ? t("versions.checked", { when: formatRelative(component.checkedUnix) }) : t("versions.neverChecked")}
            </Text>
            <Button
              size="xs"
              variant="default"
              leftSection={<RefreshIcon />}
              loading={refresh.isPending}
              aria-label={t("versions.refreshOne", { component: component.name })}
              onClick={() => {
                refresh.mutate(component.name);
              }}
            >
              {t("versions.refresh")}
            </Button>
          </Group>
        </Group>
        {component.feedError !== "" ? (
          <Alert color="yellow" title={t("versions.feedError")}>
            {component.feedError}
          </Alert>
        ) : null}
        {refresh.isError ? (
          <Alert color="yellow" role="alert">
            {errorMessage(refresh.error)}
          </Alert>
        ) : null}
        <Table verticalSpacing={4} fz="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("versions.channelCol")}</Table.Th>
              <Table.Th>{t("versions.current")}</Table.Th>
              <Table.Th>{t("versions.newest")}</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {channelsOf(component).map((channel) => {
              const to = updatableTo(component, channel);
              // An engine channel that no proxy follows moves at once: the button says so.
              const followed = component.kind !== "engine" || followsChannel(component, channel);
              return (
                <Table.Tr key={channel}>
                  <Table.Td>{term(t, "versions.channels", channel)}</Table.Td>
                  <Table.Td>{orDash(component.channelVersions[channel] ?? "")}</Table.Td>
                  <Table.Td>{orDash(component.newest[channel] ?? "")}</Table.Td>
                  <Table.Td>
                    {to !== undefined ? (
                      <Button
                        size="xs"
                        onClick={() => {
                          onRollout({ kind: "version", component: component.name, componentKind: component.kind, channel, toVersion: to, followed });
                        }}
                      >
                        {t(followed ? "versions.updateChannel" : "versions.moveChannel", { channel, version: to })}
                      </Button>
                    ) : null}
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
        <Group gap="xs">
          <Button
            size="xs"
            variant="subtle"
            onClick={() => {
              setOpen((o) => !o);
            }}
            aria-expanded={open}
          >
            {open ? t("versions.hideReleases") : t("versions.showReleases")}
          </Button>
          {component.kind === "engine" ? (
            <Button
              size="xs"
              variant="light"
              onClick={() => {
                onRollout({ kind: "switch", engine: component.name });
              }}
            >
              {t("versions.switchTo", { engine: component.name })}
            </Button>
          ) : null}
        </Group>
        {component.kind === "engine" && component.name === "mtg" ? (
          <Text size="xs" c="dimmed">
            {t("versions.rollout.mtgNote")}
          </Text>
        ) : null}
        <Collapse in={open}>
          {open ? (
            releases.data !== undefined ? (
              <ReleaseList component={component.name} releases={releases.data} />
            ) : releases.isError ? (
              <Alert color="red">{errorMessage(releases.error)}</Alert>
            ) : (
              <PageLoader />
            )
          ) : null}
        </Collapse>
      </Stack>
    </Paper>
  );
}
