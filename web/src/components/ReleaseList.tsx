import { Alert, Anchor, Badge, Button, Group, Paper, Spoiler, Stack, Table, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { usePrepareRelease, useRecheckRelease } from "../api/hooks/versions";
import { formatDateTime, orDash } from "../app/format";
import { safeUrl, statusColor, term } from "../app/versions";
import type { Release, ReleaseAsset } from "../gen/postern/panel/v1/versions_pb";

/**
 * The releases of a component, newest first: stable and prerelease badges, the
 * state of the file of each architecture with its reason and the source of its
 * checksum, Prepare and Recheck, and the release notes as plain text (never
 * HTML: React puts them in as text, and pre-wrap keeps their lines).
 */
export function ReleaseList({ component, releases }: { component: string; releases: Release[] }) {
  const { t } = useTranslation();
  const prepare = usePrepareRelease();
  const recheck = useRecheckRelease();
  const failure = prepare.isError ? prepare.error : recheck.isError ? recheck.error : undefined;

  if (releases.length === 0) {
    return (
      <Text size="sm" c="dimmed">
        {t("versions.releases.none")}
      </Text>
    );
  }

  return (
    <Stack gap="sm">
      {failure !== undefined ? (
        <Alert color="red" role="alert">
          {errorMessage(failure)}
        </Alert>
      ) : null}
      {releases.map((release) => {
        const url = safeUrl(release.url);
        const preparable = release.assets.some((a) => a.state !== "ready");
        return (
          <Paper key={release.version} withBorder p="sm" radius="sm" role="article" aria-label={release.version}>
            <Stack gap="xs">
              <Group justify="space-between" wrap="wrap" gap="xs">
                <Group gap="xs">
                  <Text fw={600}>{url !== undefined ? <Anchor href={url} target="_blank" rel="noreferrer noopener">{release.version}</Anchor> : release.version}</Text>
                  {release.stable ? (
                    <Badge color="teal" variant="light">
                      {t("versions.releases.stable")}
                    </Badge>
                  ) : null}
                  {release.prerelease ? (
                    <Badge color="orange" variant="light">
                      {t("versions.releases.prerelease")}
                    </Badge>
                  ) : null}
                  {release.channels.map((channel) => (
                    <Badge key={channel} variant="outline">
                      {t("versions.releases.channelOf", { channel })}
                    </Badge>
                  ))}
                </Group>
                <Group gap="xs">
                  <Text size="xs" c="dimmed">
                    {release.publishedUnix > 0n ? formatDateTime(release.publishedUnix) : ""}
                    {release.source !== "" ? ` · ${t("versions.releases.source", { source: release.source })}` : ""}
                  </Text>
                  {preparable ? (
                    <Button
                      size="xs"
                      variant="light"
                      loading={prepare.isPending && prepare.variables.version === release.version}
                      onClick={() => {
                        prepare.mutate({ component, version: release.version });
                      }}
                    >
                      {t("versions.releases.prepare")}
                    </Button>
                  ) : null}
                </Group>
              </Group>
              {release.assets.length > 0 ? (
                <Table.ScrollContainer minWidth={520}>
                  <Table verticalSpacing={2} fz="sm">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>{t("versions.releases.arch")}</Table.Th>
                        <Table.Th>{t("versions.releases.state")}</Table.Th>
                        <Table.Th>{t("versions.releases.checksum")}</Table.Th>
                        <Table.Th>{t("versions.releases.file")}</Table.Th>
                        <Table.Th />
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {release.assets.map((asset: ReleaseAsset) => (
                        <Table.Tr key={asset.arch}>
                          <Table.Td>{asset.arch}</Table.Td>
                          <Table.Td>
                            <Badge size="sm" variant="light" color={statusColor(asset.state)}>
                              {term(t, "versions.assetState", asset.state)}
                            </Badge>
                            {asset.reason !== "" ? (
                              <Text size="xs" c="red" style={{ whiteSpace: "pre-wrap" }}>
                                {asset.reason}
                              </Text>
                            ) : null}
                          </Table.Td>
                          <Table.Td>
                            {asset.shaSource !== "" ? term(t, "versions.shaSource", asset.shaSource) : "—"}
                            {asset.sha256 !== "" ? (
                              <Text size="xs" c="dimmed" ff="monospace" title={asset.sha256}>
                                {asset.sha256.slice(0, 12)}…
                              </Text>
                            ) : null}
                          </Table.Td>
                          <Table.Td>
                            <Text size="xs">{orDash(asset.file)}</Text>
                          </Table.Td>
                          <Table.Td>
                            {asset.state !== "ready" ? (
                              <Button
                                size="compact-xs"
                                variant="subtle"
                                aria-label={t("versions.releases.recheckOf", { version: release.version, arch: asset.arch })}
                                loading={recheck.isPending && recheck.variables.version === release.version && recheck.variables.arch === asset.arch}
                                onClick={() => {
                                  recheck.mutate({ component, version: release.version, arch: asset.arch });
                                }}
                              >
                                {t("versions.releases.recheck")}
                              </Button>
                            ) : null}
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              ) : null}
              {release.notes !== "" ? (
                <Spoiler maxHeight={96} showLabel={t("versions.releases.showNotes")} hideLabel={t("versions.releases.hideNotes")}>
                  <Text size="sm" data-testid="release-notes" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                    {release.notes}
                  </Text>
                </Spoiler>
              ) : null}
            </Stack>
          </Paper>
        );
      })}
    </Stack>
  );
}
