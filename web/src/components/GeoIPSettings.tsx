import { ConnectError } from "@connectrpc/connect";
import { Alert, Button, FileInput, Group, Paper, Stack, Switch, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { type UploadGeoIP, uploadGeoIP, useGeoIP, useRefreshGeoIP, useSetGeoIPEnabled, useUploadGeoIP } from "../api/hooks/geoip";
import { formatBytes, formatDateTime, orDash } from "../app/format";
import { notifySuccess } from "../app/notify";
import i18n from "../i18n";
import type { GeoIPStatus } from "../gen/postern/panel/v1/geoip_pb";
import { DbIpAttribution } from "./DbIpAttribution";
import { DefinitionList } from "./DefinitionList";
import { QueryView } from "./QueryView";

/**
 * Settings: the country database of the panel. Its state (month, build, size,
 * when it was received and last checked, why the last look failed), a look for a
 * newer one, the upload of a file for a panel that cannot reach DB-IP, the switch
 * of country lookups, and the attribution and licence of DB-IP.
 */
export function GeoIPSettings({ upload = uploadGeoIP }: { upload?: UploadGeoIP }) {
  const { t } = useTranslation();
  const titleId = useId();
  const status = useGeoIP();
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="xs">
        {t("insights.settings.geoip.title")}
      </Title>
      <Text size="sm" c="dimmed" mb="sm">
        {t("insights.settings.geoip.intro")}
      </Text>
      <QueryView query={status}>{(data) => <GeoIPBody status={data} upload={upload} />}</QueryView>
    </Paper>
  );
}

/**
 * Why an upload failed: the line of text that the panel answered (a file that is
 * not a country database, one too large), or that the panel could not be reached
 * (fetch rejects with a TypeError).
 */
function uploadFailure(error: unknown): string {
  if (error instanceof TypeError) return i18n.t("errors.unreachable");
  if (error instanceof Error && !(error instanceof ConnectError)) return error.message;
  return errorMessage(error);
}

function GeoIPBody({ status, upload }: { status: GeoIPStatus; upload: UploadGeoIP }) {
  const { t } = useTranslation();
  const refresh = useRefreshGeoIP();
  const setEnabled = useSetGeoIPEnabled();
  const send = useUploadGeoIP(upload);
  const [file, setFile] = useState<File | null>(null);
  const when = (unix: bigint) => (unix === 0n ? "—" : formatDateTime(unix));

  async function sendFile() {
    if (file === null) return;
    try {
      await send.mutateAsync(file);
    } catch {
      return; // shown below
    }
    setFile(null);
    notifySuccess(t("insights.settings.geoip.uploaded"));
  }

  return (
    <Stack gap="sm">
      <Switch
        label={t("insights.settings.geoip.enabled")}
        description={t("insights.settings.geoip.enabledHint")}
        checked={status.enabled}
        disabled={setEnabled.isPending}
        onChange={(event) => {
          setEnabled.mutate(event.currentTarget.checked);
        }}
      />
      {status.present ? (
        <DefinitionList
          items={[
            { label: t("insights.settings.geoip.month"), value: orDash(status.month) },
            { label: t("insights.settings.geoip.built"), value: when(status.builtUnix) },
            { label: t("insights.settings.geoip.size"), value: formatBytes(status.size) },
            { label: t("insights.settings.geoip.fetched"), value: when(status.fetchedUnix) },
            { label: t("insights.settings.geoip.checked"), value: when(status.checkedUnix) },
            {
              label: t("insights.settings.geoip.sha256"),
              value: (
                <Text size="sm" ff="monospace" style={{ wordBreak: "break-all" }}>
                  {orDash(status.sha256)}
                </Text>
              ),
            },
          ]}
        />
      ) : (
        <Text size="sm" c="dimmed">
          {t("insights.settings.geoip.none")}
        </Text>
      )}
      {status.error !== "" ? (
        <Alert color="orange" role="status">
          {t("insights.settings.geoip.error", { error: status.error })}
        </Alert>
      ) : null}
      <Group>
        <Button
          variant="default"
          size="xs"
          loading={refresh.isPending}
          disabled={!status.enabled}
          onClick={() => {
            refresh.mutate();
          }}
        >
          {t("insights.settings.geoip.refresh")}
        </Button>
      </Group>
      <Group align="flex-end" gap="sm">
        <FileInput
          label={t("insights.settings.geoip.upload")}
          description={t("insights.settings.geoip.uploadHint")}
          accept=".mmdb,.gz,application/gzip"
          clearable
          value={file}
          onChange={setFile}
          style={{ flex: 1 }}
        />
        <Button
          size="sm"
          disabled={file === null}
          loading={send.isPending}
          onClick={() => {
            void sendFile();
          }}
        >
          {t("insights.settings.geoip.uploadButton")}
        </Button>
      </Group>
      {send.isError ? (
        <Alert color="red" role="alert">
          {t("insights.settings.geoip.uploadFailed", { reason: uploadFailure(send.error) })}
        </Alert>
      ) : null}
      <Stack gap={2}>
        <DbIpAttribution text={status.attribution} url={status.attributionUrl} />
        <Text size="xs" c="dimmed">
          {t("insights.settings.geoip.licence", { licence: status.licence === "" ? "CC BY 4.0" : status.licence })}
        </Text>
      </Stack>
    </Stack>
  );
}
