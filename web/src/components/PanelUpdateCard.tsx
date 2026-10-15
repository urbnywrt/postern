import { Alert, Badge, Button, FileInput, Group, Paper, Progress, Stack, Table, Text, Title } from "@mantine/core";
import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { type UploadBundle, type UploadResult, uploadBundle, usePanelVersion, useUpdatePanel, versionKeys } from "../api/hooks/versions";
import { orDash } from "../app/format";
import type { GetPanelVersionResponse } from "../gen/postern/panel/v1/versions_pb";
import { ConfirmDialog } from "./ConfirmDialog";
import { DefinitionList } from "./DefinitionList";
import { QueryView } from "./QueryView";

/**
 * The panel itself: the version it runs and the image it started from, what
 * the last update did (the record of a rollback among it), whether the node
 * kit carries signature files, a warning when test keys are trusted, and the
 * upload of a release bundle. Its update is on top of the page (PanelUpdateAction).
 */
export function PanelDetails({ upload = uploadBundle }: { upload?: UploadBundle }) {
  const { t } = useTranslation();
  const panel = usePanelVersion();

  return (
    <Paper withBorder p="md" radius="md" role="region" aria-label={t("versions.panel.title")}>
      <Stack gap="sm">
        <Title order={2}>{t("versions.panel.title")}</Title>
        <QueryView query={panel}>
          {(info) => (
            <Stack gap="sm">
              {!info.canUpdate && info.cannotUpdateReason !== "" ? (
                <Alert color="gray" title={t("versions.panel.cannotUpdate")}>
                  {info.cannotUpdateReason}
                </Alert>
              ) : null}
              {info.trustsTestKeys ? (
                <Alert color="red" title={t("versions.panel.testKeysTitle")}>
                  {t("versions.panel.testKeys")}
                </Alert>
              ) : null}
              <DefinitionList
                items={[
                  { label: t("versions.panel.version"), value: `${info.version}${info.commit !== "" ? ` (${info.commit.slice(0, 12)})` : ""}` },
                  { label: t("versions.panel.imageVersion"), value: orDash(info.imageVersion) },
                  {
                    label: t("versions.panel.kitSigned"),
                    value: (
                      <Badge color={info.kitSigned ? "teal" : "red"} variant="light">
                        {info.kitSigned ? t("versions.panel.kitSignedYes") : t("versions.panel.kitSignedNo")}
                      </Badge>
                    ),
                  },
                  { label: t("versions.panel.lastUpdate"), value: <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{info.lastUpdate !== "" ? info.lastUpdate : t("versions.panel.noUpdate")}</Text> },
                ]}
              />
            </Stack>
          )}
        </QueryView>
        <BundleUpload upload={upload} />
      </Stack>
    </Paper>
  );
}

/**
 * The update of the panel to the newest release it knows: Update, with a
 * confirmation that names the version, or the reason why it cannot; then the
 * notice that it restarts, or why it refused.
 */
export function PanelUpdateAction({ info }: { info: GetPanelVersionResponse }) {
  const { t } = useTranslation();
  const update = useUpdatePanel();
  const [confirming, setConfirming] = useState(false);
  const target = info.releases[0]?.version ?? "";

  return (
    <Stack gap="xs" style={{ minWidth: 0 }}>
      {info.canUpdate && target !== "" ? (
        <Group>
          <Button
            size="xs"
            onClick={() => {
              setConfirming(true);
            }}
          >
            {t("versions.updates.updatePanel")}
          </Button>
        </Group>
      ) : (
        <Text size="sm" c="dimmed" style={{ overflowWrap: "anywhere" }}>
          {info.cannotUpdateReason !== "" ? info.cannotUpdateReason : t("versions.panel.cannotUpdate")}
        </Text>
      )}
      {update.data?.restarting === true ? (
        <Alert color="blue" role="status">
          {t("versions.panel.restarting", { version: update.data.version })}
        </Alert>
      ) : null}
      {update.isError ? (
        <Alert color="red" role="alert" title={t("versions.panel.refused")}>
          {errorMessage(update.error)}
        </Alert>
      ) : null}
      <ConfirmDialog
        opened={confirming}
        title={t("versions.panel.confirmTitle", { version: target })}
        message={t("versions.panel.confirmMessage", { version: target, current: info.version })}
        confirmLabel={t("versions.panel.update", { version: target })}
        loading={update.isPending}
        onClose={() => {
          setConfirming(false);
        }}
        onConfirm={() => {
          update.mutate(target, {
            onSettled: () => {
              setConfirming(false);
            },
          });
        }}
      />
    </Stack>
  );
}

/** The upload of a release bundle, for a panel that cannot reach the release source: the progress, then each asset's result. */
export function BundleUpload({ upload }: { upload: UploadBundle }) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | undefined>();
  const [result, setResult] = useState<UploadResult | undefined>();
  const [failure, setFailure] = useState<string | undefined>();

  async function send() {
    if (file === null) return;
    setResult(undefined);
    setFailure(undefined);
    setProgress(0);
    try {
      const answer = await upload(file, setProgress);
      setResult(answer);
      if (answer.accepted) await queryClient.invalidateQueries({ queryKey: versionKeys.all });
    } catch (error) {
      setFailure(error instanceof Error && error.message !== "network" ? error.message : t("errors.unreachable"));
    } finally {
      setProgress(undefined);
    }
  }

  return (
    <Stack gap="xs" role="group" aria-label={t("versions.upload.title")}>
      <Title order={3}>{t("versions.upload.title")}</Title>
      <Text size="sm" c="dimmed">
        {t("versions.upload.intro")}
      </Text>
      <Group align="flex-end">
        <FileInput
          label={t("versions.upload.file")}
          accept=".tar,application/x-tar"
          value={file}
          onChange={setFile}
          clearable
          w={320}
        />
        <Button
          disabled={file === null || progress !== undefined}
          loading={progress !== undefined}
          onClick={() => {
            void send();
          }}
        >
          {t("versions.upload.send")}
        </Button>
      </Group>
      {progress !== undefined ? <Progress value={Math.round(progress * 100)} aria-label={t("versions.upload.progress")} /> : null}
      {failure !== undefined ? (
        <Alert color="red" role="alert">
          {failure}
        </Alert>
      ) : null}
      {result !== undefined ? (
        <Stack gap="xs">
          <Alert color={result.accepted ? "teal" : "red"} role="status">
            {result.accepted
              ? t("versions.upload.accepted", { version: result.version })
              : result.error !== undefined && result.error !== ""
                ? t("versions.upload.refusedWhy", { reason: result.error })
                : t("versions.upload.refused")}
          </Alert>
          {result.assets.length > 0 ? (
            <Table fz="sm" verticalSpacing={2} aria-label={t("versions.upload.assets")}>
              <Table.Tbody>
                {result.assets.map((asset) => (
                  <Table.Tr key={asset.name}>
                    <Table.Td>{asset.name}</Table.Td>
                    <Table.Td>
                      <Badge size="sm" variant="light" color={asset.ok ? "teal" : "red"}>
                        {asset.ok ? t("versions.upload.assetOk") : t("versions.upload.assetRefused")}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" ff={asset.ok ? "monospace" : undefined} c={asset.ok ? "dimmed" : "red"} style={{ wordBreak: "break-all" }}>
                        {asset.ok ? (asset.sha256 ?? "") : (asset.reason ?? "")}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          ) : null}
          {result.stable !== undefined ? (
            <Text size="sm" c={result.stable.applied ? undefined : "red"}>
              {result.stable.applied ? t("versions.upload.stableApplied") : t("versions.upload.stableRefused", { reason: result.stable.reason ?? "" })}
            </Text>
          ) : null}
          {result.ignored !== undefined && result.ignored.length > 0 ? (
            <Text size="xs" c="dimmed">
              {t("versions.upload.ignored", { names: result.ignored.join(", ") })}
            </Text>
          ) : null}
        </Stack>
      ) : null}
    </Stack>
  );
}
