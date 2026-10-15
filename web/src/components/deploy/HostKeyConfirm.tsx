import { Alert, Button, Checkbox, Code, Group, Stack, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../../api/errors";
import type { HostKey, HostKeyChanged } from "../../gen/postern/panel/v1/deploy_pb";
import { CopyButton } from "../CopyButton";
import { DefinitionList } from "../DefinitionList";

/** The file of the public host key of a type, where sshd keeps it. */
function keyFile(type: string): string {
  if (type.startsWith("ecdsa-")) {
    return "/etc/ssh/ssh_host_ecdsa_key.pub";
  }
  if (type === "ssh-rsa") {
    return "/etc/ssh/ssh_host_rsa_key.pub";
  }
  return "/etc/ssh/ssh_host_ed25519_key.pub";
}

/** A fingerprint as it is shown: in a code font, with a button that copies it. */
function Fingerprint({ value }: { value: string }) {
  return (
    <Group gap={4} wrap="nowrap" align="center">
      <Code style={{ overflowWrap: "anywhere" }}>{value}</Code>
      <CopyButton value={value} />
    </Group>
  );
}

interface Actions {
  pending: boolean;
  error: unknown;
  onBack: () => void;
}

function Failure({ error }: { error: unknown }) {
  const { t } = useTranslation();
  if (error === null || error === undefined) {
    return null;
  }
  return (
    <Alert color="red" title={t("common.error")}>
      {errorMessage(error)}
    </Alert>
  );
}

/**
 * The first contact with a server: its host key, and how to check it on the
 * server, before the panel sends it any credentials.
 */
export function HostKeyConfirm({ hostKey, pending, error, onBack, onConfirm }: Actions & { hostKey: HostKey; onConfirm: () => void }) {
  const { t } = useTranslation();
  const command = `ssh-keygen -lf ${keyFile(hostKey.type)}`;
  return (
    <Stack gap="md" maw={640}>
      <Title order={2} size="h3">
        {t("deploy.hostKey.title")}
      </Title>
      <Text size="sm">{t("deploy.hostKey.first")}</Text>
      <DefinitionList
        items={[
          { label: t("deploy.hostKey.fingerprint"), value: <Fingerprint value={hostKey.fingerprint} /> },
          { label: t("deploy.hostKey.type"), value: hostKey.type },
        ]}
      />
      <Text size="sm">{t("deploy.hostKey.check")}</Text>
      <Group gap={4} wrap="nowrap" align="center">
        <Code block style={{ flex: 1, minWidth: 0 }}>
          {command}
        </Code>
        <CopyButton value={command} />
      </Group>
      <Failure error={error} />
      <Group>
        <Button onClick={onConfirm} loading={pending}>
          {t("deploy.hostKey.confirm")}
        </Button>
        <Button variant="default" onClick={onBack} disabled={pending}>
          {t("common.back")}
        </Button>
      </Group>
    </Stack>
  );
}

/**
 * A server that presents another key than the confirmed one: both keys, and a
 * way to trust the new one that the admin has to mean. A server that offers no
 * key of the confirmed type has no new key to trust: it is met again, as for
 * the first time, and its key is confirmed then, with the same care. Neither
 * goes with the saved credentials, which were for the old key: the admin types
 * the credentials again.
 */
export function HostKeyChangedView({
  change,
  pending,
  error,
  onBack,
  onTrust,
  savedCredentials,
}: Actions & { change: HostKeyChanged; onTrust: () => void; savedCredentials: boolean }) {
  const { t } = useTranslation();
  const [checked, setChecked] = useState(false);
  const presented = change.presented?.fingerprint ?? "";
  return (
    <Stack gap="md" maw={640}>
      <Alert color="red" title={t("deploy.hostKey.changedTitle")}>
        {t("deploy.hostKey.changed")}
      </Alert>
      <DefinitionList
        items={[
          {
            label: t("deploy.hostKey.confirmed"),
            value: <Fingerprint value={change.confirmed?.fingerprint ?? ""} />,
          },
          {
            label: t("deploy.hostKey.presented"),
            value:
              presented === "" ? (
                t("deploy.hostKey.noKeyOfType", { type: change.confirmed?.type ?? "" })
              ) : (
                <Fingerprint value={presented} />
              ),
          },
        ]}
      />
      {presented === "" ? <Text size="sm">{t("deploy.hostKey.meetAgainHint")}</Text> : null}
      {savedCredentials ? (
        <Alert color="yellow">{t("deploy.hostKey.notSaved")}</Alert>
      ) : (
        <Checkbox
          label={presented === "" ? t("deploy.hostKey.meetAgainCheck") : t("deploy.hostKey.trustCheck")}
          checked={checked}
          onChange={(event) => {
            setChecked(event.currentTarget.checked);
          }}
        />
      )}
      <Failure error={error} />
      <Group>
        <Button color="red" onClick={onTrust} loading={pending} disabled={savedCredentials || !checked}>
          {presented === "" ? t("deploy.hostKey.meetAgain") : t("deploy.hostKey.trust")}
        </Button>
        <Button variant="default" onClick={onBack} disabled={pending}>
          {t("common.back")}
        </Button>
      </Group>
    </Stack>
  );
}
