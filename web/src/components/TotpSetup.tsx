import { Badge, Button, Code, Group, Paper, Stack, Text, TextInput, Title } from "@mantine/core";
import { type ChangeEvent, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useBeginTotp, useConfirmTotp, useDisableTotp } from "../api/hooks/auth";
import { notifySuccess } from "../app/notify";
import { normalizeCode, validateCode, validatePassword, validationMessage } from "../app/validation";
import { CopyButton } from "./CopyButton";
import { PasswordField } from "./PasswordField";
import { QrCode } from "./QrCode";

/**
 * Settings: two-factor authentication. It is off until a code of a secret that
 * the panel made has been checked together with the password (ConfirmTotp), and
 * it is turned off with the password and a code (DisableTotp).
 */
export function TotpSetup({ enabled }: { enabled: boolean }) {
  const { t } = useTranslation();
  const titleId = useId();

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" wrap="nowrap" mb="sm">
        <Title order={2} size="h3" id={titleId}>
          {t("settings.totp.title")}
        </Title>
        <Badge variant="light" color={enabled ? "teal" : "gray"} style={{ flexShrink: 0 }}>
          {enabled ? t("settings.totp.on") : t("settings.totp.off")}
        </Badge>
      </Group>
      {enabled ? <DisableTotp /> : <EnrollTotp />}
    </Paper>
  );
}

interface Enrollment {
  secret: string;
  otpauthUri: string;
}

/** The secret exists only here, in memory, while the admin enrols an app. */
function EnrollTotp() {
  const { t } = useTranslation();
  const begin = useBeginTotp();
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);

  async function start() {
    try {
      const { secret, otpauthUri } = await begin.mutateAsync();
      setEnrollment({ secret, otpauthUri });
    } catch {
      // the query client has shown why
    }
  }

  if (enrollment !== null) {
    return (
      <ConfirmTotp
        enrollment={enrollment}
        onCancel={() => {
          setEnrollment(null);
          // The secret is also the answer of BeginTotp, which the mutation holds for as
          // long as this component observes it.
          begin.reset();
        }}
      />
    );
  }
  return (
    <Stack gap="sm">
      <Text size="sm" c="dimmed">
        {t("settings.totp.intro")}
      </Text>
      <Button
        w="fit-content"
        loading={begin.isPending}
        onClick={() => {
          void start();
        }}
      >
        {t("settings.totp.begin")}
      </Button>
    </Stack>
  );
}

function ConfirmTotp({ enrollment, onCancel }: { enrollment: Enrollment; onCancel: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirmTotp();
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const codeError = submitted ? validateCode(code) : null;
  const passwordError = submitted ? validatePassword(password) : null;

  async function submit() {
    if (confirm.isPending) {
      return; // a second Enter must not send the same try again
    }
    setSubmitted(true);
    if (validateCode(code) !== null || validatePassword(password) !== null) {
      return;
    }
    try {
      await confirm.mutateAsync({ code: normalizeCode(code), password });
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(t("settings.totp.enabled"));
  }

  return (
    <Stack gap="md">
      <Text size="sm">{t("settings.totp.scan")}</Text>
      <Group justify="center">
        <QrCode value={enrollment.otpauthUri} title={t("settings.totp.qrTitle")} />
      </Group>
      <Stack gap={4}>
        <Text size="sm" c="dimmed">
          {t("settings.totp.manual")}
        </Text>
        <Group gap="xs" wrap="nowrap">
          <Code fz="md" style={{ userSelect: "all", wordBreak: "break-all" }}>
            {enrollment.secret}
          </Code>
          <CopyButton value={enrollment.secret} label={t("settings.totp.copySecret")} />
        </Group>
      </Stack>
      <Text size="sm">{t("settings.totp.confirmIntro")}</Text>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Stack gap="sm">
          <TextInput
            label={t("settings.totp.code")}
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            error={validationMessage(t, codeError)}
            onChange={(event: ChangeEvent<HTMLInputElement>) => {
              setCode(event.currentTarget.value);
            }}
          />
          <PasswordField
            label={t("common.password")}
            autoComplete="current-password"
            value={password}
            error={validationMessage(t, passwordError)}
            onChange={(event: ChangeEvent<HTMLInputElement>) => {
              setPassword(event.currentTarget.value);
            }}
          />
          <Group gap="sm">
            <Button type="submit" loading={confirm.isPending}>
              {t("settings.totp.confirm")}
            </Button>
            <Button variant="default" onClick={onCancel}>
              {t("common.cancel")}
            </Button>
          </Group>
        </Stack>
      </form>
    </Stack>
  );
}

function DisableTotp() {
  const { t } = useTranslation();
  const disable = useDisableTotp();
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [submitted, setSubmitted] = useState(false);

  const passwordError = submitted ? validatePassword(password) : null;
  const codeError = submitted ? validateCode(code) : null;

  async function submit() {
    if (disable.isPending) {
      return; // a second Enter must not send the same try again
    }
    setSubmitted(true);
    if (validatePassword(password) !== null || validateCode(code) !== null) {
      return;
    }
    try {
      await disable.mutateAsync({ password, code: normalizeCode(code) });
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(t("settings.totp.disabled"));
  }

  return (
    <Stack gap="sm">
      <Text size="sm" c="dimmed">
        {t("settings.totp.enabledIntro")}
      </Text>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Stack gap="sm">
          <PasswordField
            label={t("common.password")}
            autoComplete="current-password"
            value={password}
            error={validationMessage(t, passwordError)}
            onChange={(event: ChangeEvent<HTMLInputElement>) => {
              setPassword(event.currentTarget.value);
            }}
          />
          <TextInput
            label={t("settings.totp.code")}
            inputMode="numeric"
            autoComplete="one-time-code"
            value={code}
            error={validationMessage(t, codeError)}
            onChange={(event: ChangeEvent<HTMLInputElement>) => {
              setCode(event.currentTarget.value);
            }}
          />
          <Button type="submit" color="red" w="fit-content" loading={disable.isPending}>
            {t("settings.totp.disable")}
          </Button>
        </Stack>
      </form>
    </Stack>
  );
}
