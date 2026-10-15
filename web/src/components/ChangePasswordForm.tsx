import { Button, Paper, Stack, Text, TextInput, Title } from "@mantine/core";
import { type ChangeEvent, useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useChangePassword } from "../api/hooks/auth";
import { notifySuccess } from "../app/notify";
import {
  MIN_PASSWORD_CHARS,
  normalizeCode,
  validateCode,
  validateNewPassword,
  validatePassword,
  validateRepeat,
  validationMessage,
  type ValidationError,
} from "../app/validation";
import { PasswordField } from "./PasswordField";

interface Values {
  current: string;
  next: string;
  repeat: string;
  code: string;
}

type Errors = Record<keyof Values, ValidationError | null>;

const empty: Values = { current: "", next: "", repeat: "", code: "" };

function validate(values: Values, totpEnabled: boolean): Errors {
  return {
    current: validatePassword(values.current),
    next: validateNewPassword(values.next),
    repeat: validateRepeat(values.next, values.repeat),
    // The panel ignores the code when TOTP is off, so it is not asked for then.
    code: totpEnabled ? validateCode(values.code) : null,
  };
}

const hasErrors = (errors: Errors) => Object.values(errors).some((error) => error !== null);

/** Settings: sets a new password. With TOTP on, a current code is part of the request. */
export function ChangePasswordForm({ totpEnabled }: { totpEnabled: boolean }) {
  const { t } = useTranslation();
  const titleId = useId();
  const change = useChangePassword();
  const [values, setValues] = useState(empty);
  // Mistakes are pointed out after the first try to send, and then as they are fixed.
  const [submitted, setSubmitted] = useState(false);
  const errors = submitted ? validate(values, totpEnabled) : undefined;

  const bind = (field: keyof Values) => ({
    value: values[field],
    error: validationMessage(t, errors?.[field] ?? null),
    onChange: (event: ChangeEvent<HTMLInputElement>) => {
      const { value } = event.currentTarget;
      setValues((current) => ({ ...current, [field]: value }));
    },
  });

  async function submit() {
    if (change.isPending) {
      return; // a second Enter must not send the same try again
    }
    setSubmitted(true);
    if (hasErrors(validate(values, totpEnabled))) {
      return;
    }
    try {
      await change.mutateAsync({
        currentPassword: values.current,
        newPassword: values.next,
        totpCode: totpEnabled ? normalizeCode(values.code) : "",
      });
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(t("settings.password.done"));
    setValues(empty);
    setSubmitted(false);
    // The form stays on the screen, and the mutation would keep the passwords it was sent with.
    change.reset();
  }

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId}>
        {t("settings.password.title")}
      </Title>
      <Text size="sm" c="dimmed" mb="md">
        {t("settings.password.hint")}
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
            label={t("settings.password.current")}
            autoComplete="current-password"
            {...bind("current")}
          />
          <PasswordField
            label={t("settings.password.new")}
            description={t("common.passwordHint", { min: MIN_PASSWORD_CHARS })}
            autoComplete="new-password"
            {...bind("next")}
          />
          <PasswordField
            label={t("settings.password.repeat")}
            autoComplete="new-password"
            {...bind("repeat")}
          />
          {totpEnabled ? (
            <TextInput
              label={t("settings.password.code")}
              description={t("settings.password.codeHint")}
              inputMode="numeric"
              autoComplete="one-time-code"
              {...bind("code")}
            />
          ) : null}
          <Button type="submit" w="fit-content" loading={change.isPending}>
            {t("settings.password.submit")}
          </Button>
        </Stack>
      </form>
    </Paper>
  );
}
