import { Button, Stack, Text, TextInput } from "@mantine/core";
import { type ChangeEvent, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useSearchParams } from "react-router";

import { useSetup, useSetupStatus } from "../api/hooks/auth";
import { notifySuccess } from "../app/notify";
import {
  MIN_PASSWORD_CHARS,
  validateNewPassword,
  validateRepeat,
  validateRequired,
  validateUsername,
  validationMessage,
  type ValidationError,
} from "../app/validation";
import { AuthLayout } from "../components/AuthLayout";
import { FullPageLoader } from "../components/FullPageLoader";
import { LoadError } from "../components/LoadError";
import { PasswordField } from "../components/PasswordField";

interface Values {
  token: string;
  username: string;
  password: string;
  repeat: string;
}

type Errors = Record<keyof Values, ValidationError | null>;

function validate(values: Values): Errors {
  return {
    token: validateRequired(values.token),
    username: validateUsername(values.username),
    password: validateNewPassword(values.password),
    repeat: validateRepeat(values.password, values.repeat),
  };
}

const hasErrors = (errors: Errors) => Object.values(errors).some((error) => error !== null);

/**
 * Creates the first admin. The panel prints a link to this page, with the
 * one-time setup token in `?token=`, when it starts without an admin. The page
 * reads the token and takes it out of the address.
 */
export function Setup() {
  const { t } = useTranslation();
  const [searchParams, setSearchParams] = useSearchParams();
  const status = useSetupStatus();
  const setup = useSetup();
  const [values, setValues] = useState<Values>({
    token: searchParams.get("token") ?? "",
    username: "",
    password: "",
    repeat: "",
  });
  // The token is in the state now. It leaves the address bar and the history at
  // once (replaced, not pushed), so that nobody who sees the screen or the
  // history later can finish the setup with it.
  useEffect(() => {
    if (searchParams.has("token")) {
      const rest = new URLSearchParams(searchParams);
      rest.delete("token");
      setSearchParams(rest, { replace: true });
    }
  }, [searchParams, setSearchParams]);
  // Mistakes are pointed out after the first try to send, and then as they are fixed.
  const [submitted, setSubmitted] = useState(false);

  if (status.isPending) {
    return <FullPageLoader />;
  }
  if (status.isError) {
    return (
      <LoadError
        error={status.error}
        onRetry={() => {
          void status.refetch();
        }}
      />
    );
  }
  // An admin exists: there is nothing to set up. This is also where the page
  // leaves once the first admin has been made.
  if (!status.data.needsSetup) {
    return <Navigate to="/login" replace />;
  }

  const errors = submitted ? validate(values) : undefined;
  const bind = (field: keyof Values) => ({
    value: values[field],
    error: validationMessage(t, errors?.[field] ?? null),
    onChange: (event: ChangeEvent<HTMLInputElement>) => {
      const { value } = event.currentTarget;
      setValues((current) => ({ ...current, [field]: value }));
    },
  });

  async function submit() {
    if (setup.isPending) {
      return; // a second Enter must not send the same try again
    }
    setSubmitted(true);
    if (hasErrors(validate(values))) {
      return;
    }
    try {
      await setup.mutateAsync({
        setupToken: values.token.trim(),
        username: values.username.trim(),
        password: values.password,
      });
    } catch {
      return; // the query client has shown why
    }
    // The panel has an admin now, and the page moves to the login page by itself.
    notifySuccess(t("setup.done"));
  }

  return (
    <AuthLayout title={t("setup.title")}>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <Stack gap="sm">
          <Text size="sm" c="dimmed">
            {t("setup.intro")}
          </Text>
          <TextInput
            label={t("setup.token")}
            description={t("setup.tokenHint")}
            autoComplete="off"
            spellCheck={false}
            {...bind("token")}
          />
          <TextInput
            label={t("common.username")}
            description={t("setup.usernameHint")}
            autoComplete="username"
            {...bind("username")}
          />
          <PasswordField
            label={t("common.password")}
            description={t("common.passwordHint", { min: MIN_PASSWORD_CHARS })}
            autoComplete="new-password"
            {...bind("password")}
          />
          <PasswordField
            label={t("setup.repeatPassword")}
            autoComplete="new-password"
            {...bind("repeat")}
          />
          <Button type="submit" fullWidth mt="xs" loading={setup.isPending}>
            {t("setup.submit")}
          </Button>
        </Stack>
      </form>
    </AuthLayout>
  );
}
