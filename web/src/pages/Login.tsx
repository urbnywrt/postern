import { Button, Group, Stack, Text, TextInput } from "@mantine/core";
import { type ChangeEvent, useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useLocation } from "react-router";

import { useLogin, useMe, useSetupStatus } from "../api/hooks/auth";
import { clearNotifications } from "../app/notify";
import {
  normalizeCode,
  validateCode,
  validatePassword,
  validateRequired,
  validationMessage,
} from "../app/validation";
import { AuthLayout } from "../components/AuthLayout";
import { FullPageLoader } from "../components/FullPageLoader";
import { PasswordField } from "../components/PasswordField";

/**
 * The page that the route guard sent a visitor away from, if it did (see
 * RequireAuth). Only a path of this panel is followed.
 */
function redirectTarget(state: unknown): string {
  if (typeof state === "object" && state !== null && "from" in state && typeof state.from === "string") {
    const { from } = state;
    const isPanelPath = from.startsWith("/") && !from.startsWith("//");
    const isPublicPage = from.startsWith("/login") || from.startsWith("/setup");
    if (isPanelPath && !isPublicPage) {
      return from;
    }
  }
  return "/";
}

type Step = "credentials" | "code";

/**
 * Signs an admin in. With TOTP on, the panel checks the password first and says
 * `totp_required`; the page then asks for the code and calls Login again with
 * the same credentials and the code.
 */
export function Login() {
  const { t } = useTranslation();
  const location = useLocation();
  const me = useMe();
  const setupStatus = useSetupStatus();
  const login = useLogin();
  const [step, setStep] = useState<Step>("credentials");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  // Mistakes are pointed out after the first try to send, and then as they are fixed.
  const [submitted, setSubmitted] = useState(false);

  // A session exists: there is nothing to sign in to. This is also where the
  // page leaves once Login has succeeded and `me` has been asked again.
  if (me.isSuccess) {
    return <Navigate to={redirectTarget(location.state)} replace />;
  }
  // No admin yet: the panel has to be set up first.
  if (setupStatus.data?.needsSetup) {
    return <Navigate to="/setup" replace />;
  }
  if (me.isPending || setupStatus.isPending) {
    return <FullPageLoader />;
  }

  const usernameError = submitted ? validateRequired(username) : null;
  const passwordError = submitted ? validatePassword(password) : null;
  const codeError = submitted ? validateCode(code) : null;

  async function submit() {
    if (login.isPending) {
      return; // a second Enter must not send the same try again
    }
    setSubmitted(true);
    if (step === "credentials") {
      if (validateRequired(username) !== null || validatePassword(password) !== null) {
        return;
      }
      try {
        const response = await login.mutateAsync({ username: username.trim(), password });
        if (response.totpRequired) {
          setStep("code");
          setCode("");
          setSubmitted(false);
        } else {
          clearNotifications();
        }
      } catch {
        // the query client has shown why
      }
      return;
    }

    if (validateCode(code) !== null) {
      return;
    }
    try {
      await login.mutateAsync({ username: username.trim(), password, totpCode: normalizeCode(code) });
    } catch {
      // The panel has said why. The code is spent, and the field is for the next one.
      setCode("");
      setSubmitted(false);
      return;
    }
    clearNotifications();
  }

  return (
    <AuthLayout title={t("login.title")}>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        {step === "credentials" ? (
          <Stack gap="sm">
            <TextInput
              label={t("common.username")}
              autoComplete="username"
              autoFocus
              value={username}
              error={validationMessage(t, usernameError)}
              onChange={(event: ChangeEvent<HTMLInputElement>) => {
                setUsername(event.currentTarget.value);
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
            <Button type="submit" fullWidth mt="xs" loading={login.isPending}>
              {t("login.submit")}
            </Button>
          </Stack>
        ) : (
          <Stack gap="sm">
            <Text size="sm">{t("login.totpIntro")}</Text>
            <TextInput
              label={t("login.totpCode")}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              value={code}
              error={validationMessage(t, codeError)}
              onChange={(event: ChangeEvent<HTMLInputElement>) => {
                setCode(event.currentTarget.value);
              }}
            />
            <Group grow mt="xs">
              <Button
                variant="default"
                onClick={() => {
                  setStep("credentials");
                  setCode("");
                  setSubmitted(false);
                }}
              >
                {t("common.back")}
              </Button>
              <Button type="submit" loading={login.isPending}>
                {t("login.verify")}
              </Button>
            </Group>
          </Stack>
        )}
      </form>
    </AuthLayout>
  );
}
