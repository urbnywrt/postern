import { Alert, Button, Group, SegmentedControl, Stack, Text, Textarea, TextInput } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../../api/errors";
import { hostPort } from "../../app/format";
import { checkPanelUrl } from "../../app/panelUrl";
import { type FieldErrors, useFormState } from "../../app/useFormState";
import { validatePassword, validateRequired } from "../../app/validation";
import { validateHost, validatePort, validateSshUser } from "../../app/validators";
import type { SshTarget } from "../../gen/postern/panel/v1/deploy_pb";
import { PasswordField } from "../PasswordField";

/** How the panel logs in: with a password, a private key, or the credentials that it keeps. */
export type LoginMethod = "password" | "key" | "saved";

/** What the form of the server holds, as it is typed. */
export interface TargetValues {
  host: string;
  port: string;
  user: string;
  method: LoginMethod;
  password: string;
  privateKey: string;
  passphrase: string;
  /** The address that the node reaches the panel at, on the Docker path. */
  panelUrl: string;
}

interface SshTargetFormProps {
  initial: TargetValues;
  /** The target that the panel keeps for the node, and what credentials it keeps for it ("" for none). */
  saved?: SshTarget;
  savedCredentials: string;
  /**
   * The node image of the panel, which makes the install the Docker path: the form asks for the
   * panel address too. Empty or unset for none: the kit path, without that field.
   */
  nodeImage?: string;
  pending: boolean;
  /** Why the last try failed. */
  error: unknown;
  onSubmit: (values: TargetValues) => void;
}

function isLoginMethod(value: string): value is LoginMethod {
  return value === "password" || value === "key" || value === "saved";
}

/** The server to install the node on: where it is, who to log in as, and how. */
export function SshTargetForm({ initial, saved, savedCredentials, nodeImage = "", pending, error, onSubmit }: SshTargetFormProps) {
  const { t } = useTranslation();
  const methodLabelId = useId();
  const form = useFormState<{ [K in keyof TargetValues]: string }>(initial);
  const { values } = form;
  const method = isLoginMethod(values.method) ? values.method : "password";
  const errors: FieldErrors<typeof values> = {
    host: validateHost(values.host),
    port: validatePort(values.port),
    user: validateSshUser(values.user),
    password: method === "password" ? validatePassword(values.password) : null,
    privateKey: method === "key" ? validateRequired(values.privateKey) : null,
  };
  const fields = form.check(errors);
  const dockerPath = nodeImage !== "";
  const panelUrl = checkPanelUrl(values.panelUrl.trim());
  const panelUrlError = dockerPath && form.submitted && !panelUrl.ok ? t(panelUrl.error) : undefined;

  const methods = [
    { value: "password", label: t("deploy.target.password") },
    { value: "key", label: t("deploy.target.key") },
    ...(savedCredentials === "" ? [] : [{ value: "saved", label: t("deploy.target.saved") }]),
  ];

  return (
    <form
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        if (pending) {
          return; // a second Enter must not send the same try again
        }
        form.setSubmitted(true);
        if (fields.valid && (!dockerPath || panelUrl.ok)) {
          onSubmit({ ...values, method, panelUrl: panelUrl.ok ? panelUrl.url : values.panelUrl });
        }
      }}
    >
      <Stack gap="md" maw={560}>
        {dockerPath ? (
          <>
            <Text size="sm">{t("deploy.target.dockerPath", { image: nodeImage })}</Text>
            <TextInput
              label={t("deploy.target.panelUrl")}
              description={t("deploy.target.panelUrlHint")}
              autoComplete="off"
              spellCheck={false}
              value={values.panelUrl}
              onChange={(event) => {
                form.set("panelUrl", event.currentTarget.value);
              }}
              error={panelUrlError}
            />
          </>
        ) : null}
        <Group align="flex-start" wrap="wrap" gap="md">
          <TextInput
            label={t("deploy.target.host")}
            description={t("deploy.target.hostHint")}
            autoComplete="off"
            spellCheck={false}
            style={{ flex: "3 1 14rem" }}
            {...fields.bind("host")}
          />
          <TextInput
            label={t("deploy.target.port")}
            inputMode="numeric"
            autoComplete="off"
            style={{ flex: "1 1 6rem" }}
            {...fields.bind("port")}
          />
        </Group>
        <TextInput
          label={t("deploy.target.user")}
          description={t("deploy.target.userHint")}
          autoComplete="username"
          spellCheck={false}
          {...fields.bind("user")}
        />

        <Stack gap={6}>
          <Text id={methodLabelId} size="sm" fw={500}>
            {t("deploy.target.method")}
          </Text>
          <SegmentedControl
            aria-labelledby={methodLabelId}
            data={methods}
            value={method}
            onChange={(value) => {
              form.set("method", value);
            }}
            style={{ alignSelf: "flex-start" }}
          />
        </Stack>

        {method === "password" ? (
          <PasswordField label={t("deploy.target.password")} autoComplete="off" {...fields.bind("password")} />
        ) : null}
        {method === "key" ? (
          <>
            <Textarea
              label={t("deploy.target.privateKey")}
              description={t("deploy.target.privateKeyHint")}
              autosize
              minRows={4}
              maxRows={12}
              spellCheck={false}
              autoComplete="off"
              styles={{ input: { fontFamily: "var(--mantine-font-family-monospace)", fontSize: "var(--mantine-font-size-xs)" } }}
              {...fields.bind("privateKey")}
            />
            <PasswordField
              label={t("deploy.target.passphrase")}
              description={t("deploy.target.passphraseHint")}
              autoComplete="off"
              {...fields.bind("passphrase")}
            />
          </>
        ) : null}
        {method === "saved" && saved !== undefined ? (
          <Text size="sm" c="dimmed">
            {t("deploy.target.savedHint", { user: saved.user, server: hostPort(saved.host, saved.port) })}
          </Text>
        ) : null}

        <Text size="xs" c="dimmed">
          {t("deploy.target.secrets")}
        </Text>
        {error === null || error === undefined ? null : (
          <Alert color="red" title={t("common.error")}>
            {errorMessage(error)}
          </Alert>
        )}
        <Group>
          <Button type="submit" loading={pending}>
            {t("deploy.target.submit")}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
