import { Button, Checkbox, Group, Paper, Select, Stack, Switch, Text, TextInput, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { useReleaseSource, useSetReleaseSource } from "../api/hooks/versions";
import { notifySuccess } from "../app/notify";
import { tokenField } from "../app/versions";
import type { ReleaseSource } from "../gen/postern/panel/v1/versions_pb";
import { PasswordField } from "./PasswordField";
import { QueryView } from "./QueryView";

/** Where the releases of Postern come from (GitHub or a Gitea), and the tokens, which are write-only. */
export function ReleaseSourceForm() {
  const { t } = useTranslation();
  const source = useReleaseSource();
  return (
    <Paper withBorder p="md" radius="md" role="region" aria-label={t("versions.source.title")}>
      <Stack gap="sm">
        <Title order={2}>{t("versions.source.title")}</Title>
        <QueryView query={source}>{(data) => <SourceForm key={JSON.stringify(data)} source={data} />}</QueryView>
      </Stack>
    </Paper>
  );
}

function SourceForm({ source }: { source: ReleaseSource }) {
  const { t } = useTranslation();
  const save = useSetReleaseSource();
  const [kind, setKind] = useState(source.kind || "github");
  const [baseUrl, setBaseUrl] = useState(source.baseUrl);
  const [repo, setRepo] = useState(source.repo);
  const [prereleases, setPrereleases] = useState(source.includePrereleases);
  const [token, setToken] = useState("");
  const [removeToken, setRemoveToken] = useState(false);
  const [githubToken, setGithubToken] = useState("");
  const [removeGithubToken, setRemoveGithubToken] = useState(false);

  async function submit() {
    try {
      await save.mutateAsync({
        source: { kind, baseUrl: kind === "gitea" ? baseUrl.trim() : "", repo: repo.trim(), includePrereleases: prereleases },
        token: tokenField(token, removeToken),
        githubToken: tokenField(githubToken, removeGithubToken),
      });
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(t("versions.source.saved"));
  }

  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <Stack gap="sm" maw={520}>
        <Select
          label={t("versions.source.kind")}
          data={[
            { value: "github", label: "GitHub" },
            { value: "gitea", label: "Gitea" },
          ]}
          value={kind}
          onChange={(value) => {
            setKind(value ?? "github");
          }}
          allowDeselect={false}
        />
        {kind === "gitea" ? (
          <TextInput
            label={t("versions.source.baseUrl")}
            placeholder="https://git.example.com"
            value={baseUrl}
            onChange={(event) => {
              setBaseUrl(event.currentTarget.value);
            }}
          />
        ) : null}
        <TextInput
          label={t("versions.source.repo")}
          placeholder="owner/name"
          value={repo}
          onChange={(event) => {
            setRepo(event.currentTarget.value);
          }}
        />
        <Switch
          label={t("versions.source.prereleases")}
          description={t("versions.source.prereleasesHint")}
          checked={prereleases}
          onChange={(event) => {
            setPrereleases(event.currentTarget.checked);
          }}
        />
        <PasswordField
          label={t("versions.source.token")}
          description={source.hasToken ? t("versions.source.tokenSet") : t("versions.source.tokenUnset")}
          value={token}
          autoComplete="off"
          disabled={removeToken}
          onChange={(event) => {
            setToken(event.currentTarget.value);
          }}
        />
        {source.hasToken ? (
          <Checkbox
            label={t("versions.source.removeToken")}
            checked={removeToken}
            onChange={(event) => {
              setRemoveToken(event.currentTarget.checked);
            }}
          />
        ) : null}
        <PasswordField
          label={t("versions.source.githubToken")}
          description={source.hasGithubToken ? t("versions.source.tokenSet") : t("versions.source.tokenUnset")}
          value={githubToken}
          autoComplete="off"
          disabled={removeGithubToken}
          onChange={(event) => {
            setGithubToken(event.currentTarget.value);
          }}
        />
        {source.hasGithubToken ? (
          <Checkbox
            label={t("versions.source.removeGithubToken")}
            checked={removeGithubToken}
            onChange={(event) => {
              setRemoveGithubToken(event.currentTarget.checked);
            }}
          />
        ) : null}
        <Text size="xs" c="dimmed">
          {t("versions.source.tokensHint")}
        </Text>
        <Group>
          <Button type="submit" loading={save.isPending}>
            {t("versions.source.save")}
          </Button>
        </Group>
      </Stack>
    </form>
  );
}
