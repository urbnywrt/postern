import { Alert, Button, Stack, Tabs, Text, TextInput, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useCreateJoinToken, useNodeInstall } from "../api/hooks/nodes";
import { formatDateTime } from "../app/format";
import { checkPanelUrl, rememberPanelUrl, storedPanelUrl } from "../app/panelUrl";
import type { CreateJoinTokenResponse, Node } from "../gen/postern/panel/v1/nodes_pb";
import { CommandLine } from "./CommandLine";
import { QueryView } from "./QueryView";

/**
 * The install of a node with one Docker command (CreateJoinToken): the admin gives
 * the address that the node reaches the panel at, gets the command, and runs it on
 * the server. The panel renders the command and its compose file; this only shows
 * them. A command is made on the button alone, never when the block opens: each one
 * is a new join token, which replaces the one before and goes into the audit log.
 * When the panel has no image of the node there is no command, and a note says so.
 */
export function NodeDockerInstall({ node }: { node: Node }) {
  const { t } = useTranslation();
  const install = useNodeInstall(node.id);
  return (
    <Stack gap="sm">
      <Title order={3} size="h4">
        {t("nodes.docker.title")}
      </Title>
      <QueryView query={install}>
        {(data) =>
          data.nodeImage === "" ? (
            <Alert color="blue" variant="light">
              {t("nodes.docker.noImage")}
            </Alert>
          ) : (
            <JoinCommand node={node} />
          )
        }
      </QueryView>
    </Stack>
  );
}

function JoinCommand({ node }: { node: Node }) {
  const { t } = useTranslation();
  const join = useCreateJoinToken();
  const [panelUrl, setPanelUrl] = useState(storedPanelUrl);
  // What is wrong with the address shows once the admin has left the field or pressed the button.
  const [shown, setShown] = useState(false);
  const checked = checkPanelUrl(panelUrl.trim());
  const error = shown && !checked.ok ? t(checked.error) : undefined;

  function getCommand() {
    setShown(true);
    if (!checked.ok || join.isPending) {
      return;
    }
    rememberPanelUrl(checked.url);
    join.mutate({ nodeId: node.id, panelUrl: checked.url });
  }

  return (
    <Stack gap="sm">
      <Text size="sm">{t("nodes.docker.intro")}</Text>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          getCommand();
        }}
      >
        <Stack gap="sm">
          <TextInput
            label={t("nodes.docker.panelUrl")}
            description={t("nodes.docker.panelUrlHint")}
            autoComplete="off"
            spellCheck={false}
            value={panelUrl}
            onChange={(event) => {
              setPanelUrl(event.currentTarget.value);
              // A command for another address is not left on the screen.
              join.reset();
            }}
            onBlur={() => {
              setShown(true);
            }}
            error={error}
          />
          <Button type="submit" loading={join.isPending} w="fit-content">
            {t("nodes.docker.get")}
          </Button>
        </Stack>
      </form>
      {join.isError ? (
        <Alert color="red" variant="light">
          {errorMessage(join.error)}
        </Alert>
      ) : null}
      {join.data === undefined ? null : <Command node={node} command={join.data} />}
    </Stack>
  );
}

function Command({ node, command }: { node: Node; command: CreateJoinTokenResponse }) {
  const { t } = useTranslation();
  return (
    <Stack gap="sm">
      <Tabs defaultValue="run" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="run">docker run</Tabs.Tab>
          <Tabs.Tab value="compose">compose.yaml</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="run" pt="sm">
          <CommandLine text={command.dockerCommand} copyLabel={t("nodes.docker.copyRun")} />
        </Tabs.Panel>
        <Tabs.Panel value="compose" pt="sm">
          <Stack gap="xs">
            <Text size="sm">{t("nodes.docker.composeHint")}</Text>
            <CommandLine text={command.composeYaml} copyLabel={t("nodes.docker.copyCompose")} />
          </Stack>
        </Tabs.Panel>
      </Tabs>
      <Text size="sm">
        {t("nodes.docker.expires", { at: formatDateTime(command.expiresUnix) })} {t("nodes.docker.replaces")}
      </Text>
      <Alert color="yellow" variant="light">
        {node.mgmtMode === "hidden"
          ? t("nodes.docker.firewallHidden")
          : t("nodes.docker.firewall", { port: node.mgmtPort })}
      </Alert>
    </Stack>
  );
}
