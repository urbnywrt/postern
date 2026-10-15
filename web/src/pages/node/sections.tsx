import { Badge, Button, Divider, Group, Paper, Select, Stack, Table, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useListeners } from "../../api/hooks/listeners";
import { useUpdateNode } from "../../api/hooks/nodes";
import { useProxies } from "../../api/hooks/proxies";
import { hostPort, orDash } from "../../app/format";
import { notifySuccess } from "../../app/notify";
import { DefinitionList } from "../../components/DefinitionList";
import { PlusIcon } from "../../components/icons";
import { EdgeVersion, Generation, LastError, LastSeen } from "../../components/NodeFacts";
import { NodeDockerInstall } from "../../components/NodeDockerInstall";
import { NodeManualInstall } from "../../components/NodeInstallSteps";
import { ProxyCreateDialog } from "../../components/ProxyCreateDialog";
import { ProxyTable } from "../../components/ProxyTable";
import { QueryView } from "../../components/QueryView";
import { StatusBadge } from "../../components/StatusBadge";
import type { Node } from "../../gen/postern/panel/v1/nodes_pb";

// The sections of the page of a node that only that page uses; its tabs place them.

export function NodeState({ node }: { node: Node }) {
  const { t } = useTranslation();
  const titleId = useId();
  const platform = [node.os, node.arch].filter((part) => part !== "").join(" / ");
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="md">
        {t("nodes.detail.state")}
      </Title>
      <DefinitionList
        items={[
          { label: t("node.status"), value: <StatusBadge kind="node" value={node.status} /> },
          { label: t("node.address"), value: hostPort(node.mgmtHost, node.mgmtPort) },
          { label: t("node.linkHost"), value: orDash(node.linkHost) },
          { label: t("node.agent"), value: orDash(node.agentVersion) },
          { label: t("node.edge"), value: <EdgeVersion node={node} hint /> },
          { label: t("node.platform"), value: orDash(platform) },
          { label: t("node.publicIps"), value: orDash(node.publicIps.join(", ")) },
          { label: t("node.generation"), value: <Generation node={node} /> },
          ...(node.lastError === "" ? [] : [{ label: t("node.lastError"), value: <LastError node={node} /> }]),
          { label: t("node.lastSeen"), value: <LastSeen unix={node.lastSeenUnix} /> },
          ...(node.note === "" ? [] : [{ label: t("node.note"), value: <Text size="sm" style={{ whiteSpace: "pre-wrap" }}>{node.note}</Text> }]),
        ]}
      />
    </Paper>
  );
}

/**
 * The install is for the first install, and for a node that is installed again:
 * with one Docker command, over SSH by the panel, or by hand with the kit and the
 * bundle, which are folded away. `title` says which: the install, or the reinstall.
 */
export function NodeInstall({ node, title }: { node: Node; title: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group gap="sm" mb="md">
        <Title order={2} size="h3" id={titleId}>
          {title}
        </Title>
        {node.status === "provisioning" ? (
          <Badge variant="light" color="blue">
            {t("status.node.provisioning")}
          </Badge>
        ) : null}
      </Group>
      <Stack gap="md">
        <NodeDockerInstall node={node} />
        <Divider label={t("nodes.otherWays")} labelPosition="left" />
        <Group gap="md" align="center" wrap="wrap">
          <Button component={Link} to={`/nodes/${node.id}/install`} variant="default">
            {t("deploy.open")}
          </Button>
          <Text size="sm" c="dimmed">
            {t("deploy.openHint")}
          </Text>
        </Group>
        <NodeManualInstall nodeId={node.id} />
      </Stack>
    </Paper>
  );
}

/** The artifact source as the form shows it: the default is panel. */
const artifactSourceOf = (node: Node) => (node.artifactSource === "direct" ? "direct" : "panel");

/**
 * Where the node gets the binaries of its engines and providers: uploaded by
 * the panel, or downloaded by the node itself, which needs an agent with the
 * capability artifact-direct (the panel refuses it otherwise, and says why).
 */
export function NodeArtifactSource({ node }: { node: Node }) {
  const { t } = useTranslation();
  const titleId = useId();
  const update = useUpdateNode();
  const [source, setSource] = useState(artifactSourceOf(node));
  const canDirect = node.capabilities.includes("artifact-direct");

  async function save() {
    try {
      await update.mutateAsync({ id: node.id, artifactSource: source });
    } catch {
      return; // the query client has shown why
    }
    notifySuccess(t("nodes.artifacts.saved"));
  }

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="xs">
        {t("nodes.artifacts.title")}
      </Title>
      <Text size="sm" c="dimmed" mb="md">
        {t("nodes.artifacts.intro")}
      </Text>
      <form
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <Stack gap="sm">
          <Select
            label={t("nodes.artifacts.source")}
            description={canDirect ? t("nodes.artifacts.directHint") : t("nodes.artifacts.directUnsupported")}
            data={[
              { value: "panel", label: t("nodes.artifacts.sourcePanel") },
              { value: "direct", label: t("nodes.artifacts.sourceDirect"), disabled: !canDirect && source !== "direct" },
            ]}
            value={source}
            onChange={(value) => {
              setSource(value === "direct" ? "direct" : "panel");
            }}
            allowDeselect={false}
          />
          <Group>
            <Button type="submit" size="xs" loading={update.isPending} disabled={source === artifactSourceOf(node)}>
              {t("nodes.artifacts.save")}
            </Button>
          </Group>
        </Stack>
      </form>
    </Paper>
  );
}

/**
 * What listens on the TCP ports of the node, as it said the last time that the panel asked it:
 * the containers of Postern, and the other processes, whose ports a listener cannot take.
 */
export function NodePorts({ node }: { node: Node }) {
  const { t } = useTranslation();
  const titleId = useId();
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="xs">
        {t("nodes.detail.ports")}
      </Title>
      <Text size="sm" c="dimmed" mb="md">
        {t("nodes.ports.intro")}
      </Text>
      {node.portOwners.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("nodes.ports.none")}
        </Text>
      ) : (
        <Table.ScrollContainer minWidth={420}>
          <Table verticalSpacing="xs">
            <Table.Thead>
              <Table.Tr>
                <Table.Th>{t("nodes.ports.address")}</Table.Th>
                <Table.Th>{t("nodes.ports.owner")}</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {node.portOwners.map((owner) => (
                <Table.Tr key={`${owner.bind} ${String(owner.port)} ${owner.owner}`}>
                  <Table.Td>{hostPort(owner.bind, owner.port)}</Table.Td>
                  <Table.Td>
                    <Group gap="xs" wrap="nowrap">
                      <span>{owner.owner}</span>
                      {owner.postern ? (
                        <Badge variant="light" color="teal" size="sm">
                          {t("nodes.ports.postern")}
                        </Badge>
                      ) : null}
                    </Group>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      )}
    </Paper>
  );
}

/** The proxies of the node; `canAdd` offers the form of a new one on it. */
export function NodeProxies({ node, canAdd = true }: { node: Node; canAdd?: boolean }) {
  const { t } = useTranslation();
  const titleId = useId();
  const proxies = useProxies({ nodeId: node.id });
  const listeners = useListeners(node.id);
  const [adding, setAdding] = useState(false);
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="center" mb="md" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("nodes.detail.proxies")}
        </Title>
        {canAdd ? (
          <Button
            size="xs"
            leftSection={<PlusIcon />}
            onClick={() => {
              setAdding(true);
            }}
          >
            {t("proxies.add")}
          </Button>
        ) : null}
      </Group>
      <QueryView query={proxies}>
        {(list) =>
          list.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("nodes.detail.noProxies")}
            </Text>
          ) : (
            <ProxyTable proxies={list} listeners={listeners.data} />
          )
        }
      </QueryView>
      <ProxyCreateDialog
        opened={adding}
        nodeId={node.id}
        onClose={() => {
          setAdding(false);
        }}
      />
    </Paper>
  );
}
