import { Alert, Badge, Button, Group, List, Paper, Stack, Text, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useComponents, useSetNodeChannel } from "../api/hooks/versions";
import { orDash } from "../app/format";
import { type RolloutTarget, term } from "../app/versions";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { ChannelSelect } from "./ChannelSelect";
import { DefinitionList } from "./DefinitionList";
import { RolloutDialog } from "./RolloutDialog";

/**
 * The versions of one node: its agent and edge, the previous binary, the
 * channel it follows (with the confirmation of the proxies a change alters),
 * its warnings in words, and one-node rollouts of the agent or the edge.
 */
export function NodeVersionsCard({ node }: { node: Node }) {
  const { t } = useTranslation();
  const titleId = useId();
  const components = useComponents();
  const setChannel = useSetNodeChannel();
  const [dialog, setDialog] = useState<{ opened: boolean; target?: RolloutTarget }>({ opened: false });
  const defaultChannel = components.data?.defaultChannel ?? "stable";
  const canAgent = node.capabilities.includes("update-self");
  const canEdge = node.capabilities.includes("update-edge");

  return (
    <Paper component="section" role="region" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Stack gap="md">
        <Title order={2} size="h3" id={titleId}>
          {t("versions.node.title")}
        </Title>
        <DefinitionList
          items={[
            { label: t("versions.nodes.agent"), value: orDash(node.agentVersion) },
            { label: t("versions.nodes.edge"), value: orDash(node.edgeVersion) },
            { label: t("versions.nodes.previous"), value: orDash(node.previousAgentVersion) },
            { label: t("versions.nodes.binaries"), value: orDash(node.nodeBinaries.join(", ")) },
            {
              label: t("versions.nodes.healthy"),
              value: (
                <Badge size="sm" variant="light" color={node.healthy ? "teal" : "red"}>
                  {node.healthy ? t("versions.nodes.healthyYes") : t("versions.nodes.healthyNo")}
                </Badge>
              ),
            },
          ]}
        />
        <ChannelSelect
          label={t("versions.nodes.channel")}
          value={node.engineChannelDefault ? "" : node.engineChannel}
          options={[
            { value: "", label: t("versions.nodes.followDefault", { channel: term(t, "versions.channels", defaultChannel) }) },
            { value: "stable", label: t("versions.channels.stable") },
            { value: "latest", label: t("versions.channels.latest") },
          ]}
          ask={(channel, confirm) => setChannel.mutateAsync({ nodeId: node.id, channel, confirm })}
        />
        {node.warnings.length > 0 ? (
          <Alert color="yellow" title={t("versions.nodes.warnings")}>
            <List size="sm" spacing={2}>
              {node.warnings.map((code) => (
                <List.Item key={code}>{term(t, "versions.warning", code)}</List.Item>
              ))}
            </List>
          </Alert>
        ) : null}
        <Group gap="sm">
          <Button
            disabled={!canAgent}
            onClick={() => {
              setDialog({ opened: true, target: { kind: "node", nodeIds: [node.id], agent: true, edge: false } });
            }}
          >
            {t("versions.node.updateAgent")}
          </Button>
          <Button
            variant="light"
            disabled={!canEdge}
            onClick={() => {
              setDialog({ opened: true, target: { kind: "node", nodeIds: [node.id], agent: false, edge: true } });
            }}
          >
            {t("versions.node.rollEdge")}
          </Button>
        </Group>
        {!canAgent || !canEdge ? (
          <Text size="xs" c="dimmed">
            {t("versions.node.needsInstall")}
          </Text>
        ) : null}
      </Stack>
      <RolloutDialog
        opened={dialog.opened}
        target={dialog.target}
        onClose={() => {
          setDialog((current) => ({ ...current, opened: false }));
        }}
      />
    </Paper>
  );
}
