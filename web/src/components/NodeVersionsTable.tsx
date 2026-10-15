import { Anchor, Badge, Button, Group, Paper, Stack, Table, Text, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useSetNodeChannel } from "../api/hooks/versions";
import { orDash } from "../app/format";
import { term } from "../app/versions";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { ChannelSelect } from "./ChannelSelect";

interface NodeVersionsTableProps {
  nodes: Node[];
  /** The channel of the panel, which a node without its own follows. */
  defaultChannel: string;
  onUpdateNodes: () => void;
}

/**
 * The builds of the nodes: agent and edge, the previous agent binary that a
 * rollback goes to, the binaries installed, whether the running agent wrote its
 * healthy marker, its warnings and capabilities, and the channel each follows.
 */
export function NodeVersionsTable({ nodes, defaultChannel, onUpdateNodes }: NodeVersionsTableProps) {
  const { t } = useTranslation();
  const setChannel = useSetNodeChannel();
  const options = [
    { value: "", label: t("versions.nodes.followDefault", { channel: term(t, "versions.channels", defaultChannel) }) },
    { value: "stable", label: t("versions.channels.stable") },
    { value: "latest", label: t("versions.channels.latest") },
  ];

  return (
    <Paper withBorder p="md" radius="md" role="region" aria-label={t("versions.nodes.title")}>
      <Stack gap="sm">
        <Group justify="space-between">
          <Title order={2}>{t("versions.nodes.title")}</Title>
          <Button onClick={onUpdateNodes} disabled={nodes.length === 0}>
            {t("versions.nodes.update")}
          </Button>
        </Group>
        {nodes.length === 0 ? (
          <Text size="sm" c="dimmed">
            {t("versions.nodes.none")}
          </Text>
        ) : (
          <Table.ScrollContainer minWidth={900}>
            <Table verticalSpacing={4} fz="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("versions.nodes.name")}</Table.Th>
                  <Table.Th>{t("versions.nodes.agent")}</Table.Th>
                  <Table.Th>{t("versions.nodes.edge")}</Table.Th>
                  <Table.Th>{t("versions.nodes.previous")}</Table.Th>
                  <Table.Th>{t("versions.nodes.binaries")}</Table.Th>
                  <Table.Th>{t("versions.nodes.healthy")}</Table.Th>
                  <Table.Th>{t("versions.nodes.warnings")}</Table.Th>
                  <Table.Th>{t("versions.nodes.capabilities")}</Table.Th>
                  <Table.Th>{t("versions.nodes.channel")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {nodes.map((node) => (
                  <Table.Tr key={node.id}>
                    <Table.Td>
                      <Anchor component={Link} to={`/nodes/${node.id}/settings`} size="sm">
                        {node.name}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>{orDash(node.agentVersion)}</Table.Td>
                    <Table.Td>{orDash(node.edgeVersion)}</Table.Td>
                    <Table.Td>{orDash(node.previousAgentVersion)}</Table.Td>
                    <Table.Td>{orDash(node.nodeBinaries.join(", "))}</Table.Td>
                    <Table.Td>
                      <Badge size="sm" variant="light" color={node.healthy ? "teal" : "red"}>
                        {node.healthy ? t("versions.nodes.healthyYes") : t("versions.nodes.healthyNo")}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {node.warnings.length > 0 ? (
                        <Group gap={4}>
                          {node.warnings.map((w) => (
                            <Badge key={w} size="xs" color="yellow" variant="light">
                              {w}
                            </Badge>
                          ))}
                        </Group>
                      ) : (
                        "—"
                      )}
                    </Table.Td>
                    <Table.Td>
                      <Text size="xs" c="dimmed">
                        {orDash(node.capabilities.join(", "))}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <ChannelSelect
                        label={t("versions.nodes.channelOf", { name: node.name })}
                        size="xs"
                        value={node.engineChannelDefault ? "" : node.engineChannel}
                        options={options}
                        ask={(channel, confirm) => setChannel.mutateAsync({ nodeId: node.id, channel, confirm })}
                      />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Stack>
    </Paper>
  );
}
