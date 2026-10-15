import { Anchor, Button, Group, Stack, Table, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useNodes } from "../api/hooks/nodes";
import { hostPort, orDash } from "../app/format";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { PlusIcon } from "../components/icons";
import { NodeCreateDialog } from "../components/NodeCreateDialog";
import { EdgeOutdatedBadge, Generation, LastSeen } from "../components/NodeFacts";
import { QueryView } from "../components/QueryView";
import { StatusBadge } from "../components/StatusBadge";

/** The nodes in a table, and the dialog that adds one. */
export function Nodes() {
  const { t } = useTranslation();
  const nodes = useNodes();
  const [adding, setAdding] = useState(false);

  return (
    <Stack gap="lg">
      <Group justify="space-between" align="flex-end" wrap="wrap">
        <Title order={1}>{t("nodes.title")}</Title>
        <Button
          leftSection={<PlusIcon />}
          onClick={() => {
            setAdding(true);
          }}
        >
          {t("nodes.add")}
        </Button>
      </Group>

      <QueryView query={nodes}>
        {(list) => (list.length === 0 ? <Text c="dimmed">{t("nodes.empty")}</Text> : <NodesTable nodes={list} />)}
      </QueryView>

      <NodeCreateDialog
        opened={adding}
        onClose={() => {
          setAdding(false);
        }}
      />
    </Stack>
  );
}

function NodesTable({ nodes }: { nodes: Node[] }) {
  const { t } = useTranslation();
  return (
    <Table.ScrollContainer minWidth={720}>
      <Table verticalSpacing="sm" highlightOnHover>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>{t("nodes.columns.name")}</Table.Th>
            <Table.Th>{t("nodes.columns.status")}</Table.Th>
            <Table.Th>{t("nodes.columns.address")}</Table.Th>
            <Table.Th>{t("nodes.columns.versions")}</Table.Th>
            <Table.Th>{t("nodes.columns.generation")}</Table.Th>
            <Table.Th>{t("nodes.columns.lastSeen")}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {nodes.map((node) => (
            <Table.Tr key={node.id}>
              <Table.Td>
                <Anchor component={Link} to={`/nodes/${node.id}`} fw={500}>
                  {node.name}
                </Anchor>
              </Table.Td>
              <Table.Td>
                <StatusBadge kind="node" value={node.status} />
              </Table.Td>
              <Table.Td>{hostPort(node.mgmtHost, node.mgmtPort)}</Table.Td>
              <Table.Td>
                <Group gap="xs" wrap="nowrap">
                  <span>{`${orDash(node.agentVersion)} / ${orDash(node.edgeVersion)}`}</span>
                  <EdgeOutdatedBadge node={node} />
                </Group>
              </Table.Td>
              <Table.Td>
                <Generation node={node} />
              </Table.Td>
              <Table.Td>
                <LastSeen unix={node.lastSeenUnix} />
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
