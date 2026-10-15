import { Badge, Group, Paper, Stack, Table, Text, Title } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { useNodeEgressHealth } from "../api/hooks/egress";
import { isExperimental } from "../app/egress";
import { formatRelative, orDash } from "../app/format";
import type { EgressMemberHealth, GetNodeEgressHealthResponse } from "../gen/postern/panel/v1/egress_pb";
import { LastSeen } from "./NodeFacts";
import { QueryView } from "./QueryView";

/** The chain and the egress that a node without a default chain of its own has: it goes out directly. */
const IMPLICIT_CHAIN = "default";
const IMPLICIT_EGRESS = "direct";

const statusColors: Record<string, string> = { up: "teal", down: "red", unknown: "gray" };

/** What a stale member says is dimmed: it may no longer hold. */
const DIMMED = { opacity: 0.5 };

/**
 * The health of the members of the chains of a node, as the node reported it
 * last: whether the edge got an answer of a datacenter of Telegram through
 * each, how long it took, the address that the member goes out from (the exit
 * IP of a WARP egress, for one) and when it was checked. What the panel calls
 * stale (the node is not online, or the report or the check is older than three
 * intervals of the checks of the node) is marked so in words, and dimmed.
 */
export function EgressHealth({ nodeId }: { nodeId: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const health = useNodeEgressHealth(nodeId);
  const reported = health.data !== undefined && health.data.reportedUnix > 0n;
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="baseline" mb="xs" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("egressHealth.title")}
        </Title>
        {health.data !== undefined && reported ? (
          <Group gap="xs">
            {health.data.stale ? <StaleBadge /> : null}
            <Text size="xs" c="dimmed">
              {t("egressHealth.reported", { when: formatRelative(health.data.reportedUnix) })}
            </Text>
          </Group>
        ) : null}
      </Group>
      <Text size="sm" c="dimmed" mb="md">
        {t("egressHealth.intro")}
      </Text>
      {health.data !== undefined && reported ? <StaleNotice report={health.data} /> : null}
      <QueryView query={health}>
        {(data) =>
          data.members.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("egressHealth.empty")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={640}>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("egressHealth.columns.chain")}</Table.Th>
                    <Table.Th>{t("egressHealth.columns.egress")}</Table.Th>
                    <Table.Th>{t("egressHealth.columns.status")}</Table.Th>
                    <Table.Th>{t("egressHealth.columns.latency")}</Table.Th>
                    <Table.Th>{t("egressHealth.columns.exitIp")}</Table.Th>
                    <Table.Th>{t("egressHealth.columns.checked")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data.members.map((member) => (
                    <MemberRow key={`${member.chainId} ${member.egressId} ${member.member}`} member={member} />
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )
        }
      </QueryView>
    </Paper>
  );
}

/** Why the report says nothing of now, when it does not: the node is not online, or it has not reported for long. */
function StaleNotice({ report }: { report: GetNodeEgressHealthResponse }) {
  const { t } = useTranslation();
  if (!report.stale) {
    return null;
  }
  return (
    <Text size="sm" c="orange" mb="md">
      {report.nodeStatus !== "online" ? t("egressHealth.nodeOffline") : t("egressHealth.staleReport")}
    </Text>
  );
}

function StaleBadge() {
  const { t } = useTranslation();
  return (
    <Badge variant="outline" color="orange" size="sm" miw="max-content">
      {t("egressHealth.stale")}
    </Badge>
  );
}

function MemberRow({ member }: { member: EgressMemberHealth }) {
  const { t } = useTranslation();
  const chain = member.chainName || (member.chainId === IMPLICIT_CHAIN ? t("egressHealth.direct") : member.chainId);
  const egress = member.egressName || (member.egressId === IMPLICIT_EGRESS ? t("egressHealth.direct") : member.egressId);
  const dim = member.stale ? DIMMED : undefined;
  return (
    <Table.Tr>
      <Table.Td>{chain}</Table.Td>
      <Table.Td>
        <Stack gap={0}>
          <Group gap="xs" wrap="nowrap">
            <Text size="sm">{egress}</Text>
            {isExperimental(member.egressKind) ? (
              <Badge variant="light" color="yellow" size="sm">
                {t("egress.experimental")}
              </Badge>
            ) : null}
          </Group>
          {member.member !== "" ? (
            <Text size="xs" c="dimmed" ff="monospace">
              {member.member}
            </Text>
          ) : null}
        </Stack>
      </Table.Td>
      <Table.Td style={dim}>
        <StatusOf status={member.status} />
      </Table.Td>
      <Table.Td style={dim}>{member.latencyMs > 0 ? t("egressHealth.latency", { ms: member.latencyMs }) : "—"}</Table.Td>
      <Table.Td style={dim}>
        <Text size="sm" ff="monospace">
          {orDash(member.exitIp)}
        </Text>
      </Table.Td>
      <Table.Td>
        <Group gap="xs" wrap="nowrap">
          {member.checkedUnix > 0n ? <LastSeen unix={member.checkedUnix} /> : "—"}
          {member.stale ? <StaleBadge /> : null}
        </Group>
      </Table.Td>
    </Table.Tr>
  );
}

/** The status of a member; one that this version does not know is shown as it is. */
function StatusOf({ status }: { status: string }) {
  const { t } = useTranslation();
  const label =
    status === "up"
      ? t("egressHealth.status.up")
      : status === "down"
        ? t("egressHealth.status.down")
        : status === "unknown"
          ? t("egressHealth.status.unknown")
          : status;
  return (
    <Badge variant="light" color={statusColors[status] ?? "gray"} miw="max-content">
      {label}
    </Badge>
  );
}
