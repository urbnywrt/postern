import { Anchor, Table, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useTopProxies } from "../api/hooks/metrics";
import { formatBytes, formatNumber } from "../app/format";
import type { Node } from "../gen/postern/panel/v1/nodes_pb";
import { QueryView } from "./QueryView";
import { StatsCard } from "./StatsCard";

/** The proxies that carried the most over the last 24 hours, of every node: their bytes, connections and peak unique IPs. */
export function TopProxiesCard({ nodes }: { nodes: readonly Node[] }) {
  const { t } = useTranslation();
  const top = useTopProxies("", "24h", 10);
  const nodeName = (id: string) => nodes.find((node) => node.id === id)?.name ?? id;

  return (
    <StatsCard title={t("insights.overview.topProxies.title")}>
      <QueryView query={top}>
        {(data) =>
          data.proxies.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("insights.overview.topProxies.empty")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={560}>
              <Table verticalSpacing="xs">
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("insights.overview.topProxies.proxy")}</Table.Th>
                    <Table.Th>{t("insights.overview.topProxies.node")}</Table.Th>
                    <Table.Th ta="right">{t("insights.overview.topProxies.traffic")}</Table.Th>
                    <Table.Th ta="right">{t("insights.overview.topProxies.conns")}</Table.Th>
                    <Table.Th ta="right">{t("insights.overview.topProxies.devices")}</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data.proxies.map((proxy) => (
                    <Table.Tr key={proxy.proxyId}>
                      <Table.Td>
                        <Anchor component={Link} to={`/proxies/${proxy.proxyId}`} size="sm">
                          {proxy.name === "" ? proxy.proxyId : proxy.name}
                        </Anchor>
                      </Table.Td>
                      <Table.Td>{nodeName(proxy.nodeId)}</Table.Td>
                      <Table.Td ta="right">
                        {t("insights.overview.trafficValue", { down: formatBytes(proxy.down), up: formatBytes(proxy.up) })}
                      </Table.Td>
                      <Table.Td ta="right">{formatNumber(proxy.connsNew)}</Table.Td>
                      <Table.Td ta="right">{formatNumber(proxy.devicesPeak)}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )
        }
      </QueryView>
    </StatsCard>
  );
}
