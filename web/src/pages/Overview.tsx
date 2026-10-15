import { Badge, Button, Group, SimpleGrid, Stack, Text, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useNodesOverview } from "../api/hooks/metrics";
import { useNodes } from "../api/hooks/nodes";
import { useComponents, usePanelVersion } from "../api/hooks/versions";
import { localMidnightUnix } from "../app/midnight";
import { channelUpdates, posternUpdatable, term } from "../app/versions";
import { CountriesCard } from "../components/CountriesCard";
import { PlusIcon } from "../components/icons";
import { NodeCard } from "../components/NodeCard";
import { ProblemFeed } from "../components/ProblemFeed";
import { QueryView } from "../components/QueryView";
import { TopProxiesCard } from "../components/TopProxiesCard";

/**
 * The landing page: a tile for each node, to see at a glance which of them are up,
 * with its load and the traffic of the day (since the local midnight of the
 * browser, taken when the page opens), and the busiest proxies and the countries
 * of the clients of the last 24 hours. What is wrong now comes first: the problem feed.
 */
export function Overview() {
  const { t } = useTranslation();
  const nodes = useNodes();
  const [since] = useState(() => localMidnightUnix(new Date()));
  const overview = useNodesOverview(since);
  const statsOf = (id: string) => overview.data?.nodes.find((entry) => entry.nodeId === id);

  return (
    <Stack gap="lg">
      <Group gap="sm" align="center">
        <Title order={1}>{t("overview.title")}</Title>
        <UpdateBadges />
      </Group>
      <QueryView query={nodes}>
        {(list) =>
          list.length === 0 ? (
            <Stack gap="sm" align="flex-start">
              <Text c="dimmed">{t("overview.empty")}</Text>
              <Button component={Link} to="/nodes" leftSection={<PlusIcon />}>
                {t("nodes.add")}
              </Button>
            </Stack>
          ) : (
            <Stack gap="lg">
              <ProblemFeed />
              <SimpleGrid cols={{ base: 1, sm: 2, xl: 3 }} spacing="md">
                {list.map((node) => (
                  <NodeCard key={node.id} node={node} stats={statsOf(node.id)} />
                ))}
              </SimpleGrid>
              <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="md">
                <TopProxiesCard nodes={list} />
                <CountriesCard />
              </SimpleGrid>
            </Stack>
          )
        }
      </QueryView>
    </Stack>
  );
}

/**
 * A badge when Postern can be updated (the panel, or a node to the panel's
 * version), and one for each channel that a rollout could move to a newer
 * release; each links to the page of versions.
 */
function UpdateBadges() {
  const { t } = useTranslation();
  const components = useComponents();
  const panel = usePanelVersion();
  const nodes = useNodes();
  const updates = Object.entries(channelUpdates(components.data?.components ?? []));
  return (
    <>
      {posternUpdatable(panel.data, nodes.data ?? []) ? (
        <Badge component={Link} to="/versions" color="orange" variant="light" style={{ cursor: "pointer" }}>
          {t("overview.posternUpdate")}
        </Badge>
      ) : null}
      {updates.map(([channel, names]) => (
        <Badge key={channel} component={Link} to="/versions" color="orange" variant="light" style={{ cursor: "pointer" }}>
          {t("overview.updateAvailable", { channel: term(t, "versions.channels", channel), components: names.join(", ") })}
        </Badge>
      ))}
    </>
  );
}
