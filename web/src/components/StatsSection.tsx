import { Group, SimpleGrid, Stack, Title } from "@mantine/core";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";

import { useCountries } from "../api/hooks/metrics";
import { useProxySeries } from "../api/hooks/stats";
import { DEFAULT_RANGE, LONGEST_RANGE, type StatsRange } from "../app/ranges";
import { ConnectionsPanel } from "./ConnectionsPanel";
import { CountriesPanel } from "./CountriesPanel";
import { DevicesPanel } from "./DevicesPanel";
import { IpHistoryTable } from "./IpHistoryTable";
import { QueryView } from "./QueryView";
import { RangeSelect } from "./RangeSelect";
import { TrafficPanel } from "./TrafficPanel";

/**
 * The statistics of a proxy over a range that the admin picks (1 hour to 1
 * year): traffic, connections, unique IPs, countries, the IP history when the IP
 * policy keeps it. The probes are in the availability section. It draws charts, so it is only on the page of a
 * proxy, which is loaded on demand.
 */
export function StatsSection({ proxyId }: { proxyId: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const [range, setRange] = useState<StatsRange>(DEFAULT_RANGE);
  const series = useProxySeries(proxyId, range);
  const countries = useCountries({ proxyId }, range);
  // The filter of the IP history offers every country that the panel has data of, not only those of the range:
  // the history is not of the range. It is asked for only under the policy "full", which keeps the history.
  const kept = useCountries({ proxyId }, LONGEST_RANGE, { enabled: countries.data?.policy === "full" });

  return (
    <Stack component="section" aria-labelledby={titleId} gap="md">
      <Group justify="space-between" align="center" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {t("insights.stats.title")}
        </Title>
        <RangeSelect value={range} onChange={setRange} />
      </Group>
      <QueryView query={series}>
        {(data) => (
          <Stack gap="md">
            <TrafficPanel series={data} />
            <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
              <ConnectionsPanel series={data} />
              <DevicesPanel series={data} />
            </SimpleGrid>
          </Stack>
        )}
      </QueryView>
      <CountriesPanel query={countries} />
      {countries.data === undefined ? null : (
        <IpHistoryTable proxyId={proxyId} policy={countries.data.policy} countries={kept.data?.countries ?? countries.data.countries} />
      )}
    </Stack>
  );
}
