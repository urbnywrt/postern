import "@mantine/charts/styles.css";

import { BarChart } from "@mantine/charts";
import { Stack, Table, Text } from "@mantine/core";
import type { UseQueryResult } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";

import { countryName } from "../app/countries";
import { formatBytes, formatNumber } from "../app/format";
import type { CountriesResponse } from "../gen/postern/panel/v1/metrics_pb";
import { DbIpAttribution } from "./DbIpAttribution";
import { QueryView } from "./QueryView";
import { StatsCard } from "./StatsCard";

/** The countries in the chart: the rest are in the table. */
const CHART_COUNTRIES = 10;

/**
 * The countries of the clients over the range: the bytes of each, as a bar chart
 * and a table that has "peak unique IPs in a minute" too, with the attribution
 * that DB-IP asks for under it. Under the IP policy "off" nothing is kept, and the
 * panel says so.
 */
export function CountriesPanel({ query }: { query: UseQueryResult<CountriesResponse> }) {
  const { t } = useTranslation();
  return (
    <StatsCard title={t("insights.countries.title")}>
      <QueryView query={query}>{(data) => <CountriesBody data={data} />}</QueryView>
    </StatsCard>
  );
}

function CountriesBody({ data }: { data: CountriesResponse }) {
  const { t, i18n } = useTranslation();
  if (data.policy === "off") {
    return (
      <Text size="sm" c="dimmed">
        {t("insights.countries.off")}
      </Text>
    );
  }
  const name = (code: string) => countryName(code, i18n.language) ?? t("insights.countries.unknown");
  const rows = data.countries.map((country) => ({ ...country, name: name(country.country) }));

  return (
    <Stack gap="sm">
      {data.geoipMonth === "" ? (
        <Text size="sm" c="dimmed">
          {t("insights.countries.noDatabase")}
        </Text>
      ) : null}
      {rows.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.countries.empty")}
        </Text>
      ) : (
        <>
          <BarChart
            h={Math.max(120, Math.min(rows.length, CHART_COUNTRIES) * 32)}
            data={rows.slice(0, CHART_COUNTRIES).map((row) => ({ name: row.name, bytes: Number(row.bytes) }))}
            dataKey="name"
            orientation="vertical"
            series={[{ name: "bytes", label: t("insights.countries.bytes"), color: "indigo.6" }]}
            valueFormatter={(value) => formatBytes(value)}
            yAxisProps={{ width: 120 }}
            barProps={{ isAnimationActive: false }}
          />
          <Table.ScrollContainer minWidth={360}>
            <Table verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("insights.countries.country")}</Table.Th>
                  <Table.Th ta="right">{t("insights.countries.bytes")}</Table.Th>
                  <Table.Th ta="right">{t("insights.countries.ipsPeak")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rows.map((row) => (
                  <Table.Tr key={row.country}>
                    <Table.Td>{row.name}</Table.Td>
                    <Table.Td ta="right">{formatBytes(row.bytes)}</Table.Td>
                    <Table.Td ta="right">{formatNumber(row.ipsPeak)}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </>
      )}
      <DbIpAttribution text={data.attribution} url={data.attributionUrl} />
    </Stack>
  );
}
