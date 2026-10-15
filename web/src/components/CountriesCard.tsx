import { Stack, Table, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { useCountries } from "../api/hooks/metrics";
import { countryName } from "../app/countries";
import { formatBytes, formatNumber } from "../app/format";
import type { CountriesResponse } from "../gen/postern/panel/v1/metrics_pb";
import { DbIpAttribution } from "./DbIpAttribution";
import { QueryView } from "./QueryView";
import { StatsCard } from "./StatsCard";

/** The countries listed on the Overview; the page of a proxy has them all. */
const SHOWN = 10;

/**
 * The countries of the clients of every proxy over the last 24 hours, with the
 * attribution that DB-IP asks for. A table and no chart: the Overview is in the
 * chunk that every page loads, and the chart library is not.
 */
export function CountriesCard() {
  const { t } = useTranslation();
  const countries = useCountries({}, "24h");
  return (
    <StatsCard title={t("insights.overview.countries.title")}>
      <QueryView query={countries}>{(data) => <CountriesTable data={data} />}</QueryView>
    </StatsCard>
  );
}

function CountriesTable({ data }: { data: CountriesResponse }) {
  const { t, i18n } = useTranslation();
  if (data.policy === "off") {
    return (
      <Text size="sm" c="dimmed">
        {t("insights.countries.off")}
      </Text>
    );
  }
  const shown = data.countries.slice(0, SHOWN);
  const more = data.countries.length - shown.length;
  return (
    <Stack gap="sm">
      {shown.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.countries.empty")}
        </Text>
      ) : (
        <Table verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("insights.countries.country")}</Table.Th>
              <Table.Th ta="right">{t("insights.countries.bytes")}</Table.Th>
              <Table.Th ta="right">{t("insights.countries.ipsPeak")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {shown.map((country) => (
              <Table.Tr key={country.country}>
                <Table.Td>{countryName(country.country, i18n.language) ?? t("insights.countries.unknown")}</Table.Td>
                <Table.Td ta="right">{formatBytes(country.bytes)}</Table.Td>
                <Table.Td ta="right">{formatNumber(country.ipsPeak)}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      {more > 0 ? (
        <Text size="xs" c="dimmed">
          {t("insights.overview.countries.more", { count: more })}
        </Text>
      ) : null}
      <DbIpAttribution text={data.attribution} url={data.attributionUrl} />
    </Stack>
  );
}
