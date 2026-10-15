import { Code as ConnectCode, ConnectError } from "@connectrpc/connect";
import { Alert, Group, Pagination, Select, Stack, Table, Text } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useIpSightings } from "../api/hooks/metrics";
import { countryName } from "../app/countries";
import { formatBytes, formatDateTime, formatNumber } from "../app/format";
import type { CountryTotal } from "../gen/postern/panel/v1/metrics_pb";
import { PageLoader } from "./PageLoader";
import { StatsCard } from "./StatsCard";

/** The rows of a page. */
export const IP_PAGE_SIZE = 50;

const POLICIES = ["full", "countries", "off"] as const;
type Policy = (typeof POLICIES)[number];
const isPolicy = (value: string): value is Policy => POLICIES.some((policy) => policy === value);

const isFailedPrecondition = (error: unknown) =>
  error instanceof ConnectError && error.code === ConnectCode.FailedPrecondition;

interface IpHistoryTableProps {
  proxyId: string;
  /** The IP policy, as the countries of the proxy said it. */
  policy: string;
  /** The countries that the panel has data of (over the longest range): the choices of the filter. */
  countries: readonly CountryTotal[];
}

/**
 * Where client addresses were seen on a proxy, the ones seen last first, a page
 * at a time, of every country or of one. The panel keeps them only under the IP
 * policy "full": under another one the table is not asked for, and a note names
 * the policy instead. A policy that changes while the page is open makes the panel
 * refuse (FAILED_PRECONDITION), and the note says so.
 */
export function IpHistoryTable({ proxyId, policy, countries }: IpHistoryTableProps) {
  const { t } = useTranslation();
  return (
    <StatsCard title={t("insights.ipHistory.title")}>
      {policy === "full" ? (
        <Sightings proxyId={proxyId} countries={countries} />
      ) : (
        <Text size="sm" c="dimmed">
          {t("insights.ipHistory.policyNote", {
            policy,
            meaning: isPolicy(policy) ? t(`insights.ipHistory.meaning.${policy}`) : "",
          })}
        </Text>
      )}
    </StatsCard>
  );
}

function Sightings({ proxyId, countries }: { proxyId: string; countries: readonly CountryTotal[] }) {
  const { t, i18n } = useTranslation();
  const [country, setCountry] = useState("");
  const [page, setPage] = useState(1);
  const sightings = useIpSightings(proxyId, {
    country,
    limit: IP_PAGE_SIZE,
    offset: (page - 1) * IP_PAGE_SIZE,
    enabled: true,
  });
  const name = (code: string) => countryName(code, i18n.language) ?? t("insights.countries.unknown");
  // The country of the clients whose country is unknown ("") cannot be asked for: empty is every country.
  const choices = countries.filter((entry) => entry.country !== "");

  if (sightings.isError && isFailedPrecondition(sightings.error)) {
    return (
      <Text size="sm" c="dimmed">
        {t("insights.ipHistory.policyChanged", { reason: errorMessage(sightings.error) })}
      </Text>
    );
  }

  const data = sightings.data;
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / IP_PAGE_SIZE));
  const first = total === 0 ? 0 : (page - 1) * IP_PAGE_SIZE + 1;
  const last = Math.min(total, page * IP_PAGE_SIZE);

  return (
    <Stack gap="sm">
      <Select
        label={t("insights.ipHistory.filter")}
        maw={280}
        data={[
          { value: "", label: t("insights.ipHistory.allCountries") },
          ...choices.map((entry) => ({ value: entry.country, label: name(entry.country) })),
        ]}
        value={country}
        onChange={(value) => {
          setCountry(value ?? "");
          setPage(1);
        }}
        allowDeselect={false}
      />
      {sightings.isError ? (
        <Alert color="red" title={t("errors.loadTitle")}>
          {errorMessage(sightings.error)}
        </Alert>
      ) : null}
      {data === undefined ? (
        sightings.isError ? null : (
          <PageLoader />
        )
      ) : data.sightings.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.ipHistory.empty")}
        </Text>
      ) : (
        <>
          <Table.ScrollContainer minWidth={640}>
            <Table verticalSpacing="xs">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>{t("insights.ipHistory.ip")}</Table.Th>
                  <Table.Th>{t("insights.ipHistory.country")}</Table.Th>
                  <Table.Th>{t("insights.ipHistory.firstSeen")}</Table.Th>
                  <Table.Th>{t("insights.ipHistory.lastSeen")}</Table.Th>
                  <Table.Th ta="right">{t("insights.ipHistory.bytes")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {data.sightings.map((sighting) => (
                  <Table.Tr key={sighting.ip}>
                    <Table.Td ff="monospace">{sighting.ip}</Table.Td>
                    <Table.Td>{name(sighting.country)}</Table.Td>
                    <Table.Td>{formatDateTime(sighting.firstSeenUnix)}</Table.Td>
                    <Table.Td>{formatDateTime(sighting.lastSeenUnix)}</Table.Td>
                    <Table.Td ta="right">{formatBytes(sighting.bytes)}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
          <Group justify="space-between" wrap="wrap">
            <Text size="xs" c="dimmed">
              {t("insights.ipHistory.shown", {
                from: formatNumber(first),
                to: formatNumber(last),
                total: formatNumber(total),
              })}
            </Text>
            {pages > 1 ? <Pagination size="sm" total={pages} value={page} onChange={setPage} /> : null}
          </Group>
        </>
      )}
    </Stack>
  );
}
