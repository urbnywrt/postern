import { Paper, Stack, Table, Text, Title } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { useStorage } from "../api/hooks/settings";
import { formatBytes, formatNumber } from "../app/format";
import type { Storage } from "../gen/postern/panel/v1/settings_pb";
import { DefinitionList } from "./DefinitionList";
import { QueryView } from "./QueryView";

/** Settings: how much room the database of the panel takes, and the rows of the tables that grow. */
export function StorageInfo() {
  const { t } = useTranslation();
  const titleId = useId();
  const storage = useStorage();
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="sm">
        {t("insights.settings.storage.title")}
      </Title>
      <QueryView query={storage}>{(data) => <StorageBody storage={data} />}</QueryView>
    </Paper>
  );
}

function StorageBody({ storage }: { storage: Storage }) {
  const { t } = useTranslation();
  const rows = Object.entries(storage.rows).sort(([a], [b]) => a.localeCompare(b));
  return (
    <Stack gap="sm">
      <DefinitionList
        items={[
          { label: t("insights.settings.storage.file"), value: formatBytes(storage.fileBytes) },
          { label: t("insights.settings.storage.free"), value: formatBytes(storage.freeBytes) },
        ]}
      />
      {rows.length === 0 ? (
        <Text size="sm" c="dimmed">
          {t("insights.settings.storage.empty")}
        </Text>
      ) : (
        <Table verticalSpacing="xs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>{t("insights.settings.storage.table")}</Table.Th>
              <Table.Th ta="right">{t("insights.settings.storage.rows")}</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map(([table, count]) => (
              <Table.Tr key={table}>
                <Table.Td ff="monospace">{table}</Table.Td>
                <Table.Td ta="right">{formatNumber(count)}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
    </Stack>
  );
}
