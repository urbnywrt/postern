import { Alert, Badge, Button, Group, Paper, Select, SimpleGrid, Stack, Table, Tabs, Text, TextInput, Title } from "@mantine/core";
import { useState } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useJournal } from "../api/hooks/diagnostics";
import { useNodes } from "../api/hooks/nodes";
import { useProxies } from "../api/hooks/proxies";
import {
  EMPTY_JOURNAL_FILTER,
  JOURNAL_PERIODS,
  type JournalFilter,
  type JournalPeriod,
  type JournalSource,
} from "../app/diagnostics";
import { formatDateTime } from "../app/format";
import { proxyTitle } from "../app/proxy";
import type { JournalAudit, JournalEvent } from "../gen/postern/panel/v1/diagnostics_pb";
import { PageLoader } from "../components/PageLoader";

/** The value of a Select for "any": a Select has no empty value. */
const ANY = "-";
const SEVERITY_COLORS: Record<string, string> = { error: "red", warning: "yellow", warn: "yellow", info: "blue" };
const SEVERITIES = ["info", "warning", "error"] as const;

const nowSeconds = () => Math.floor(Date.now() / 1000);

/**
 * The journal: what happened to the nodes and proxies (events), and what the
 * admins did (the audit log, fixes among it), newest first, filtered, a page at a
 * time. A filter takes effect when it is applied; its period ends then.
 */
export function Journal() {
  const { t } = useTranslation();
  const [draft, setDraft] = useState<JournalFilter>(EMPTY_JOURNAL_FILTER);
  const [applied, setApplied] = useState<{ filter: JournalFilter; nowUnix: number }>(() => ({
    filter: EMPTY_JOURNAL_FILTER,
    nowUnix: nowSeconds(),
  }));
  const apply = (filter: JournalFilter) => {
    setDraft(filter);
    setApplied({ filter, nowUnix: nowSeconds() });
  };

  return (
    <Stack gap="lg">
      <Title order={1}>{t("insights.journal.title")}</Title>
      <Text size="sm" c="dimmed">
        {t("insights.journal.intro")}
      </Text>
      <Tabs
        value={draft.source}
        onChange={(value) => {
          apply({ ...draft, source: value === "audit" ? "audit" : "events" });
        }}
      >
        <Tabs.List>
          <Tabs.Tab value="events">{t("insights.journal.tabs.events")}</Tabs.Tab>
          <Tabs.Tab value="audit">{t("insights.journal.tabs.audit")}</Tabs.Tab>
        </Tabs.List>
      </Tabs>
      <Filters
        draft={draft}
        onChange={setDraft}
        onApply={() => {
          apply(draft);
        }}
      />
      <Entries source={applied.filter.source} filter={applied.filter} nowUnix={applied.nowUnix} />
    </Stack>
  );
}

function Filters({ draft, onChange, onApply }: { draft: JournalFilter; onChange: (filter: JournalFilter) => void; onApply: () => void }) {
  const { t } = useTranslation();
  const nodes = useNodes();
  const proxies = useProxies({ nodeId: draft.nodeId });
  const set = (patch: Partial<JournalFilter>) => {
    onChange({ ...draft, ...patch });
  };
  const period = (
    <Select
      label={t("insights.journal.period.label")}
      data={JOURNAL_PERIODS.map((value) => ({ value, label: t(`insights.journal.period.${value}`) }))}
      value={draft.period}
      onChange={(value) => {
        set({ period: (value ?? "all") as JournalPeriod });
      }}
      allowDeselect={false}
    />
  );

  return (
    <Paper withBorder p="md" radius="md">
      <form
        noValidate
        aria-label={t("insights.journal.filters")}
        onSubmit={(event) => {
          event.preventDefault();
          onApply();
        }}
      >
        <Stack gap="sm">
          {draft.source === "events" ? (
            <SimpleGrid cols={{ base: 1, sm: 2, lg: 5 }} spacing="sm">
              <Select
                label={t("insights.journal.node")}
                data={[{ value: ANY, label: t("insights.journal.any") }, ...(nodes.data ?? []).map((node) => ({ value: node.id, label: node.name }))]}
                value={draft.nodeId === "" ? ANY : draft.nodeId}
                onChange={(value) => {
                  set({ nodeId: value === null || value === ANY ? "" : value, proxyId: "" });
                }}
                allowDeselect={false}
              />
              <Select
                label={t("insights.journal.proxy")}
                data={[
                  { value: ANY, label: t("insights.journal.any") },
                  ...(proxies.data ?? []).map((proxy) => ({ value: proxy.id, label: proxyTitle(proxy) })),
                ]}
                value={draft.proxyId === "" ? ANY : draft.proxyId}
                onChange={(value) => {
                  set({ proxyId: value === null || value === ANY ? "" : value });
                }}
                allowDeselect={false}
              />
              <Select
                label={t("insights.journal.severity.label")}
                data={[
                  { value: ANY, label: t("insights.journal.severity.all") },
                  ...SEVERITIES.map((value) => ({ value, label: t(`insights.journal.severity.${value}`) })),
                ]}
                value={draft.minSeverity === "" ? ANY : draft.minSeverity}
                onChange={(value) => {
                  set({ minSeverity: value === null || value === ANY ? "" : value });
                }}
                allowDeselect={false}
              />
              <TextInput
                label={t("insights.journal.kind")}
                placeholder="check."
                value={draft.kindPrefix}
                onChange={(event) => {
                  set({ kindPrefix: event.currentTarget.value });
                }}
              />
              {period}
            </SimpleGrid>
          ) : (
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <TextInput
                label={t("insights.journal.action")}
                placeholder="diagnostics."
                value={draft.actionPrefix}
                onChange={(event) => {
                  set({ actionPrefix: event.currentTarget.value });
                }}
              />
              {period}
            </SimpleGrid>
          )}
          <Group>
            <Button type="submit" size="xs">
              {t("insights.journal.apply")}
            </Button>
          </Group>
        </Stack>
      </form>
    </Paper>
  );
}

function Entries({ source, filter, nowUnix }: { source: JournalSource; filter: JournalFilter; nowUnix: number }) {
  const { t } = useTranslation();
  const journal = useJournal(filter, nowUnix);
  if (journal.data === undefined) {
    return journal.isError ? (
      <Alert color="red" role="alert" title={t("errors.loadTitle")}>
        {errorMessage(journal.error)}
      </Alert>
    ) : (
      <PageLoader />
    );
  }
  const events = journal.data.pages.flatMap((page) => page.events);
  const audit = journal.data.pages.flatMap((page) => page.audit);
  const empty = source === "audit" ? audit.length === 0 : events.length === 0;

  return (
    <Stack gap="sm">
      {journal.isError ? (
        <Alert color="red" role="alert">
          {errorMessage(journal.error)}
        </Alert>
      ) : null}
      {empty ? (
        <Text size="sm" c="dimmed">
          {t("insights.journal.none")}
        </Text>
      ) : source === "audit" ? (
        <AuditTable rows={audit} />
      ) : (
        <EventsTable rows={events} />
      )}
      {journal.hasNextPage ? (
        <Group>
          <Button
            variant="light"
            size="xs"
            loading={journal.isFetchingNextPage}
            onClick={() => {
              void journal.fetchNextPage();
            }}
          >
            {t("insights.journal.loadMore")}
          </Button>
        </Group>
      ) : empty ? null : (
        <Text size="xs" c="dimmed">
          {t("insights.journal.end")}
        </Text>
      )}
    </Stack>
  );
}

/** The details of an entry, as "key: value" lines; the panel has scrubbed the values. */
function Details({ details }: { details: Record<string, string> }) {
  const entries = Object.entries(details).sort(([a], [b]) => a.localeCompare(b));
  if (entries.length === 0) {
    return null;
  }
  return (
    <Text size="xs" c="dimmed" style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
      {entries.map(([key, value]) => `${key}: ${value}`).join("\n")}
    </Text>
  );
}

function EventsTable({ rows }: { rows: JournalEvent[] }) {
  const { t } = useTranslation();
  return (
    <Table.ScrollContainer minWidth={720}>
      <Table verticalSpacing="xs" aria-label={t("insights.journal.tabs.events")}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>{t("insights.journal.time")}</Table.Th>
            <Table.Th>{t("insights.journal.severity.label")}</Table.Th>
            <Table.Th>{t("insights.journal.kindColumn")}</Table.Th>
            <Table.Th>{t("insights.journal.message")}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((event) => (
            <Table.Tr key={event.id}>
              <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDateTime(event.tsUnix)}</Table.Td>
              <Table.Td>
                <Badge variant="light" color={SEVERITY_COLORS[event.severity] ?? "gray"}>
                  {event.severity}
                </Badge>
              </Table.Td>
              <Table.Td>{event.kind}</Table.Td>
              <Table.Td>
                <Stack gap={2}>
                  <Text size="sm">{event.message}</Text>
                  <Details details={event.details} />
                </Stack>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}

function AuditTable({ rows }: { rows: JournalAudit[] }) {
  const { t } = useTranslation();
  return (
    <Table.ScrollContainer minWidth={720}>
      <Table verticalSpacing="xs" aria-label={t("insights.journal.tabs.audit")}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>{t("insights.journal.time")}</Table.Th>
            <Table.Th>{t("insights.journal.admin")}</Table.Th>
            <Table.Th>{t("insights.journal.actionColumn")}</Table.Th>
            <Table.Th>{t("insights.journal.targetColumn")}</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {rows.map((entry) => (
            <Table.Tr key={entry.id}>
              <Table.Td style={{ whiteSpace: "nowrap" }}>{formatDateTime(entry.tsUnix)}</Table.Td>
              <Table.Td>
                {entry.adminName !== ""
                  ? entry.adminName
                  : entry.adminId === ""
                    ? t("insights.journal.system")
                    : t("insights.journal.adminGone")}
              </Table.Td>
              <Table.Td>{entry.action}</Table.Td>
              <Table.Td>
                <Stack gap={2}>
                  <Text size="sm">{entry.target}</Text>
                  <Details details={entry.details} />
                </Stack>
              </Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
