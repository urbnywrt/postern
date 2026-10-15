import { Badge, Button, Group, Stack, Table, Text, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { type DiagnosticsTarget, useRuns } from "../api/hooks/diagnostics";
import { isRunning, pairRuns, runCounts, runReason } from "../app/diagnostics";
import { formatDateTime, formatNumber } from "../app/format";
import type { DiagnosticRun } from "../gen/postern/panel/v1/diagnostics_pb";
import { QueryView } from "./QueryView";

const RUN_STATE_COLORS: Record<string, string> = { running: "blue", done: "teal", partial: "yellow", skipped: "gray", failed: "red" };
const RUN_STATES = ["running", "done", "partial", "skipped", "failed"] as const;

/** The state of a run as a colored label. */
export function RunStateBadge({ state }: { state: string }) {
  const { t } = useTranslation();
  const known = (RUN_STATES as readonly string[]).includes(state);
  return (
    <Badge variant="light" color={RUN_STATE_COLORS[state] ?? "gray"}>
      {known ? t(`insights.diagnostics.run.state.${state as (typeof RUN_STATES)[number]}`) : state}
    </Badge>
  );
}

/** The label of a regressed after-run. */
export function RegressedBadge() {
  const { t } = useTranslation();
  return (
    <Badge variant="filled" color="red" title={t("insights.diagnostics.run.regressedHint")}>
      {t("insights.diagnostics.run.regressed")}
    </Badge>
  );
}

/**
 * The full runs of a node, or those that cover a proxy, newest first: why each
 * was made, its state, the counts of its results (which the panel gives once
 * the run has ended), and for a run after a change the run before it, with
 * "regressed" when a check got worse.
 */
export function RunHistory({ target, onOpen }: { target: DiagnosticsTarget; onOpen: (runId: string) => void }) {
  const { t } = useTranslation();
  const runs = useRuns(target);
  return (
    <Stack gap="xs">
      <Title order={3} size="h4">
        {t("insights.diagnostics.history.title")}
      </Title>
      <QueryView query={runs}>
        {(data) =>
          data.runs.length === 0 ? (
            <Text size="sm" c="dimmed">
              {t("insights.diagnostics.history.none")}
            </Text>
          ) : (
            <Table.ScrollContainer minWidth={640}>
              <Table verticalSpacing="xs" aria-label={t("insights.diagnostics.history.title")}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>{t("insights.diagnostics.history.started")}</Table.Th>
                    <Table.Th>{t("insights.diagnostics.history.reason")}</Table.Th>
                    <Table.Th>{t("insights.diagnostics.history.state")}</Table.Th>
                    <Table.Th>{t("insights.diagnostics.history.results")}</Table.Th>
                    <Table.Th>{t("insights.diagnostics.history.comparedWith")}</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {pairRuns(data.runs).map(({ run, before }) => (
                    <RunRow key={run.id} run={run} before={before} onOpen={onOpen} />
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          )
        }
      </QueryView>
    </Stack>
  );
}

function RunRow({ run, before, onOpen }: { run: DiagnosticRun; before?: DiagnosticRun; onOpen: (runId: string) => void }) {
  const { t } = useTranslation();
  const started = formatDateTime(run.startedUnix);
  const counts = runCounts(run);
  return (
    <Table.Tr>
      <Table.Td>{started}</Table.Td>
      <Table.Td>
        <Stack gap={0}>
          <Text size="sm">{runReason(t, run.reason)}</Text>
          {run.change === "" ? null : (
            <Text size="xs" c="dimmed">
              {run.change}
            </Text>
          )}
        </Stack>
      </Table.Td>
      <Table.Td>
        <Group gap="xs">
          <RunStateBadge state={run.state} />
          {run.regressed ? <RegressedBadge /> : null}
        </Group>
      </Table.Td>
      <Table.Td>
        {isRunning(run) ? (
          "—"
        ) : (
          <Text size="xs">
            {t("insights.diagnostics.run.counts", {
              ok: formatNumber(counts.ok),
              warn: formatNumber(counts.warn),
              fail: formatNumber(counts.fail),
              skip: formatNumber(counts.skip),
            })}
          </Text>
        )}
      </Table.Td>
      <Table.Td>
        {before === undefined ? (
          run.relatedRunId === "" ? (
            "—"
          ) : (
            <Button size="compact-xs" variant="subtle" onClick={() => { onOpen(run.relatedRunId); }}>
              {t("insights.diagnostics.history.openBefore")}
            </Button>
          )
        ) : (
          <Button size="compact-xs" variant="subtle" onClick={() => { onOpen(before.id); }}>
            {t("insights.diagnostics.history.openRun", { when: formatDateTime(before.startedUnix) })}
          </Button>
        )}
      </Table.Td>
      <Table.Td>
        <Button size="compact-xs" variant="light" onClick={() => { onOpen(run.id); }} aria-label={t("insights.diagnostics.history.openRun", { when: started })}>
          {t("insights.diagnostics.history.open")}
        </Button>
      </Table.Td>
    </Table.Tr>
  );
}
