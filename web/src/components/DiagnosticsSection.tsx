import { Alert, Button, Group, Paper, Stack, Text, Title } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { useSearchParams } from "react-router";

import { errorMessage } from "../api/errors";
import { useLatestChecks, useRun, useStartRun } from "../api/hooks/diagnostics";
import { isRunning, runCounts, runReason, scopeOf } from "../app/diagnostics";
import { formatDateTime, formatNumber } from "../app/format";
import type { DiagnosticRun } from "../gen/postern/panel/v1/diagnostics_pb";
import { CheckList } from "./CheckList";
import { QueryView } from "./QueryView";
import { RegressedBadge, RunHistory, RunStateBadge } from "./RunHistory";

/**
 * The diagnostics of a node, or of one of its proxies (`proxyId`): the light
 * checks that the node runs all the time, a full check on request whose results
 * come in while it runs, and the history of the full checks. A run named in the
 * address (`?run=<id>`, from a link after a change or a fix) is opened.
 */
export function DiagnosticsSection({ nodeId, proxyId }: { nodeId: string; proxyId?: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  // The run that is open is in the address, so that a link to it opens it also on this page.
  const [params, setParams] = useSearchParams();
  const runId = params.get("run") ?? "";
  const setRunId = (id: string) => {
    setParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        if (id === "") {
          next.delete("run");
        } else {
          next.set("run", id);
        }
        return next;
      },
      { replace: true, preventScrollReset: true },
    );
  };
  const target = { nodeId, proxyId };
  const latest = useLatestChecks(target);
  const start = useStartRun();
  const forProxy = proxyId !== undefined && proxyId !== "";

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="center" mb="xs" wrap="wrap">
        <Title order={2} size="h3" id={titleId}>
          {forProxy ? t("insights.diagnostics.proxyTitle") : t("insights.diagnostics.title")}
        </Title>
        <Button
          size="xs"
          loading={start.isPending}
          onClick={() => {
            start.mutate(
              { nodeId, scope: scopeOf(proxyId) },
              {
                onSuccess: (answer) => {
                  setRunId(answer.runId);
                },
              },
            );
          }}
        >
          {forProxy ? t("insights.diagnostics.runProxy") : t("insights.diagnostics.runFull")}
        </Button>
      </Group>
      <Text size="sm" c="dimmed" mb="md">
        {forProxy ? t("insights.diagnostics.proxyIntro") : t("insights.diagnostics.intro")}
      </Text>
      <Stack gap="lg">
        {start.isError ? (
          <Alert color="red" role="alert">
            {t("insights.diagnostics.startFailed", { reason: errorMessage(start.error) })}
          </Alert>
        ) : null}
        {runId === "" ? null : (
          <RunView
            key={runId}
            runId={runId}
            onOpen={setRunId}
            onClose={() => {
              setRunId("");
            }}
          />
        )}
        <Stack gap="xs">
          <Title order={3} size="h4">
            {t("insights.diagnostics.light")}
          </Title>
          <QueryView query={latest}>
            {(data) =>
              data.results.length === 0 ? (
                <Text size="sm" c="dimmed">
                  {t("insights.diagnostics.lightNone")}
                </Text>
              ) : (
                <CheckList results={data.results} nodeId={nodeId} offeredRunId="" />
              )
            }
          </QueryView>
        </Stack>
        <RunHistory target={target} onOpen={setRunId} />
      </Stack>
    </Paper>
  );
}

/** A full run: asked for every second while it runs, its results by layer, and the run it is compared with. */
function RunView({ runId, onOpen, onClose }: { runId: string; onOpen: (runId: string) => void; onClose: () => void }) {
  const { t } = useTranslation();
  const titleId = useId();
  const run = useRun(runId);
  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="md" radius="md" bg="var(--mantine-color-default-hover)">
      <Group justify="space-between" align="center" mb="sm" wrap="wrap">
        <Title order={3} size="h4" id={titleId}>
          {t("insights.diagnostics.run.title")}
        </Title>
        <Button size="compact-xs" variant="subtle" onClick={onClose}>
          {t("insights.diagnostics.close")}
        </Button>
      </Group>
      <QueryView query={run}>{(data) => <RunBody run={data} onOpen={onOpen} />}</QueryView>
    </Paper>
  );
}

function RunBody({ run, onOpen }: { run: DiagnosticRun; onOpen: (runId: string) => void }) {
  const { t } = useTranslation();
  const counts = runCounts(run);
  return (
    <Stack gap="sm">
      <Group gap="xs" wrap="wrap">
        <RunStateBadge state={run.state} />
        {run.regressed ? <RegressedBadge /> : null}
        <Text size="sm">{runReason(t, run.reason)}</Text>
        <Text size="xs" c="dimmed">
          {run.scope}
        </Text>
        <Text size="xs" c="dimmed">
          {t("insights.diagnostics.run.started", { when: formatDateTime(run.startedUnix) })}
        </Text>
      </Group>
      {run.change === "" ? null : <Text size="sm">{run.change}</Text>}
      <Text size="sm" role="status">
        {t("insights.diagnostics.run.counts", {
          ok: formatNumber(counts.ok),
          warn: formatNumber(counts.warn),
          fail: formatNumber(counts.fail),
          skip: formatNumber(counts.skip),
        })}
      </Text>
      {run.error === "" ? null : (
        <Alert color="red">{t("insights.diagnostics.run.error", { error: run.error })}</Alert>
      )}
      {run.regressed ? (
        <Text size="sm" c="red">
          {t("insights.diagnostics.run.regressedHint")}
        </Text>
      ) : null}
      {run.relatedRunId === "" ? null : (
        <Group>
          <Button
            size="compact-xs"
            variant="subtle"
            onClick={() => {
              onOpen(run.relatedRunId);
            }}
          >
            {t("insights.diagnostics.history.openBefore")}
          </Button>
        </Group>
      )}
      {isRunning(run) ? (
        <Text size="sm" c="dimmed">
          {t("insights.diagnostics.run.running")}
        </Text>
      ) : null}
      {run.results.length === 0 && isRunning(run) ? null : (
        <CheckList results={run.results} nodeId={run.nodeId} offeredRunId={run.id} />
      )}
    </Stack>
  );
}
