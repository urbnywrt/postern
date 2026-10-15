import { Anchor, Badge, Button, Collapse, Group, Paper, Stack, Text, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useId, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { useProblemHide, useProblems } from "../api/hooks/diagnostics";
import { problemLink } from "../app/diagnostics";
import { formatRelative } from "../app/format";
import type { Problem } from "../gen/postern/panel/v1/diagnostics_pb";
import { FixButton } from "./CheckRow";
import { FixDialog, type FixOffer } from "./FixDialog";
import { QueryView } from "./QueryView";

const SEVERITY_COLORS: Record<string, string> = { error: "red", warning: "yellow" };

const LIST_STYLE = { listStyle: "none", padding: 0, margin: 0 };

/**
 * What is wrong now across the fleet, errors first: each problem with what it
 * is, since when, a link to its node or proxy, and its fix when the panel can
 * apply one, through ApplyFix with no offered run: also that of an outdated
 * edge, which the panel offers for its own check panel.versions. A problem can
 * be hidden until it changes; the hidden ones are under the feed, behind a
 * toggle, and the count is of the visible ones only.
 */
export function ProblemFeed() {
  const { t } = useTranslation();
  const titleId = useId();
  const hiddenId = useId();
  const problems = useProblems({ includeHidden: true });
  const hide = useProblemHide();
  const [offer, setOffer] = useState<FixOffer | null>(null);
  const [showHidden, { toggle }] = useDisclosure(false);
  const visible = problems.data?.problems.filter((problem) => !problem.hidden).length ?? 0;
  const onHide = (problem: Problem, hidden: boolean) => {
    hide.mutate({ key: problem.key, hide: hidden });
  };

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Group justify="space-between" align="baseline" mb="sm" wrap="wrap">
        <Group gap="xs" align="baseline">
          <Title order={2} size="h3" id={titleId}>
            {t("insights.problems.title")}
          </Title>
          {visible > 0 ? (
            <Badge variant="light" color="red" aria-label={t("insights.problems.count", { count: visible })}>
              {visible}
            </Badge>
          ) : null}
        </Group>
        <Anchor component={Link} to="/journal" size="sm">
          {t("insights.problems.journal")}
        </Anchor>
      </Group>
      <QueryView query={problems}>
        {(data) => {
          const shown = data.problems.filter((problem) => !problem.hidden);
          const hidden = data.problems.filter((problem) => problem.hidden);
          return (
            <Stack gap="xs">
              {shown.length === 0 ? (
                <Text size="sm" c="dimmed">
                  {t("insights.problems.none")}
                </Text>
              ) : (
                <Stack gap="xs" component="ul" style={LIST_STYLE}>
                  {shown.map((problem) => (
                    <ProblemRow key={problem.key} problem={problem} onFix={setOffer} onHide={onHide} busy={hide.isPending && hide.variables.key === problem.key} />
                  ))}
                </Stack>
              )}
              {hidden.length === 0 ? null : (
                <>
                  <Group>
                    <Button variant="subtle" size="compact-sm" onClick={toggle} aria-expanded={showHidden} aria-controls={hiddenId}>
                      {t("insights.problems.hiddenToggle", { count: hidden.length })}
                    </Button>
                  </Group>
                  <Collapse in={showHidden} id={hiddenId}>
                    <Stack gap="xs" component="ul" style={LIST_STYLE}>
                      {hidden.map((problem) => (
                        <ProblemRow key={problem.key} problem={problem} onFix={setOffer} onHide={onHide} busy={hide.isPending && hide.variables.key === problem.key} />
                      ))}
                    </Stack>
                  </Collapse>
                </>
              )}
            </Stack>
          );
        }}
      </QueryView>
      <FixDialog
        offer={offer}
        onClose={() => {
          setOffer(null);
        }}
      />
    </Paper>
  );
}

interface ProblemRowProps {
  problem: Problem;
  onFix: (offer: FixOffer) => void;
  onHide: (problem: Problem, hide: boolean) => void;
  busy: boolean;
}

function ProblemRow({ problem, onFix, onHide, busy }: ProblemRowProps) {
  const { t } = useTranslation();
  const where =
    problem.proxyName !== "" || problem.proxyId !== ""
      ? problem.proxyName || problem.proxyId
      : problem.nodeName !== "" || problem.nodeId !== ""
        ? problem.nodeName || problem.nodeId
        : t("insights.problems.panel");
  const severity = problem.severity === "error" || problem.severity === "warning" ? t(`insights.problems.severity.${problem.severity}`) : problem.severity;

  return (
    <Paper component="li" withBorder p="sm" radius="sm">
      <Stack gap={4}>
        <Group justify="space-between" align="flex-start" wrap="wrap" gap="xs">
          <Group gap="xs" wrap="wrap">
            <Badge variant="light" color={SEVERITY_COLORS[problem.severity] ?? "gray"}>
              {severity}
            </Badge>
            <Anchor component={Link} to={problemLink(problem)} size="sm" fw={600}>
              {where}
            </Anchor>
            {problem.proxyId !== "" && problem.nodeName !== "" ? (
              <Text size="xs" c="dimmed">
                {problem.nodeName}
              </Text>
            ) : null}
          </Group>
          <Group gap="xs" wrap="wrap">
            {problem.sinceUnix > 0n ? (
              <Text size="xs" c="dimmed">
                {t("insights.diagnostics.since", { when: formatRelative(problem.sinceUnix) })}
              </Text>
            ) : null}
            <Button
              variant="subtle"
              color="gray"
              size="compact-xs"
              disabled={busy}
              onClick={() => {
                onHide(problem, !problem.hidden);
              }}
            >
              {problem.hidden ? t("insights.problems.show") : t("insights.problems.hide")}
            </Button>
          </Group>
        </Group>
        <Text size="sm">{problem.summary}</Text>
        {problem.hint === "" ? null : (
          <Text size="xs" c="dimmed">
            {problem.hint}
          </Text>
        )}
        {problem.hidden ? (
          <Text size="xs" c="dimmed" fs="italic">
            {t("insights.problems.hiddenNote")}
          </Text>
        ) : null}
        {problem.fix === "" ? null : (
          <Group>
            <FixButton
              fix={problem.fix}
              available={problem.fixAvailable}
              reason={problem.fixUnavailableReason}
              onFix={() => {
                onFix({ nodeId: problem.nodeId, checkId: problem.checkId, target: problem.target, fix: problem.fix, offeredRunId: "" });
              }}
            />
          </Group>
        )}
      </Stack>
    </Paper>
  );
}
