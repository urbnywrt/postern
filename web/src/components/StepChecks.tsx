import { Anchor, Group, Stack, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

import { runLink } from "../app/diagnostics";
import type { RolloutStep } from "../gen/postern/panel/v1/versions_pb";
import { RegressedBadge, RunStateBadge } from "./RunHistory";

/**
 * The full checks of a step's node before and after the step, each a link to
 * the run on the node's page, with its state and, after the step, the badge
 * of a regression. They inform: a regression never fails a step.
 */
export function StepChecks({ step }: { step: RolloutStep }) {
  const { t } = useTranslation();
  if (step.beforeRunId === "" && step.afterRunId === "") {
    return (
      <Text size="sm" c="dimmed" title={t("insights.stepChecks.hint")}>
        {t("insights.stepChecks.none")}
      </Text>
    );
  }
  return (
    <Stack gap={2} title={t("insights.stepChecks.hint")}>
      {step.beforeRunId !== "" ? (
        <Group gap={4} wrap="nowrap">
          <Anchor component={Link} to={runLink(step.nodeId, step.beforeRunId)} size="sm" aria-label={t("insights.stepChecks.openBefore")}>
            {t("insights.stepChecks.before")}
          </Anchor>
          <RunStateBadge state={step.beforeRunState} />
        </Group>
      ) : null}
      {step.afterRunId !== "" ? (
        <Group gap={4} wrap="nowrap">
          <Anchor component={Link} to={runLink(step.nodeId, step.afterRunId)} size="sm" aria-label={t("insights.stepChecks.openAfter")}>
            {t("insights.stepChecks.after")}
          </Anchor>
          <RunStateBadge state={step.afterRunState} />
          {step.afterRegressed ? <RegressedBadge /> : null}
        </Group>
      ) : null}
    </Stack>
  );
}
