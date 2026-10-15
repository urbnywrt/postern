import { Alert, Badge, Button, Group, Paper, Stack, Table, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { isActiveRollout, type RolloutAction, useRollout, useRolloutAction } from "../api/hooks/versions";
import { formatDateTime, orDash } from "../app/format";
import { rolloutActions, rolloutSummary, statusColor, term } from "../app/versions";
import type { Rollout } from "../gen/postern/panel/v1/versions_pb";
import { StepChecks } from "./StepChecks";

/** One rollout with its steps and the actions that its status takes; asked for every 2 s while it is active. */
export function RolloutView({ rollout: initial }: { rollout: Rollout }) {
  const { t } = useTranslation();
  const query = useRollout(initial.id, initial);
  const rollout = query.data ?? initial;
  const act = useRolloutAction();
  const labels: Record<RolloutAction, string> = {
    continue: t("versions.rolloutView.continue"),
    pause: t("versions.rolloutView.pause"),
    retry: t("versions.rolloutView.retry"),
    abort: t("versions.rolloutView.abort"),
  };

  return (
    <Paper withBorder p="md" radius="md" aria-label={rolloutSummary(rollout, t)} role="region">
      <Stack gap="sm">
        <Group justify="space-between" wrap="wrap">
          <Group gap="xs">
            <Text fw={600}>{rolloutSummary(rollout, t)}</Text>
            <Badge color={statusColor(rollout.status)} variant="light">
              {term(t, "versions.status", rollout.status)}
            </Badge>
            <Badge variant="outline" color="gray">
              {rollout.mode === "auto" ? t("versions.rollout.modeAutoShort", { seconds: String(rollout.pauseSeconds || 120) }) : t("versions.rollout.modeManualShort")}
            </Badge>
          </Group>
          <Group gap="xs">
            {rolloutActions(rollout.status).map((action) => (
              <Button
                key={action}
                size="xs"
                variant={action === "abort" ? "light" : "filled"}
                color={action === "abort" ? "red" : undefined}
                loading={act.isPending && act.variables.action === action}
                disabled={act.isPending}
                onClick={() => {
                  act.mutate({ id: rollout.id, action });
                }}
              >
                {labels[action]}
              </Button>
            ))}
          </Group>
        </Group>
        <Text size="xs" c="dimmed">
          {t("versions.rolloutView.created", { at: formatDateTime(rollout.createdUnix) })}
          {rollout.finishedUnix > 0n ? ` · ${t("versions.rolloutView.finished", { at: formatDateTime(rollout.finishedUnix) })}` : ""}
          {isActiveRollout(rollout.status) && rollout.resumeUnix > 0n
            ? ` · ${t("versions.rolloutView.resumes", { at: formatDateTime(rollout.resumeUnix) })}`
            : ""}
        </Text>
        {rollout.error !== "" ? (
          <Alert color="red" title={t("versions.rolloutView.error")}>
            {rollout.error}
          </Alert>
        ) : null}
        {act.isError ? (
          <Alert color="red" role="alert" title={t("versions.rolloutView.refused")}>
            {errorMessage(act.error)}
          </Alert>
        ) : null}
        {rollout.steps.length > 0 ? (
          <Table.ScrollContainer minWidth={720}>
            <Table verticalSpacing={4} fz="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>#</Table.Th>
                  <Table.Th>{t("versions.rolloutView.step")}</Table.Th>
                  <Table.Th>{t("versions.rolloutView.stepStatus")}</Table.Th>
                  <Table.Th>{t("versions.rolloutView.items")}</Table.Th>
                  <Table.Th>{t("versions.rolloutView.stepError")}</Table.Th>
                  <Table.Th>{t("insights.stepChecks.column")}</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {rollout.steps.map((step) => (
                  <Table.Tr key={step.index} aria-current={step.index === rollout.currentStep && isActiveRollout(rollout.status) ? "step" : undefined}>
                    <Table.Td>{step.index + 1}</Table.Td>
                    <Table.Td>
                      {orDash(step.nodeName || step.nodeId)}
                      {step.proxyId !== "" ? (
                        <Badge ml="xs" size="xs" variant="light">
                          {t("versions.rolloutView.canary")}
                        </Badge>
                      ) : null}
                    </Table.Td>
                    <Table.Td>
                      <Badge size="sm" variant="light" color={statusColor(step.status)}>
                        {term(t, "versions.stepStatus", step.status)}
                      </Badge>
                    </Table.Td>
                    <Table.Td>
                      {t("versions.rolloutView.itemsDone", { done: String(step.itemsDone), total: String(step.items) })}
                      {step.itemsDeferred > 0 ? ` · ${t("versions.rolloutView.itemsDeferred", { count: step.itemsDeferred })}` : ""}
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c={step.error !== "" ? "red" : undefined} style={{ whiteSpace: "pre-wrap" }}>
                        {orDash(step.error)}
                      </Text>
                    </Table.Td>
                    <Table.Td>
                      <StepChecks step={step} />
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        ) : null}
      </Stack>
    </Paper>
  );
}
