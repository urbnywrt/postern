import { Badge, Button, Code, Collapse, Group, Paper, Stack, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { checkText, fixName, isStatus, offersFix } from "../app/diagnostics";
import { formatRelative } from "../app/format";
import type { CheckResult } from "../gen/postern/panel/v1/diagnostics_pb";

const STATUS_COLORS = { ok: "teal", warn: "yellow", fail: "red", skip: "gray" } as const;

/** The status of a check as a colored label; one of a newer panel is shown as it is. */
export function CheckStatusBadge({ status }: { status: string }) {
  const { t } = useTranslation();
  return (
    <Badge variant="light" color={isStatus(status) ? STATUS_COLORS[status] : "gray"}>
      {isStatus(status) ? t(`insights.diagnostics.status.${status}`) : status}
    </Badge>
  );
}

/**
 * The fix of a result or of a problem: a button that opens the confirmation when
 * the panel can apply the fix now, else a disabled one with the reason beside it.
 */
export function FixButton({
  fix,
  available,
  reason,
  onFix,
}: {
  fix: string;
  available: boolean;
  reason: string;
  onFix: () => void;
}) {
  const { t } = useTranslation();
  const label = t("insights.diagnostics.fix.action", { fix: fixName(t, fix) });
  if (available) {
    return (
      <Button size="xs" variant="light" color="orange" onClick={onFix}>
        {label}
      </Button>
    );
  }
  return (
    <Group gap="xs" wrap="wrap">
      <Button size="xs" variant="light" disabled>
        {label}
      </Button>
      <Text size="xs" c="dimmed">
        {t("insights.diagnostics.fix.unavailableReason", { reason })}
      </Text>
    </Group>
  );
}

/**
 * One result of a check: its status, what it found and since when, and, opened,
 * the evidence and the hint. All of that text has been scrubbed of secrets and
 * client addresses by the node and the panel. A warn or a fail with a fix has
 * the fix button.
 */
export function CheckRow({ result, onFix }: { result: CheckResult; onFix: (result: CheckResult) => void }) {
  const { t } = useTranslation();
  const [opened, { toggle }] = useDisclosure(false);
  const detailsId = useId();
  const hasDetails = result.evidence !== "" || result.hint !== "";
  const target = result.target === "" ? t("insights.diagnostics.targetNode") : result.target;
  const text = checkText(t, result.id);

  return (
    <Paper withBorder p="sm" radius="sm" data-check={`${result.id} ${result.target}`}>
      <Stack gap={6}>
        <Group justify="space-between" align="flex-start" wrap="wrap" gap="xs">
          <Group gap="xs" align="center" wrap="wrap">
            <CheckStatusBadge status={result.status} />
            <Text size="sm" fw={600}>
              {text === undefined ? result.id : text.label}
            </Text>
            {text === undefined ? null : (
              <Text size="xs" c="dimmed" ff="monospace">
                {result.id}
              </Text>
            )}
            <Text size="xs" c="dimmed">
              {target}
            </Text>
          </Group>
          <Text size="xs" c="dimmed">
            {result.sinceUnix > 0n
              ? t("insights.diagnostics.since", { when: formatRelative(result.sinceUnix) })
              : result.checkedUnix > 0n
                ? t("insights.diagnostics.checked", { when: formatRelative(result.checkedUnix) })
                : null}
          </Text>
        </Group>
        {text === undefined ? null : (
          <Text size="xs" c="dimmed">
            {text.description}
          </Text>
        )}
        <Text size="sm">{result.summary}</Text>
        <Group gap="xs" wrap="wrap">
          {hasDetails ? (
            <Button size="compact-xs" variant="subtle" onClick={toggle} aria-expanded={opened} aria-controls={detailsId}>
              {opened ? t("insights.diagnostics.hideDetails") : t("insights.diagnostics.details")}
            </Button>
          ) : null}
          {offersFix(result) ? (
            <FixButton
              fix={result.fix}
              available={result.fixAvailable}
              reason={result.fixUnavailableReason}
              onFix={() => {
                onFix(result);
              }}
            />
          ) : null}
        </Group>
        {hasDetails ? (
          <Collapse in={opened} id={detailsId}>
            <Stack gap={6}>
              {result.evidence === "" ? null : (
                <div>
                  <Text size="xs" fw={600}>
                    {t("insights.diagnostics.evidence")}
                  </Text>
                  <Code block style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                    {result.evidence}
                  </Code>
                </div>
              )}
              {result.hint === "" ? null : (
                <div>
                  <Text size="xs" fw={600}>
                    {t("insights.diagnostics.hint")}
                  </Text>
                  <Text size="sm">{result.hint}</Text>
                </div>
              )}
            </Stack>
          </Collapse>
        ) : null}
      </Stack>
    </Paper>
  );
}
