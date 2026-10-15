import { Alert, Anchor, Button, Group, Stack, Text } from "@mantine/core";
import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";
import { useCheckPublicPage } from "../api/hooks/publicpage";
import type { CheckPublicPageResponse } from "../gen/postern/panel/v1/publicpage_pb";

/** The section of the README that sets up on-demand TLS in Caddy. */
export const REVERSE_PROXY_GUIDE = "https://github.com/urbnywrt/postern/blob/main/deploy/panel/README.md#behind-a-reverse-proxy";

/** DD.MM of a time in Unix seconds, in local time. */
function dayMonth(unix: bigint): string {
  const date = new Date(Number(unix) * 1000);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(date.getDate())}.${pad(date.getMonth() + 1)}`;
}

/**
 * The check of the stored host of the public page: a button, and what the panel
 * found, DNS and HTTPS. It runs by itself once when `autoRun` is set at mount: the
 * page is on and has a host. `unsaved` says that the field holds another host, not
 * saved yet, which the check does not see.
 */
export function PublicPageCheck({
  host,
  autoRun,
  unsaved = false,
}: {
  host: string;
  autoRun: boolean;
  unsaved?: boolean;
}) {
  const { t } = useTranslation();
  const check = useCheckPublicPage();
  const started = useRef(false);
  const { mutate } = check;

  useEffect(() => {
    if (autoRun && !started.current) {
      started.current = true;
      mutate();
    }
  }, [autoRun, mutate]);

  // A result for another host (the host was changed and saved since) is not shown.
  const result = check.data?.host === host ? check.data : undefined;

  return (
    <Stack gap={4}>
      <Group gap="sm">
        <Button
          variant="default"
          size="xs"
          loading={check.isPending}
          onClick={() => {
            check.mutate();
          }}
        >
          {t("insights.publicPage.check.button")}
        </Button>
        {unsaved ? (
          <Text size="xs" c="dimmed">
            {t("insights.publicPage.check.unsaved", { host })}
          </Text>
        ) : null}
      </Group>
      {check.isError ? (
        <Text size="sm" c="red" role="alert">
          {t("insights.publicPage.check.failed", { reason: errorMessage(check.error) })}
        </Text>
      ) : null}
      {result !== undefined && !check.isPending ? <CheckResult result={result} /> : null}
    </Stack>
  );
}

function CheckResult({ result }: { result: CheckPublicPageResponse }) {
  const { t } = useTranslation();
  const dns =
    result.addresses.length > 0
      ? t("insights.publicPage.check.dnsFound", { addresses: result.addresses.join(", ") })
      : result.dnsError === "" || result.dnsError === "not found"
        ? t("insights.publicPage.check.dnsNotFound")
        : result.dnsError;
  const https = result.httpsOk
    ? t("insights.publicPage.check.httpsOk", { date: dayMonth(result.certNotAfterUnix) })
    : result.httpsError;
  return (
    <Stack gap={4} aria-live="polite">
      <Text size="sm">
        {t("insights.publicPage.check.dns")}: {dns}
      </Text>
      <Text size="sm" c={result.httpsOk ? undefined : "red"}>
        {t("insights.publicPage.check.https")}: {https}
      </Text>
      {result.httpsOk && !result.servedByPanel ? (
        <Text size="sm" c="orange">
          {t("insights.publicPage.check.notPanel")}
        </Text>
      ) : null}
      {result.httpsOk ? null : (
        <Alert color="blue" role="note" p="xs">
          {t("insights.publicPage.check.hint")}{" "}
          <Anchor href={REVERSE_PROXY_GUIDE} target="_blank" rel="noopener noreferrer">
            {t("insights.publicPage.check.hintLink")}
          </Anchor>
          .
        </Alert>
      )}
    </Stack>
  );
}
