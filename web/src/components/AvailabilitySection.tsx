import { Stack, Text, Title } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import type { Proxy } from "../gen/postern/panel/v1/proxies_pb";
import { DiagnosticsSection } from "./DiagnosticsSection";
import { ProbesPanel } from "./ProbesPanel";

/**
 * Whether a proxy can be reached: its probes from the panel and from its node,
 * and the checks of its scope, run on request ("check this proxy").
 */
export function AvailabilitySection({ proxy }: { proxy: Proxy }) {
  const { t } = useTranslation();
  const titleId = useId();
  return (
    <Stack component="section" aria-labelledby={titleId} gap="md">
      <Title order={2} size="h3" id={titleId}>
        {t("insights.availability.title")}
      </Title>
      <Text size="sm" c="dimmed">
        {t("insights.availability.intro")}
      </Text>
      <ProbesPanel proxyId={proxy.id} />
      <DiagnosticsSection nodeId={proxy.nodeId} proxyId={proxy.id} />
    </Stack>
  );
}
