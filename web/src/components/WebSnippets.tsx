import { Paper, Stack, Text, Title } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { useWebSnippets } from "../api/hooks/proxies";
import { CommandLine } from "./CommandLine";
import { QueryView } from "./QueryView";

/**
 * The configuration of the web server in front of a WEB proxy on an
 * http-upstream listener: a Caddy and an nginx fragment that hand the base path
 * of the proxy to the node, as the panel wrote them.
 */
export function WebSnippets({ proxyId }: { proxyId: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const snippets = useWebSnippets(proxyId);

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="xs">
        {t("proxy.snippets.title")}
      </Title>
      <Text size="sm" c="dimmed" mb="md">
        {t("proxy.snippets.intro")}
      </Text>
      <QueryView query={snippets}>
        {(data) => (
          <Stack gap="md">
            <Stack gap={4}>
              <Text size="sm" fw={500}>
                {t("proxy.snippets.caddy")}
              </Text>
              <CommandLine text={data.caddy} copyLabel={t("proxy.snippets.copyCaddy")} />
            </Stack>
            <Stack gap={4}>
              <Text size="sm" fw={500}>
                {t("proxy.snippets.nginx")}
              </Text>
              <CommandLine text={data.nginx} copyLabel={t("proxy.snippets.copyNginx")} />
            </Stack>
          </Stack>
        )}
      </QueryView>
    </Paper>
  );
}
