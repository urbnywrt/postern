import { Box, Group, Paper, Stack, Text, Title } from "@mantine/core";
import { useId } from "react";
import { useTranslation } from "react-i18next";

import { useProxyLinks } from "../api/hooks/proxies";
import { qrDataUri } from "../app/format";
import { LinkCard } from "./LinkCard";
import { QueryView } from "./QueryView";

/**
 * The links of a proxy, which carry its secret, and the QR code of the tg link.
 * They are asked for when the page opens and are not kept after it is left.
 */
export function ProxyLinks({ proxyId }: { proxyId: string }) {
  const { t } = useTranslation();
  const titleId = useId();
  const links = useProxyLinks(proxyId);

  return (
    <Paper component="section" aria-labelledby={titleId} withBorder p="lg" radius="md">
      <Title order={2} size="h3" id={titleId} mb="md">
        {t("proxy.detail.links")}
      </Title>
      <QueryView query={links}>
        {(data) => {
          // The panel draws the QR code as an SVG. It goes to the page as an image,
          // never as markup: an image is drawn statically, and nothing in it can run.
          const qr = qrDataUri(data.qrSvg);
          return (
            <Group align="flex-start" gap="xl" wrap="wrap">
              <Stack gap="md" style={{ flex: "1 1 280px", minWidth: 0 }}>
                <LinkCard label={t("proxy.links.tg")} value={data.tg} copyLabel={t("proxy.links.copyTg")} />
                <LinkCard label={t("proxy.links.https")} value={data.https} copyLabel={t("proxy.links.copyHttps")} />
              </Stack>
              {qr === undefined ? null : (
                <Stack gap={6} align="center">
                  {/* Black modules on a transparent image: white behind them, in the dark theme too. */}
                  <Box style={{ backgroundColor: "#ffffff", lineHeight: 0, borderRadius: "var(--mantine-radius-md)", overflow: "hidden" }}>
                    <img src={qr} alt={t("proxy.links.qrAlt")} width={200} height={200} decoding="async" />
                  </Box>
                  <Text size="xs" c="dimmed" maw={200} ta="center">
                    {t("proxy.links.qrHint")}
                  </Text>
                </Stack>
              )}
            </Group>
          );
        }}
      </QueryView>
    </Paper>
  );
}
