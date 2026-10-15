import { Anchor, Text } from "@mantine/core";
import { useTranslation } from "react-i18next";

/** Where the attribution links to, as DB-IP asks. */
export const DBIP_URL = "https://db-ip.com";

/**
 * The attribution that DB-IP asks for next to everything that shows its data
 * (CC BY 4.0): "IP Geolocation by DB-IP", linked to db-ip.com. The panel sends
 * the text and the address with its answers; what it sent is shown, else the same
 * words from here.
 */
export function DbIpAttribution({ text, url }: { text?: string; url?: string }) {
  const { t } = useTranslation();
  const href = url?.startsWith("https://") ? url : DBIP_URL;
  return (
    <Text size="xs" c="dimmed">
      <Anchor href={href} target="_blank" rel="noopener noreferrer" size="xs">
        {text !== undefined && text !== "" ? text : t("insights.attribution.text")}
      </Anchor>
    </Text>
  );
}
