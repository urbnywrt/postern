import { Anchor, Button, Group, Modal, Stack, Text, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { useGeoIP } from "../api/hooks/geoip";
import { usePanelVersion } from "../api/hooks/versions";
import { orDash } from "../app/format";
import { DbIpAttribution } from "./DbIpAttribution";
import { DefinitionList } from "./DefinitionList";
import { QueryView } from "./QueryView";

/** The licence of Postern, linked to its text. */
export const AGPL_URL = "https://www.gnu.org/licenses/agpl-3.0.html";
/** The licence of the DB-IP database when the panel does not say. */
const DBIP_LICENCE = "CC BY 4.0";

/**
 * About Postern, from the shell: the version of the panel, its licence
 * (AGPL-3.0), and the attribution and licence of the DB-IP country data. The
 * calls are made only while the dialog is open.
 */
export function AboutDialog({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Modal opened={opened} onClose={onClose} title={t("insights.about.title")} centered>
      <AboutBody onClose={onClose} />
    </Modal>
  );
}

function AboutBody({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const version = usePanelVersion();
  const geoip = useGeoIP();
  const licence = geoip.data?.licence !== undefined && geoip.data.licence !== "" ? geoip.data.licence : DBIP_LICENCE;

  return (
    <Stack gap="md">
      <QueryView query={version}>
        {(info) => (
          <DefinitionList
            items={[
              { label: t("insights.about.version"), value: orDash(info.version) },
              { label: t("insights.about.commit"), value: orDash(info.commit) },
              { label: t("insights.about.built"), value: orDash(info.date) },
            ]}
          />
        )}
      </QueryView>
      <Text size="sm">
        {t("insights.about.licence")}{" "}
        <Anchor href={AGPL_URL} target="_blank" rel="noopener noreferrer" size="sm">
          {t("insights.about.licenceLink")}
        </Anchor>
      </Text>
      <Stack gap={4}>
        <Title order={3} size="h5">
          {t("insights.about.geoip")}
        </Title>
        <Text size="sm">{t("insights.about.geoipText", { licence })}</Text>
        <DbIpAttribution text={geoip.data?.attribution} url={geoip.data?.attributionUrl} />
      </Stack>
      <Group justify="flex-end">
        <Button variant="default" onClick={onClose}>
          {t("insights.about.close")}
        </Button>
      </Group>
    </Stack>
  );
}
