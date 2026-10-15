import { Center, Loader, Stack, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { useMe } from "../api/hooks/auth";
import { ChangePasswordForm } from "../components/ChangePasswordForm";
import { GeoIPSettings } from "../components/GeoIPSettings";
import { PublicPageForm } from "../components/PublicPageForm";
import { StatsSettingsForm } from "../components/StatsSettingsForm";
import { StorageInfo } from "../components/StorageInfo";
import { TotpSetup } from "../components/TotpSetup";

/**
 * The account of the signed-in admin (password, two-factor authentication), the
 * statistics and privacy settings, the country database, the storage of the
 * panel and the public page.
 */
export function Settings() {
  const { t } = useTranslation();
  const { data: me } = useMe();

  if (me === undefined) {
    // The route guard has the answer before it shows a page, so this is brief.
    return (
      <Center>
        <Loader role="status" aria-label={t("common.loading")} />
      </Center>
    );
  }

  return (
    <Stack gap="lg" maw={640}>
      <Title order={1}>{t("settings.title")}</Title>
      <ChangePasswordForm totpEnabled={me.totpEnabled} />
      <TotpSetup enabled={me.totpEnabled} />
      <StatsSettingsForm />
      <GeoIPSettings />
      <StorageInfo />
      <PublicPageForm />
    </Stack>
  );
}
