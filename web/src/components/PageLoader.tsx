import { Center, Loader } from "@mantine/core";
import { useTranslation } from "react-i18next";

/** A spinner for the part of a page that is on its way, inside the app shell (FullPageLoader is for the whole window). */
export function PageLoader() {
  const { t } = useTranslation();
  return (
    <Center py="xl">
      <Loader role="status" aria-label={t("common.loading")} />
    </Center>
  );
}
