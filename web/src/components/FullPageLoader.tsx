import { Center, Loader } from "@mantine/core";
import { useTranslation } from "react-i18next";

export function FullPageLoader() {
  const { t } = useTranslation();
  return (
    <Center h="100vh">
      <Loader role="status" aria-label={t("common.loading")} />
    </Center>
  );
}
