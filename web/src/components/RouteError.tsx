import { Button, Center, Stack, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";

/**
 * Shown when a page breaks while it renders. It says nothing of the cause: React
 * Router has logged the details to the console, and they stay out of the page.
 */
export function RouteError() {
  const { t } = useTranslation();
  return (
    <Center h="100vh" p="md">
      <Stack align="center" gap="sm">
        <Title order={2} ta="center">
          {t("errors.routeTitle")}
        </Title>
        <Button
          onClick={() => {
            window.location.reload();
          }}
        >
          {t("errors.reload")}
        </Button>
      </Stack>
    </Center>
  );
}
