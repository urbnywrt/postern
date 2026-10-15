import { Button, Center, Stack, Text, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { errorMessage } from "../api/errors";

/** A whole page that could not be loaded: what went wrong, and a way to try again. */
export function LoadError({ error, onRetry }: { error: unknown; onRetry: () => void }) {
  const { t } = useTranslation();
  return (
    <Center h="100vh" p="md">
      <Stack align="center" gap="sm" maw={420}>
        <Title order={2} ta="center">
          {t("errors.loadTitle")}
        </Title>
        <Text c="dimmed" ta="center">
          {errorMessage(error)}
        </Text>
        <Button onClick={onRetry}>{t("common.retry")}</Button>
      </Stack>
    </Center>
  );
}
