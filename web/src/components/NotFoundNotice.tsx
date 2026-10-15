import { Button, Stack, Text, Title } from "@mantine/core";
import { useTranslation } from "react-i18next";
import { Link } from "react-router";

/** A page about a node or a proxy that is not there (any more), with the way back to the list. */
export function NotFoundNotice({ backTo, backLabel }: { backTo: string; backLabel: string }) {
  const { t } = useTranslation();
  return (
    <Stack gap="xs" align="flex-start">
      <Title order={1}>{t("errors.notFoundTitle")}</Title>
      <Text c="dimmed">{t("errors.notFound")}</Text>
      <Button component={Link} to={backTo} variant="light">
        {backLabel}
      </Button>
    </Stack>
  );
}
