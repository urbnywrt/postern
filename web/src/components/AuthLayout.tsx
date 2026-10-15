import { Container, Group, Paper, Text, Title } from "@mantine/core";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

import { LanguageSwitcher } from "./LanguageSwitcher";
import { ThemeToggle } from "./ThemeToggle";

/** The page around the forms that are open to a visitor: Setup and Login. */
export function AuthLayout({ title, children }: { title: string; children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <Container size={440} py={48}>
      <Group justify="flex-end" gap="xs" mb="xl">
        <LanguageSwitcher />
        <ThemeToggle />
      </Group>
      <Text ta="center" fw={700} size="sm" tt="uppercase" c="dimmed">
        {t("app.name")}
      </Text>
      <Title order={1} ta="center" mb="lg">
        {title}
      </Title>
      <Paper withBorder shadow="md" p="xl" radius="md">
        {children}
      </Paper>
    </Container>
  );
}
