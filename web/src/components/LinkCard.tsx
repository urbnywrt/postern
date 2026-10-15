import { Code, Group, Stack, Text } from "@mantine/core";

import { CopyButton } from "./CopyButton";

interface LinkCardProps {
  /** What the link is: "Link for Telegram (tg://)". */
  label: string;
  /** The link as it is, with the secret in it. */
  value: string;
  /** What the copy button is called, for a screen reader: "Copy the tg link". */
  copyLabel: string;
}

/** A link of a proxy, shown whole and selectable, with a button that copies it. */
export function LinkCard({ label, value, copyLabel }: LinkCardProps) {
  return (
    <Stack gap={4}>
      <Text size="sm" fw={500}>
        {label}
      </Text>
      <Group gap="xs" wrap="nowrap" align="flex-start">
        <Code block style={{ flex: 1, minWidth: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", userSelect: "all" }}>
          {value}
        </Code>
        <CopyButton value={value} label={copyLabel} />
      </Group>
    </Stack>
  );
}
