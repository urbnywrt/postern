import { Code, Group } from "@mantine/core";

import { CopyButton } from "./CopyButton";

/** A command to copy and run on a server, and the button that copies it. */
export function CommandLine({ text, copyLabel }: { text: string; copyLabel: string }) {
  return (
    <Group gap="xs" wrap="nowrap" align="flex-start">
      <Code block style={{ flex: 1, minWidth: 0, whiteSpace: "pre-wrap", wordBreak: "break-all", userSelect: "all" }}>
        {text}
      </Code>
      <CopyButton value={text} label={copyLabel} />
    </Group>
  );
}
