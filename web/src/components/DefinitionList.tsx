import { Box, Text } from "@mantine/core";
import type { ReactNode } from "react";

export interface DefinitionItem {
  label: string;
  value: ReactNode;
}

/** Facts as labels and values, one pair to a line: the state of a node, the settings of a listener. */
export function DefinitionList({ items }: { items: DefinitionItem[] }) {
  return (
    <Box
      component="dl"
      m={0}
      style={{ display: "grid", gridTemplateColumns: "minmax(0, max-content) minmax(0, 1fr)", gap: "6px 16px" }}
    >
      {items.map((item) => (
        <DefinitionRow key={item.label} {...item} />
      ))}
    </Box>
  );
}

function DefinitionRow({ label, value }: DefinitionItem) {
  return (
    <>
      <Text component="dt" size="sm" c="dimmed">
        {label}
      </Text>
      <Text component="dd" size="sm" m={0} style={{ overflowWrap: "anywhere" }}>
        {value}
      </Text>
    </>
  );
}
