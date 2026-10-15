import { ActionIcon, Tooltip, useComputedColorScheme, useMantineColorScheme } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { MoonIcon, SunIcon } from "./icons";

/** Dark or light. The first visit follows the system; a click is remembered. */
export function ThemeToggle() {
  const { t } = useTranslation();
  const { setColorScheme } = useMantineColorScheme();
  const scheme = useComputedColorScheme("light", { getInitialValueInEffect: false });
  const next = scheme === "dark" ? "light" : "dark";
  const label = t(next === "dark" ? "theme.toDark" : "theme.toLight");

  return (
    <Tooltip label={label}>
      <ActionIcon
        variant="default"
        size="lg"
        aria-label={label}
        onClick={() => {
          setColorScheme(next);
        }}
      >
        {scheme === "dark" ? <SunIcon /> : <MoonIcon />}
      </ActionIcon>
    </Tooltip>
  );
}
