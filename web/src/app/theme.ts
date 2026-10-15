import {
  createTheme,
  type MantineColorScheme,
  type MantineColorSchemeManager,
} from "@mantine/core";

import { readStored, removeStored, writeStored } from "./storage";

export const COLOR_SCHEME_KEY = "postern.colorScheme";

export const theme = createTheme({
  primaryColor: "indigo",
  defaultRadius: "md",
  // System fonts only: the panel sends `default-src 'self'`, so no web fonts.
  fontFamily:
    'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif',
  fontFamilyMonospace: 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
});

function isColorScheme(value: unknown): value is MantineColorScheme {
  return value === "light" || value === "dark" || value === "auto";
}

/**
 * Keeps the color scheme in localStorage. It is Mantine's own manager with two
 * differences: a stored value that is not a scheme is ignored, and a storage
 * that throws never gets in the way (see storage.ts).
 */
export function createColorSchemeManager(key = COLOR_SCHEME_KEY): MantineColorSchemeManager {
  let listener: ((event: StorageEvent) => void) | undefined;

  return {
    get: (defaultValue) => {
      const stored = readStored(key);
      return isColorScheme(stored) ? stored : defaultValue;
    },
    set: (value) => {
      writeStored(key, value);
    },
    // Another tab of the panel changed the theme.
    subscribe: (onUpdate) => {
      listener = (event) => {
        if (event.key === key && isColorScheme(event.newValue)) {
          onUpdate(event.newValue);
        }
      };
      window.addEventListener("storage", listener);
    },
    unsubscribe: () => {
      if (listener) {
        window.removeEventListener("storage", listener);
        listener = undefined;
      }
    },
    clear: () => {
      removeStored(key);
    },
  };
}

export const colorSchemeManager = createColorSchemeManager();
