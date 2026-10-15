import type { Transport } from "@connectrpc/connect";
import { MantineProvider } from "@mantine/core";
import { Notifications } from "@mantine/notifications";
import { type QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { type ReactNode, useState } from "react";
import { I18nextProvider } from "react-i18next";

import { TransportContext } from "../api/client";
import { transport as browserTransport } from "../api/transport";
import i18n from "../i18n";
import { createQueryClient } from "./queryClient";
import { colorSchemeManager, theme } from "./theme";

interface AppProvidersProps {
  children: ReactNode;
  /** The API to talk to. The app uses the browser's; tests pass an in-memory one. */
  transport?: Transport;
  queryClient?: QueryClient;
  /** "test" turns off the transitions and the portals of Mantine, which a test has no layout for. */
  mantineEnv?: "default" | "test";
}

export function AppProviders({
  children,
  transport = browserTransport,
  queryClient,
  mantineEnv = "default",
}: AppProvidersProps) {
  const [client] = useState(() => queryClient ?? createQueryClient());
  return (
    <I18nextProvider i18n={i18n}>
      <MantineProvider
        theme={theme}
        colorSchemeManager={colorSchemeManager}
        defaultColorScheme="auto"
        env={mantineEnv}
      >
        <Notifications />
        <TransportContext value={transport}>
          <QueryClientProvider client={client}>{children}</QueryClientProvider>
        </TransportContext>
      </MantineProvider>
    </I18nextProvider>
  );
}
