import type { Transport } from "@connectrpc/connect";
import type { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { createMemoryRouter, MemoryRouter, RouterProvider } from "react-router";

import { AppProviders } from "../app/providers";
import { createQueryClient } from "../app/queryClient";
import { routes } from "../app/router";

/**
 * The whole app, at the given path, with the same providers as in the browser.
 * `transport` is the API that the pages talk to; see createFakePanel.
 */
export function renderApp({ route = "/", transport }: { route?: string; transport: Transport }) {
  const router = createMemoryRouter(routes, { initialEntries: [route] });
  const queryClient = createQueryClient();
  const view = render(
    <AppProviders transport={transport} queryClient={queryClient} mantineEnv="test">
      <RouterProvider router={router} />
    </AppProviders>,
  );
  return { ...view, router, queryClient };
}

/** One component inside the providers and a router that starts at `route`. */
export function renderWithProviders(
  ui: ReactElement,
  { transport, route = "/" }: { transport?: Transport; route?: string } = {},
) {
  const queryClient = createQueryClient();
  const view = render(
    <AppProviders transport={transport} queryClient={queryClient} mantineEnv="test">
      <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
    </AppProviders>,
  );
  return { ...view, queryClient };
}

/**
 * Everything that the mutation cache holds, as text: what the mutations were sent
 * with (passwords, codes) and what they answered (a TOTP secret). A test looks for
 * a secret in it to see that the app has let go of it.
 */
export function heldByMutations(queryClient: QueryClient): string {
  const held = queryClient
    .getMutationCache()
    .getAll()
    .map((mutation) => ({ variables: mutation.state.variables, data: mutation.state.data }));
  return JSON.stringify(held, (_key, value: unknown) => (typeof value === "bigint" ? value.toString() : value));
}
