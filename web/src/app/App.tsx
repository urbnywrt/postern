import { RouterProvider } from "react-router/dom";

import { AppProviders } from "./providers";
import { createAppRouter } from "./router";

// A data router lives outside React: it is made once, not held in state.
const router = createAppRouter();

export function App() {
  return (
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  );
}
