import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { createMemoryRouter, RouterProvider } from "react-router";

import { AppProviders } from "../app/providers";
import { t } from "../test/t";
import { RouteError } from "./RouteError";

function Broken(): never {
  throw new Error("secret detail of the failure");
}

describe("RouteError", () => {
  it("replaces a page that breaks, and does not show why", () => {
    // React and React Router log what they catch; the log is not what is tested.
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const router = createMemoryRouter([{ path: "/", Component: Broken, ErrorBoundary: RouteError }]);

    render(
      <AppProviders>
        <RouterProvider router={router} />
      </AppProviders>,
    );

    expect(screen.getByRole("heading", { name: t("errors.routeTitle") })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: t("errors.reload") })).toBeInTheDocument();
    expect(screen.queryByText(/secret detail/)).not.toBeInTheDocument();
  });
});
