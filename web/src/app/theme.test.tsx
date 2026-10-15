import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ThemeToggle } from "../components/ThemeToggle";
import { createFakePanel } from "../test/fakePanel";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { COLOR_SCHEME_KEY } from "./theme";

const scheme = () => document.documentElement.getAttribute("data-mantine-color-scheme");

function renderToggle() {
  return renderWithProviders(<ThemeToggle />, { transport: createFakePanel().transport });
}

describe("theme toggle", () => {
  it("switches between the dark and the light theme", async () => {
    const user = userEvent.setup();
    renderToggle();

    // The test browser has no dark preference, so the theme starts light.
    expect(scheme()).toBe("light");
    await user.click(screen.getByRole("button", { name: t("theme.toDark") }));
    expect(scheme()).toBe("dark");
    await user.click(screen.getByRole("button", { name: t("theme.toLight") }));
    expect(scheme()).toBe("light");
  });

  it("remembers the choice in localStorage", async () => {
    const user = userEvent.setup();
    renderToggle();

    await user.click(screen.getByRole("button", { name: t("theme.toDark") }));
    expect(window.localStorage.getItem(COLOR_SCHEME_KEY)).toBe("dark");
  });

  it("starts with the theme that was chosen before", () => {
    window.localStorage.setItem(COLOR_SCHEME_KEY, "dark");
    renderToggle();

    expect(scheme()).toBe("dark");
    expect(screen.getByRole("button", { name: t("theme.toLight") })).toBeInTheDocument();
  });

  it("ignores a stored value that is not a theme", () => {
    window.localStorage.setItem(COLOR_SCHEME_KEY, "purple");
    renderToggle();

    expect(scheme()).toBe("light");
  });

  describe("survives a localStorage that throws", () => {
    const denied = () => new DOMException("storage is blocked", "SecurityError");

    it.each([
      [
        "reads and writes",
        () => {
          vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
            throw denied();
          });
          vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
            throw denied();
          });
        },
      ],
      [
        "the property itself",
        () => {
          vi.spyOn(window, "localStorage", "get").mockImplementation(() => {
            throw denied();
          });
        },
      ],
    ])("when %s fail", async (_name, breakStorage) => {
      breakStorage();
      const user = userEvent.setup();
      renderToggle();

      expect(scheme()).toBe("light");
      await user.click(screen.getByRole("button", { name: t("theme.toDark") }));

      // The choice holds for this page view even though it cannot be saved.
      expect(scheme()).toBe("dark");
      expect(screen.getByRole("button", { name: t("theme.toLight") })).toBeInTheDocument();
    });
  });
});
