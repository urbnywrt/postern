import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import i18n from "../i18n";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { PasswordField } from "./PasswordField";

describe("PasswordField", () => {
  it("has a button that shows the password, named and in the tab order", async () => {
    const user = userEvent.setup();
    renderWithProviders(<PasswordField label="Secret word" />);

    const field = screen.getByLabelText("Secret word");
    const toggle = screen.getByRole("button", { name: t("common.showPassword") });
    expect(toggle).toHaveAttribute("tabindex", "0");
    expect(field).toHaveAttribute("type", "password");

    // Tab from the field reaches the button, and a space bar presses it.
    await user.click(field);
    await user.tab();
    expect(toggle).toHaveFocus();
    await user.keyboard(" ");
    expect(field).toHaveAttribute("type", "text");
    expect(toggle).toHaveAttribute("aria-pressed", "true");

    await user.keyboard(" ");
    expect(field).toHaveAttribute("type", "password");
    expect(toggle).toHaveAttribute("aria-pressed", "false");
  });

  it("shows the password to a mouse, too", async () => {
    const user = userEvent.setup();
    renderWithProviders(<PasswordField label="Secret word" defaultValue="hunter2" />);

    await user.click(screen.getByRole("button", { name: t("common.showPassword") }));

    expect(screen.getByLabelText("Secret word")).toHaveAttribute("type", "text");
  });

  it("passes the other properties on to the field", () => {
    renderWithProviders(<PasswordField label="Secret word" autoComplete="new-password" description="Help text" />);

    expect(screen.getByLabelText("Secret word")).toHaveAttribute("autocomplete", "new-password");
    expect(screen.getByText("Help text")).toBeInTheDocument();
  });

  it("names the button in the language of the page", async () => {
    await i18n.changeLanguage("ru");
    renderWithProviders(<PasswordField label="Секрет" />);

    const name = i18n.t("common.showPassword");
    expect(name).not.toBe(t("common.showPassword"));
    expect(screen.getByRole("button", { name })).toBeInTheDocument();
  });
});
