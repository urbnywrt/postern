import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { LANGUAGE_KEY } from "../i18n";
import ru from "../i18n/ru.json";
import { createFakePanel } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

describe("LanguageSwitcher", () => {
  it("switches the page between Russian and English, and remembers the choice", async () => {
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: createFakePanel().transport });

    expect(await screen.findByRole("heading", { name: t("login.title") })).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: "EN" })).toBeChecked();

    await user.click(screen.getByRole("radio", { name: "RU" }));
    expect(await screen.findByRole("heading", { name: ru.login.title })).toBeInTheDocument();
    expect(screen.getByLabelText(ru.common.username)).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("ru");
    expect(window.localStorage.getItem(LANGUAGE_KEY)).toBe("ru");

    await user.click(screen.getByRole("radio", { name: "EN" }));
    expect(await screen.findByRole("heading", { name: t("login.title") })).toBeInTheDocument();
    expect(document.documentElement.lang).toBe("en");
  });

  it("changes the texts of the server errors that the app adds, and leaves the server's own words", async () => {
    const user = userEvent.setup();
    const panel = createFakePanel();
    renderApp({ route: "/login", transport: panel.transport });

    await user.click(await screen.findByRole("radio", { name: "RU" }));
    await user.type(await screen.findByLabelText(ru.common.username), "admin");
    await user.type(screen.getByLabelText(ru.common.password), "w".repeat(16));
    await user.click(screen.getByRole("button", { name: ru.login.submit }));

    // The title of the notification is in Russian, the message is the panel's own.
    expect(await screen.findByText(ru.common.error)).toBeInTheDocument();
    expect(screen.getByText("invalid user name or password")).toBeInTheDocument();
  });
});
