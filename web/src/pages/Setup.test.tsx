import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { ADMIN, createFakePanel, PASSWORD, SETUP_TOKEN } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

type User = ReturnType<typeof userEvent.setup>;

const submitButton = () => screen.getByRole("button", { name: t("setup.submit") });

interface FormValues {
  username?: string;
  password?: string;
  /** What is typed to repeat the password; the password itself when left out. */
  repeat?: string;
}

async function fillForm(user: User, { username = ADMIN, password = PASSWORD, repeat = password }: FormValues = {}) {
  await user.type(await screen.findByLabelText(t("common.username")), username);
  await user.type(screen.getByLabelText(t("common.password")), password);
  await user.type(screen.getByLabelText(t("setup.repeatPassword")), repeat);
}

describe("Setup", () => {
  it("has a show button, named and in the tab order, on both password fields", async () => {
    const panel = createFakePanel({ needsSetup: true });
    renderApp({ route: "/setup", transport: panel.transport });

    await screen.findByLabelText(t("setup.token"));
    const toggles = screen.getAllByRole("button", { name: t("common.showPassword") });
    expect(toggles).toHaveLength(2);
    for (const toggle of toggles) {
      expect(toggle).toHaveAttribute("tabindex", "0");
    }
  });

  it("takes the setup token from the ?token= query", async () => {
    const panel = createFakePanel({ needsSetup: true });
    renderApp({ route: `/setup?token=${SETUP_TOKEN}`, transport: panel.transport });

    expect(await screen.findByLabelText(t("setup.token"))).toHaveValue(SETUP_TOKEN);
  });

  it("takes the setup token out of the address once it has read it", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const { router } = renderApp({ route: `/setup?token=${SETUP_TOKEN}&lang=ru`, transport: panel.transport });

    expect(await screen.findByLabelText(t("setup.token"))).toHaveValue(SETUP_TOKEN);
    expect(router.state.location.pathname).toBe("/setup");
    expect(router.state.location.search).toBe("?lang=ru");
    // Replaced, not pushed: the address with the token is not in the history.
    expect(router.state.historyAction).toBe("REPLACE");
  });

  it("lets the admin type the token when the link had none", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: "/setup", transport: panel.transport });

    await user.type(await screen.findByLabelText(t("setup.token")), SETUP_TOKEN);
    await fillForm(user);
    await user.click(submitButton());

    expect(await screen.findByRole("heading", { name: t("login.title") })).toBeInTheDocument();
    expect(panel.rpc.setup.mock.calls[0]?.[0]).toMatchObject({ setupToken: SETUP_TOKEN });
  });

  it("creates the first admin, then sends the visitor to the login page", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: `/setup?token=${SETUP_TOKEN}`, transport: panel.transport });

    await fillForm(user);
    await user.click(submitButton());

    expect(await screen.findByRole("heading", { name: t("login.title") })).toBeInTheDocument();
    expect(await screen.findByText(t("setup.done"))).toBeInTheDocument();
    expect(panel.rpc.setup).toHaveBeenCalledTimes(1);
    expect(panel.rpc.setup.mock.calls[0]?.[0]).toMatchObject({
      setupToken: SETUP_TOKEN,
      username: ADMIN,
      password: PASSWORD,
    });
  });

  it("sends the token and the user name without the spaces around them", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: "/setup", transport: panel.transport });

    await user.type(await screen.findByLabelText(t("setup.token")), `  ${SETUP_TOKEN}  `);
    await fillForm(user, { username: ` ${ADMIN} ` });
    await user.click(submitButton());

    expect(await screen.findByRole("heading", { name: t("login.title") })).toBeInTheDocument();
    expect(panel.rpc.setup.mock.calls[0]?.[0]).toMatchObject({ setupToken: SETUP_TOKEN, username: ADMIN });
  });

  it("does not call the server with an empty form", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: "/setup", transport: panel.transport });

    await screen.findByLabelText(t("setup.token"));
    await user.click(submitButton());

    // The token, the user name and the password are asked for.
    expect(await screen.findAllByText(t("validation.required"))).toHaveLength(3);
    expect(panel.rpc.setup).not.toHaveBeenCalled();
  });

  it("refuses a password of fewer than 12 characters, and one that is repeated wrongly", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: `/setup?token=${SETUP_TOKEN}`, transport: panel.transport });

    await fillForm(user, { password: "short", repeat: "other" });
    await user.click(submitButton());

    expect(await screen.findByText(t("validation.passwordShort", { min: 12 }))).toBeInTheDocument();
    expect(screen.getByText(t("validation.mismatch"))).toBeInTheDocument();
    expect(panel.rpc.setup).not.toHaveBeenCalled();
  });

  it("counts the characters of a password, not its bytes", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: `/setup?token=${SETUP_TOKEN}`, transport: panel.transport });

    // Twelve Cyrillic letters are 24 bytes and 12 characters: long enough.
    const password = "п".repeat(12);
    await fillForm(user, { password });
    await user.click(submitButton());

    expect(await screen.findByRole("heading", { name: t("login.title") })).toBeInTheDocument();
    expect(panel.rpc.setup.mock.calls[0]?.[0]).toMatchObject({ password });
  });

  it("refuses a user name with a space in it", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: `/setup?token=${SETUP_TOKEN}`, transport: panel.transport });

    await fillForm(user, { username: "two words" });
    await user.click(submitButton());

    expect(await screen.findByText(t("validation.usernameChars"))).toBeInTheDocument();
    expect(panel.rpc.setup).not.toHaveBeenCalled();
  });

  it("shows the message of the server when the token is wrong, and stays on the page", async () => {
    const panel = createFakePanel({ needsSetup: true });
    const user = userEvent.setup();
    renderApp({ route: `/setup?token=${"w".repeat(24)}`, transport: panel.transport });

    await fillForm(user);
    await user.click(submitButton());

    expect(
      await screen.findByText("the setup token is wrong or has expired; restart the panel to get a new one"),
    ).toBeInTheDocument();
    expect(screen.getByLabelText(t("setup.token"))).toBeInTheDocument();
  });

  it("leaves for the login page when the panel is set up already", async () => {
    const panel = createFakePanel({ needsSetup: false });
    renderApp({ route: `/setup?token=${SETUP_TOKEN}`, transport: panel.transport });

    expect(await screen.findByRole("heading", { name: t("login.title") })).toBeInTheDocument();
    expect(panel.rpc.setup).not.toHaveBeenCalled();
  });
});
