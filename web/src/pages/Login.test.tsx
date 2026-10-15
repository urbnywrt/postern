import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { ADMIN, createFakePanel, PASSWORD, TOTP_CODE } from "../test/fakePanel";
import { renderApp } from "../test/render";
import { t } from "../test/t";

type User = ReturnType<typeof userEvent.setup>;

async function fillCredentials(user: User, password = PASSWORD) {
  await user.type(await screen.findByLabelText(t("common.username")), ADMIN);
  await user.type(screen.getByLabelText(t("common.password")), password);
}

const submitButton = () => screen.getByRole("button", { name: t("login.submit") });
const codeField = () => screen.queryByLabelText(t("login.totpCode"));
const overviewHeading = () => screen.findByRole("heading", { name: t("overview.title") });

describe("Login", () => {
  it("has a password field whose show button is named and in the tab order", async () => {
    const panel = createFakePanel();
    renderApp({ route: "/login", transport: panel.transport });

    await screen.findByLabelText(t("common.username"));
    const toggle = screen.getByRole("button", { name: t("common.showPassword") });
    expect(toggle).toHaveAttribute("tabindex", "0");
    expect(screen.getByLabelText(t("common.password"))).toHaveAttribute("type", "password");
  });

  it("does not trim the password: a password of spaces is sent as it is", async () => {
    const panel = createFakePanel();
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user, "            ");
    await user.click(submitButton());

    // It is not "required": the field is not empty, and the panel says that it is wrong.
    expect(await screen.findByText("invalid user name or password")).toBeInTheDocument();
    expect(screen.queryByText(t("validation.required"))).not.toBeInTheDocument();
    expect(panel.rpc.login).toHaveBeenCalledTimes(1);
    expect(panel.rpc.login.mock.calls[0]?.[0]).toMatchObject({ username: ADMIN, password: "            " });
  });

  it("still asks for a password that is empty", async () => {
    const panel = createFakePanel();
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await user.type(await screen.findByLabelText(t("common.username")), ADMIN);
    await user.click(submitButton());

    expect(await screen.findByText(t("validation.required"))).toBeInTheDocument();
    expect(panel.rpc.login).not.toHaveBeenCalled();
  });

  it("shows the TOTP field when the server says totp_required, and signs in with the code", async () => {
    const panel = createFakePanel({ totpEnabled: true });
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user);
    expect(codeField()).not.toBeInTheDocument();
    await user.click(submitButton());

    // The password was right, and the panel wants the second step.
    expect(await screen.findByLabelText(t("login.totpCode"))).toBeInTheDocument();
    expect(panel.rpc.login).toHaveBeenCalledTimes(1);
    expect(panel.rpc.login.mock.calls[0]?.[0]).toMatchObject({ username: ADMIN, password: PASSWORD, totpCode: "" });
    expect(screen.queryByLabelText(t("common.password"))).not.toBeInTheDocument();

    await user.type(screen.getByLabelText(t("login.totpCode")), TOTP_CODE);
    await user.click(screen.getByRole("button", { name: t("login.verify") }));

    // The second call repeats the credentials and adds the code.
    await waitFor(() => {
      expect(panel.rpc.login).toHaveBeenCalledTimes(2);
    });
    expect(panel.rpc.login.mock.calls[1]?.[0]).toMatchObject({
      username: ADMIN,
      password: PASSWORD,
      totpCode: TOTP_CODE,
    });
    expect(await overviewHeading()).toBeInTheDocument();
  });

  it("accepts a code that was typed in two groups", async () => {
    const panel = createFakePanel({ totpEnabled: true });
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user);
    await user.click(submitButton());
    await user.type(await screen.findByLabelText(t("login.totpCode")), "123 456");
    await user.click(screen.getByRole("button", { name: t("login.verify") }));

    expect(await overviewHeading()).toBeInTheDocument();
    expect(panel.rpc.login.mock.calls[1]?.[0]).toMatchObject({ totpCode: TOTP_CODE });
  });

  it("does not ask for a code when the admin has no TOTP", async () => {
    const panel = createFakePanel();
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user);
    await user.click(submitButton());

    expect(await overviewHeading()).toBeInTheDocument();
    expect(panel.rpc.login).toHaveBeenCalledTimes(1);
    expect(codeField()).not.toBeInTheDocument();
  });

  it("sends one try, not two, when Enter is pressed twice", async () => {
    const panel = createFakePanel();
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user);
    await user.keyboard("{Enter}{Enter}");

    expect(await overviewHeading()).toBeInTheDocument();
    expect(panel.rpc.login).toHaveBeenCalledTimes(1);
  });

  it("does not call the server with an empty form", async () => {
    const panel = createFakePanel();
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await screen.findByLabelText(t("common.username"));
    await user.click(submitButton());

    expect(await screen.findAllByText(t("validation.required"))).toHaveLength(2);
    expect(panel.rpc.login).not.toHaveBeenCalled();
  });

  it("shows the message of the server when the credentials are wrong, and stays on the page", async () => {
    const panel = createFakePanel();
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user, "w".repeat(16));
    await user.click(submitButton());

    expect(await screen.findByText("invalid user name or password")).toBeInTheDocument();
    expect(screen.getByLabelText(t("common.password"))).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: t("overview.title") })).not.toBeInTheDocument();
  });

  it("shows the message of the server when the code is wrong, and keeps the code step", async () => {
    const panel = createFakePanel({ totpEnabled: true });
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user);
    await user.click(submitButton());
    await user.type(await screen.findByLabelText(t("login.totpCode")), "000000");
    await user.click(screen.getByRole("button", { name: t("login.verify") }));

    expect(await screen.findByText("invalid verification code")).toBeInTheDocument();
    // The code is spent: the field is empty for the next one, and does not scold.
    expect(screen.getByLabelText(t("login.totpCode"))).toHaveValue("");
    expect(screen.queryByText(t("validation.code"))).not.toBeInTheDocument();
  });

  it("goes back from the code step to the credentials", async () => {
    const panel = createFakePanel({ totpEnabled: true });
    const user = userEvent.setup();
    renderApp({ route: "/login", transport: panel.transport });

    await fillCredentials(user);
    await user.click(submitButton());
    await screen.findByLabelText(t("login.totpCode"));
    await user.click(screen.getByRole("button", { name: t("common.back") }));

    expect(await screen.findByLabelText(t("common.username"))).toBeInTheDocument();
    expect(codeField()).not.toBeInTheDocument();
  });

  it("sends a visitor who is signed in already to the overview", async () => {
    const panel = createFakePanel({ signedIn: true });
    renderApp({ route: "/login", transport: panel.transport });

    expect(await overviewHeading()).toBeInTheDocument();
  });

  it("sends a visitor to Setup when the panel has no admin yet", async () => {
    const panel = createFakePanel({ needsSetup: true });
    renderApp({ route: "/login", transport: panel.transport });

    expect(await screen.findByRole("heading", { name: t("setup.title") })).toBeInTheDocument();
  });

  it("returns to the page that the visitor came for", async () => {
    const panel = createFakePanel();
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    await fillCredentials(user);
    await user.click(submitButton());

    expect(await screen.findByRole("heading", { name: t("settings.title") })).toBeInTheDocument();
  });
});
