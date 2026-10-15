import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createFakePanel, NEW_PASSWORD, PASSWORD, TOTP_CODE } from "../test/fakePanel";
import { heldByMutations, renderApp } from "../test/render";
import { t } from "../test/t";

async function passwordSection() {
  return within(await screen.findByRole("region", { name: t("settings.password.title") }));
}

describe("Settings: change password", () => {
  it("has a show button, named and in the tab order, on each of the three password fields", async () => {
    const panel = createFakePanel({ signedIn: true });
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    const toggles = section.getAllByRole("button", { name: t("common.showPassword") });
    expect(toggles).toHaveLength(3);
    for (const toggle of toggles) {
      expect(toggle).toHaveAttribute("tabindex", "0");
    }
  });

  it("does not trim the current password: a password of spaces is sent as it is", async () => {
    const panel = createFakePanel({ signedIn: true });
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.current")), "            ");
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await screen.findByText("the password is wrong")).toBeInTheDocument();
    expect(panel.rpc.changePassword).toHaveBeenCalledTimes(1);
    expect(panel.rpc.changePassword.mock.calls[0]?.[0]).toMatchObject({ currentPassword: "            " });
  });

  it("asks for the current password when the field is empty", async () => {
    const panel = createFakePanel({ signedIn: true });
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await section.findByText(t("validation.required"))).toBeInTheDocument();
    expect(panel.rpc.changePassword).not.toHaveBeenCalled();
  });

  it("does not keep the passwords in memory once they are changed", async () => {
    const panel = createFakePanel({ signedIn: true });
    const user = userEvent.setup();
    const { queryClient } = renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.current")), PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));
    expect(await screen.findByText(t("settings.password.done"))).toBeInTheDocument();

    // The form is still on the screen, and so is what the mutation was sent with, unless the
    // form lets go of it.
    await waitFor(() => {
      expect(heldByMutations(queryClient)).not.toContain(PASSWORD);
    });
    expect(heldByMutations(queryClient)).not.toContain(NEW_PASSWORD);
  });

  it("shows the code field when TOTP is enabled", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    expect(section.getByLabelText(t("settings.password.code"))).toBeInTheDocument();
  });

  it("has no code field when TOTP is off", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: false });
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    expect(section.getByLabelText(t("settings.password.current"))).toBeInTheDocument();
    expect(section.queryByLabelText(t("settings.password.code"))).not.toBeInTheDocument();
  });

  it("sends the current password, the new one and the code, and clears the form", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.current")), PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.code")), TOTP_CODE);
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await screen.findByText(t("settings.password.done"))).toBeInTheDocument();
    expect(panel.rpc.changePassword).toHaveBeenCalledTimes(1);
    expect(panel.rpc.changePassword.mock.calls[0]?.[0]).toMatchObject({
      currentPassword: PASSWORD,
      newPassword: NEW_PASSWORD,
      totpCode: TOTP_CODE,
    });
    expect(section.getByLabelText(t("settings.password.current"))).toHaveValue("");
    expect(section.getByLabelText(t("settings.password.new"))).toHaveValue("");
  });

  it("does not send a code when TOTP is off", async () => {
    const panel = createFakePanel({ signedIn: true });
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.current")), PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await screen.findByText(t("settings.password.done"))).toBeInTheDocument();
    expect(panel.rpc.changePassword.mock.calls[0]?.[0]).toMatchObject({ totpCode: "" });
  });

  it("refuses a new password that is too short, and one that is repeated wrongly", async () => {
    const panel = createFakePanel({ signedIn: true });
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.current")), PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.new")), "short");
    await user.type(section.getByLabelText(t("settings.password.repeat")), "other");
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await section.findByText(t("validation.passwordShort", { min: 12 }))).toBeInTheDocument();
    expect(section.getByText(t("validation.mismatch"))).toBeInTheDocument();
    expect(panel.rpc.changePassword).not.toHaveBeenCalled();
  });

  it("asks for the code when TOTP is on, before it calls the server", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.current")), PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await section.findByText(t("validation.code"))).toBeInTheDocument();
    expect(panel.rpc.changePassword).not.toHaveBeenCalled();
  });

  it("shows the message of the server when the current password is wrong", async () => {
    const panel = createFakePanel({ signedIn: true });
    const user = userEvent.setup();
    renderApp({ route: "/settings", transport: panel.transport });

    const section = await passwordSection();
    await user.type(section.getByLabelText(t("settings.password.current")), "w".repeat(16));
    await user.type(section.getByLabelText(t("settings.password.new")), NEW_PASSWORD);
    await user.type(section.getByLabelText(t("settings.password.repeat")), NEW_PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.password.submit") }));

    expect(await screen.findByText("the password is wrong")).toBeInTheDocument();
    await waitFor(() => {
      expect(section.getByRole("button", { name: t("settings.password.submit") })).toBeEnabled();
    });
  });
});
