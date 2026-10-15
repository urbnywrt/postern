import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import {
  createFakePanel,
  type FakePanel,
  OTPAUTH_URI,
  PASSWORD,
  TOTP_CODE,
  TOTP_SECRET,
} from "../test/fakePanel";
import { decodeQrFromSvg } from "../test/qr";
import { heldByMutations, renderApp } from "../test/render";
import { t } from "../test/t";

async function openSettings(panel: FakePanel) {
  const user = userEvent.setup();
  const { queryClient } = renderApp({ route: "/settings", transport: panel.transport });
  const section = within(await screen.findByRole("region", { name: t("settings.totp.title") }));
  return { user, section, queryClient };
}

describe("TotpSetup: turning two-factor authentication on", () => {
  it("asks the panel for a secret and shows it as a QR code and as text", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);
    expect(section.getByText(t("settings.totp.off"))).toBeInTheDocument();
    expect(section.queryByRole("img")).not.toBeInTheDocument();

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));

    expect(await section.findByRole("img", { name: t("settings.totp.qrTitle") })).toBeInTheDocument();
    expect(section.getByText(TOTP_SECRET)).toBeInTheDocument();
    expect(panel.rpc.beginTotp).toHaveBeenCalledTimes(1);
  });

  it("turns TOTP on with the code and the password", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await user.type(await section.findByLabelText(t("settings.totp.code")), TOTP_CODE);
    await user.type(section.getByLabelText(t("common.password")), PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.totp.confirm") }));

    expect(await screen.findByText(t("settings.totp.enabled"))).toBeInTheDocument();
    expect(panel.rpc.confirmTotp).toHaveBeenCalledTimes(1);
    expect(panel.rpc.confirmTotp.mock.calls[0]?.[0]).toMatchObject({ code: TOTP_CODE, password: PASSWORD });

    // The page learns it from the panel: the state is "on", the secret is gone,
    // and the password form asks for a code from now on.
    expect(await section.findByText(t("settings.totp.on"))).toBeInTheDocument();
    expect(section.queryByRole("img")).not.toBeInTheDocument();
    expect(section.queryByText(TOTP_SECRET)).not.toBeInTheDocument();
    const passwordSection = within(screen.getByRole("region", { name: t("settings.password.title") }));
    expect(await passwordSection.findByLabelText(t("settings.password.code"))).toBeInTheDocument();
  });

  it("asks for a code and a password before it calls the panel", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await user.type(await section.findByLabelText(t("settings.totp.code")), "12345");
    await user.click(section.getByRole("button", { name: t("settings.totp.confirm") }));

    expect(await section.findByText(t("validation.code"))).toBeInTheDocument();
    expect(section.getByText(t("validation.required"))).toBeInTheDocument();
    expect(panel.rpc.confirmTotp).not.toHaveBeenCalled();
  });

  it("shows the message of the panel when the code is wrong, and keeps the secret on the screen", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await user.type(await section.findByLabelText(t("settings.totp.code")), "000000");
    await user.type(section.getByLabelText(t("common.password")), PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.totp.confirm") }));

    expect(await screen.findByText("the verification code is wrong")).toBeInTheDocument();
    expect(section.getByText(TOTP_SECRET)).toBeInTheDocument();
    expect(section.getByText(t("settings.totp.off"))).toBeInTheDocument();
  });

  it("drops the secret when the admin cancels", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await section.findByText(TOTP_SECRET);
    await user.click(section.getByRole("button", { name: t("common.cancel") }));

    expect(section.queryByText(TOTP_SECRET)).not.toBeInTheDocument();
    expect(section.queryByRole("img")).not.toBeInTheDocument();
    expect(section.getByRole("button", { name: t("settings.totp.begin") })).toBeInTheDocument();
  });

  it("does not keep the secret in memory after the admin cancels, nor once TOTP is on", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section, queryClient } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await section.findByText(TOTP_SECRET);
    // While the QR code is on the screen, the answer of the panel is what it is made of.
    expect(heldByMutations(queryClient)).toContain(TOTP_SECRET);

    await user.click(section.getByRole("button", { name: t("common.cancel") }));
    await waitFor(() => {
      expect(heldByMutations(queryClient)).not.toContain(TOTP_SECRET);
    });
    expect(heldByMutations(queryClient)).not.toContain("otpauth:");

    // The same after a set-up that is carried through: neither the secret nor the password stay.
    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await user.type(await section.findByLabelText(t("settings.totp.code")), TOTP_CODE);
    await user.type(section.getByLabelText(t("common.password")), PASSWORD);
    await user.click(section.getByRole("button", { name: t("settings.totp.confirm") }));
    expect(await section.findByText(t("settings.totp.on"))).toBeInTheDocument();
    await waitFor(() => {
      expect(heldByMutations(queryClient)).not.toContain(TOTP_SECRET);
    });
    expect(heldByMutations(queryClient)).not.toContain(PASSWORD);
  });

  it("has a show button, named and in the tab order, on the password field", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await section.findByLabelText(t("settings.totp.code"));

    const toggle = section.getByRole("button", { name: t("common.showPassword") });
    expect(toggle).toHaveAttribute("tabindex", "0");
  });

  it("does not trim the password: a password of spaces is sent as it is", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await user.type(await section.findByLabelText(t("settings.totp.code")), TOTP_CODE);
    await user.type(section.getByLabelText(t("common.password")), "            ");
    await user.click(section.getByRole("button", { name: t("settings.totp.confirm") }));

    expect(await screen.findByText("the password is wrong")).toBeInTheDocument();
    expect(panel.rpc.confirmTotp.mock.calls[0]?.[0]).toMatchObject({ password: "            " });
  });

  it("puts the secret on the clipboard", async () => {
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));
    await user.click(await section.findByRole("button", { name: t("settings.totp.copySecret") }));

    expect(await screen.findByText(t("common.copied"))).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(TOTP_SECRET);
  });

  it("shows a QR code of exactly the URI that the panel made", async () => {
    const panel = createFakePanel({ signedIn: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.begin") }));

    const picture = await section.findByRole("img", { name: t("settings.totp.qrTitle") });
    expect(decodeQrFromSvg(picture)).toBe(OTPAUTH_URI);
  });
});

describe("TotpSetup: turning two-factor authentication off", () => {
  it("shows that TOTP is on, and asks for the password and a code", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const { section } = await openSettings(panel);

    expect(section.getByText(t("settings.totp.on"))).toBeInTheDocument();
    expect(section.getByLabelText(t("common.password"))).toBeInTheDocument();
    expect(section.getByLabelText(t("settings.totp.code"))).toBeInTheDocument();
    expect(section.queryByRole("button", { name: t("settings.totp.begin") })).not.toBeInTheDocument();
  });

  it("turns TOTP off with the password and a code", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const { user, section } = await openSettings(panel);

    await user.type(section.getByLabelText(t("common.password")), PASSWORD);
    await user.type(section.getByLabelText(t("settings.totp.code")), TOTP_CODE);
    await user.click(section.getByRole("button", { name: t("settings.totp.disable") }));

    expect(await screen.findByText(t("settings.totp.disabled"))).toBeInTheDocument();
    expect(panel.rpc.disableTotp.mock.calls[0]?.[0]).toMatchObject({ password: PASSWORD, code: TOTP_CODE });
    expect(await section.findByText(t("settings.totp.off"))).toBeInTheDocument();
    expect(section.getByRole("button", { name: t("settings.totp.begin") })).toBeInTheDocument();
    // With TOTP off, the password form no longer asks for a code.
    const passwordSection = within(screen.getByRole("region", { name: t("settings.password.title") }));
    expect(passwordSection.queryByLabelText(t("settings.password.code"))).not.toBeInTheDocument();
  });

  it("asks for both before it calls the panel", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const { user, section } = await openSettings(panel);

    await user.click(section.getByRole("button", { name: t("settings.totp.disable") }));

    expect(await section.findByText(t("validation.required"))).toBeInTheDocument();
    expect(section.getByText(t("validation.code"))).toBeInTheDocument();
    expect(panel.rpc.disableTotp).not.toHaveBeenCalled();
  });

  it("has a show button, named and in the tab order, on the password field", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const { section } = await openSettings(panel);

    expect(section.getByRole("button", { name: t("common.showPassword") })).toHaveAttribute("tabindex", "0");
  });

  it("does not trim the password: a password of spaces is sent as it is", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const { user, section } = await openSettings(panel);

    await user.type(section.getByLabelText(t("common.password")), "            ");
    await user.type(section.getByLabelText(t("settings.totp.code")), TOTP_CODE);
    await user.click(section.getByRole("button", { name: t("settings.totp.disable") }));

    expect(await screen.findByText("the password is wrong")).toBeInTheDocument();
    expect(panel.rpc.disableTotp.mock.calls[0]?.[0]).toMatchObject({ password: "            " });
  });

  it("shows the message of the panel when the password is wrong, and keeps TOTP on", async () => {
    const panel = createFakePanel({ signedIn: true, totpEnabled: true });
    const { user, section } = await openSettings(panel);

    await user.type(section.getByLabelText(t("common.password")), "w".repeat(16));
    await user.type(section.getByLabelText(t("settings.totp.code")), TOTP_CODE);
    await user.click(section.getByRole("button", { name: t("settings.totp.disable") }));

    expect(await screen.findByText("the password is wrong")).toBeInTheDocument();
    expect(section.getByText(t("settings.totp.on"))).toBeInTheDocument();
    expect(panel.state.totpEnabled).toBe(true);
  });
});
