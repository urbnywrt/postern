import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { OTPAUTH_URI } from "../test/fakePanel";
import { decodeQrFromSvg } from "../test/qr";
import { renderWithProviders } from "../test/render";
import { QrCode } from "./QrCode";

describe("QrCode", () => {
  it("is a picture with a title", () => {
    renderWithProviders(<QrCode value={OTPAUTH_URI} title="The secret as a QR code" />);

    const picture = screen.getByRole("img", { name: "The secret as a QR code" });
    expect(picture.tagName.toLowerCase()).toBe("svg");
  });

  it("holds exactly the value that it was given, which an independent decoder reads back", () => {
    renderWithProviders(<QrCode value={OTPAUTH_URI} title="QR" />);

    expect(decodeQrFromSvg(screen.getByRole("img"))).toBe(OTPAUTH_URI);
  });

  it("holds text that is not ASCII, too", () => {
    const value = "otpauth://totp/Postern:%D0%B0%D0%B4%D0%BC%D0%B8%D0%BD?secret=ABCDEFGHIJKLMNOP&issuer=Postern";
    renderWithProviders(<QrCode value={value} title="QR" />);

    expect(decodeQrFromSvg(screen.getByRole("img"))).toBe(value);
  });

  it("holds a different picture for a different value", () => {
    const first = renderWithProviders(<QrCode value="otpauth://totp/A?secret=AAAA" title="QR" />);
    const before = first.container.querySelector("svg")?.innerHTML;
    first.unmount();

    const second = renderWithProviders(<QrCode value="otpauth://totp/B?secret=BBBB" title="QR" />);
    expect(second.container.querySelector("svg")?.innerHTML).not.toBe(before);
  });
});
