import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { LinkCard } from "./LinkCard";

// A made-up secret, by repetition: it cannot be taken for a real one.
const TG_LINK = `tg://proxy?server=203.0.113.7&port=443&secret=ee${"ab".repeat(16)}7777772e6578616d706c652e636f6d`;

function setSecureContext(value: boolean) {
  Object.defineProperty(window, "isSecureContext", { configurable: true, value });
}

afterEach(() => {
  Reflect.deleteProperty(window, "isSecureContext");
  Reflect.deleteProperty(document, "execCommand");
});

describe("LinkCard", () => {
  it("shows the link whole, under its name", () => {
    renderWithProviders(<LinkCard label="Link for Telegram" value={TG_LINK} copyLabel="Copy the tg link" />);

    expect(screen.getByText("Link for Telegram")).toBeInTheDocument();
    expect(screen.getByText(TG_LINK)).toBeInTheDocument();
  });

  it("copies the tg link, and says so", async () => {
    setSecureContext(true);
    const user = userEvent.setup();
    renderWithProviders(<LinkCard label="Link for Telegram" value={TG_LINK} copyLabel="Copy the tg link" />);

    await user.click(screen.getByRole("button", { name: "Copy the tg link" }));

    expect(await screen.findByText(t("common.copied"))).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe(TG_LINK);
  });

  it("copies when the page is not a secure context, as on plain HTTP", async () => {
    setSecureContext(false);
    let copied: string | undefined;
    Object.defineProperty(document, "execCommand", {
      configurable: true,
      value: vi.fn((command: string) => {
        copied = document.activeElement instanceof HTMLTextAreaElement ? document.activeElement.value : undefined;
        return command === "copy";
      }),
    });
    const user = userEvent.setup();
    renderWithProviders(<LinkCard label="Link for Telegram" value={TG_LINK} copyLabel="Copy the tg link" />);

    await user.click(screen.getByRole("button", { name: "Copy the tg link" }));

    expect(await screen.findByText(t("common.copied"))).toBeInTheDocument();
    expect(copied).toBe(TG_LINK);
  });

  it("names each copy button for what it copies, so that two cards can be told apart", () => {
    renderWithProviders(
      <>
        <LinkCard label="tg" value="tg://proxy?x=1" copyLabel="Copy the tg link" />
        <LinkCard label="https" value="https://t.me/proxy?x=1" copyLabel="Copy the https link" />
      </>,
    );

    expect(screen.getByRole("button", { name: "Copy the tg link" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Copy the https link" })).toBeInTheDocument();
  });
});
