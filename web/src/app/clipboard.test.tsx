import { Code, ConnectError } from "@connectrpc/connect";
import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CopyButton } from "../components/CopyButton";
import { renderWithProviders } from "../test/render";
import { t } from "../test/t";
import { copyText, useCopy } from "./clipboard";

function setSecureContext(value: boolean) {
  Object.defineProperty(window, "isSecureContext", { configurable: true, value });
}

function stubClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(window.navigator, "clipboard", { configurable: true, value: { writeText } });
  return writeText;
}

/** jsdom has no execCommand. */
function stubExecCommand(result: boolean | Error) {
  const execCommand = vi.fn((command: string) => {
    if (result instanceof Error) {
      throw result;
    }
    return command === "copy" ? result : false;
  });
  Object.defineProperty(document, "execCommand", { configurable: true, value: execCommand });
  return execCommand;
}

/** jsdom has no ClipboardItem; this one keeps what it was made of. */
function stubClipboardItem() {
  class FakeClipboardItem {
    constructor(readonly items: Record<string, Promise<Blob>>) {}
  }
  Object.defineProperty(globalThis, "ClipboardItem", { configurable: true, value: FakeClipboardItem });
}

afterEach(() => {
  Reflect.deleteProperty(document, "execCommand");
  Reflect.deleteProperty(window, "isSecureContext");
  Reflect.deleteProperty(window.navigator, "clipboard");
  Reflect.deleteProperty(globalThis, "ClipboardItem");
});

describe("copyText", () => {
  it("uses the clipboard API in a secure context", async () => {
    setSecureContext(true);
    const writeText = stubClipboard(vi.fn(() => Promise.resolve()));

    await expect(copyText("tg://proxy")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("tg://proxy");
  });

  it("falls back to a text area when the page is not a secure context, as on plain HTTP", async () => {
    setSecureContext(false);
    let copied: string | undefined;
    const execCommand = stubExecCommand(true);
    execCommand.mockImplementation((command: string) => {
      copied = document.activeElement instanceof HTMLTextAreaElement ? document.activeElement.value : undefined;
      return command === "copy";
    });

    await expect(copyText("tg://proxy")).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(copied).toBe("tg://proxy");
    // The text area is not left behind.
    expect(document.querySelector("textarea")).toBeNull();
  });

  it("copies from inside a dialog and gives the focus back to what had it", async () => {
    setSecureContext(false);
    const dialog = document.body.appendChild(document.createElement("div"));
    dialog.setAttribute("role", "dialog");
    const button = dialog.appendChild(document.createElement("button"));
    button.focus();
    let parent: Element | null | undefined;
    stubExecCommand(true).mockImplementation(() => {
      parent = document.activeElement?.parentElement;
      return true;
    });

    await expect(copyText("text")).resolves.toBe(true);
    expect(parent).toBe(dialog);
    expect(document.activeElement).toBe(button);
    dialog.remove();
  });

  it("does not touch the clipboard API outside a secure context, even if it is there", async () => {
    setSecureContext(false);
    const writeText = stubClipboard(vi.fn(() => Promise.resolve()));
    stubExecCommand(true);

    await expect(copyText("text")).resolves.toBe(true);
    expect(writeText).not.toHaveBeenCalled();
  });

  it("falls back to a text area when the clipboard API refuses", async () => {
    setSecureContext(true);
    const writeText = stubClipboard(vi.fn(() => Promise.reject(new DOMException("denied", "NotAllowedError"))));
    const execCommand = stubExecCommand(true);

    await expect(copyText("text")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalled();
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("says no when nothing can copy", async () => {
    setSecureContext(false);
    stubExecCommand(false);
    await expect(copyText("text")).resolves.toBe(false);
    expect(document.querySelector("textarea")).toBeNull();

    stubExecCommand(new Error("not allowed"));
    await expect(copyText("text")).resolves.toBe(false);
    expect(document.querySelector("textarea")).toBeNull();
  });
});

describe("copyText of a text that is still being made", () => {
  it("hands a clipboard item over at once, before the text is there: Safari copies only inside the click", async () => {
    setSecureContext(true);
    stubClipboardItem();
    const write = vi.fn<(items: ClipboardItem[]) => Promise<void>>(() => Promise.resolve());
    Object.defineProperty(window.navigator, "clipboard", { configurable: true, value: { write } });
    let resolveText: (text: string) => void = () => undefined;
    const pending = new Promise<string>((resolve) => {
      resolveText = resolve;
    });

    const result = copyText(pending);
    // Nothing has been fetched yet, and the clipboard has been asked already.
    expect(write).toHaveBeenCalledTimes(1);
    resolveText("tg://proxy?server=203.0.113.7");
    await expect(result).resolves.toBe(true);

    const item = write.mock.calls[0]?.[0][0] as unknown as { items: Record<string, Promise<Blob>> };
    const blob = await item.items["text/plain"];
    expect(blob?.type).toBe("text/plain");
    expect(await blob?.text()).toBe("tg://proxy?server=203.0.113.7");
  });

  it("waits for the text where there are no clipboard items", async () => {
    setSecureContext(true);
    const writeText = stubClipboard(vi.fn(() => Promise.resolve()));

    await expect(copyText(Promise.resolve("later"))).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("later");
  });

  it("waits for the text outside a secure context, and copies it through the text area", async () => {
    setSecureContext(false);
    let copied: string | undefined;
    const execCommand = stubExecCommand(true);
    execCommand.mockImplementation((command: string) => {
      copied = document.activeElement instanceof HTMLTextAreaElement ? document.activeElement.value : undefined;
      return command === "copy";
    });

    await expect(copyText(Promise.resolve("later"))).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(copied).toBe("later");
  });

  it("falls back to the text area when the clipboard refuses the item", async () => {
    setSecureContext(true);
    stubClipboardItem();
    const write = vi.fn<(items: ClipboardItem[]) => Promise<void>>(() =>
      Promise.reject(new DOMException("denied", "NotAllowedError")),
    );
    Object.defineProperty(window.navigator, "clipboard", { configurable: true, value: { write } });
    const execCommand = stubExecCommand(true);

    await expect(copyText(Promise.resolve("later"))).resolves.toBe(true);
    expect(write).toHaveBeenCalled();
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("fails with the reason when the text cannot be made, and copies nothing", async () => {
    setSecureContext(true);
    stubClipboardItem();
    const write = vi.fn((items: ClipboardItem[]) => {
      // A real clipboard waits for the content of the item, and fails when it does.
      const item = items[0] as unknown as { items: Record<string, Promise<Blob>> };
      return item.items["text/plain"]?.then(() => undefined) ?? Promise.resolve();
    });
    Object.defineProperty(window.navigator, "clipboard", { configurable: true, value: { write } });
    const execCommand = stubExecCommand(true);

    await expect(copyText(Promise.reject(new Error("no link for you")))).rejects.toThrow("no link for you");
    expect(execCommand).not.toHaveBeenCalled();
  });
});

describe("useCopy", () => {
  function Copier({ text, failure }: { text: () => string | Promise<string>; failure?: string }) {
    const copy = useCopy();
    return (
      <button
        type="button"
        onClick={() => {
          // Made when the button is clicked: a promise that fails is not left without a handler.
          void copy(text(), failure);
        }}
      >
        copy it
      </button>
    );
  }

  it("says that a text that was waited for was copied", async () => {
    setSecureContext(true);
    const user = userEvent.setup();
    renderWithProviders(<Copier text={() => Promise.resolve("later")} />);

    await user.click(screen.getByRole("button", { name: "copy it" }));

    expect(await screen.findByText(t("common.copied"))).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe("later");
  });

  it("shows why when the text could not be made, and does not claim a copy failed", async () => {
    setSecureContext(true);
    const user = userEvent.setup();
    const reason = new ConnectError("no such proxy", Code.NotFound);
    reason.isWireError = true;
    renderWithProviders(<Copier text={() => Promise.reject(reason)} />);

    await user.click(screen.getByRole("button", { name: "copy it" }));

    expect(await screen.findByText("no such proxy")).toBeInTheDocument();
    expect(screen.queryByText(t("common.copied"))).not.toBeInTheDocument();
    expect(screen.queryByText(t("common.copyFailed"))).not.toBeInTheDocument();
  });

  it("says what the caller wants when nothing could copy", async () => {
    setSecureContext(false);
    stubExecCommand(false);
    const user = userEvent.setup();
    renderWithProviders(<Copier text={() => "text"} failure="Open the proxy and copy it there." />);

    await user.click(screen.getByRole("button", { name: "copy it" }));

    expect(await screen.findByText("Open the proxy and copy it there.")).toBeInTheDocument();
    expect(screen.queryByText(t("common.copyFailed"))).not.toBeInTheDocument();
  });
});

describe("CopyButton", () => {
  it("copies the value and says so", async () => {
    setSecureContext(true);
    const user = userEvent.setup();
    renderWithProviders(<CopyButton value="tg://proxy?server=203.0.113.7" />);

    await user.click(screen.getByRole("button", { name: t("common.copy") }));

    expect(await screen.findByText(t("common.copied"))).toBeInTheDocument();
    expect(await navigator.clipboard.readText()).toBe("tg://proxy?server=203.0.113.7");
  });

  it("says so when it could not copy", async () => {
    setSecureContext(false);
    stubExecCommand(false);
    const user = userEvent.setup();
    renderWithProviders(<CopyButton value="text" label="Copy the link" />);

    await user.click(screen.getByRole("button", { name: "Copy the link" }));

    expect(await screen.findByText(t("common.copyFailed"))).toBeInTheDocument();
    expect(screen.queryByText(t("common.copied"))).not.toBeInTheDocument();
  });
});
