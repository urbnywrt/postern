import { useCallback } from "react";
import { useTranslation } from "react-i18next";

import { notifyError, notifyFailure, notifySuccess } from "./notify";

/** Whether the browser can be handed a clipboard item whose content is still on its way. */
function canWriteItems(): boolean {
  return typeof ClipboardItem !== "undefined" && typeof navigator.clipboard.write === "function";
}

/**
 * Puts text on the clipboard. The async clipboard API exists only in a secure
 * context (HTTPS or localhost), and the panel is often opened over plain HTTP on
 * a home network, so there is a fallback through a hidden text area.
 *
 * The text may be a promise, for a text that has to be fetched first (the link
 * of a proxy). Safari copies only inside the click that asked for it, and a
 * fetch is over by then, so the clipboard is handed an item at once that gets its
 * content when the text is there. The promise that fails fails the copy, with
 * its reason: nothing is copied.
 */
export async function copyText(text: string | Promise<string>): Promise<boolean> {
  if (window.isSecureContext && "clipboard" in navigator) {
    try {
      if (typeof text !== "string" && canWriteItems()) {
        const blob = text.then((value) => new Blob([value], { type: "text/plain" }));
        await navigator.clipboard.write([new ClipboardItem({ "text/plain": blob })]);
      } else {
        await navigator.clipboard.writeText(await text);
      }
      return true;
    } catch {
      // Permission denied, or the page has no focus, or the text could not be made
      // (it fails again below, and that is the answer): try the old way.
    }
  }
  return copyThroughTextArea(await text);
}

function copyThroughTextArea(text: string): boolean {
  const previous = document.activeElement;
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "0";
  area.style.opacity = "0";
  // Inside the dialog that the copy button is in, if there is one: a dialog keeps
  // the focus to itself, and the text has to be selected in the focused element.
  (previous?.closest("[role='dialog']") ?? document.body).appendChild(area);
  try {
    area.focus({ preventScroll: true });
    area.select();
    area.setSelectionRange(0, text.length);
    // Deprecated, but the one way to copy in a page that is not a secure context.
    // eslint-disable-next-line @typescript-eslint/no-deprecated
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    area.remove();
    if (previous instanceof HTMLElement) {
      previous.focus({ preventScroll: true });
    }
  }
}

/**
 * A function that copies text and tells the admin whether it worked. `failure`
 * is what to say when nothing could copy, where "select the text and copy it by
 * hand" is not an option. A text that could not be made is reported with its
 * own reason, the message of the panel, and not as a failure to copy.
 */
export function useCopy(): (text: string | Promise<string>, failure?: string) => Promise<boolean> {
  const { t } = useTranslation();
  return useCallback(
    async (text: string | Promise<string>, failure?: string) => {
      let copied: boolean;
      try {
        copied = await copyText(text);
      } catch (error) {
        notifyError(error);
        return false;
      }
      if (copied) {
        notifySuccess(t("common.copied"));
      } else {
        notifyFailure(failure ?? t("common.copyFailed"));
      }
      return copied;
    },
    [t],
  );
}
