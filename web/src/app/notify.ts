import { notifications } from "@mantine/notifications";

import { errorMessage } from "../api/errors";
import i18n from "../i18n";

export function notifyFailure(message: string): void {
  notifications.show({
    color: "red",
    title: i18n.t("common.error"),
    message,
    autoClose: 8000,
  });
}

/** Tells an admin that a call failed, in the words of the panel. */
export function notifyError(error: unknown): void {
  notifyFailure(errorMessage(error));
}

export function notifySuccess(message: string): void {
  notifications.show({ color: "teal", message });
}

/** Warns an admin about something that was done but needs a look. It stays until it is closed. */
export function notifyWarning(title: string, message: string): void {
  notifications.show({ color: "yellow", title, message, autoClose: false });
}

/** Removes the notifications that are still on the screen, such as the errors of an earlier try. */
export function clearNotifications(): void {
  notifications.clean();
}
