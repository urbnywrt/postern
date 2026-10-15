import { Code, ConnectError } from "@connectrpc/connect";

import i18n from "../i18n";

/** The call came without a session, or the session has ended. */
export function isUnauthenticated(error: unknown): boolean {
  return error instanceof ConnectError && error.code === Code.Unauthenticated;
}

/** There is no such thing: a node, listener or proxy that is gone, or never was. */
export function isNotFound(error: unknown): boolean {
  return error instanceof ConnectError && error.code === Code.NotFound;
}

/**
 * The text that tells an admin why a call failed: what the panel said, when it
 * said something; else a general text. A failure of the network, or of a
 * gateway in front of the panel, has no message of the panel in it.
 */
export function errorMessage(error: unknown): string {
  const failure = ConnectError.from(error);
  if (failure.isWireError) {
    return failure.rawMessage !== "" ? failure.rawMessage : i18n.t("errors.failed");
  }
  switch (failure.code) {
    case Code.Unavailable:
    case Code.DeadlineExceeded:
      // A gateway that cannot reach the panel (HTTP 502, 503, 504), or a timeout.
      return i18n.t("errors.unreachable");
    case Code.Unknown:
      // Two things end up here. fetch() rejects with a TypeError when the request
      // did not get through (no network, a refused connection, a TLS failure), and
      // the client keeps that TypeError as the cause. Anything else is what the
      // client made of an answer that is not the panel's: a bare "HTTP 500", or a
      // page that is not Connect. The server did answer, so it is no lost connection.
      return failure.cause instanceof TypeError ? i18n.t("errors.unreachable") : i18n.t("errors.server");
    default:
      return i18n.t("errors.failed");
  }
}
