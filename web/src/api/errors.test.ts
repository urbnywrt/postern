import { Code, ConnectError, createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { describe, expect, it } from "vitest";

import { AuthService } from "../gen/postern/panel/v1/auth_pb";
import i18n from "../i18n";
import { t } from "../test/t";
import { errorMessage, isUnauthenticated } from "./errors";

/** An error as the client makes it from the answer of the panel. */
function fromPanel(message: string, code: Code) {
  const error = new ConnectError(message, code);
  error.isWireError = true;
  return error;
}

/** What the real Connect client throws when its `fetch` does this: a call that is made and fails. */
async function failureOf(fetch: typeof globalThis.fetch): Promise<unknown> {
  const client = createClient(AuthService, createConnectTransport({ baseUrl: "/api", fetch }));
  try {
    await client.me({});
  } catch (error) {
    return error;
  }
  throw new Error("the call did not fail");
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("errorMessage", () => {
  it("is the message of the panel, as it said it", () => {
    expect(errorMessage(fromPanel("the password is wrong", Code.PermissionDenied))).toBe("the password is wrong");
    expect(errorMessage(fromPanel("too many failed attempts; try again in 30 seconds", Code.ResourceExhausted))).toBe(
      "too many failed attempts; try again in 30 seconds",
    );
  });

  it("is a general text when the panel said nothing", () => {
    expect(errorMessage(fromPanel("", Code.Internal))).toBe(t("errors.failed"));
    expect(errorMessage(fromPanel("", Code.Unknown))).toBe(t("errors.failed"));
  });

  it("says that the panel cannot be reached when the network failed, or a gateway answered for it", () => {
    // fetch() rejects with a TypeError when there is no connection.
    expect(errorMessage(new TypeError("Failed to fetch"))).toBe(t("errors.unreachable"));
    expect(errorMessage(new ConnectError("HTTP 502", Code.Unavailable))).toBe(t("errors.unreachable"));
    expect(errorMessage(new ConnectError("timed out", Code.DeadlineExceeded))).toBe(t("errors.unreachable"));
  });

  it("says so for a network failure as the client reports it: an error of code unknown, caused by a TypeError", () => {
    expect(errorMessage(ConnectError.from(new TypeError("Failed to fetch")))).toBe(t("errors.unreachable"));
    // Firefox and Safari word it differently; it is a TypeError in all of them.
    expect(errorMessage(new TypeError("NetworkError when attempting to fetch resource."))).toBe(
      t("errors.unreachable"),
    );
    expect(errorMessage(new TypeError("Load failed"))).toBe(t("errors.unreachable"));
  });

  it("does not take an answer of the server for a lost connection: a bare HTTP 500 is a server error", () => {
    // The client makes a code-unknown error of "HTTP 500" when the body is no Connect error.
    const bare = new ConnectError("HTTP 500", Code.Unknown);
    expect(errorMessage(bare)).toBe(t("errors.server"));
    expect(errorMessage(bare)).not.toBe(t("errors.unreachable"));
    expect(errorMessage(new ConnectError("unsupported content type text/html", Code.Unknown))).toBe(
      t("errors.server"),
    );
    // An error that is not a TypeError is not a lost connection either.
    expect(errorMessage(new Error("boom"))).toBe(t("errors.server"));
  });

  it("is a general text for a failure that is not of the network and not of the panel", () => {
    expect(errorMessage(new ConnectError("protocol error", Code.InvalidArgument))).toBe(t("errors.failed"));
    expect(errorMessage(new ConnectError("HTTP 400", Code.Internal))).toBe(t("errors.failed"));
  });

  it("tells a lost connection from an answer of the server as the real client reports them", async () => {
    const offline = await failureOf(() => Promise.reject(new TypeError("Failed to fetch")));
    expect(errorMessage(offline)).toBe(t("errors.unreachable"));

    const crashed = await failureOf(() => Promise.resolve(new Response("", { status: 500 })));
    expect(errorMessage(crashed)).toBe(t("errors.server"));

    const gateway = await failureOf(() =>
      Promise.resolve(new Response("<h1>Bad gateway</h1>", { status: 502, headers: { "content-type": "text/html" } })),
    );
    expect(errorMessage(gateway)).toBe(t("errors.unreachable"));

    const refused = await failureOf(() =>
      Promise.resolve(json(403, { code: "permission_denied", message: "the password is wrong" })),
    );
    expect(errorMessage(refused)).toBe("the password is wrong");
  });

  it("speaks the language of the page", async () => {
    await i18n.changeLanguage("ru");
    expect(errorMessage(new TypeError("Failed to fetch"))).toBe(i18n.t("errors.unreachable"));
    expect(i18n.t("errors.unreachable")).not.toBe(t("errors.unreachable"));
    expect(errorMessage(new ConnectError("HTTP 500", Code.Unknown))).toBe(i18n.t("errors.server"));
    expect(i18n.t("errors.server")).not.toBe(t("errors.server"));
    // The message of the panel is not translated.
    expect(errorMessage(fromPanel("the password is wrong", Code.PermissionDenied))).toBe("the password is wrong");
  });
});

describe("isUnauthenticated", () => {
  it("is true for a 401 of the panel only", () => {
    expect(isUnauthenticated(fromPanel("authentication required", Code.Unauthenticated))).toBe(true);
    expect(isUnauthenticated(fromPanel("the password is wrong", Code.PermissionDenied))).toBe(false);
    expect(isUnauthenticated(new Error("authentication required"))).toBe(false);
    expect(isUnauthenticated(undefined)).toBe(false);
  });
});
