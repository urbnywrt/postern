import { Code, ConnectError } from "@connectrpc/connect";

/**
 * A part of an answer of the panel that the panel always sends. In protobuf a
 * message field may be unset, so the type says `| undefined`; one that is
 * missing is a fault of the panel, shown like an error of the call.
 */
export function present<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new ConnectError("the answer of the panel is incomplete", Code.Internal);
  }
  return value;
}
