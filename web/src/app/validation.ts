import type { TFunction } from "i18next";

import { formatNumber } from "./format";
import {
  INTERNAL_PORT_FIRST,
  INTERNAL_PORT_LAST,
  MAX_CHECK_INTERVAL,
  MAX_CHECK_THRESHOLD,
  MAX_CHECK_TIMEOUT,
  MAX_HTTP_CREDENTIAL_BYTES,
  MAX_LIMIT,
  MAX_NAME_CHARS,
  MAX_NOTE_CHARS,
  MAX_SELECT_NAME_BYTES,
  MAX_SOCKS5_CREDENTIAL_BYTES,
  MAX_SUBSCRIPTION_URL_BYTES,
} from "./validators";

// The limits are those of AuthService (proto/postern/panel/v1/auth.proto). The
// panel checks them again; the UI only saves a round trip, and says what is wrong.
export const MIN_PASSWORD_CHARS = 12;
export const MAX_PASSWORD_BYTES = 256;
export const MAX_USERNAME_CHARS = 64;

/** What can be wrong with a field. It is a key of "validation" in the translations. */
export type ValidationError =
  | "required"
  | "usernameLength"
  | "usernameChars"
  | "passwordShort"
  | "passwordLong"
  | "mismatch"
  | "code"
  | "nameLong"
  | "noteLong"
  | "controlChars"
  | "host"
  | "port"
  | "portInternal"
  | "bindIp"
  | "maskTarget"
  | "maskTargetInternal"
  | "domain"
  | "secret"
  | "adTag"
  | "limit"
  | "hostPort"
  | "hostPortPort"
  | "hostPortChars"
  | "hostPortBrackets"
  | "passwordUser"
  | "passwordAgain"
  | "credentialLong"
  | "httpCredentialLong"
  | "usernameColon"
  | "interface"
  | "sourceIp"
  | "urlLong"
  | "urlSpaces"
  | "selectLong"
  | "checkInterval"
  | "checkTimeout"
  | "checkThreshold"
  | "webDomain"
  | "basePath"
  | "basePathRequired"
  | "trustedCidr"
  | "trustedCidrsRequired"
  | "upstreamBindIp"
  | "email"
  | "certificate"
  | "sshUser"
  | "partnerId"
  | "partnerPair";

/** Code points, not UTF-16 units: the panel counts runes. */
const length = (text: string) => Array.from(text).length;

export function validateRequired(value: string): ValidationError | null {
  return value.trim() === "" ? "required" : null;
}

/**
 * A password that is typed to sign in or to confirm an action: the panel says
 * whether it is the right one. Spaces are part of a password (see
 * validateNewPassword), so it is missing only when the field is empty; it is
 * not trimmed here or when it is sent.
 */
export function validatePassword(value: string): ValidationError | null {
  return value === "" ? "required" : null;
}

export function validateUsername(value: string): ValidationError | null {
  const name = value.trim();
  if (name === "") {
    return "required";
  }
  if (length(name) > MAX_USERNAME_CHARS) {
    return "usernameLength";
  }
  if (/[\s\p{Cc}]/u.test(name)) {
    return "usernameChars";
  }
  return null;
}

/** A password that is to be set. The one that is typed to sign in is not checked: the panel does it. */
export function validateNewPassword(value: string): ValidationError | null {
  if (value === "") {
    return "required";
  }
  if (new TextEncoder().encode(value).length > MAX_PASSWORD_BYTES) {
    return "passwordLong";
  }
  if (length(value) < MIN_PASSWORD_CHARS) {
    return "passwordShort";
  }
  return null;
}

export function validateRepeat(password: string, repeat: string): ValidationError | null {
  return password === repeat ? null : "mismatch";
}

/** Apps show the code in two groups of three, and people type or paste it so. */
export function normalizeCode(value: string): string {
  return value.replace(/\s+/g, "");
}

export function validateCode(value: string): ValidationError | null {
  return /^\d{6}$/.test(normalizeCode(value)) ? null : "code";
}

/** The words for an error, in the language of the page. */
export function validationMessage(t: TFunction, error: ValidationError | null): string | undefined {
  switch (error) {
    case null:
      return undefined;
    case "required":
      return t("validation.required");
    case "usernameLength":
      return t("validation.usernameLength", { max: MAX_USERNAME_CHARS });
    case "usernameChars":
      return t("validation.usernameChars");
    case "passwordShort":
      return t("validation.passwordShort", { min: MIN_PASSWORD_CHARS });
    case "passwordLong":
      return t("validation.passwordLong", { max: MAX_PASSWORD_BYTES });
    case "mismatch":
      return t("validation.mismatch");
    case "code":
      return t("validation.code");
    case "nameLong":
      return t("validation.textLong", { max: MAX_NAME_CHARS });
    case "noteLong":
      return t("validation.textLong", { max: MAX_NOTE_CHARS });
    case "controlChars":
      return t("validation.controlChars");
    case "host":
      return t("validation.host");
    case "port":
      return t("validation.port");
    case "portInternal":
      return t("validation.portInternal", { first: INTERNAL_PORT_FIRST, last: INTERNAL_PORT_LAST });
    case "bindIp":
      return t("validation.bindIp");
    case "maskTarget":
      return t("validation.maskTarget");
    case "maskTargetInternal":
      return t("validation.maskTargetInternal", { first: INTERNAL_PORT_FIRST, last: INTERNAL_PORT_LAST });
    case "domain":
      return t("validation.domain");
    case "secret":
      return t("validation.secret");
    case "adTag":
      return t("validation.adTag");
    case "limit":
      return t("validation.limit", { max: formatNumber(MAX_LIMIT) });
    case "hostPort":
      return t("validation.hostPort");
    case "hostPortPort":
      return t("validation.hostPortPort");
    case "hostPortChars":
      return t("validation.hostPortChars");
    case "hostPortBrackets":
      return t("validation.hostPortBrackets");
    case "passwordUser":
      return t("validation.passwordUser");
    case "passwordAgain":
      return t("validation.passwordAgain");
    case "credentialLong":
      return t("validation.bytesLong", { max: MAX_SOCKS5_CREDENTIAL_BYTES });
    case "httpCredentialLong":
      return t("validation.bytesLong", { max: MAX_HTTP_CREDENTIAL_BYTES });
    case "usernameColon":
      return t("validation.usernameColon");
    case "interface":
      return t("validation.interface");
    case "sourceIp":
      return t("validation.sourceIp");
    case "urlLong":
      return t("validation.bytesLong", { max: MAX_SUBSCRIPTION_URL_BYTES });
    case "urlSpaces":
      return t("validation.urlSpaces");
    case "selectLong":
      return t("validation.bytesLong", { max: MAX_SELECT_NAME_BYTES });
    case "checkInterval":
      return t("validation.checkInterval", { max: MAX_CHECK_INTERVAL });
    case "checkTimeout":
      return t("validation.checkTimeout", { max: MAX_CHECK_TIMEOUT });
    case "checkThreshold":
      return t("validation.checkThreshold", { max: MAX_CHECK_THRESHOLD });
    case "webDomain":
      return t("validation.webDomain");
    case "basePath":
      return t("validation.basePath");
    case "basePathRequired":
      return t("validation.basePathRequired");
    case "trustedCidr":
      return t("validation.trustedCidr");
    case "trustedCidrsRequired":
      return t("validation.trustedCidrsRequired");
    case "upstreamBindIp":
      return t("validation.upstreamBindIp");
    case "email":
      return t("validation.email");
    case "certificate":
      return t("validation.certificate");
    case "sshUser":
      return t("validation.sshUser");
    case "partnerId":
      return t("validation.partnerId");
    case "partnerPair":
      return t("validation.partnerPair");
  }
}
