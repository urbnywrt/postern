import { describe, expect, it } from "vitest";

import { t } from "../test/t";
import {
  normalizeCode,
  validateCode,
  validateNewPassword,
  validatePassword,
  validateRepeat,
  validateRequired,
  validateUsername,
  validationMessage,
} from "./validation";

describe("validateRequired", () => {
  it.each([
    ["", "required"],
    ["   ", "required"],
    ["a", null],
    [" a ", null],
  ] as const)("%j gives %s", (value, expected) => {
    expect(validateRequired(value)).toBe(expected);
  });
});

describe("validatePassword", () => {
  // Spaces are part of a password (validateNewPassword takes twelve of them), so a
  // password that is typed to sign in or to confirm an action is missing only when
  // the field is empty. The panel is the one that says whether it is the right one.
  it.each([
    ["", "required"],
    ["a", null],
    [" ", null],
    ["   ", null],
    [" a ", null],
    ["\t", null],
  ] as const)("%j gives %s", (value, expected) => {
    expect(validatePassword(value)).toBe(expected);
  });

  it("is the same rule as the one for a new password: only an empty field is missing", () => {
    for (const value of ["", " ", "x".repeat(12)]) {
      expect(validatePassword(value) === "required").toBe(validateNewPassword(value) === "required");
    }
  });
});

describe("validateUsername", () => {
  it.each([
    ["admin", null],
    ["  admin  ", null], // the panel trims it
    ["Админ", null],
    ["a".repeat(64), null],
    ["a".repeat(65), "usernameLength"],
    ["я".repeat(64), null], // 64 characters, 128 bytes
    ["я".repeat(65), "usernameLength"],
    ["", "required"],
    ["   ", "required"],
    ["two words", "usernameChars"],
    ["tab\tin", "usernameChars"],
    ["bell\u0007", "usernameChars"],
  ] as const)("%j gives %s", (value, expected) => {
    expect(validateUsername(value)).toBe(expected);
  });
});

describe("validateNewPassword", () => {
  it.each([
    ["", "required"],
    ["short", "passwordShort"],
    ["x".repeat(11), "passwordShort"],
    ["x".repeat(12), null],
    ["x".repeat(256), null],
    ["x".repeat(257), "passwordLong"],
    // 12 characters are enough, whatever their size in bytes ...
    ["п".repeat(12), null],
    ["п".repeat(11), "passwordShort"],
    // ... and an emoji is one character of 4 bytes, not two.
    ["😀".repeat(12), null],
    ["😀".repeat(11), "passwordShort"],
    // The panel allows 256 bytes: 128 Cyrillic letters, not 129.
    ["п".repeat(128), null],
    ["п".repeat(129), "passwordLong"],
    // Spaces are part of a password.
    [" ".repeat(12), null],
  ] as const)("%j gives %s", (value, expected) => {
    expect(validateNewPassword(value)).toBe(expected);
  });
});

describe("validateRepeat", () => {
  it("accepts the same password and refuses another", () => {
    expect(validateRepeat("abc", "abc")).toBeNull();
    expect(validateRepeat("abc", "abd")).toBe("mismatch");
    expect(validateRepeat("abc", "")).toBe("mismatch");
    expect(validateRepeat("", "")).toBeNull();
  });
});

describe("codes", () => {
  it.each([
    ["123456", "123456"],
    ["123 456", "123456"],
    [" 123  456 ", "123456"],
    ["123 456", "123456"],
    ["", ""],
  ])("normalizes %j to %j", (value, expected) => {
    expect(normalizeCode(value)).toBe(expected);
  });

  it.each([
    ["123456", null],
    ["123 456", null],
    ["000000", null],
    ["12345", "code"],
    ["1234567", "code"],
    ["12345a", "code"],
    ["", "code"],
    ["١٢٣٤٥٦", "code"], // Arabic-Indic digits are not the digits of a TOTP code
  ] as const)("%j gives %s", (value, expected) => {
    expect(validateCode(value)).toBe(expected);
  });
});

describe("validationMessage", () => {
  it("has a text for every error, with the limits filled in", () => {
    expect(validationMessage(t, null)).toBeUndefined();
    expect(validationMessage(t, "required")).toBe(t("validation.required"));
    expect(validationMessage(t, "usernameLength")).toBe("Use 1 to 64 characters");
    expect(validationMessage(t, "usernameChars")).toBe(t("validation.usernameChars"));
    expect(validationMessage(t, "passwordShort")).toBe("At least 12 characters");
    expect(validationMessage(t, "passwordLong")).toBe("At most 256 bytes");
    expect(validationMessage(t, "mismatch")).toBe(t("validation.mismatch"));
    expect(validationMessage(t, "code")).toBe(t("validation.code"));
  });

  it("has a text for the errors of nodes, listeners and proxies, with the limits filled in", () => {
    expect(validationMessage(t, "nameLong")).toBe("At most 64 characters");
    expect(validationMessage(t, "noteLong")).toBe("At most 1024 characters");
    expect(validationMessage(t, "controlChars")).toBe(t("validation.controlChars"));
    expect(validationMessage(t, "host")).toBe(t("validation.host"));
    expect(validationMessage(t, "port")).toBe(t("validation.port"));
    expect(validationMessage(t, "portInternal")).toContain("20000");
    expect(validationMessage(t, "portInternal")).toContain("40999");
    expect(validationMessage(t, "bindIp")).toBe(t("validation.bindIp"));
    expect(validationMessage(t, "maskTarget")).toBe(t("validation.maskTarget"));
    expect(validationMessage(t, "maskTargetInternal")).toContain("40999");
    expect(validationMessage(t, "domain")).toBe(t("validation.domain"));
    expect(validationMessage(t, "secret")).toBe(t("validation.secret"));
    expect(validationMessage(t, "adTag")).toBe(t("validation.adTag"));
    expect(validationMessage(t, "limit")).toContain("4,294,967,295");
  });
});
