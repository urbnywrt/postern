import type { ParseKeys } from "i18next";

import i18n from "../i18n";

/** The English strings of the UI, typed by key: tests look text up instead of repeating it. */
export const t = i18n.getFixedT("en");

/** A key of the translation files, for a helper that takes one. */
export type TKey = ParseKeys;
