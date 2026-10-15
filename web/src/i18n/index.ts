import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import { readStored, writeStored } from "../app/storage";
import en from "./en.json";
import insightsEn from "./insights.en.json";
import insightsRu from "./insights.ru.json";
import ru from "./ru.json";

export const LANGUAGES = ["ru", "en"] as const;
export type Language = (typeof LANGUAGES)[number];

export const LANGUAGE_KEY = "postern.language";

export function isLanguage(value: unknown): value is Language {
  return LANGUAGES.some((language) => language === value);
}

/** The language for a browser language tag: "ru" and "ru-RU" give Russian, anything else English. */
export function languageFromTag(tag: string | undefined): Language {
  return tag?.toLowerCase().split("-")[0] === "ru" ? "ru" : "en";
}

/** What an admin chose before, else the language of the browser. */
export function detectLanguage(): Language {
  const stored = readStored(LANGUAGE_KEY);
  return isLanguage(stored) ? stored : languageFromTag(navigator.language);
}

/** Switches the language and remembers the choice. */
export async function setLanguage(language: Language): Promise<void> {
  writeStored(LANGUAGE_KEY, language);
  await i18n.changeLanguage(language);
}

i18n.on("languageChanged", (language) => {
  document.documentElement.lang = language;
});

// The resources are bundled, so init is synchronous and nothing has to suspend.
void i18n.use(initReactI18next).init({
  // The strings of statistics, diagnostics and the public page live in their own files
  // (top-level key "insights"), merged into the one namespace.
  resources: { en: { translation: { ...en, ...insightsEn } }, ru: { translation: { ...ru, ...insightsRu } } },
  lng: detectLanguage(),
  fallbackLng: "en",
  supportedLngs: LANGUAGES,
  // React escapes what it renders.
  interpolation: { escapeValue: false },
  react: { useSuspense: false },
});

export default i18n;
