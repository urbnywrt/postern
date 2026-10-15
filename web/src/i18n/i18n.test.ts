import { describe, expect, it, vi } from "vitest";

import en from "./en.json";
import i18n, { detectLanguage, languageFromTag, LANGUAGE_KEY, setLanguage } from "./index";
import insightsEn from "./insights.en.json";
import insightsRu from "./insights.ru.json";
import ru from "./ru.json";

/** The path of every string in a translation file: "settings.password.title". */
function leafPaths(node: unknown, prefix = ""): string[] {
  if (typeof node === "string") {
    return [prefix];
  }
  if (typeof node !== "object" || node === null || Array.isArray(node)) {
    throw new Error(`${prefix || "<root>"} is neither a string nor an object`);
  }
  return Object.keys(node).flatMap((key) =>
    leafPaths((node as Record<string, unknown>)[key], prefix === "" ? key : `${prefix}.${key}`),
  );
}

function valueAt(node: unknown, path: string): string {
  const value = path.split(".").reduce<unknown>((at, key) => (at as Record<string, unknown>)[key], node);
  if (typeof value !== "string") {
    throw new Error(`${path} is not a string`);
  }
  return value;
}

const placeholders = (text: string) => [...new Set([...text.matchAll(/{{\s*(\w+)\s*}}/g)].map((m) => m[1]))].sort();

// A string that depends on a number has a form for each plural category of its
// language ("message_one", "message_other"; Russian has "few" and "many" too), as
// i18next looks them up. A language may also have the one plain key for all counts.
const PLURAL = /_(zero|one|two|few|many|other)$/;
const baseOf = (path: string) => path.replace(PLURAL, "");

/** The strings of a file by their key without the plural suffix: the forms of a plural are one entry. */
function byBase(file: unknown): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const path of leafPaths(file)) {
    map.set(baseOf(path), [...(map.get(baseOf(path)) ?? []), path]);
  }
  return map;
}

// The strings of the UI, file by file, so that a key that is missing in one language is named.
const FILES = [
  { name: "main", en, ru },
  { name: "insights", en: insightsEn, ru: insightsRu },
] as const;

describe.each(FILES)("translations: $name", ({ en, ru }) => {
  it("have the same keys in ru and en, the forms of a plural counted as one", () => {
    expect([...byBase(ru).keys()].sort()).toEqual([...byBase(en).keys()].sort());
  });

  it("have every plural form of the language where a key has plural forms", () => {
    for (const [language, file] of [
      ["en", en],
      ["ru", ru],
    ] as const) {
      const categories = new Intl.PluralRules(language).resolvedOptions().pluralCategories.slice().sort();
      for (const [base, paths] of byBase(file)) {
        if (paths.some((path) => PLURAL.test(path))) {
          const forms = paths.map((path) => PLURAL.exec(path)?.[1] ?? "").sort();
          expect(forms, `${language}: ${base}`).toEqual(categories);
        }
      }
    }
  });

  it("have plural forms in ru wherever en has them", () => {
    const ruByBase = byBase(ru);
    for (const [base, paths] of byBase(en)) {
      if (paths.some((path) => PLURAL.test(path))) {
        expect(
          (ruByBase.get(base) ?? []).every((path) => PLURAL.test(path)),
          `ru: ${base} has a plain key where en has plural forms`,
        ).toBe(true);
      }
    }
  });

  it("have no empty strings", () => {
    for (const [name, file] of [
      ["en", en],
      ["ru", ru],
    ] as const) {
      for (const path of leafPaths(file)) {
        expect(valueAt(file, path).trim(), `${name}: ${path}`).not.toBe("");
      }
    }
  });

  it("use the same placeholders in both languages", () => {
    const ruByBase = byBase(ru);
    const all = (file: unknown, paths: string[]) => [...new Set(paths.flatMap((path) => placeholders(valueAt(file, path))))].sort();
    for (const [base, paths] of byBase(en)) {
      expect(all(ru, ruByBase.get(base) ?? []), base).toEqual(all(en, paths));
    }
  });
});

describe("translations: the files together", () => {
  it("share no top-level key, so that the merge loses nothing", () => {
    const overlap = Object.keys(insightsEn).filter((key) => key in en);
    expect(overlap).toEqual([]);
  });

  it("serve the strings of the insights file through the one namespace", () => {
    expect(i18n.getFixedT("en")("insights.publicPage.title")).toBe(insightsEn.insights.publicPage.title);
    expect(i18n.getFixedT("ru")("insights.publicPage.title")).toBe(insightsRu.insights.publicPage.title);
  });
});

describe("language", () => {
  it.each([
    ["ru", "ru"],
    ["ru-RU", "ru"],
    ["RU-ru", "ru"],
    ["en-US", "en"],
    ["en", "en"],
    ["de-DE", "en"],
    ["", "en"],
    [undefined, "en"],
  ])("maps the browser language %j to %s", (tag, expected) => {
    expect(languageFromTag(tag)).toBe(expected);
  });

  it("defaults to the language of the browser", () => {
    vi.spyOn(window.navigator, "language", "get").mockReturnValue("ru-RU");
    expect(detectLanguage()).toBe("ru");
    vi.spyOn(window.navigator, "language", "get").mockReturnValue("fr-FR");
    expect(detectLanguage()).toBe("en");
  });

  it("prefers the language that was chosen before", () => {
    vi.spyOn(window.navigator, "language", "get").mockReturnValue("en-US");
    window.localStorage.setItem(LANGUAGE_KEY, "ru");
    expect(detectLanguage()).toBe("ru");
  });

  it("ignores a stored language that is not offered", () => {
    vi.spyOn(window.navigator, "language", "get").mockReturnValue("ru-RU");
    window.localStorage.setItem(LANGUAGE_KEY, "klingon");
    expect(detectLanguage()).toBe("ru");
  });

  it("works when the storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("denied", "SecurityError");
    });
    vi.spyOn(window.navigator, "language", "get").mockReturnValue("ru");
    expect(detectLanguage()).toBe("ru");
  });

  it("switches the texts and the lang attribute of the page, and remembers the choice", async () => {
    await setLanguage("ru");
    expect(i18n.t("nav.settings")).toBe(ru.nav.settings);
    expect(document.documentElement.lang).toBe("ru");
    expect(window.localStorage.getItem(LANGUAGE_KEY)).toBe("ru");

    await setLanguage("en");
    expect(i18n.t("nav.settings")).toBe(en.nav.settings);
    expect(document.documentElement.lang).toBe("en");
  });

  it("still switches when the storage throws", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("quota", "QuotaExceededError");
    });
    await setLanguage("ru");
    expect(i18n.t("nav.settings")).toBe(ru.nav.settings);
  });
});
