// The names of countries come from the browser (Intl.DisplayNames), in the
// language of the page: no list of names ships with the app, and no flag or font
// is fetched from anywhere.

const cache = new Map<string, Intl.DisplayNames>();

function displayNames(language: string): Intl.DisplayNames {
  let names = cache.get(language);
  if (names === undefined) {
    names = new Intl.DisplayNames([language], { type: "region", fallback: "code" });
    cache.set(language, names);
  }
  return names;
}

/**
 * The name of a country by its ISO code, "DE", in `language`. A code that the
 * browser does not know is shown as it is. The country "" is that of the clients
 * whose country is not known: it has no name here, and the caller says "unknown".
 */
export function countryName(code: string, language: string): string | null {
  if (code === "") {
    return null;
  }
  try {
    return displayNames(language).of(code.toUpperCase()) ?? code;
  } catch {
    // Not a region code at all (RangeError).
    return code;
  }
}
