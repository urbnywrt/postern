// localStorage keeps the theme, the language and the panel address for nodes
// (app/panelUrl.ts), and nothing else: sessions are
// HttpOnly cookies, and no secret is stored in the page.
//
// The storage can throw on any access: a browser that blocks site data throws
// on the property itself, a private window or a full quota throws on writes.
// Nothing in the UI may depend on it, so every access is wrapped here.

export function readStored(key: string): string | null {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

export function writeStored(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // The choice is not saved, and it still holds until the page is reloaded.
  }
}

export function removeStored(key: string): void {
  try {
    window.localStorage.removeItem(key);
  } catch {
    // Nothing to remove, or not allowed to.
  }
}
