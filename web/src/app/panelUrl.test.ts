import { afterEach, describe, expect, it, vi } from "vitest";

import { checkPanelUrl, PANEL_URL_KEY, rememberPanelUrl, storedPanelUrl } from "./panelUrl";

// The same table as TestCheckPanelURL in internal/panel/nodes/installcmd_test.go.
describe("checkPanelUrl", () => {
  it.each([
    ["https://panel.example.com", "https://panel.example.com"],
    ["https://panel.example.com/", "https://panel.example.com"],
    ["HTTPS://Panel.Example.COM:8443/", "https://panel.example.com:8443"],
    ["https://192.0.2.10", "https://192.0.2.10"],
    ["https://[2001:DB8::1]:443", "https://[2001:db8::1]:443"],
    ["https://[2001:db8:0:0:0:0:0:1]", "https://[2001:db8::1]"],
    ["http://localhost:8080", "http://localhost:8080"],
    ["http://LOCALHOST", "http://localhost"],
    ["http://127.0.0.1:8080/", "http://127.0.0.1:8080"],
    ["http://127.1.2.3", "http://127.1.2.3"],
    ["http://[::1]:8080", "http://[::1]:8080"],
  ])("takes %s as %s", (raw, want) => {
    expect(checkPanelUrl(raw)).toEqual({ ok: true, url: want });
  });

  it.each([
    "",
    "panel.example.com",
    "//panel.example.com",
    "ftp://panel.example.com",
    "http://panel.example.com",
    "http://192.0.2.10",
    "http://[::ffff:127.0.0.1]",
    "https://[::ffff:192.0.2.10]",
    "http://128.0.0.1",
    "https://panel.example.com/admin",
    "https://panel.example.com//",
    "https://panel.example.com?x=1",
    "https://panel.example.com/?",
    "https://panel.example.com#frag",
    "https://panel.example.com#",
    "https://user@panel.example.com",
    "https://user:pass@panel.example.com",
    "https://panel.example.com:0",
    "https://panel.example.com:65536",
    "https://panel.example.com:080",
    "https://panel.example.com:",
    "https://pa nel.example.com",
    "https://panel'.example.com",
    'https://panel".example.com',
    "https://panel\\.example.com",
    "https://panel_x.example.com",
    "https://-panel.example.com",
    "https://[fe80::1%25eth0]",
    "https://[not-an-address]",
    "https://панель.example",
    "https:panel.example.com",
  ])("refuses %s", (raw) => {
    expect(checkPanelUrl(raw).ok).toBe(false);
  });

  it("says why, where it can", () => {
    expect(checkPanelUrl("http://panel.example.com")).toEqual({ ok: false, error: "validation.panelUrlHttp" });
    expect(checkPanelUrl("https://panel.example.com/admin")).toEqual({ ok: false, error: "validation.panelUrlPath" });
    expect(checkPanelUrl("https://panel.example.com:70000")).toEqual({ ok: false, error: "validation.panelUrlPort" });
    expect(checkPanelUrl("panel.example.com")).toEqual({ ok: false, error: "validation.panelUrl" });
  });
});

describe("the remembered panel address", () => {
  afterEach(() => {
    window.localStorage.clear();
    vi.restoreAllMocks();
  });

  it("starts from the address of the page, then from the one last used", () => {
    expect(storedPanelUrl()).toBe(window.location.origin);
    rememberPanelUrl("https://panel.example.com");
    expect(window.localStorage.getItem(PANEL_URL_KEY)).toBe("https://panel.example.com");
    expect(storedPanelUrl()).toBe("https://panel.example.com");
  });

  it("does without a storage that throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(() => {
      rememberPanelUrl("https://panel.example.com");
    }).not.toThrow();
    expect(storedPanelUrl()).toBe(window.location.origin);
  });
});
