import { describe, expect, it } from "vitest";

import i18n from "../i18n";
import {
  formatBytes,
  formatClock,
  formatDateTime,
  formatNumber,
  formatRelative,
  hostPort,
  qrDataUri,
} from "./format";

describe("formatBytes", () => {
  it.each([
    [0n, "0 byte"],
    [999n, "999 byte"],
    [1_000n, "1 kB"],
    [1_536n, "1.5 kB"],
    [1_000_000n, "1 MB"],
    [123_456_789n, "123 MB"],
    [5_000_000_000n, "5 GB"],
    [2_500_000_000_000n, "2.5 TB"],
  ])("writes %s as %j", (bytes, expected) => {
    expect(formatBytes(bytes)).toBe(expected);
  });

  it("takes a number as well, and never writes a negative size", () => {
    expect(formatBytes(1_500_000)).toBe("1.5 MB");
    expect(formatBytes(-5)).toBe("0 byte");
    expect(formatBytes(Number.NaN)).toBe("0 byte");
  });

  it("does not run out of units", () => {
    expect(formatBytes(3n * 10n ** 15n)).toBe("3 PB");
    expect(formatBytes(3n * 10n ** 21n)).toBe("3,000,000 PB");
  });

  it("moves to the next unit when rounding would make 1000 of the one it is in", () => {
    expect(formatBytes(999_999n)).toBe("1 MB");
    expect(formatBytes(999_499n)).toBe("999 kB");
    expect(formatBytes(9_999_999n)).toBe("10 MB");
  });

  it("uses the units and the separators of the language of the page", async () => {
    await i18n.changeLanguage("ru");
    expect(formatBytes(1_500_000n)).toMatch(/^1,5\s?МБ$/);
  });
});

describe("formatNumber", () => {
  it("groups digits as the language does", async () => {
    expect(formatNumber(1234567)).toBe("1,234,567");
    expect(formatNumber(12n)).toBe("12");
    await i18n.changeLanguage("ru");
    expect(formatNumber(1234567).replace(/\s/g, " ")).toBe("1 234 567");
  });
});

describe("formatRelative", () => {
  const now = 1_800_000_000;

  it.each([
    [now, "now"],
    [now - 4, "now"],
    [now - 30, "30 seconds ago"],
    [now - 60, "1 minute ago"],
    [now - 5 * 60, "5 minutes ago"],
    [now - 3 * 3600, "3 hours ago"],
    [now - 86_400, "yesterday"],
    [now - 10 * 86_400, "10 days ago"],
  ])("writes %d as %j", (unix, expected) => {
    expect(formatRelative(BigInt(unix), now)).toBe(expected);
  });

  it("writes a time that is ahead of the clock as now, not as a time to come", () => {
    // Clocks differ by a few seconds between the panel and a browser.
    expect(formatRelative(BigInt(now + 20), now)).toBe("now");
  });

  it("speaks the language of the page", async () => {
    await i18n.changeLanguage("ru");
    expect(formatRelative(BigInt(now - 5 * 60), now)).toBe("5 минут назад");
  });
});

describe("formatDateTime and formatClock", () => {
  // 2027-01-15 08:00:00 UTC, written in the zone of the machine that runs the test.
  const unix = 1_800_000_000n;

  it("write the moment in the language of the page", async () => {
    expect(formatDateTime(unix)).toContain("2027");
    expect(formatClock(unix)).toMatch(/^\d{1,2}:\d{2}/);
    await i18n.changeLanguage("ru");
    expect(formatDateTime(unix)).toContain("2027");
  });
});

describe("hostPort", () => {
  it.each([
    ["203.0.113.7", 8443, "203.0.113.7:8443"],
    ["node.example.com", 22, "node.example.com:22"],
    ["2001:db8::1", 8443, "[2001:db8::1]:8443"],
    ["::1", 1, "[::1]:1"],
  ])("writes %s and %d as %s", (host, port, expected) => {
    expect(hostPort(host, port)).toBe(expected);
  });
});

describe("qrDataUri", () => {
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 2 2"><path d="M0 0h1v1H0z"/></svg>';

  it("is an image address that decodes back to the SVG", () => {
    const uri = qrDataUri(svg);
    expect(uri).toMatch(/^data:image\/svg\+xml;base64,[A-Za-z0-9+/]+=*$/);
    expect(atob(uri?.slice("data:image/svg+xml;base64,".length) ?? "")).toBe(svg);
  });

  it("keeps text that is not ASCII", () => {
    const uri = qrDataUri('<svg xmlns="http://www.w3.org/2000/svg"><title>Привет</title></svg>');
    const bytes = Uint8Array.from(atob(uri?.slice("data:image/svg+xml;base64,".length) ?? ""), (c) => c.charCodeAt(0));
    expect(new TextDecoder().decode(bytes)).toContain("Привет");
  });

  it("copes with a large picture", () => {
    const big = `<svg xmlns="http://www.w3.org/2000/svg">${"<path d='M0 0h1v1H0z'/>".repeat(20_000)}</svg>`;
    expect(qrDataUri(big)).toBeDefined();
  });

  it("is nothing for an answer that is not an SVG image", () => {
    expect(qrDataUri("")).toBeUndefined();
    expect(qrDataUri("<html><body>hello</body></html>")).toBeUndefined();
    expect(qrDataUri("javascript:alert(1)")).toBeUndefined();
  });
});
