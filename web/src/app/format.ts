import i18n from "../i18n";

// What the panel reports as numbers, written for people, in the language of the
// page: sizes, counts and moments. The Intl formatters know the units, the digit
// grouping and the plural forms of both languages, so none of this is in the
// translation files.

const BYTE_UNITS = ["byte", "kilobyte", "megabyte", "gigabyte", "terabyte", "petabyte"] as const;

/** A number of bytes, such as "1.5 MB": decimal units, one decimal place below 10. */
export function formatBytes(bytes: bigint | number): string {
  let value = typeof bytes === "bigint" ? Number(bytes) : bytes;
  if (!Number.isFinite(value) || value < 0) {
    value = 0;
  }
  let unit = 0;
  const digitsFor = (n: number) => (n < 10 && unit > 0 ? 1 : 0);
  while (unit < BYTE_UNITS.length - 1 && Number(value.toFixed(digitsFor(value))) >= 1000) {
    value /= 1000;
    unit++;
  }
  const format = new Intl.NumberFormat(i18n.language, {
    style: "unit",
    unit: BYTE_UNITS[unit],
    unitDisplay: "short",
    maximumFractionDigits: digitsFor(value),
  });
  return format.format(value);
}

export function formatNumber(value: bigint | number): string {
  return new Intl.NumberFormat(i18n.language).format(value);
}

const nowSeconds = () => Date.now() / 1000;

/**
 * How long ago a moment was, such as "5 minutes ago". The clocks of the panel
 * and of the browser differ by a few seconds, so a moment a little ahead of the
 * clock is "now" as well.
 */
export function formatRelative(unix: bigint, now: number = nowSeconds()): string {
  const seconds = Math.max(0, Math.floor(now - Number(unix)));
  const format = new Intl.RelativeTimeFormat(i18n.language, { numeric: "auto" });
  if (seconds < 5) {
    return format.format(0, "second");
  }
  if (seconds < 60) {
    return format.format(-seconds, "second");
  }
  if (seconds < 3600) {
    return format.format(-Math.floor(seconds / 60), "minute");
  }
  if (seconds < 86_400) {
    return format.format(-Math.floor(seconds / 3600), "hour");
  }
  return format.format(-Math.floor(seconds / 86_400), "day");
}

/** A moment, with the date: "Jan 15, 2027, 8:00:00 AM". */
export function formatDateTime(unix: bigint): string {
  return new Intl.DateTimeFormat(i18n.language, { dateStyle: "medium", timeStyle: "medium" }).format(
    new Date(Number(unix) * 1000),
  );
}

/** The time of day of a moment, for the axis of a chart. */
export function formatClock(unix: bigint | number): string {
  return new Intl.DateTimeFormat(i18n.language, { hour: "2-digit", minute: "2-digit" }).format(
    new Date(Number(unix) * 1000),
  );
}

/**
 * The label of a point on the axis of a chart: the time of day over a day or
 * less, the date and the hour over periods shorter than a day, the date alone
 * for days.
 */
export function formatTick(unix: number, spanSeconds: number, periodSeconds: number): string {
  const date = new Date(unix * 1000);
  if (periodSeconds >= 86_400) {
    return new Intl.DateTimeFormat(i18n.language, { month: "short", day: "numeric" }).format(date);
  }
  if (spanSeconds > 0 && spanSeconds <= 86_400) {
    return formatClock(unix);
  }
  return new Intl.DateTimeFormat(i18n.language, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(
    date,
  );
}

/** A share, 0 to 1, as a percentage: "98.5%". */
export function formatPercent(ratio: number): string {
  return new Intl.NumberFormat(i18n.language, { style: "percent", maximumFractionDigits: 1 }).format(ratio);
}

/** A length of time in whole units: "1 hour", "18 hours", "1 day". */
export function formatDuration(seconds: number): string {
  const [value, unit] =
    seconds % 86_400 === 0 ? [seconds / 86_400, "day"] : seconds % 3600 === 0 ? [seconds / 3600, "hour"] : [seconds / 60, "minute"];
  return new Intl.NumberFormat(i18n.language, { style: "unit", unit, unitDisplay: "long" }).format(value);
}

/** A latency: "120 ms". */
export function formatMilliseconds(ms: number): string {
  return new Intl.NumberFormat(i18n.language, { style: "unit", unit: "millisecond", unitDisplay: "short", maximumFractionDigits: 0 }).format(
    ms,
  );
}

/** The text, or a dash for an empty one: a version that a node has not reported yet. */
export function orDash(text: string): string {
  return text === "" ? "—" : text;
}

/** "host:port"; an IPv6 address goes in brackets. */
export function hostPort(host: string, port: number): string {
  return host.includes(":") ? `[${host}]:${String(port)}` : `${host}:${String(port)}`;
}

const SVG_DATA_PREFIX = "data:image/svg+xml;base64,";

/**
 * The address of an image for an SVG that the panel made, to put in an `img`
 * (see GetProxyLinks). An image that is loaded through an `img` is drawn
 * statically: no script of it runs and nothing is fetched, so the QR code is
 * never put in the page as markup. Nothing is returned for an answer that is
 * not an SVG, which is not shown at all.
 */
export function qrDataUri(svg: string): string | undefined {
  if (!svg.trimStart().startsWith("<svg")) {
    return undefined;
  }
  const bytes = new TextEncoder().encode(svg);
  let binary = "";
  // btoa takes a string of bytes; the pieces keep the call below the limit on arguments.
  for (let at = 0; at < bytes.length; at += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(at, at + 0x8000));
  }
  return SVG_DATA_PREFIX + btoa(binary);
}
