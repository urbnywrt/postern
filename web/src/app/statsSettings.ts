import { isIPv4, isIPv6, parseLines } from "./validators";

// The settings of the statistics as the form edits them, and the ranges that
// SettingsService accepts (proto/postern/panel/v1/settings.proto).

export const STATS_LIMITS = {
  minutesHours: { min: 6, max: 168 },
  hoursDays: { min: 7, max: 730 },
  ipDays: { min: 1, max: 30 },
  probeIntervalMinutes: { min: 0, max: 60 },
} as const;

/** At most this many extra probe sources. */
export const MAX_EXTRA_SOURCES = 16;

export const IP_POLICIES = ["full", "countries", "off"] as const;
export type IpPolicy = (typeof IP_POLICIES)[number];

export function isIpPolicy(value: string): value is IpPolicy {
  return IP_POLICIES.some((policy) => policy === value);
}

type NumberField = keyof typeof STATS_LIMITS;

/** The fields as typed. */
export interface StatsForm extends Record<NumberField, string> {
  ipPolicy: IpPolicy;
  /** One address a line. */
  extraProbeSources: string;
}

export interface StatsSettingsValue extends Record<NumberField, number> {
  ipPolicy: IpPolicy;
  extraProbeSources: string[];
}

export type StatsErrors = Partial<Record<NumberField, { min: number; max: number }>> & {
  extraProbeSources?: { invalid: string } | { tooMany: number };
};

/** The settings of a form, or what is wrong with it. An extra source is a single address: a prefix or a name is refused. */
export function parseStatsForm(form: StatsForm): { settings: StatsSettingsValue | null; errors: StatsErrors } {
  const errors: StatsErrors = {};
  const numbers = {} as Record<NumberField, number>;
  for (const field of Object.keys(STATS_LIMITS) as NumberField[]) {
    const { min, max } = STATS_LIMITS[field];
    const text = form[field].trim();
    const value = /^\d+$/.test(text) ? Number(text) : Number.NaN;
    if (!(value >= min && value <= max)) {
      errors[field] = { min, max };
    }
    numbers[field] = value;
  }
  const sources = parseLines(form.extraProbeSources);
  const invalid = sources.find((source) => !isIPv4(source) && !isIPv6(source));
  if (invalid !== undefined) {
    errors.extraProbeSources = { invalid };
  } else if (sources.length > MAX_EXTRA_SOURCES) {
    errors.extraProbeSources = { tooMany: MAX_EXTRA_SOURCES };
  }
  if (Object.keys(errors).length > 0) {
    return { settings: null, errors };
  }
  return { settings: { ...numbers, ipPolicy: form.ipPolicy, extraProbeSources: sources }, errors };
}

/**
 * What a change of the IP policy deletes at once: leaving "full" the IP history,
 * becoming "off" the country history. The form asks before it saves either.
 */
export function deletionsFor(from: string, to: string): { ipHistory: boolean; countryHistory: boolean } {
  return { ipHistory: from === "full" && to !== "full", countryHistory: from !== "off" && to === "off" };
}
