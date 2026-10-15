import { describe, expect, it } from "vitest";

import { deletionsFor, parseStatsForm, STATS_LIMITS, type StatsForm } from "./statsSettings";

const form = (init: Partial<StatsForm> = {}): StatsForm => ({
  minutesHours: "48",
  hoursDays: "90",
  ipDays: "7",
  probeIntervalMinutes: "5",
  ipPolicy: "countries",
  extraProbeSources: "",
  ...init,
});

describe("parseStatsForm", () => {
  it("gives the settings of a valid form, the extra sources one per line", () => {
    const { settings, errors } = parseStatsForm(form({ extraProbeSources: " 192.0.2.10 \n\n2001:db8::7\n" }));

    expect(errors).toEqual({});
    expect(settings).toEqual({
      minutesHours: 48,
      hoursDays: 90,
      ipDays: 7,
      probeIntervalMinutes: 5,
      ipPolicy: "countries",
      extraProbeSources: ["192.0.2.10", "2001:db8::7"],
    });
  });

  it.each([
    ["minutesHours", "5"],
    ["minutesHours", "169"],
    ["hoursDays", "6"],
    ["hoursDays", "731"],
    ["ipDays", "0"],
    ["ipDays", "31"],
    ["probeIntervalMinutes", "61"],
    ["probeIntervalMinutes", "-1"],
    ["minutesHours", "12.5"],
    ["hoursDays", ""],
  ] as const)("refuses %s = %j, out of its range", (field, value) => {
    const { settings, errors } = parseStatsForm(form({ [field]: value }));

    expect(settings).toBeNull();
    expect(errors[field]).toEqual({ min: STATS_LIMITS[field].min, max: STATS_LIMITS[field].max });
  });

  it("takes the ends of every range", () => {
    expect(parseStatsForm(form({ minutesHours: "6", hoursDays: "730", ipDays: "30", probeIntervalMinutes: "0" })).errors).toEqual({});
  });

  it("refuses a prefix or a name as an extra source, and more than 16", () => {
    expect(parseStatsForm(form({ extraProbeSources: "192.0.2.0/24" })).errors.extraProbeSources).toEqual({
      invalid: "192.0.2.0/24",
    });
    expect(parseStatsForm(form({ extraProbeSources: "probe.example.com" })).errors.extraProbeSources).toEqual({
      invalid: "probe.example.com",
    });
    const many = Array.from({ length: 17 }, (_, i) => `192.0.2.${String(i + 1)}`).join("\n");
    expect(parseStatsForm(form({ extraProbeSources: many })).errors.extraProbeSources).toEqual({ tooMany: 16 });
  });
});

describe("deletionsFor", () => {
  it("deletes the IP history when the policy leaves full, and the countries when it becomes off", () => {
    expect(deletionsFor("full", "countries")).toEqual({ ipHistory: true, countryHistory: false });
    expect(deletionsFor("countries", "off")).toEqual({ ipHistory: false, countryHistory: true });
    expect(deletionsFor("full", "off")).toEqual({ ipHistory: true, countryHistory: true });
  });

  it("deletes nothing otherwise", () => {
    expect(deletionsFor("countries", "full")).toEqual({ ipHistory: false, countryHistory: false });
    expect(deletionsFor("off", "countries")).toEqual({ ipHistory: false, countryHistory: false });
    expect(deletionsFor("full", "full")).toEqual({ ipHistory: false, countryHistory: false });
    expect(deletionsFor("off", "off")).toEqual({ ipHistory: false, countryHistory: false });
  });
});
