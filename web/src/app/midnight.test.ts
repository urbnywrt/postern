import { describe, expect, it } from "vitest";

import { localMidnightUnix } from "./midnight";

describe("localMidnightUnix", () => {
  it("is the start of the local day", () => {
    const now = new Date(2027, 0, 15, 8, 30, 15);
    const midnight = new Date(localMidnightUnix(now) * 1000);

    expect([midnight.getFullYear(), midnight.getMonth(), midnight.getDate()]).toEqual([2027, 0, 15]);
    expect([midnight.getHours(), midnight.getMinutes(), midnight.getSeconds()]).toEqual([0, 0, 0]);
  });

  it("is the moment itself at midnight, and the day before a second earlier", () => {
    const midnight = new Date(2027, 2, 1, 0, 0, 0);
    expect(localMidnightUnix(midnight)).toBe(midnight.getTime() / 1000);
    expect(localMidnightUnix(new Date(midnight.getTime() - 1000))).toBe(new Date(2027, 1, 28).getTime() / 1000);
  });

  it("is never in the future and at most a day ago", () => {
    for (const hour of [0, 1, 12, 23]) {
      const now = new Date(2027, 5, 10, hour, 59, 59);
      const seconds = now.getTime() / 1000 - localMidnightUnix(now);
      expect(seconds).toBeGreaterThanOrEqual(0);
      expect(seconds).toBeLessThan(25 * 3600);
    }
  });
});
