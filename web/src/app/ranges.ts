/** The ranges of the statistics, as the panel names them. */
export const RANGES = ["1h", "24h", "7d", "30d", "90d", "1y"] as const;
export type StatsRange = (typeof RANGES)[number];

/** The hours of egress members are kept for 30 days, so their ranges stop there. */
export const EGRESS_RANGES = ["1h", "24h", "7d", "30d"] as const satisfies readonly StatsRange[];

export const DEFAULT_RANGE: StatsRange = "24h";

/** The longest range: whatever the panel keeps of the statistics is in it. */
export const LONGEST_RANGE: StatsRange = "1y";
