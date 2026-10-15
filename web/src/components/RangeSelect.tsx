import { SegmentedControl } from "@mantine/core";
import { useTranslation } from "react-i18next";

import { RANGES, type StatsRange } from "../app/ranges";

interface RangeSelectProps<R extends StatsRange> {
  value: R;
  onChange: (range: R) => void;
  /** The ranges offered; every range unless this says otherwise. */
  ranges?: readonly R[];
}

/** The range of the statistics shown: 1 hour to 1 year. */
export function RangeSelect<R extends StatsRange>({ value, onChange, ranges }: RangeSelectProps<R>) {
  const { t } = useTranslation();
  const offered = ranges ?? (RANGES as readonly StatsRange[] as readonly R[]);
  return (
    <SegmentedControl
      size="xs"
      aria-label={t("insights.ranges.label")}
      value={value}
      onChange={(next) => {
        const range = offered.find((entry) => entry === next);
        if (range !== undefined) {
          onChange(range);
        }
      }}
      data={offered.map((range) => ({ value: range, label: t(`insights.ranges.${range}`) }))}
    />
  );
}
