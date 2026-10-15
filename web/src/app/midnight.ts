/**
 * The last local midnight before `now`, in Unix seconds: where the Overview counts
 * the traffic of the day from. The browser knows the time zone of the admin and the
 * panel does not, so it is computed here. Built from the calendar date, it is right
 * on the days that a change of daylight saving time makes 23 or 25 hours long.
 */
export function localMidnightUnix(now: Date): number {
  const midnight = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  return Math.floor(midnight.getTime() / 1000);
}
