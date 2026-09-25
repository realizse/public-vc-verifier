// Tracks which verification is the latest, so a slower earlier run can't
// overwrite the progress or result shown for a newer credential.
export function createLatestRunTracker() {
  let latest = 0;
  return {
    start() {
      const run = ++latest;
      return () => run === latest;
    },
  };
}
