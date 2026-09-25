import assert from "node:assert/strict";
import test from "node:test";
import { createLatestRunTracker } from "./latest-run.js";

test("starting a new run makes the previous one stale", () => {
  const runs = createLatestRunTracker();
  const first = runs.start();
  assert.equal(first(), true);
  const second = runs.start();
  assert.equal(first(), false);
  assert.equal(second(), true);
});

test("a slower earlier verification cannot overwrite a newer result", async () => {
  const runs = createLatestRunTracker();
  const shown = [];
  let finishA, finishB;
  const verify = (isCurrent, pending) =>
    pending.then((result) => {
      if (isCurrent()) shown.push(result);
    });

  const a = verify(runs.start(), new Promise((resolve) => (finishA = resolve)));
  const b = verify(runs.start(), new Promise((resolve) => (finishB = resolve)));
  finishB("B: forged credential refused");
  await b;
  finishA("A: earlier credential verified");
  await a;

  assert.deepEqual(shown, ["B: forged credential refused"]);
});
