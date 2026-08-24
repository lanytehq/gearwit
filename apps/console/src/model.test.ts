import { describe, expect, test } from "vitest";
import { events, scenarios, seats } from "./fixtures";
import {
  canRingController,
  countArmedWaits,
  countUnknownFacts,
  filterEvents,
  lifecycleIsOrdered,
  prependEventOnce,
} from "./model";

describe("attention projection", () => {
  test("filters without changing source order", () => {
    expect(filterEvents(events, "act").map((event) => event.id)).toEqual(["evt-1"]);
    expect(filterEvents(events, "watch").map((event) => event.id)).toEqual(["evt-2"]);
    expect(filterEvents(events, "all").map((event) => event.id)).toEqual([
      "evt-1",
      "evt-2",
      "evt-3",
    ]);
  });

  test("counts unknown facts rather than unknown seats", () => {
    expect(countUnknownFacts(seats)).toBe(5);
  });

  test("does not count ended wait coverage as armed", () => {
    expect(countArmedWaits(seats)).toBe(1);
  });

  test("rings only a controller-proven attachment", () => {
    expect(canRingController(seats[0]!)).toBe(true);
    expect(canRingController(seats[1]!)).toBe(false);
    expect(canRingController(seats[2]!)).toBe(false);
  });

  test("suppresses a duplicate ring receipt", () => {
    const ring = { ...events[0]!, id: "fixture-ring:seat-1" };
    const first = prependEventOnce(events, ring);
    const duplicate = prependEventOnce(first, ring);
    expect(first).toHaveLength(events.length + 1);
    expect(duplicate).toHaveLength(first.length);
    expect(duplicate[0]?.id).toBe(ring.id);
  });

  test("requires one ordered status for every lifecycle phase", () => {
    expect(events.every((event) => lifecycleIsOrdered(event.lifecycle))).toBe(true);
    expect(events.every((event) => event.lifecycle[0]?.state === "complete")).toBe(true);
    expect(events.every((event) => event.lifecycle[4]?.state === "unknown")).toBe(true);
  });

  test("covers operational failure and recovery fixtures", () => {
    expect(new Set(scenarios.map((scenario) => scenario.id)).size).toBe(scenarios.length);
    expect(scenarios.map((scenario) => scenario.id)).toEqual(
      expect.arrayContaining([
        "offline",
        "denied",
        "pending",
        "retrying",
        "unhandled",
        "handled",
        "expired",
      ]),
    );
  });
});
