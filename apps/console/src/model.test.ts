import { describe, expect, test } from "vitest";
import { events, seats } from "./fixtures";
import { countArmedWaits, countUnknownFacts, filterEvents } from "./model";

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
    expect(countUnknownFacts(seats)).toBe(3);
  });

  test("does not count ended wait coverage as armed", () => {
    expect(countArmedWaits(seats)).toBe(1);
  });
});
