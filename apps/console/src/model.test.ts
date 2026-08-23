import { describe, expect, test } from "bun:test";
import { events, seats } from "./fixtures";
import { countUnknownFacts, filterEvents } from "./model";

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
});
