export type EvidenceClass =
  | "controller_proven"
  | "self_declared"
  | "census_inferred"
  | "unknown";

export type AttentionLevel = "act" | "watch" | "record";
export type AttentionFilter = "all" | "act" | "watch";

export interface ObservedFact<T> {
  value: T | null;
  evidence: EvidenceClass;
}

export interface AttentionEvent {
  id: string;
  level: AttentionLevel;
  kind: string;
  title: string;
  detail: string;
  seat: string;
  age: string;
  source: ObservedFact<string>;
}

export interface Seat {
  id: string;
  name: string;
  source: "sourced-runwit" | "sourced-open";
  harness: ObservedFact<string>;
  activity: ObservedFact<string>;
  wait: ObservedFact<string>;
}

export const evidenceLabel: Record<EvidenceClass, string> = {
  controller_proven: "Controller-proven",
  self_declared: "Self-declared",
  census_inferred: "Census-inferred",
  unknown: "Unknown",
};

export const evidenceGlyph: Record<EvidenceClass, string> = {
  controller_proven: "P",
  self_declared: "D",
  census_inferred: "I",
  unknown: "?",
};

export function filterEvents(
  events: readonly AttentionEvent[],
  filter: AttentionFilter,
): AttentionEvent[] {
  if (filter === "all") return [...events];
  return events.filter((event) => event.level === filter);
}

export function countUnknownFacts(seats: readonly Seat[]): number {
  return seats.reduce((count, seat) => {
    return count + [seat.harness, seat.activity, seat.wait].filter(
      (fact) => fact.evidence === "unknown",
    ).length;
  }, 0);
}
