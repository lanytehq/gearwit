export type EvidenceClass =
  | "controller_proven"
  | "self_declared"
  | "census_inferred"
  | "unknown";
export type KnownEvidenceClass = Exclude<EvidenceClass, "unknown">;

export type AttentionLevel = "act" | "watch" | "record";
export type AttentionFilter = "all" | "act" | "watch";

export type ObservedFact<T> =
  | { kind: "known"; value: T; evidence: KnownEvidenceClass }
  | { kind: "unknown"; evidence: "unknown" };

export interface WaitState {
  label: string;
  phase: "armed" | "coverage_ended";
}

export type ControllerAttachment = "attached" | "detached";

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
  wait: ObservedFact<WaitState>;
  controller: ObservedFact<ControllerAttachment>;
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
    return count + [seat.harness, seat.activity, seat.wait, seat.controller].filter(
      (fact) => fact.kind === "unknown",
    ).length;
  }, 0);
}

export function countArmedWaits(seats: readonly Seat[]): number {
  return seats.filter(
    (seat) => seat.wait.kind === "known" && seat.wait.value.phase === "armed",
  ).length;
}

export function canRingController(seat: Seat): boolean {
  return (
    seat.controller.kind === "known" &&
    seat.controller.value === "attached" &&
    seat.controller.evidence === "controller_proven"
  );
}

export function prependEventOnce(
  events: readonly AttentionEvent[],
  event: AttentionEvent,
): AttentionEvent[] {
  if (events.some((candidate) => candidate.id === event.id)) return [...events];
  return [event, ...events];
}
