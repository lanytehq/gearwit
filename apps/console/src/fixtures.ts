import type { AttentionEvent, Seat } from "./model";

export const events: AttentionEvent[] = [
  {
    id: "evt-1",
    level: "act",
    kind: "Wait coverage ended",
    title: "A declared wait needs a decision",
    detail: "Coverage ended 8 minutes ago without a renewed wait or seat-acted receipt.",
    seat: "November / reviewer",
    age: "8m",
    source: { kind: "known", value: "renewal expected", evidence: "self_declared" },
  },
  {
    id: "evt-2",
    level: "watch",
    kind: "Reachability changed",
    title: "Controller attachment is no longer current",
    detail: "The seat remains registered, but no current controller lease proves reachability.",
    seat: "November / builder",
    age: "14m",
    source: { kind: "known", value: "lease expired", evidence: "controller_proven" },
  },
  {
    id: "evt-3",
    level: "record",
    kind: "Process observed",
    title: "An unregistered harness may be present",
    detail: "Host census observed a process. Its work state and control authority are unknown.",
    seat: "Open seat / local",
    age: "22m",
    source: { kind: "known", value: "process present", evidence: "census_inferred" },
  },
];

export const seats: Seat[] = [
  {
    id: "seat-1",
    name: "November / reviewer",
    source: "sourced-runwit",
    harness: { kind: "known", value: "Codex", evidence: "controller_proven" },
    activity: { kind: "known", value: "Waiting for review", evidence: "self_declared" },
    wait: {
      kind: "known",
      value: { label: "Coverage ended", phase: "coverage_ended" },
      evidence: "self_declared",
    },
    controller: { kind: "known", value: "attached", evidence: "controller_proven" },
  },
  {
    id: "seat-2",
    name: "November / builder",
    source: "sourced-open",
    harness: { kind: "known", value: "Grok", evidence: "self_declared" },
    activity: { kind: "unknown", evidence: "unknown" },
    wait: {
      kind: "known",
      value: { label: "Completion doorbell", phase: "armed" },
      evidence: "self_declared",
    },
    controller: { kind: "unknown", evidence: "unknown" },
  },
  {
    id: "seat-3",
    name: "Open seat / local",
    source: "sourced-open",
    harness: { kind: "known", value: "Possible OpenCode", evidence: "census_inferred" },
    activity: { kind: "unknown", evidence: "unknown" },
    wait: { kind: "unknown", evidence: "unknown" },
    controller: { kind: "unknown", evidence: "unknown" },
  },
];
