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
    source: { value: "renewal expected", evidence: "self_declared" },
  },
  {
    id: "evt-2",
    level: "watch",
    kind: "Reachability changed",
    title: "Controller attachment is no longer current",
    detail: "The seat remains registered, but no current controller lease proves reachability.",
    seat: "November / builder",
    age: "14m",
    source: { value: "lease expired", evidence: "controller_proven" },
  },
  {
    id: "evt-3",
    level: "record",
    kind: "Process observed",
    title: "An unregistered harness may be present",
    detail: "Host census observed a process. Its work state and control authority are unknown.",
    seat: "Open seat / local",
    age: "22m",
    source: { value: "process present", evidence: "census_inferred" },
  },
];

export const seats: Seat[] = [
  {
    id: "seat-1",
    name: "November / reviewer",
    source: "sourced-runwit",
    harness: { value: "Codex", evidence: "controller_proven" },
    activity: { value: "Waiting for review", evidence: "self_declared" },
    wait: { value: "Coverage ended", evidence: "self_declared" },
  },
  {
    id: "seat-2",
    name: "November / builder",
    source: "sourced-open",
    harness: { value: "Grok", evidence: "self_declared" },
    activity: { value: null, evidence: "unknown" },
    wait: { value: "Completion doorbell", evidence: "self_declared" },
  },
  {
    id: "seat-3",
    name: "Open seat / local",
    source: "sourced-open",
    harness: { value: "Possible OpenCode", evidence: "census_inferred" },
    activity: { value: null, evidence: "unknown" },
    wait: { value: null, evidence: "unknown" },
  },
];
