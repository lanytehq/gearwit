import type {
  AttentionEvent,
  KnownEvidenceClass,
  LifecyclePhase,
  Seat,
  SystemScenario,
} from "./model";

function observedOnly(evidence: KnownEvidenceClass, detail: string): LifecyclePhase[] {
  return [
    { id: "observed", label: "Observed", state: "complete", evidence, detail },
    { id: "drained", label: "Drained", state: "unknown", evidence: "unknown", detail: "No drain receipt" },
    { id: "delivery", label: "Delivery", state: "unknown", evidence: "unknown", detail: "No delivery receipt" },
    { id: "turn", label: "Turn", state: "unknown", evidence: "unknown", detail: "No harness evidence" },
    { id: "handled", label: "Handled", state: "unknown", evidence: "unknown", detail: "No seat acknowledgement" },
  ];
}

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
    lifecycle: observedOnly("self_declared", "Coverage obligation declared by seat"),
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
    lifecycle: observedOnly("controller_proven", "Controller lease expiry observed"),
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
    lifecycle: observedOnly("census_inferred", "Host census observed a process"),
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

export const scenarios: SystemScenario[] = [
  { id: "fixture", status: "fixture", title: "Fixture mode", detail: "No daemon attached" },
  { id: "offline", status: "offline", title: "Daemon offline", detail: "Gearwit endpoint is not listening" },
  { id: "denied", status: "denied", title: "Gearwit home denied", detail: "Sandbox cannot access the private runtime path" },
  { id: "pending", status: "pending", title: "Delivery pending", detail: "Events observed; attached return has not completed" },
  { id: "retrying", status: "retrying", title: "Link lost / retrying", detail: "Stable delivery is waiting for an authority-matched link" },
  { id: "unhandled", status: "warning", title: "Delivered, not handled", detail: "Return completed; handled cursor remains unknown" },
  { id: "handled", status: "healthy", title: "Handled and covered", detail: "Seat acknowledged and successor coverage is armed" },
  { id: "expired", status: "warning", title: "Coverage expired", detail: "Expected renewal was not observed" },
];
