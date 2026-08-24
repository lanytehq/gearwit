import { events, seats } from "./fixtures";
import {
  canRingController,
  countArmedWaits,
  countUnknownFacts,
  evidenceGlyph,
  evidenceLabel,
  filterEvents,
  prependEventOnce,
  type AttentionEvent,
  type AttentionFilter,
  type EvidenceClass,
  type ObservedFact,
  type Seat,
} from "./model";

let visibleEvents = [...events];

function requiredElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) throw new Error(`Missing required element: ${selector}`);
  return element;
}

function text(tag: string, value: string, className?: string): HTMLElement {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
}

function tier(evidence: EvidenceClass): HTMLElement {
  const badge = text("span", evidenceGlyph[evidence], `tier tier-${evidence.split("_")[1] ?? evidence}`);
  badge.title = evidenceLabel[evidence];
  badge.setAttribute("aria-label", evidenceLabel[evidence]);
  return badge;
}

function factRow<T>(
  label: string,
  fact: ObservedFact<T>,
  format: (value: T) => string,
): HTMLElement {
  const row = document.createElement("div");
  row.className = "fact-row";
  row.append(text("dt", label));

  const value = document.createElement("dd");
  const displayValue = fact.kind === "known" ? format(fact.value) : "Unknown";
  value.append(tier(fact.evidence), document.createTextNode(displayValue));
  row.append(value);
  return row;
}

function eventItem(event: AttentionEvent): HTMLLIElement {
  const item = document.createElement("li");
  item.className = `event event-${event.level}`;

  const rail = document.createElement("div");
  rail.className = "event-rail";
  rail.append(text("span", event.age, "event-age"));

  const content = document.createElement("article");
  const meta = document.createElement("p");
  meta.className = "event-meta";
  meta.append(text("span", event.kind), tier(event.source.evidence));
  content.append(meta, text("h3", event.title), text("p", event.detail, "event-detail"));

  const footer = document.createElement("p");
  footer.className = "event-seat";
  footer.append(text("span", event.seat), text("span", event.level === "act" ? "Act now" : event.level));
  content.append(footer);
  item.append(rail, content);
  return item;
}

function seatCard(seat: Seat): HTMLElement {
  const article = document.createElement("article");
  article.className = "seat-card";

  const heading = document.createElement("header");
  heading.append(text("h3", seat.name), text("span", seat.source, `source source-${seat.source}`));

  const facts = document.createElement("dl");
  facts.append(
    factRow("Harness", seat.harness, String),
    factRow("Activity", seat.activity, String),
    factRow("Wait", seat.wait, (wait) => wait.label),
    factRow("Control", seat.controller, String),
  );
  article.append(heading, facts);
  return article;
}

function renderEvents(filter: AttentionFilter): void {
  const list = requiredElement<HTMLOListElement>("#event-list");
  const empty = requiredElement<HTMLParagraphElement>("#event-empty");
  const visible = filterEvents(visibleEvents, filter);
  list.replaceChildren(...visible.map(eventItem));
  empty.hidden = visible.length > 0;
}

function selectFilter(filter: AttentionFilter): void {
  document.querySelectorAll<HTMLButtonElement>(".filter").forEach((button) => {
    const selected = button.dataset.filter === filter;
    button.classList.toggle("is-active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
  renderEvents(filter);
}

function renderDoorbellSeat(seat: Seat): void {
  const readout = requiredElement("#route-readout");
  const ring = requiredElement<HTMLButtonElement>("#ring-test");
  const guidance = requiredElement("#ring-guidance");
  const result = requiredElement("#ring-result");
  const controllerAvailable = canRingController(seat);

  readout.replaceChildren();
  const controller = document.createElement("div");
  controller.append(
    text("span", "Controller ring"),
    tier(seat.controller.evidence),
    text("strong", controllerAvailable ? "Attached" : "Unavailable"),
  );
  const foreground = document.createElement("div");
  foreground.append(
    text("span", "Foreground return"),
    tier("self_declared"),
    text("strong", seat.wait.kind === "known" ? seat.wait.value.label : "Arm with wait-on"),
  );
  readout.append(controller, foreground);

  ring.disabled = !controllerAvailable;
  guidance.textContent = controllerAvailable
    ? "Fixture attachment is controller-proven. Test creates one idempotent attention receipt."
    : "No controller-proven route. The seat must wear a foreground wait-on or use operator notify.";
  result.textContent = "";
}

function setupDoorbellBench(): void {
  const select = requiredElement<HTMLSelectElement>("#doorbell-seat");
  const ring = requiredElement<HTMLButtonElement>("#ring-test");
  const result = requiredElement("#ring-result");

  select.replaceChildren(
    ...seats.map((seat) => {
      const option = document.createElement("option");
      option.value = seat.id;
      option.textContent = seat.name;
      return option;
    }),
  );

  const selectedSeat = (): Seat => {
    const seat = seats.find((candidate) => candidate.id === select.value);
    if (!seat) throw new Error("Selected doorbell seat is unavailable");
    return seat;
  };

  select.addEventListener("change", () => renderDoorbellSeat(selectedSeat()));
  ring.addEventListener("click", () => {
    const seat = selectedSeat();
    if (!canRingController(seat)) return;
    const event: AttentionEvent = {
      id: `fixture-ring:${seat.id}`,
      level: "act",
      kind: "Fixture doorbell",
      title: "Test ring reached an attached route",
      detail: "Simulation only: no daemon, provider, or model turn was contacted.",
      seat: seat.name,
      age: "now",
      source: { kind: "known", value: "fixture receipt", evidence: "controller_proven" },
    };
    const previousCount = visibleEvents.length;
    visibleEvents = prependEventOnce(visibleEvents, event);
    requiredElement("#attention-count").textContent = String(
      visibleEvents.filter((candidate) => candidate.level === "act").length,
    );
    selectFilter("all");
    result.textContent =
      visibleEvents.length === previousCount
        ? "Duplicate test suppressed by fixture ring ID."
        : "Fixture receipt added to attention. No real interrupt was claimed.";
  });

  renderDoorbellSeat(selectedSeat());
}

function render(): void {
  requiredElement("#attention-count").textContent = String(
    visibleEvents.filter((event) => event.level === "act").length,
  );
  requiredElement("#armed-count").textContent = String(countArmedWaits(seats));
  requiredElement("#unknown-count").textContent = String(countUnknownFacts(seats));
  requiredElement("#seat-count").textContent = `${seats.length} seats`;

  const roster = requiredElement("#roster-list");
  roster.replaceChildren(...seats.map(seatCard));
  renderEvents("all");
  setupDoorbellBench();

  document.querySelectorAll<HTMLButtonElement>(".filter").forEach((button) => {
    button.addEventListener("click", () => {
      selectFilter(button.dataset.filter as AttentionFilter);
    });
  });
}

render();
