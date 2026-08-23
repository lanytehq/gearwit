import { events, seats } from "./fixtures";
import {
  countArmedWaits,
  countUnknownFacts,
  evidenceGlyph,
  evidenceLabel,
  filterEvents,
  type AttentionEvent,
  type AttentionFilter,
  type EvidenceClass,
  type ObservedFact,
  type Seat,
} from "./model";

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
  );
  article.append(heading, facts);
  return article;
}

function renderEvents(filter: AttentionFilter): void {
  const list = requiredElement<HTMLOListElement>("#event-list");
  const empty = requiredElement<HTMLParagraphElement>("#event-empty");
  const visible = filterEvents(events, filter);
  list.replaceChildren(...visible.map(eventItem));
  empty.hidden = visible.length > 0;
}

function render(): void {
  requiredElement("#attention-count").textContent = String(
    events.filter((event) => event.level === "act").length,
  );
  requiredElement("#armed-count").textContent = String(countArmedWaits(seats));
  requiredElement("#unknown-count").textContent = String(countUnknownFacts(seats));
  requiredElement("#seat-count").textContent = `${seats.length} seats`;

  const roster = requiredElement("#roster-list");
  roster.replaceChildren(...seats.map(seatCard));
  renderEvents("all");

  document.querySelectorAll<HTMLButtonElement>(".filter").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll<HTMLButtonElement>(".filter").forEach((candidate) => {
        const selected = candidate === button;
        candidate.classList.toggle("is-active", selected);
        candidate.setAttribute("aria-pressed", String(selected));
      });
      renderEvents(button.dataset.filter as AttentionFilter);
    });
  });
}

render();
