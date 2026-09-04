# Decision records

Gearwit adopts the five-type `*DR` family ratified by the 3 Leaps Crucible
decision-record taxonomy:

| Type | Captures |
| --- | --- |
| `ADR` | Significant architecture or technical choice |
| `DDR` | Design, data-model, or schema choice |
| `SecDR` | Security posture or control choice |
| `PDR` | Process or ways-of-working choice |
| `EPR` | Durable engineering principle |

## Naming and numbering

Files use `<TYPE>-<NNNN>-<kebab-slug>.md`.

- The number is four-digit and zero-padded.
- Numbering is monotonic and repo-global per type, regardless of storage
  folder.
- Different types maintain independent sequences.
- A withdrawn or rejected record keeps its number.

This repository stores all five types in `docs/decisions/`; that location is a
Gearwit choice, not part of the shared taxonomy.

## Lifecycle

New records begin Proposed. The preferred lifecycle is:

```text
Proposed → Accepted → (Superseded | Rejected | Withdrawn)
```

Accepted records are superseded with explicit pointers rather than silently
rewritten.

## Current records

- [ADR-0001: Product workspace boundaries](ADR-0001-product-workspace-boundaries.md)
- [ADR-0002: Local persistence provider boundary](ADR-0002-local-persistence-boundary.md)
- [ADR-0003: No-follow private paths](ADR-0003-no-follow-private-paths.md)
