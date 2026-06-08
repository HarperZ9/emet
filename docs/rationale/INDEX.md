# Rationale — Index

This is the reading-order index for the EMET rationale curation: a set of
derivation essays that show the existing EMET design as the worked
proof-of-concept of the corpus thesis. Each essay is a *derivation* you can
re-derive, not a warrant you must accept; `research/` is further reading only,
never authority-of-record. If an essay and [SPEC.md](../../SPEC.md) disagree,
SPEC governs and the essay is wrong.

Entry point: [RATIONALE.md](../../RATIONALE.md) (the spine — framing note, the
one-page map, and reading order). This file expands the spine's map into a
row→essay table and lists every essay in order.

## Reading order (00 → 08)

- [00 — Orientation](./00-orientation.md): the five frames (no-aseity, the is/ought seam, teleosemantic deflationism, occasionalism, the spoken-*for*) for a reader who never opens `research/`.
- [01 — The Is/Ought Seam: Facts, Not Authority](./01-is-ought-seam.md): EMET does the authentication-grade byte decision and refuses the authorization crossing — it *locates* the seam and won't launder across it.
- [02 — No-Aseity: Why the Lattice Cannot Emit `TRUSTED`](./02-no-aseity.md): trust has no *svabhāva*; the verdict lattice is closed and conferral-dependent, never a `TRUSTED` value.
- [03 — Process over Property: Re-derivability, and the Name that Is the Hash](./03-occasionalism.md): a verdict persists by no construction — re-derived per operation, nothing cached, no held key — and identity is intrinsic (the name is the hash).
- [04 — The Spoken-*For*: Potential Without Intent](./04-spoken-for.md): EMET is the direction-neutral seed; the *for* is authored downstream by the operator, never by EMET.
- [05 — The Authored Root: EMET Is Not Its Own Root of Trust](./05-authored-root.md): EMET cannot ground itself; an external verifier is the check of record — integrity is *esse ab alio*.
- [06 — The Aleph: The Boundaries as the Smallest Edge](./06-aleph.md): the six boundaries *are* the aleph — the smallest edge that keeps *emet* (truth) from collapsing to *met* (death).
- [07 — Worked Example: Authority Injection Through EMET](./07-walkthrough.md): the runnable transcript essay, annotating each command as the philosophy made operative — EMET as the antidote to its own operating context.
- [08 — Membrane Taxonomy: Where EMET Sits](./08-taxonomy.md): EMET placed as a *literal* engineered membrane in the authentication register, among literal / isomorphic / lineage membranes.

## Map: EMET element → law → essay

The same eight rows as the [spine](../../RATIONALE.md), each linking the essay
that derives it. Status marks each mapping **load-bearing** vs
**illumination/lineage**, so "membrane" never becomes a universal solvent.

| EMET element | Law | Essay | Status |
|---|---|---|---|
| Closed lattice; no `TRUSTED` (§2) | L1 No-Aseity | [02](./02-no-aseity.md) | load-bearing |
| `verify` MATCH/DRIFT; `refuse` strips in-band (§6.1) | L8 + membrane-errata | [01](./01-is-ought-seam.md) | load-bearing |
| Re-derivability; recomputed each `verify` (§8) | L11 Process>Property | [03](./03-occasionalism.md) | load-bearing |
| SHA-256 over exact raw bytes (§3) | L6 Intrinsic Substitution | [03](./03-occasionalism.md) | load-bearing |
| Zero actuation; undecided "for" (§6.6) | L2 + L3 | [04](./04-spoken-for.md) | load-bearing |
| Not its own root of trust (§11) | L1 reflexive | [05](./05-authored-root.md) | load-bearing |
| Advisory; attests, never adjudicates (§6.2, §6.4) | L8 + autonomy of the deontic | [01](./01-is-ought-seam.md) | load-bearing |
| The six boundaries as a set | emet/met/aleph | [06](./06-aleph.md) | literal (byte seam) / illumination (figure) |

## Reference and apparatus

- [GLOSSARY.md](./GLOSSARY.md): every corpus term the essays use, each with one
  definition and a provenance pointer (provenance = further reading, never
  warrant). Read it alongside the Orientation primer to keep each essay
  self-contained.
- [walkthrough/](./walkthrough/): the regeneratable worked example. The
  stdlib-only harness [`render.py`](./walkthrough/render.py) runs the real EMET
  commands against the crafted fixture [`input.txt`](./walkthrough/input.txt) in
  an isolated sandbox and emits the committed
  [`transcript.txt`](./walkthrough/transcript.txt) byte-for-byte; essay
  [07](./07-walkthrough.md) embeds and annotates it.
