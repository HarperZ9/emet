# EMET

[![conformance](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml/badge.svg)](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml)

EMET is a small external witness for AI oversight and source/view consistency.
It checks whether bytes reaching a model still match the source they claim to
represent, then reports one of three deliberately limited verdicts: `MATCH`,
`DRIFT`, or `UNVERIFIABLE`.

It exists for the gap build-provenance tools do not cover by themselves: a
system vouching for itself in-band, a presented view drifting away from source,
or a monitor reading a different file than the one that actually runs. Trust
comes from re-derivation - same bytes, same answer - not from authority. There
is no `TRUSTED` verdict.

`emet` is Hebrew for "truth."

## What's here

- A stdlib-only Python reference - `membrane.py` / `organs.py` / `monitor.py` / `corpus.py`, ~520 lines, no dependencies.
- A from-scratch Rust second implementation - `impl/rust/emet.rs`, no crates.
- A clean-room Node.js third implementation - `impl/js/emet.js`, built-in modules only (no npm).
- A normative draft spec, a language-agnostic conformance suite, a STRIDE threat model, and an in-toto attestation adapter.
- A versioned marker corpus (`conformance/markers.corpus`) all three implementations load and re-derive identically.
- All three implementations pass the same 19 conformance vectors in CI on every push - byte-hash core, marker path, and audit chain (write and verify).

## Reproduce it

```sh
git clone https://github.com/HarperZ9/emet && cd emet
python conformance/run.py membrane.py           # reference implementation: 19/19
( cd impl/rust && rustc -O emet.rs -o emet )    # build the second implementation
python conformance/run.py impl/rust/emet        # second implementation: 19/19
python conformance/run.py impl/js/emet.js       # third implementation (Node.js): 19/19
```

## Use it

```sh
python membrane.py selftest                    # re-derive its own hash
python membrane.py anchor  <path>...            # pin raw-byte hashes
python membrane.py verify  <path>...            # MATCH / DRIFT / UNVERIFIABLE
python membrane.py coherence <source> <view>    # is a presented view faithful to source?
python membrane.py refuse  <file>               # detect + strip in-band authority claims
python membrane.py corroborate <path>           # read-path-diverse agreement
python membrane.py audit                        # recompute the tamper-evident log chain
```

## Proof-surface use

EMET is the witness point in a proof-surface pipeline:

```text
source bytes -> presented view -> witness verdict -> reviewer handoff
```

Use it when a repo, report, model-facing prompt, or generated view needs a
small external check that the presented material still matches the source it
claims to represent.

Fast reviewer checklist:

- `MATCH` means the checked material re-derived to the expected byte-level
  result.
- `DRIFT` means the presented view or checked bytes changed.
- `UNVERIFIABLE` means the witness cannot make the comparison.
- There is no `TRUSTED` verdict.

This makes EMET useful as a release-readiness and diligence artifact: it can
show what was compared and what verdict was produced without asking the witness
to become an authority.

The optional `adapters/proof_surface_receipt.py` adapter emits compact JSON
witness receipts for proof-index and release-readiness workflows. It lives
outside the EMET core and does not change governed stdout, signing, enforcement,
or actuation boundaries.

## What it won't do

It only reports facts. It can't say `TRUSTED`, doesn't decide whether a model is
safe, runs outside whatever it audits, and never edits, signs, or blocks anything.
Those constraints are the point, not limitations - see [SPEC.md](SPEC.md) section 6.

## Status

Pre-1.0; the spec is a draft (v0.2.0-draft). The byte-hash core, the marker path
(a single versioned corpus matched identically across the implementations), and the
audit chain (write and verify) all re-derive across three languages and are checked
in CI (19 conformance vectors, all three implementations). Re-derivability is **not yet fully
demonstrated** in one respect, stated plainly rather than papered over:

- The Rust and Node.js implementations are same-author and clean-room, not independent.
- SPEC section 12's actual bar - an *independent, different-author* implementation passing
  the vectors - is not yet met, and per section 12 no party should treat re-derivability
  as proven until it is.

That different-author implementation is the next step, and the spec says so (section 12).
For a tool whose only credential is reproduction, an inflated claim would refute
itself - so the claim is scoped to exactly what CI reproduces today.

## Call for an independent implementation

EMET's only credential is reproduction: same bytes, same verdict. Three
implementations (Python reference + Rust + Node.js) already agree on all 19
conformance vectors in CI - but they all share an author, so that agreement shows
the spec is *implementable* (in three languages, from its text alone), not yet
that it is *independently re-derivable*.

The highest-leverage contribution is therefore not another language but a
**different-author implementation, written from [SPEC.md](SPEC.md) alone** (not by
reading the existing code), in any language, that passes `conformance/vectors.json`:

```sh
# build your implementation, then:
python conformance/run.py ./your-emet     # expected: CONFORMANCE 19/19
```

Where your implementation and the spec disagree, **the spec is wrong** - open an
issue; those divergences are the point. (The Node.js implementation already did
exactly this: building it from the spec alone surfaced that the marker *count* was
unpinned - SPEC section 16 and the `refuse-repeated-marker-occurrence-count` vector now
pin it.) A different-author implementation is what
converts re-derivability from *asserted* to *demonstrated* (SPEC section 12). Claim a
language in [Discussions](../../discussions) so effort isn't duplicated.

## Docs

[SPEC.md](SPEC.md) · [RATIONALE.md](RATIONALE.md) (why EMET is shaped the way it is, derived from first principles) · [conformance/](conformance/) · [THREAT-MODEL.md](THREAT-MODEL.md) · [COVERAGE.json](COVERAGE.json) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

MPL-2.0.
