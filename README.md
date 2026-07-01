# EMET

> A small external witness for AI oversight: re-derive the bytes, get one of three verdicts, trust nothing in-band.

![EMET advisory integrity witness architecture](assets/emet-hero.svg)

[![license: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)
![python](https://img.shields.io/badge/python-3.x-blue.svg)
![version](https://img.shields.io/badge/version-1.0.0-blue.svg)
[![PyPI](https://img.shields.io/pypi/v/emet-witness.svg)](https://pypi.org/project/emet-witness/)
[![CI](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml/badge.svg)](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml)
![deps: none](https://img.shields.io/badge/deps-none-success.svg)
[![part of: AI-accountability toolkit](https://img.shields.io/badge/part_of-AI--accountability_toolkit-7a5cff.svg)](https://harperz9.github.io)

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

## Why it matters

EMET is an advisory integrity witness for AI work. Its public value is narrow
and testable: it re-derives bytes, compares source and view material, and emits
closed verdicts without claiming authority, safety, approval, or permission.

That makes it useful anywhere Project Telos needs provenance without another
self-attesting layer. A model-facing view can drift from its source; a monitor
can observe the wrong artifact; a generated report can overstate what was
checked. EMET gives those surfaces a small external witness that says what
matched, what drifted, and what could not be verified.

## Usage

Run the core checks directly from a checkout:

```sh
python membrane.py selftest
python conformance/run.py membrane.py
python test_forward_delivery_contract.py
```

For complete command examples and captured outputs, see [USAGE.md](USAGE.md).

## For developers

Keep EMET small, external, and advisory. Before changing public-facing docs,
conformance behavior, or witness adapters, run the targeted checks:

```sh
python test_forward_delivery_contract.py
python test_membrane.py
python conformance/run.py membrane.py
python -m public_surface_sweeper . --workspace --json
```

Spec changes, conformance-vector changes, and implementation behavior must move
together. EMET must not emit `TRUSTED`, `APPROVED`, `SAFE`, or any value that
grants authority or permission.

## What's here

- A stdlib-only Python reference - `membrane.py` / `organs.py` / `monitor.py` / `corpus.py` / `verdict.py` / `report.py`, no dependencies; run it straight from a checkout or `pip install emet-witness` for the `emet` console script.
- A from-scratch Rust second implementation - `impl/rust/emet.rs`, no crates.
- A clean-room Node.js third implementation - `impl/js/emet.js`, built-in modules only (no npm).
- A clean-room Go fourth implementation - `impl/go/emet.go`, standard library only (no third-party modules).
- A normative, frozen v1.0 spec, a language-agnostic conformance suite, a STRIDE threat model, and an in-toto attestation adapter.
- A versioned marker corpus (`conformance/markers.corpus`) all four implementations load and re-derive identically.
- All four implementations pass the same 31 conformance vectors in CI on every push - byte-hash core, the exit-code split, the `--json` envelope, the marker path, and the audit chain (write and verify).

## Reproduce it

```sh
git clone https://github.com/HarperZ9/emet && cd emet
python conformance/run.py membrane.py            # Python reference: 31/31
( cd impl/rust && rustc -O emet.rs -o emet )     # build the Rust second implementation
python conformance/run.py impl/rust/emet         # Rust:    31/31
python conformance/run.py impl/js/emet.js        # Node.js: 31/31
( cd impl/go && go build -o emet emet.go )       # build the Go fourth implementation
python conformance/run.py impl/go/emet           # Go:      31/31
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

For an install/build line, per-command worked examples with expected output, the
companion tools (`monitor.py`, `organs.py`), and a runnable demo, see
[USAGE.md](USAGE.md) and [examples/](examples/).

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
or actuation boundaries. The adapter only accepts governed verdict tokens as
whole tokens and refuses authority-shaped stdout before it enters a receipt.

## What it won't do

It only reports facts. It can't say `TRUSTED`, doesn't decide whether a model is
safe, runs outside whatever it audits, and never edits, signs, or blocks anything.
Those constraints are the point, not limitations - see [SPEC.md](SPEC.md) section 6.

## Status

v1.0.0 - the spec is **frozen and stable** (v1.0.0). The byte-hash core, the
exit-code split, the `--json` envelope, the marker path (a single versioned corpus
matched identically across the implementations), and the audit chain (write and
verify) all re-derive across four languages and are checked in CI (31 conformance
vectors, all four implementations). What 1.0.0 asserts is exactly two things: the
**contract is frozen**, and the **reference implementations are production-grade**.
It deliberately does **not** claim re-derivability is *proven* - that is a distinct,
still-open axis, stated plainly rather than papered over:

- The Rust, Node.js, and Go implementations are same-author (two of them clean-room
  from the spec alone), not independent.
- SPEC section 12's actual bar - an *independent, different-author* implementation
  passing the vectors - is not yet met, and per section 12 no party should treat
  re-derivability as proven until it is.

Freezing the contract and demonstrating independent re-derivation are orthogonal;
conflating them would be the exact in-band overclaim EMET's `refuse` strips. For a
tool whose only credential is reproduction, an inflated claim would refute itself -
so the claim is scoped to exactly what CI reproduces today.

## Call for an independent implementation

EMET's only credential is reproduction: same bytes, same verdict. Four
implementations (Python reference + Rust + Node.js + Go) already agree on all 31
conformance vectors in CI - but they all share an author, so that agreement shows
the spec is *implementable* (in four languages, from its text alone), not yet
that it is *independently re-derivable*.

The highest-leverage contribution is therefore not another language but a
**different-author implementation, written from [SPEC.md](SPEC.md) alone** (not by
reading the existing code), in any language, that passes `conformance/vectors.json`:

```sh
# build your implementation, then:
python conformance/run.py ./your-emet     # expected: CONFORMANCE 31/31
```

Where your implementation and the spec disagree, **the spec is wrong** - open an
issue; those divergences are the point. (Both clean-room ports already did exactly
this: the Node.js impl surfaced that the marker *count* was unpinned - SPEC section
16 and the `refuse-repeated-marker-occurrence-count` vector now pin it - and the Go
impl surfaced the reason-code enum and default-JSON-encoder gaps, now pinned; see
[docs/spec-findings-from-go-impl.md](docs/spec-findings-from-go-impl.md).) A
different-author implementation is what converts re-derivability from *asserted* to
*demonstrated* (SPEC section 12). Claim a language in [Discussions](../../discussions)
so effort isn't duplicated.

## Docs

[SPEC.md](SPEC.md) · [RATIONALE.md](RATIONALE.md) (why EMET is shaped the way it is, derived from first principles) · [conformance/](conformance/) · [THREAT-MODEL.md](THREAT-MODEL.md) · [COVERAGE.json](COVERAGE.json) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

MPL-2.0.
