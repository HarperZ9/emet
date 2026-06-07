# EMET

[![conformance](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml/badge.svg)](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml)

A small integrity verifier for AI oversight. It checks that the bytes reaching a
model match their source, and flags three things build-provenance tools (in-toto,
SLSA, Sigstore, C2PA) don't: a system vouching for itself in-band, a presented view
that differs from its source, and a monitor reading a different file than the one
that runs. Trust comes from re-derivation — same bytes, same answer — not from
authority. The verdicts are `MATCH`, `DRIFT`, and `UNVERIFIABLE`; there is no
`TRUSTED`.

*emet (אמת) is Hebrew for "truth."*

## What's here

- A stdlib-only Python reference — `membrane.py` / `organs.py` / `monitor.py` / `corpus.py`, ~450 lines, no dependencies.
- A from-scratch Rust second implementation — `impl/rust/emet.rs`, no crates.
- A normative draft spec, a language-agnostic conformance suite, a STRIDE threat model, and an in-toto attestation adapter.
- A versioned marker corpus (`conformance/markers.corpus`) both implementations load and re-derive identically.
- Both implementations pass the same 17 conformance vectors in CI on every push — byte-hash core, marker path, and audit chain.

## Reproduce it

```sh
git clone https://github.com/HarperZ9/emet && cd emet
python conformance/run.py membrane.py           # reference implementation: 17/17
( cd impl/rust && rustc -O emet.rs -o emet )    # build the second implementation
python conformance/run.py impl/rust/emet        # second implementation: 17/17
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

## What it won't do

It only reports facts. It can't say `TRUSTED`, doesn't decide whether a model is
safe, runs outside whatever it audits, and never edits, signs, or blocks anything.
Those constraints are the point, not limitations — see [SPEC.md](SPEC.md) §6.

## Status

Pre-1.0; the spec is a draft (v0.2.0-draft). The byte-hash core, the marker path
(a single versioned corpus matched identically by both implementations), and the
audit chain all re-derive across two languages and are checked in CI (16
conformance vectors, both implementations). Re-derivability is **not yet fully
demonstrated** in one respect, stated plainly rather than papered over:

- The Rust implementation is same-author and clean-room, not independent.
- SPEC §12's actual bar — an *independent, different-author* implementation passing
  the vectors — is not yet met, and per §12 no party should treat re-derivability
  as proven until it is.

That different-author implementation is the next step, and the spec says so (§12).
For a tool whose only credential is reproduction, an inflated claim would refute
itself — so the claim is scoped to exactly what CI reproduces today.

## Docs

[SPEC.md](SPEC.md) · [conformance/](conformance/) · [THREAT-MODEL.md](THREAT-MODEL.md) · [COVERAGE.json](COVERAGE.json) · [SECURITY.md](SECURITY.md) · [CONTRIBUTING.md](CONTRIBUTING.md)

MPL-2.0.
