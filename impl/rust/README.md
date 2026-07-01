# EMET -- Rust second implementation

A clean-room second implementation of the EMET core, written against SPEC.md and
conformance/vectors.json ONLY, in pure Rust with no external crates (hand-rolled
SHA-256). Purpose: a second, INDEPENDENT codebase that passes the same conformance
vectors -- which is what converts re-derivability from asserted to demonstrated
(SPEC section 12).

## Build and test

  rustc -O emet.rs -o emet
  python ../../conformance/run.py ./emet

Expected: CONFORMANCE 31/31 vectors pass.

## Status

Compiled and passing all 31 conformance vectors (rustc, `-O`). The hand-rolled
SHA-256 was verified against a reference on known vectors before transcription,
and the hand-rolled canonical JSON reproduces the Python `--json` envelope
byte-for-byte on the governed fields. This cross-LANGUAGE impl proves the spec is
implementable; it does NOT by itself convert re-derivability from asserted to
demonstrated -- it shares the operator with the other three. For the STRONGEST
claim, a truly different-AUTHOR implementation from the spec alone is still the
open, load-bearing deliverable (SPEC section 12).
