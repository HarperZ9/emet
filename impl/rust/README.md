# EMET -- Rust second implementation

A clean-room second implementation of the EMET core, written against SPEC.md and
conformance/vectors.json ONLY, in pure Rust with no external crates (hand-rolled
SHA-256). Purpose: a second, INDEPENDENT codebase that passes the same conformance
vectors -- which is what converts re-derivability from asserted to demonstrated
(SPEC section 12).

## Build and test

  rustc -O emet.rs -o emet
  python ../../conformance/run.py ./emet

Expected: CONFORMANCE 18/18 vectors pass.

## Status

Algorithm-verified, not yet compiled by the original author (no Rust toolchain in
the authoring environment). The SHA-256 was verified against a reference on known
vectors (empty, abc, and the two conformance inputs) BEFORE transcription, so the
crypto core is proven; minor first-compile syntax fixes may still be needed.
Until the conformance run passes, this is written, not yet proven. For the
STRONGEST re-derivability claim a truly third-party author should also implement
from the spec alone -- this cross-LANGUAGE impl proves the spec is implementable;
a different-AUTHOR impl makes it airtight.
