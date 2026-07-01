# Changelog

## 1.0.0 - 2026-06-30 - Frozen contract, four implementations

First tagged release. The spec is frozen at 1.0.0; the reference implementations
are production-grade. 1.0.0 asserts a stable contract and solid implementations -
NOT that re-derivability is independently proven (SPEC section 12's
different-author bar stays open; the call for it stands).

Breaking (no prior tagged release existed, so no installed base to migrate):

- **Exit-code split (SPEC s.5):** `0` held; `1` a negative finding (DRIFT,
  VIEW_DIFFERS_FROM_SOURCE, QUARANTINE_READ_PATH_DIVERGENCE, BROKEN); `2`
  UNVERIFIABLE; `3` markers; `64` usage. Previously DRIFT/UNVERIFIABLE/etc. all
  collapsed to `2`. verify uses a precedence rule (a difference dominates an
  inability to check). organs and monitor adopt the same semantic.
- **selftest token rename (SPEC s.14):** the canonical token is
  `emet_self_sha256=`; the legacy `membrane_self_sha256=` alias is still emitted
  through the 1.x window and removed at 2.0. The Python artifact-of-record is now
  the sorted concatenation of the core source files, not just `membrane.py`.

Added:

- **`--json` envelope (SPEC s.13):** a machine-readable canonical-JSON output mode
  (sorted keys, `", "`/`": "`, ensure_ascii) whose governed fields are
  byte-identical across implementations; the closed lattice holds in JSON too.
- **A fourth implementation, Go** (`impl/go/emet.go`, stdlib-only, clean-room from
  the spec), joining the Python reference, Rust, and Node.js. All four pass the
  same 35 conformance vectors in CI.
- **Packaging:** installable as `emet-witness` with an `emet` console script,
  zero runtime dependencies; the run-from-checkout story is preserved.

Freeze hardening (SPEC): pinned the reason-code enum (s.9), the audit prev-linkage
check and UTF-8 canonical-hash encoding (s.7), the `.refused` replacement token
and filename (s.4), the absent-log genesis behavior (s.13), and a warning that
default JSON encoders do not produce the canonical form. New vectors enforce the
reason codes, the governed `spec_version`, and multi-path verify precedence.

An adversarial verification pass then pinned four more edge cases with vectors and
aligned all four implementations on them: a logged fact containing an astral
(surrogate-pair) character audits INTACT (s.7); an unparseable log line is BROKEN,
not UNVERIFIABLE (s.7); `verify` of an absent+unanchored path reports E_NO_ANCHOR
(anchor-relative, s.13); and `coherence` carries the failing leg as
`source:`/`view:` in its reason (s.13). It also corrected the docs to stop listing
`self_sha256` among the cross-impl byte-identical fields - it is a per-implementation
identity (s.14), never compared across implementations. 35 conformance vectors, all
four implementations.

## 2026-06-29 - EMET Forward Delivery Contract

- Added a root delivery regression test for README, usage, changelog, funding,
  authorship, contribution, license, CI, and visual asset coverage.
- Added README sections for public value, usage, and developer workflow.
- Added the `assets/emet-hero.svg` visual identity asset.
- Renamed credential-shaped illustrative variables in documentation examples.
- Added `public-surface-sweeper` as the local delivery verification gate.
- Preserved EMET's advisory-only witness boundary and closed verdict lattice.

## Current Status

- Visibility: public-facing advisory integrity witness.
- Runtime posture: stdlib-only external verifier; no enforcement, deployment,
  signing, or actuation.
- Verdict posture: closed lattice only: `MATCH`, `DRIFT`, `UNVERIFIABLE`.
