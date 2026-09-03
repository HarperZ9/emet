<p align="center"><img src="docs/art/emet-header.svg" alt="emet: byte-level integrity witness. A witness that reports what it found, and decides nothing." width="100%"></p>

**Byte-level integrity witness. Four independent implementations, one verdict lattice.**

[![PyPI](https://img.shields.io/pypi/v/emet?style=flat-square&labelColor=14041b&color=ff35aa)](https://pypi.org/project/emet/)
[![license: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-8f8095?style=flat-square&labelColor=14041b)](LICENSE)
[![downloads](https://img.shields.io/pypi/dm/emet?label=downloads&style=flat-square&labelColor=14041b)](https://pypi.org/project/emet/)
[![CI](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml/badge.svg)](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml)
![python](https://img.shields.io/badge/python-3.x-8f8095?style=flat-square&labelColor=14041b)
![deps: none](https://img.shields.io/badge/deps-none-8f8095?style=flat-square&labelColor=14041b)

EMET checks whether the bytes reaching a model, a reviewer, or a pipeline still
match the source they claim to represent, then emits one of three closed
verdicts: `MATCH`, `DRIFT`, or `UNVERIFIABLE`. Four clean-room implementations,
in stdlib-only Python, Rust, Node.js, and Go, load the same marker corpus and
re-derive it identically against a shared conformance suite. Zero dependencies:
run it straight from a checkout or `pip install emet`.

`emet` is Hebrew for "truth."

## Features

- **Portable witness receipts** (SPEC s.17). Seal any verdict into a
  self-contained, content-addressed JSON receipt; a different party re-verifies
  it offline with `emet check`, zero shared state, zero trust in the producer.
  The same subject and verdict yield a **byte-identical `receipt_id` across
  Python, Rust, and Node.js**, and each implementation verifies the others'
  HMAC signatures. Cross-language parity, including the tampered-receipt
  negatives, is gated in CI.
- **Stripped-credential rebind** (SPEC s.18, experimental). When a re-encode,
  screenshot, or copy strips a C2PA-style embedded credential, the artifact is
  orphaned to embedded-metadata verifiers. EMET anchored the raw bytes out of
  band, so `emet rebind` re-derives the naked bytes' content hash and rebinds
  them to a known anchor: `MATCH` (rebound), `DRIFT` (a claimed identity over
  substituted bytes), or `UNVERIFIABLE` (no known anchor, the honest default).
- **Byte-hash core.** `anchor` pins raw-byte SHA-256 hashes, `verify`
  recomputes them, `coherence` compares a presented view against its source,
  `corroborate` hashes the same file through disjoint read paths to catch a
  tampered read path, not just a broken hash.
- **In-band authority stripping.** `refuse` scans bytes against a versioned
  marker corpus, reports every embedded authority claim by offset, and writes a
  neutralized copy. It reports the claims; it never obeys them.
- **Tamper-evident audit chain.** Every command appends to a hash-chained log;
  `emet audit` recomputes the chain and reports `INTACT` or `BROKEN`.
- **Four implementations, one contract.** A frozen v1.0 spec, a
  language-agnostic conformance suite (48 vectors: 35 core, 5 receipt, 4
  rebind, 4 eval-receipt), and clean-room ports in Rust, Node.js, and Go, all
  scored in CI on every push against exactly the capabilities each claims.
- **Machine-readable everywhere.** `--json` on any command emits one
  canonical-JSON envelope; the governed fields are byte-identical across all
  four implementations and the exit code is unchanged.
- **Zero dependencies, by construction.** Stdlib-only Python, no crates, no
  npm packages, no Go modules.

## Usage

```sh
pip install emet
emet selftest        # re-derives the tool's own hash: emet_self_sha256=...
```

Or run it straight from a checkout, no install step at all:

```sh
git clone https://github.com/HarperZ9/emet && cd emet
python membrane.py selftest
```

`emet <cmd>` and `python membrane.py <cmd>` are equivalent. The full command
surface:

```sh
emet anchor  <path>...              # pin raw-byte hashes
emet verify  <path>...              # MATCH / DRIFT / UNVERIFIABLE
emet coherence <source> <view>      # is a presented view faithful to source?
emet refuse  <file>                 # detect + strip in-band authority claims
emet corroborate <path>             # read-path-diverse agreement
emet audit                          # recompute the tamper-evident log chain
emet receipt --from-json <file|->   # portable, content-addressed witness receipt
emet check <receipt.json>           # stateless offline re-verify
emet rebind <naked> --manifest <m>  # rebind stripped bytes (experimental)
emet <any> --json                   # machine-readable canonical envelope
```

Exit codes (SPEC section 5): `0` held · `1` a difference found (DRIFT /
VIEW_DIFFERS_FROM_SOURCE / QUARANTINE / BROKEN) · `2` UNVERIFIABLE · `3`
markers found · `64` usage.

Note: the marker corpus ships separately from the wheel (SPEC s.8), so an
installed `refuse` needs `EMET_CORPUS` set or a source checkout; without it,
the answer is `UNVERIFIABLE reason=E_NO_CORPUS`, never a silent pass.

## Worked example: anchor, verify, let the verdict travel

<p align="center"><img src="docs/art/witness-lane.svg" alt="The witness lane: subject, anchor, read paths, recompute, compare, markers, lattice, chain, ending in match, drift, or unverifiable." width="100%"></p>

```sh
$ printf 'hello world\n' > report.md
$ emet anchor report.md
anchored report.md sha256=a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447

$ emet verify report.md
MATCH report.md want=a948904f2f0f479b got=a948904f2f0f479b     # exit 0

$ printf 'hello world CHANGED\n' > report.md
$ emet verify report.md
DRIFT report.md want=a948904f2f0f479b got=9fc0ea6515ceadd9     # exit 1
```

Two things in that lane are worth naming, because they are what keep the rest of it
honest. The closed lattice is structural rather than reviewed: every governed token
leaves through `governed(channel, token)`, which raises inside the core when the token
is not a member of its channel's set, and `TRUSTED` is pinned in a forbidden set on top
of that. An unsanctioned verdict is a construction error before a byte reaches stdout,
not a review miss afterward. And `corroborate` treats a single working read path as an
inability, not as agreement: with nothing to disagree with, it reports `UNVERIFIABLE
reason=E_NO_SECOND_READ_PATH` rather than `CORROBORATED`.

Seal the verdict into a receipt and hand it to someone else:

```sh
emet verify report.md --json | emet receipt --from-json - > receipt.json
emet check receipt.json          # on ANY machine: RECEIPT_VALID / TAMPERED / UNVERIFIABLE
```

Add `--recompute-from-paths` to `emet check` to also re-hash the subject bytes
on disk against the recorded digests. For every command with captured real
output, the companion tools (`monitor.py`, `organs.py`), and a runnable demo,
see [USAGE.md](USAGE.md) and [examples/](examples/).

<p align="center"><img src="docs/art/receipt-lane.svg" alt="The receipt lane: envelope, subjects, identity, canonical form, address, signature, re-derive, verdict, ending in receipt valid, receipt tampered, or receipt unverifiable." width="100%"></p>

The address in the middle of that diagram is a hash of the receipt with its own
`receipt_id`, `signature`, and per-implementation `witness` block removed, and the
optional HMAC covers that same body. Both therefore describe exactly the same bytes, and
a doctored field changes the address the receipt is stored under. Reading one back never
trusts the stored id; it recomputes the address and compares. Two precedence rules follow
the primary lattice: a confirmed divergence outranks an inability, so a changed subject
reads `RECEIPT_TAMPERED` rather than `RECEIPT_UNVERIFIABLE`, and a receipt that carries a
signature with no key available to check it reads `RECEIPT_UNVERIFIABLE`, never valid.

## DeepEval reporter (`emet.reporters.deepeval`)

An optional reporter turns a completed [DeepEval](https://github.com/confident-ai/deepeval)
evaluation into a portable witness receipt. It ships in the wheel as the
out-of-core `emet.reporters` subpackage and pulls DeepEval only as an extra:

```sh
pip install emet[deepeval]
```

```python
from emet.reporters.deepeval import mint_receipt
# `result` is whatever deepeval.evaluate(...) returned.
receipt, record_path, receipt_path = mint_receipt(
    result, model="gpt-4o-2024-08-06",
    config={"temperature": "0", "run": "nightly"}, out_dir="eval-out")
# then, on any isolated machine, zero shared state:
#   emet check eval-out/emet-eval-receipt.json                 -> RECEIPT_VALID
#   emet check eval-out/emet-eval-receipt.json --recompute-from-paths
```

It seals a canonical eval record (model, dataset digest + count over the
test-case inputs, metric/judge name + version, per-case pass/score as strings,
config) and mints an emet receipt that binds the record's integrity; corrupting
one byte flips the verdict away from `RECEIPT_VALID`. The record carries no
floats and the receipt's `verdict_record` is empty by design, so it asserts
provenance and integrity, never model quality beyond the numbers the metrics
already reported. DeepEval is a lazy import: `mint_receipt` and
`build_eval_record` read an already-completed evaluation structurally and need
no DeepEval install; only `evaluate_and_mint`, which runs the evaluation, imports
it and raises a clear error when it is absent. The reporter stays out-of-core:
it is excluded from the minimal TCB and the selftest artifact-of-record (SPEC
section 10, s.14), and the byte-hash core keeps zero runtime dependencies.

## For developers

The repo ships its own delivery contract; re-check it any time with
`python test_forward_delivery_contract.py`.

Each implementation declares the optional capabilities it does not yet claim
(`EMET_SKIP_CAPABILITIES`), and the runner scores it only on what it does
claim, exactly as CI does:

```sh
git clone https://github.com/HarperZ9/emet && cd emet
python conformance/run.py membrane.py                # Python reference: 48/48

( cd impl/rust && rustc -O emet.rs -o emet )
EMET_SKIP_CAPABILITIES=rebind,eval-receipt \
  python conformance/run.py impl/rust/emet           # Rust:    40/40

EMET_SKIP_CAPABILITIES=rebind,eval-receipt \
  python conformance/run.py impl/js/emet.js          # Node.js: 40/40

( cd impl/go && go build -o emet emet.go )
EMET_SKIP_CAPABILITIES=receipt,rebind,eval-receipt \
  python conformance/run.py impl/go/emet             # Go:      35/35 (core)
```

### Per-implementation capability matrix

| Implementation | Core (35 vectors) | Receipt (5, SPEC s.17) | Rebind (4, SPEC s.18) | Eval-receipt (4, reporter) |
| --- | --- | --- | --- | --- |
| Python (reference) | yes | yes | yes | yes |
| Rust (`impl/rust`) | yes | yes (HMAC hand-composed over its own SHA-256, verified against RFC 4231) | not yet | not yet |
| Node.js (`impl/js`) | yes | yes (native `crypto`) | not yet | not yet |
| Go (`impl/go`) | yes | not yet ported | not yet | not yet |

The eval-receipt vectors check an ordinary witness receipt minted by the
out-of-core [DeepEval reporter](#deepeval-reporter-emetreportersdeepeval) over an
eval record; any receipt-capable implementation can re-verify them, and they are
capability-tagged so a port that has not validated the profile skips them.

An unsigned receipt verifies on the content address alone; the HMAC-SHA256
signature is optional and only strengthens integrity when producer and
verifier share a key channel (`EMET_RECEIPT_SIGNING_KEY`). The rebind
cross-language port contract is [docs/REBIND-SPEC.md](docs/REBIND-SPEC.md).

## What it won't do

EMET is an advisory integrity witness: it only reports facts. It can't say `TRUSTED`, doesn't decide whether a model
is safe, runs outside whatever it audits, and never edits, signs, or blocks
anything. Those constraints are the point, not limitations: see
[SPEC.md](SPEC.md) section 6.

## Status

v1.2.0. The spec is **frozen and stable** at 1.0.0. The byte-hash core, the
exit-code split, the `--json` envelope, the marker path, and the audit chain
re-derive across four languages and are checked in CI on every push. What the
1.x line asserts is exactly two things: the **contract is frozen**, and the
**reference implementations are production-grade**. It deliberately does **not** claim
re-derivability is *proven*: all four implementations share an author, and
SPEC section 12's bar, an independent different-author implementation passing
the vectors, is not yet met. For a tool whose only credential is reproduction,
an inflated claim would refute itself, so the claim is scoped to exactly what
CI reproduces today.

## Call for an independent implementation

The highest-leverage contribution is not another language but a
**different-author implementation, written from [SPEC.md](SPEC.md) alone**
(not by reading the existing code), in any language, that passes the core
vectors:

```sh
EMET_SKIP_CAPABILITIES=receipt,rebind \
  python conformance/run.py ./your-emet     # expected: CONFORMANCE 35/35
```

Where your implementation and the spec disagree, **the spec is wrong**: open
an issue; those divergences are the point. Both clean-room ports already did
exactly this. The Node.js port surfaced that the marker occurrence count was
unpinned (now pinned in SPEC section 16 and a dedicated vector), and the Go
port surfaced the reason-code enum and default-JSON-encoder gaps, now pinned;
see [docs/spec-findings-from-go-impl.md](docs/spec-findings-from-go-impl.md).
Claim a language in [Discussions](../../discussions) so effort isn't
duplicated.

## Why it matters

A model-facing view can drift from its source, a monitor can observe the wrong
artifact, and a generated report can overstate what was checked. EMET is the
small external witness for those seams: it re-derives the bytes and reports
what matched, what drifted, and what could not be verified, without ever
becoming an authority. The public value is exactly that: every verdict is a
fact anyone can re-check, same bytes, same answer. It composes with its peer tools
[forum](https://github.com/HarperZ9/forum) (accountable multi-agent
orchestration) and
[accountable-surface](https://github.com/HarperZ9/accountable-surface) (live
perceive/gate/actuate surface), and stands alone just as well.

## Docs

[docs/INTRODUCTION.md](docs/INTRODUCTION.md) (start here) ·
[USAGE.md](USAGE.md) (every command, captured output) ·
[SPEC.md](SPEC.md) (the frozen normative contract) ·
[RATIONALE.md](RATIONALE.md) (why EMET is shaped this way) ·
[conformance/](conformance/) · [THREAT-MODEL.md](THREAT-MODEL.md) ·
[COVERAGE.json](COVERAGE.json) · [SECURITY.md](SECURITY.md) ·
[CONTRIBUTING.md](CONTRIBUTING.md)

MPL-2.0.

## What this believes

This tool is one lane of a family that holds a single belief steady across
every surface: knowledge open to anyone who can attain the means; acceptance
decided by external checks, never reputation; every result re-runnable;
honest nulls first-class; ownership earned by comprehension; learning woven
into the work. The full text lives in [CREDO.md](CREDO.md).
The long form of this belief: [The Unbundling](https://github.com/HarperZ9/flywheel/blob/fix/release-model-identity/docs/essays/2026-07-13-the-unbundling.md).

---

**[Zentropy Labs](https://github.com/ZentropyLabs-ai)** · order out of entropy. An independent lab building evidence-first tools that leave a re-checkable artifact behind. Built by Zain Dana Harper in Seattle. The full workbench is at [Project Telos](https://harperz9.github.io).
