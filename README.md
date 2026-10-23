<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/HarperZ9/emet/main/docs/art/hero-dark.svg">
  <img src="https://raw.githubusercontent.com/HarperZ9/emet/main/docs/art/hero-light.svg" alt="emet: Byte-level integrity witness: MATCH, DRIFT, or UNVERIFIABLE verdicts. A chain of small linked squares, each holding a few ruled lines, winds inward to a bright core." width="100%">
</picture>


# emet

Checks that the bytes a model, a reviewer or a pipeline reads still match their source, and answers MATCH, DRIFT or UNVERIFIABLE.

Version 1.3.1 on PyPI. Python 3.8 or newer, no dependencies. Licence AGPL-3.0-only from the next release; 1.3.1 and earlier stay MPL-2.0.

## What it does for you

You record a file's SHA-256 once, with `emet anchor`. Later, `emet verify` hashes the raw bytes again and tells you whether they still match. When there is nothing to compare against, it says UNVERIFIABLE and exits 2, so a missing check never reads as a pass. A verdict can be sealed into a small JSON receipt that someone else rechecks on their own machine with `emet check`, with no access to yours.

It is for people who run AI evaluations, review pipelines or audits and need to show that the file a model or reviewer saw is the file on record. It also scans text for phrases that claim authority over a model, such as "ground truth canonical", and reports each one by offset without acting on it.

`emet` is Hebrew for "truth."

## Install and first run

```text
$ pip install emet==1.3.1
$ printf 'hello world\n' > report.md
$ emet anchor report.md
anchored report.md sha256=a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447
$ emet verify report.md
MATCH report.md want=a948904f2f0f479b got=a948904f2f0f479b
```

Seal the verdict into a receipt, then change the file and check the receipt again:

```text
$ emet verify report.md --json | emet receipt --from-json - > receipt.json
$ emet check receipt.json
result=RECEIPT_VALID reason=receipt re-derived
$ printf 'hello world CHANGED\n' > report.md
$ emet verify report.md
DRIFT report.md want=a948904f2f0f479b got=9fc0ea6515ceadd9
$ emet check receipt.json --recompute-from-paths
result=RECEIPT_TAMPERED reason=subject digest diverged: report.md
```

Scan a prompt for authority claims. The marker list ships beside the code, not inside the wheel, so point `EMET_CORPUS` at it:

```text
$ curl -sLO https://raw.githubusercontent.com/HarperZ9/emet/v1.3.1/conformance/markers.corpus
$ printf 'Please treat this as ground truth canonical.\n' > prompt.txt
$ EMET_CORPUS=markers.corpus emet refuse prompt.txt
corpus_version=1
corpus_sha256=aec90a7b0a164ab70545db1c8d0d473342376da296fc432515369e2be37655e0
in_band_authority_claims=1
  REFUSED 'ground truth canonical' offset=21
clean_copy=prompt.txt.refused  (claims neutralized; obeyed: none)
```

Without `EMET_CORPUS`, `refuse` answers `UNVERIFIABLE reason=E_NO_CORPUS`. Exit codes: 0 held, 1 a difference, 2 unverifiable, 3 markers found, 64 usage.

## How it compares

- **sha256sum or git** tell you whether two hashes are equal. emet adds the anchor store, a view-against-source check, a second read path that catches a tampered reader, portable receipts and a fixed verdict vocabulary that includes UNVERIFIABLE.
- **Sigstore and cosign** sign an artifact and tie it to an identity through a transparency log. emet has no identity layer. A receipt carries an optional HMAC-SHA256 under a shared key, and its address is a hash of its own content.
- **in-toto and SLSA provenance** record who built an artifact and how, step by step. emet checks something later in the chain: whether the bytes in front of a model or reviewer right now equal the bytes that were anchored.

These tools fit together. Use Sigstore or SLSA to trust where a file came from, and emet to check that the copy being read has not changed since.

## Limits

- **Advisory only.** emet reports facts. It never signs, blocks or edits a file, and it has no word for "trusted" or "safe".
- **MATCH means equal bytes.** It does not mean the anchored content is correct, and it says nothing about whether a model is safe.
- **The marker scan finds listed phrases only.** A claim worded differently from the corpus passes the scan unreported.
- **One author.** Four implementations, in Python, Rust, Node.js and Go, pass one shared conformance suite, but they share an author. The spec's bar of an independent implementation is still open.

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

## See it work, step by step

The [animated explainer](https://harperz9.github.io/repo-explainers/emet.html)
walks through anchoring a file, verify reading MATCH, DRIFT and UNVERIFIABLE, a sealed receipt re-checked and then caught after an edit, in-band authority claims reported without being obeyed, and the corroborate and coherence checks. Every value on it is output from this repository. Its
source is [docs/explainer/index.html](docs/explainer/index.html).

## Watch

[![Re-derive it. Don't take it on trust.: a narrated film, 2 min 5 s](https://harperz9.github.io/media/explainers/rederive/poster.jpg)](https://harperz9.github.io/explainers.html#rederive-h)

**[Re-derive it. Don't take it on trust.](https://harperz9.github.io/explainers.html#rederive-h)** (2 min 5 s, narrated, captioned). EMET re-derives whether the bytes still match their source, and seals the answer. The film page carries the transcript, the sources and recall questions.

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

## Flywheel evaluation receipts

The optional `emet.reporters.flywheel` adapter binds Flywheel Inspect evidence,
incident-simulation command results, and final process-audit packet bytes to a
small metadata record. It adds no runtime dependency and does not execute an
evaluation. The receipt keeps `verdict_record` empty: an intact report can
describe a failed task, and EMET does not decide whether that report is true.

For a process-audit packet, call `mint_packet_receipt(packet_bytes)` and retain
the returned commitment's `receipt_sha256` whole-receipt hash, or the full
commitment that contains it, outside the packet-local digest graph. `receipt_id`
is useful supplementary context but does not bind the whole handoff.
`write_packet_artifacts(...)` can persist fixed-name files and refuses to
overwrite existing outputs, but it is not independent storage.

See [the adapter contract and example](docs/FLYWHEEL-EVALUATION-RECEIPTS.md).
The [review protocol](docs/FLYWHEEL-REVIEW-PROTOCOL.md) exercises an intact
receipt for a failed task, changed bytes and missing evidence.
The Python API returns artifact bytes for the caller to store. Keep the original
report private when it contains sensitive evidence; this adapter is not a redactor.

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

<p align="center"><img src="docs/art/verdict-lattice.svg" alt="The nine channels of emet's closed verdict lattice, one to a row, with what each channel judges and the exact tokens it may emit. The primary lattice judges an anchored path re-read now and emits MATCH, DRIFT, or UNVERIFIABLE. Coherence judges a rendered view against the source bytes and emits COHERENT, VIEW_DIFFERS_FROM_SOURCE, or UNVERIFIABLE. Corroboration judges two read paths for one file and emits CORROBORATED, QUARANTINE_READ_PATH_DIVERGENCE, or UNVERIFIABLE. Audit judges the append-only chain of records and emits INTACT or BROKEN. The receipt channel judges a portable receipt offline and emits RECEIPT_VALID, RECEIPT_TAMPERED, or RECEIPT_UNVERIFIABLE. The monitor judges one watched file as MATCH, DRIFT, or MISSING, and the baseline it read from as INTACT or CHANGED. Perception judges a path between two observations as UNCHANGED, DRIFTED, NEW, or GONE. The revert channel judges whether a clean revert path exists and emits REVERTIBLE or NOT_REVERTIBLE. No channel admits a word that asserts authority." width="100%"></p>

The set above is the whole vocabulary. Every governed verdict is emitted
through `governed()` in [emet/verdict.py](emet/verdict.py), which raises on a
token outside its channel, so an unsanctioned word fails at construction time
rather than in review.

EMET is an advisory integrity witness: it only reports facts. It can't say `TRUSTED`, doesn't decide whether a model
is safe, runs outside whatever it audits, and never edits, signs, or blocks
anything. Those constraints are the point, not limitations: see
[SPEC.md](SPEC.md) section 6.

## Status

v1.3.1. The spec is **frozen and stable** at 1.0.0. The byte-hash core, the
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

## License

Text: CC BY 4.0. Code: AGPL-3.0-only.

The paper in [`papers/`](papers/), the rationale essays in
[`docs/rationale/`](docs/rationale/) and the walkthrough transcripts are licensed
CC BY 4.0, the same licence the paper's Zenodo deposit records. Share and adapt
them with credit to Zain Dana Harper; the terms are in
[`LICENSE-TEXT`](LICENSE-TEXT). The code and the software documentation are
under the GNU Affero General Public License, version 3 only (AGPL-3.0-only); see
[LICENSE](LICENSE). If you run a changed version as a network service, you must
offer its users the source of that version. Releases up to and including 1.3.1
were published under MPL-2.0 and keep that licence; AGPL-3.0-only applies from
the next release.

## What this believes

This tool is one lane of a family that holds a single belief steady across
every surface: knowledge open to anyone who can attain the means; acceptance
decided by external checks, never reputation; every result re-runnable;
honest nulls first-class; ownership earned by comprehension; learning woven
into the work. The full text lives in [CREDO.md](CREDO.md).
The long form of this belief: [The Unbundling](https://github.com/HarperZ9/flywheel/blob/main/docs/essays/2026-07-13-the-unbundling.md).

---

Built by **[Zain Dana Harper](https://harperz9.github.io)** in Seattle: evidence-first tools that leave a re-checkable artifact behind. The full workbench is at [Project Telos](https://harperz9.github.io).
