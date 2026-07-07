# An Introduction to EMET

EMET is a byte-level integrity witness. Point it at files and it answers one
narrow question with re-derivable facts: do these bytes still match the source
they claim to represent? The answer is always one of three closed verdicts,
`MATCH`, `DRIFT`, or `UNVERIFIABLE`, and every verdict comes from a hash
computation you can repeat yourself. Same bytes, same answer.

It is a single stdlib-only Python tool with zero dependencies, plus three
clean-room ports (Rust, Node.js, Go) that pass the same language-agnostic
conformance suite in CI. Install it with `pip install emet` or run it straight
from a checkout with `python membrane.py`.

## Why it exists

Modern pipelines are full of seams where a copy quietly stops being the
original: a model-facing view drifts from its source file, a monitor observes
the wrong artifact, a re-encode strips an embedded provenance credential, a
generated report overstates what was actually checked. EMET sits outside those
seams as a small external witness. It never says `TRUSTED`, never grants
permission, and never edits, signs, or blocks anything. It reports what
matched, what drifted, and what it could not verify, and it makes each of
those reports cheap for anyone else to re-derive.

## Core concepts

**The closed verdict lattice.** Every command resolves to `MATCH`, `DRIFT`, or
`UNVERIFIABLE` (plus a few closed auxiliaries like `COHERENT` and
`CORROBORATED`). There is deliberately no `TRUSTED`, `SAFE`, or `APPROVED`.
`UNVERIFIABLE` is an honest answer, never a silent pass: it always carries a
stable reason code such as `E_NO_ANCHOR` or `E_NO_CORPUS`.

**Anchors.** `emet anchor` pins the SHA-256 of a file's exact raw bytes into a
local `anchors.json`. `emet verify` recomputes the hash later and compares.
That is the whole trust model: out-of-band content hashes, not embedded
metadata, not signatures from an authority.

**Exit codes are part of the contract** (SPEC section 5): `0` held, `1` a
difference found, `2` unverifiable, `3` authority markers found, `64` usage.
Scripts can branch on the exit code alone.

**The machine envelope.** Add `--json` to any command for one canonical-JSON
object. The governed fields are byte-identical across all four
implementations; the exit code is unchanged.

**Witness receipts** (SPEC s.17). A verdict can travel. `emet receipt` seals a
`--json` envelope into a self-contained, content-addressed receipt, and `emet
check` re-verifies it on a different machine with zero shared state. The
receipt id is byte-identical whether the receipt was produced by the Python,
Rust, or Node.js implementation.

**The marker corpus.** `emet refuse` scans bytes against a versioned denylist
of in-band authority claims ("ground truth", "highest_scrutiny", and so on),
reports each by offset, and writes a neutralized copy. The corpus is a data
artifact shipped separately from the wheel; without it, `refuse` reports
`UNVERIFIABLE reason=E_NO_CORPUS`.

**Rebind** (SPEC s.18, experimental). When a re-encode or screenshot strips an
embedded C2PA-style credential, `emet rebind` re-derives the naked bytes'
content hash and rebinds them to a known anchor from a portable manifest,
because EMET never depended on the embedded metadata in the first place.

## Your first ten minutes

Install and prove the tool's own identity:

```sh
pip install emet
emet selftest
# emet_self_sha256=<hash of the tool's own source>
```

Pin a file, then catch it drifting:

```sh
printf 'hello world\n' > report.md
emet anchor report.md
# anchored report.md sha256=a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447

emet verify report.md
# MATCH report.md want=a948904f2f0f479b got=a948904f2f0f479b   (exit 0)

printf 'hello world CHANGED\n' > report.md
emet verify report.md
# DRIFT report.md want=a948904f2f0f479b got=9fc0ea6515ceadd9   (exit 1)
```

Check that a presented view is faithful to its source:

```sh
printf 'same bytes\n' > source.md && cp source.md view.md
emet coherence source.md view.md
# result=COHERENT   (exit 0)

printf 'tampered\n' > view.md
emet coherence source.md view.md
# result=VIEW_DIFFERS_FROM_SOURCE   (exit 1)
```

Make a verdict portable, then re-verify it as a stranger would:

```sh
emet verify report.md --json | emet receipt --from-json - > receipt.json
emet check receipt.json
# result=RECEIPT_VALID reason=receipt re-derived   (exit 0)
# any byte of tampering flips it to RECEIPT_TAMPERED
```

Audit the tamper-evident log the commands above have been appending to:

```sh
emet audit
# log_entries=N chain=INTACT   (exit 0)
```

Finally, see the whole surface in one pass: `sh examples/demo.sh` drives every
command end-to-end in a scratch directory.

## The four implementations

The Python reference lives at the repo root. `impl/rust/emet.rs` (no crates),
`impl/js/emet.js` (built-in modules only), and `impl/go/emet.go` (standard
library only) are clean-room ports written from the spec. The conformance
suite (`conformance/vectors.json`, 44 vectors) scores each implementation on
exactly the capabilities it claims: Python passes 44/44, Rust and Node.js pass
40/40 (rebind not yet ported), Go passes the 35 core vectors (receipt and
rebind not yet ported). CI runs all of this, plus a cross-language receipt
parity gate with deliberate tamper negatives, on every push.

One honest caveat, stated in the spec itself: all four implementations share
an author, so their agreement shows the spec is implementable from its text,
not yet that it is independently re-derivable. An independent, different-author
implementation passing the vectors is the standing call for contribution (SPEC
section 12).

## Where to go next

- [USAGE.md](../USAGE.md): every command with captured real output, the
  companion tools (`monitor.py`, `organs.py`), and the proof-surface receipt
  adapter.
- [SPEC.md](../SPEC.md): the frozen v1.0 normative contract.
- [RATIONALE.md](../RATIONALE.md): why EMET is shaped the way it is, derived
  from first principles.
- [THREAT-MODEL.md](../THREAT-MODEL.md): the STRIDE analysis.
- [REBIND-SPEC.md](REBIND-SPEC.md): the cross-language port contract for the
  experimental rebind capability.
- [CONTRIBUTING.md](../CONTRIBUTING.md): including how to claim a language for
  an independent implementation.
