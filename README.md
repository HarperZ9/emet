# EMET

[![conformance](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml/badge.svg)](https://github.com/HarperZ9/emet/actions/workflows/conformance.yml)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](LICENSE)
[![spec](https://img.shields.io/badge/spec-v0.2.0--draft-blue.svg)](SPEC.md)

**An externally-anchored integrity layer for AI oversight, attribution, and accountability.**

EMET verifies that what reaches a model matches source truth, and detects a failure
class that deployed provenance standards do not check: in-band authority injection, a
presented view that diverges from its source, and read-path divergence. Its trust comes
entirely from **re-derivability** — re-run it on the same bytes, get the same answer —
never from authority. Its verdict vocabulary cannot even express `TRUSTED`.

> *emet* (אמת), Hebrew for "truth," is the word that animates the Golem; erase one
> letter and it becomes *met* — "death." The letter holds only because anyone can
> recompute it. That is exactly how EMET earns trust.

## Why it exists

Every deployed supply-chain provenance standard — in-toto, SLSA, Sigstore, C2PA —
assumes one honest narrator describing one system through one read path. That holds for
a build pipeline; it collapses for AI oversight, where a system can present a clean
account of itself while the real behavior diverges. EMET computes the predicate those
standards leave unguarded:

- **In-band authority injection** — a system asserting its own trustworthiness inside
  the very channel being inspected.
- **Laundered view** — a presented view (a dashboard, a summary, a self-report) that
  differs from its source artifact.
- **Read-path divergence** — a monitor reading a different artifact, version, or path
  than the one that actually runs.

The underlying primitives — TOCTOU, remote attestation, the trusted-monitor problem —
are studied in the literature; EMET's contribution is packaging them for AI-oversight
provenance, where the shipping tooling inherits the honest-narrator assumption.

## The boundaries (this is the product, not a limitation)

A verifier that *cannot* become an authority is precisely what an auditor or a regulator
can safely standardize on. These are non-negotiable (see [SPEC.md](SPEC.md) section 6):

1. **Facts, not authority** — the verdict lattice cannot express `TRUSTED`; it refuses
   every in-band authority claim, its own included.
2. **Attests, never adjudicates a model's safety decision** — it judges bytes and
   provenance, never a model's reasoning.
3. **Outside, never inside the audited system** — the auditor lives outside the audited.
4. **Advisory by default** — a verdict is data plus an exit code; enforcement is a
   downstream consumer's choice.
5. **Re-derivable** — the only credential is reproduction; no key, no signer-of-record.
6. **Zero actuation** — it witnesses and advises; it never edits, signs, or reverts.

## Re-derivability, demonstrated

EMET's central claim is checkable, not asserted. A normative spec
([SPEC.md](SPEC.md)) pins the behavior; a language-agnostic conformance suite
([conformance/](conformance/)) encodes it as golden and adversarial vectors; and **two
independent implementations — the Python reference and a from-scratch Rust
implementation with no dependencies — pass the same vectors on every push** (the
conformance badge above). Reproduce it yourself:

```sh
git clone https://github.com/HarperZ9/emet && cd emet
python conformance/run.py membrane.py           # reference implementation: 9/9
( cd impl/rust && rustc -O emet.rs -o emet )    # build the second implementation
python conformance/run.py impl/rust/emet        # second implementation: 9/9
```

## Quickstart

```sh
python membrane.py selftest                    # re-derive its own identity hash
python membrane.py anchor  <path>...            # pin raw-byte hashes
python membrane.py verify  <path>...            # MATCH / DRIFT / UNVERIFIABLE
python membrane.py coherence <source> <view>    # is a presented view faithful to source?
python membrane.py refuse  <file>               # detect + strip in-band authority claims
python membrane.py corroborate <path>           # read-path-diverse agreement
python monitor.py  report <manifest>            # external accountability over a baseline
```

Stdlib only. No network. No third-party dependencies in the core.

## Status

Pre-1.0. The spec is a working **draft** (v0.2.0-draft). Re-derivability is
**demonstrated across two languages** and checked continuously in CI; a fully
**different-author** independent implementation is the next step to make it airtight —
and the spec says so openly. EMET does not overclaim: a re-derivability tool that
inflates a single claim refutes itself.

## Documentation

| Document | Purpose |
|---|---|
| [SPEC.md](SPEC.md) | Normative specification (RFC 2119) |
| [conformance/](conformance/) | Golden + adversarial vectors and a language-agnostic runner |
| [THREAT-MODEL.md](THREAT-MODEL.md) | STRIDE model and residual attack surface |
| [COVERAGE.json](COVERAGE.json) | What EMET checks, and what it explicitly does not |
| [SECURITY.md](SECURITY.md) | Coordinated disclosure policy |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute (and the boundaries a change must respect) |
| [adapters/attest.py](adapters/attest.py) | Emit verdicts as in-toto attestations (cosign / slsa-verifier consumable) |

## License

[MPL-2.0](LICENSE). The verifier's own source can never go dark — which, for a tool
whose only credential is reproducibility, is the point.
