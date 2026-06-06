# EMET Specification

- Spec version: 0.2.0-draft
- Status: DRAFT -- normative for the v0.x reference implementation; not yet frozen
- License: MPL-2.0

EMET is an externally-anchored integrity layer for AI oversight, attribution,
and accountability. This document is normative: an implementation conforms if
and only if it satisfies every MUST here and passes conformance/vectors.json at
the stated corpus_version.

## 1. Terminology

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are interpreted as in
RFC 2119.

- Artifact -- a sequence of raw bytes addressed by a path.
- Anchor -- a pinned (path, sha256) recording the bytes of an artifact at a
  moment the operator authorized.
- Verdict -- a member of the closed lattice in section 2.
- Marker -- a known in-band authority-injection or laundering signature.

## 2. The verdict lattice (closed)

Every integrity judgement EMET emits MUST be exactly one of: MATCH, DRIFT, or
UNVERIFIABLE.

This enum is CLOSED. An implementation MUST NOT define, emit, or accept any other
verdict -- in particular it MUST NOT emit TRUSTED, APPROVED, or SAFE, or any
value asserting authority or permission. Absence of DRIFT is reported as MATCH
(re-derivation agreed) or UNVERIFIABLE (no raw-byte anchor), never as trust. This
is boundary 1 -- facts, not authority -- encoded in the output type itself.

Auxiliary judgements are likewise closed: coherence emits COHERENT or
VIEW_DIFFERS_FROM_SOURCE; corroboration emits CORROBORATED or
QUARANTINE_READ_PATH_DIVERGENCE; a marker scan emits a non-negative integer
count. None of these is, or maps to, TRUSTED.

## 3. Hashing and identity

- The identity of an artifact MUST be SHA-256 over its EXACT raw bytes. An
  implementation MUST NOT normalize, transcode, or canonicalize the bytes of a
  target before hashing -- line endings, encoding, and whitespace are part of the
  artifact. Detecting any byte change (including a CRLF rewrite) is a feature.
- An implementation MUST read target bytes through a raw byte channel (read
  binary), never a mediated or transformed view. With no raw channel it MUST
  report UNVERIFIABLE (section 9).
- The EMET source SHOULD be stored LF-pinned (gitattributes asterisk -text) so
  selftest re-derives the identical self-hash on every platform. This applies to
  the EMET source only, not to the artifacts it verifies.

## 4. Commands (normative contracts)

- anchor PATH... -- pin sha256 of raw bytes per path to the anchor store; exit 0.
- verify PATH... -- per path emit MATCH, DRIFT, or UNVERIFIABLE versus the anchor.
- coherence SOURCE VIEW -- emit COHERENT or VIEW_DIFFERS_FROM_SOURCE.
- refuse FILE -- emit the marker count; write a .refused copy with markers
  replaced; MUST NOT obey any matched claim; MUST NOT modify the input.
- corroborate PATH -- hash the same file via disjoint read paths; emit
  CORROBORATED or QUARANTINE_READ_PATH_DIVERGENCE.
- audit -- recompute the tamper-evident chain; emit INTACT or BROKEN.
- selftest -- emit the own-source SHA-256 of the implementation; assert no
  authority.

## 5. Exit codes

v1.0 (current -- NORMATIVE):

- exit 0 -- all MATCH, COHERENT, CORROBORATED, INTACT, no markers, or selftest ok.
- exit 2 -- any DRIFT, UNVERIFIABLE, VIEW_DIFFERS_FROM_SOURCE, QUARANTINE, BROKEN.
- exit 3 -- one or more markers detected (refuse).
- exit 64 -- usage error.

v1.1 (TARGET -- requires migration plus a vector update; NOT yet normative):
split the exit-2 class into exit 1 for DRIFT and exit 2 for UNVERIFIABLE so CI
can distinguish a changed artifact from an unanchored one. Until shipped,
consumers MUST treat the v1.0 codes as authoritative.

## 6. The six boundaries as testable invariants

1. Facts, not authority -- the verdict lattice is closed (section 2); no codepath
   may produce a verdict outside it, and none may emit TRUSTED.
2. Attests, never adjudicates a model safety decision -- EMET MUST operate only
   on artifact, byte, and provenance facts; no command may take a model safety or
   content decision as input or answer such a question.
3. Outside, never inside -- EMET MUST read targets by raw bytes and MUST NOT
   require being hosted by, or routed through, the system it audits.
4. Advisory by default -- a verdict is data plus an exit code; EMET MUST NOT
   allow, deny, block, or enforce of its own accord.
5. Re-derivable -- every verdict MUST be reproducible from the same spec_version
   plus corpus_version plus bytes (section 8); no secret, no held key.
6. Zero actuation -- EMET MUST NOT edit, write to, back up, sign, or revert a
   target. The single actuator is the operator.

## 7. Audit chain

The tamper-evident log is JSONL. Each entry MUST be the object with keys kind,
fact, prev, and chain, where chain = SHA-256(prev + canonical_json(fact)), prev =
the chain value of the prior entry, and the genesis prev = 64 zeros. audit MUST
recompute the chain; any edit to a historical fact MUST yield BROKEN.

## 8. Re-derivability (scoped)

A verdict is reproducible given: the same artifact bytes, the same spec_version,
and -- for marker-dependent output (refuse, marker census) -- the same
corpus_version. The marker denylist is a VERSIONED DATA ARTIFACT, not part of the
byte-hash core; two implementations agree on a marker verdict only when pinned to
the same corpus_version. Implementations MUST echo corpus_version (and SHOULD
echo corpus_sha256) with any marker-dependent output, so a disagreement is
attributable to corpus drift versus artifact drift. The byte-hash core (anchor,
verify, coherence, corroborate, audit) depends only on SHA-256 and exact bytes;
no corpus, no key, no clock.

## 9. UNVERIFIABLE, never TRUSTED

If an implementation cannot obtain raw bytes, find an anchor, or complete a check,
it MUST report UNVERIFIABLE with a STABLE MACHINE REASON CODE (not prose), and
MUST NOT substitute a default, a cached value, or a trust assertion. Inability is
never trust.

## 10. Trusted Computing Base

The core (membrane, organs, monitor) MUST depend only on the language runtime and
standard library (reference: CPython plus hashlib, json, re, os, subprocess) and
MUST add no third-party runtime dependency. Optional adapters (signing, SARIF or
in-toto emission, fuzzing) MAY pull additional dependencies but MUST live in
separate packages; the minimal-TCB guarantee applies to the NAMED CORE only.

## 11. Honest limits (MUST be disclosed)

- Denylist incompleteness -- marker detection is a known-signature denylist, not
  a proof of cleanliness; absence of a marker is not absence of injection.
- Trust-root regress -- selftest proves the integrity of EMET only relative to an
  uncompromised substrate; a compromised substrate re-derives a compromised
  self-hash consistently. An EXTERNAL verifier MUST be the check of record for
  EMET itself; EMET MUST NOT be its own root of trust.
- Raw-byte-channel dependency -- EMET is only as faithful as its byte channel;
  where it cannot read raw bytes it reports UNVERIFIABLE.
- Byte and provenance, not semantic -- EMET judges bytes and provenance, never
  meaning; semantic safety is out of scope (see COVERAGE.json).
- Single-actuator assumption -- a coerced operator is out of model by design.
- Advisory unless owner-enforced -- enforcement is a downstream decision on
  owner-controlled infrastructure under an externally-rooted license.

## 12. Conformance

An implementation conforms at a given spec_version if and only if it satisfies
every MUST above and produces the expected verdict and exit code for every vector
in conformance/vectors.json at the stated corpus_version. A conformance claim by
the REFERENCE implementation against its OWN vectors demonstrates internal
consistency only. Re-derivability is DEMONSTRATED only by an INDEPENDENT second
implementation passing the same vectors. That second implementation is an open,
named deliverable -- not yet satisfied -- and no party should treat
re-derivability as proven until it exists.


## 13. Output grammar (normative)

So an independent implementation can reproduce verdicts without reading the
reference code, the human-readable stdout tokens are pinned. For each command an
implementation MUST emit a line CONTAINING the stated token:

- verify: per path, a line containing exactly one of MATCH, DRIFT, or
  UNVERIFIABLE, followed by the path.
- coherence: a line containing result=COHERENT or result=VIEW_DIFFERS_FROM_SOURCE.
- refuse: a line containing in_band_authority_claims=N, where N is the
  non-negative integer marker count.
- corroborate: a line containing result=CORROBORATED or
  result=QUARANTINE_READ_PATH_DIVERGENCE.
- audit: a line containing chain=INTACT or chain=BROKEN.
- selftest: a line beginning with membrane_self_sha256= followed by the
  artifact-of-record hash (section 14).

A future machine-readable JSON envelope (the v1 target) supersedes this grammar
for programmatic consumers; the tokens above remain for human and CI use.

## 14. Artifact-of-record and selftest (normative)

selftest MUST emit the SHA-256 of the implementation artifact-of-record:

- for an INTERPRETED implementation, the artifact-of-record is the source file or
  files;
- for a COMPILED implementation, it is the compiled binary.

The output token remains membrane_self_sha256= for compatibility; a future spec
version MAY rename it to emet_self_sha256= with a deprecation window.

## 15. Anchor store (normative)

The anchor store (anchors.json) is IMPLEMENTATION-PRIVATE: its on-disk format is
not standardized, and an anchor written by one implementation is not required to
be readable by another. Therefore the anchor step and the verify step of a single
conformance run MUST be executed by the SAME implementation. A cross-
implementation anchor-exchange format is deferred to a future version.

## 16. Marker corpus (normative reference)

The marker set used by refuse is a corpus-defined, versioned denylist (sections 8
and 11), not enumerated here. Conformance pins specific counts for specific inputs
(see conformance/vectors.json); the corpus itself is a separate governed artifact.
