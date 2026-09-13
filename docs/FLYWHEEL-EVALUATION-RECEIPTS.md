# Flywheel evaluation receipts

`emet.reporters.flywheel` is an optional adapter for exact Flywheel JSON report
bytes. It does not import Flywheel, run Inspect, execute an incident simulation,
call a scorer, access the network, or write to the filesystem.

The adapter accepts UTF-8 JSON bytes for two development schemas:

- `flywheel.inspect-evidence/v1`
- `flywheel.incident-sim-command/v1`

It returns a portable EMET witness receipt plus two fixed-name byte artifacts for
the caller to persist:

```python
from emet.reporters.flywheel import build_eval_record, mint_receipt

record = build_eval_record(raw_flywheel_json_bytes)
receipt, artifacts = mint_receipt(raw_flywheel_json_bytes)

artifacts["flywheel-evaluation.json"]  # exact raw bytes supplied by caller
artifacts["flywheel-record.json"]      # canonical EMET metadata record bytes
```

The receipt is minted from an anchor-style command envelope. It addresses both
artifacts by SHA-256 and keeps `verdict_record` empty. A valid receipt means the
receipt body re-derives, and, when checked with subject recomputation, the
persisted artifact bytes still match the recorded digests. It does not mean the
Flywheel report is semantically correct.

The metadata record copies only a bounded projection of producer claims after
checking closed tokens for the direct fields it projects:

- for Inspect evidence, `reported_status` must be one of `started`, `success`,
  `cancelled`, or `error`; `assessment` must be one of `reported`,
  `incomplete`, or `error`; `semantic_verification` must be `UNVERIFIABLE`;
  and `invalidated` must be boolean
- for incident simulation, the reported overall evaluation verdict must be one
  of `MATCH`, `DRIFT`, or `UNVERIFIABLE`

The record also stores the raw byte length and raw SHA-256. It labels semantic
conclusions as unverified by EMET. Private operator inputs, source values, local
paths, and trace contents remain in the raw Flywheel artifact only. This adapter
is not a general redactor; callers should store and share the raw artifact only
where its contents are allowed.

Malformed inputs fail before receipt construction with bounded `E_*` errors.
The parser rejects non-bytes input, oversized input above 16 MiB, invalid UTF-8,
duplicate JSON object keys, non-finite JSON numbers, non-string or unknown
schema values, excessive nesting, missing direct fields needed for the bounded
projection, wrongly typed direct fields, and unknown projected producer tokens.
It does not fully validate every nested Flywheel schema field.

One useful false-success control is an incident report whose Flywheel result says
`DRIFT`. EMET can still produce a valid integrity receipt for that report. The
receipt proves the report bytes were witnessed; it does not upgrade the reported
task result to a pass, prove the actions actually happened, or provide
independent ground truth.

Run the focused behavior proof:

```powershell
python test_reporter_flywheel.py
python -m pytest test_reporter_flywheel.py -q
```

The first command is the CI-compatible plain-script path. The second is a local
developer convenience when pytest is installed.
