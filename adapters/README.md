# EMET adapters

Optional, out-of-core integrations. The minimal-TCB guarantee (SPEC section 10)
applies to membrane / organs / monitor ONLY, never to anything in this directory.

Adapters EMIT DATA. They never sign, enforce, upload, or actuate -- the operator
does that downstream (SPEC boundaries 5 and 6). An adapter that signed, blocked,
or wrote to a transparency log would breach EMET. EMET attests; the operator acts.

## Available adapters

- `attest.py` emits unsigned in-toto statement JSON for downstream signing.
- `proof_surface_receipt.py` emits compact witness receipts with `receipt_id`,
  `verdict`, `witness`, `subject`, and evidence metadata for proof-index and
  release-readiness workflows.
- `deepeval_reporter.py` turns a completed DeepEval evaluation into a portable
  emet witness receipt (SPEC s.17). It gathers a canonical eval record - model
  identifier, dataset digest + count (a hash of the test-case inputs, never the
  raw cases), metric/judge name + version, per-case pass/score as strings, and
  config - and seals it so `emet check` re-verifies it offline; corrupting one
  byte flips the verdict away from `RECEIPT_VALID`. The record carries no floats
  and the receipt's `verdict_record` is empty by design, so it binds the record's
  integrity and provenance without asserting anything about model quality beyond
  the numbers the metrics reported. DeepEval is an optional, lazy import
  (`pip install emet[deepeval]`); minting from an already-completed evaluation
  needs no deepeval install.

DeepEval reporter example:

```python
from adapters.deepeval_reporter import mint_receipt
receipt, record_path, receipt_path = mint_receipt(
    result,                              # whatever deepeval.evaluate(...) returned
    model="gpt-4o-2024-08-06",
    config={"temperature": "0", "run": "nightly"},
    out_dir="eval-out",
)
# then, on any isolated machine, zero shared state:
#   emet check eval-out/emet-eval-receipt.json                      -> RECEIPT_VALID
#   emet check eval-out/emet-eval-receipt.json --recompute-from-paths
```

The `bundle` witness re-derives a content-addressed proof-surface bundle: for
every `files[]` entry in `bundle.json` it recomputes the sibling file's sha256 and
compares it to the recorded digest. `MATCH` iff every file re-derives; `DRIFT` if a
recorded digest no longer matches disk; `UNVERIFIABLE` if a listed file is missing
or the manifest is malformed. It runs entirely inside EMET (no proof-surface
import) and refuses authority tokens exactly as the other checks do.

Receipt adapter examples:

```sh
python adapters/proof_surface_receipt.py verify README.md anchors.json
python adapters/proof_surface_receipt.py coherence SPEC.md rendered-view.md
python adapters/proof_surface_receipt.py corroborate SPEC.md
python adapters/proof_surface_receipt.py bundle path/to/packet/bundle.json
```
