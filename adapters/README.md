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
