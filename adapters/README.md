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

Receipt adapter examples:

```sh
python adapters/proof_surface_receipt.py verify README.md anchors.json
python adapters/proof_surface_receipt.py coherence SPEC.md rendered-view.md
python adapters/proof_surface_receipt.py corroborate SPEC.md
```
