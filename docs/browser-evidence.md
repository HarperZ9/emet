# Browser Evidence Witness Recipe

Project Telos browser evidence packets use the `project-telos.browser-evidence/v1`
schema to carry compact refs, artifact hashes, side-effect class, and a local
verification verdict for browser automation or research capture.

EMET does not control the browser. It does not inspect sessions, bypass login
flows, click pages, or decide whether automation should run. EMET only witnesses
the packet bytes that Telos, Gather, Index, Forum, Learn, or Crucible already
produced.

## Witness Flow

Write the packet to a file such as `browser-evidence.json`, then anchor and
verify the exact bytes:

```sh
emet anchor browser-evidence.json
emet verify browser-evidence.json
emet audit
```

The useful pipeline shape is:

```text
browser state -> Telos packet -> emet anchor -> emet verify -> emet audit
```

The witness remains deliberately small:

- `MATCH` means the current packet bytes match the anchored bytes.
- `DRIFT` means the packet bytes changed after anchoring.
- `UNVERIFIABLE` means EMET cannot perform the comparison.

This is useful before model council or review escalation. Index and Forum can
route a compact packet ref into a council path while EMET preserves a local,
re-derivable check on the packet bytes. The packet may point to richer artifacts,
but EMET does not dereference those artifacts or expand raw browser data into the
model boundary.

See `examples/browser-evidence-anchor.json` for a compact receipt shape.
