# Using EMET

EMET is a small external witness for AI oversight and source/view consistency.
It re-derives bytes and reports one of a few deliberately limited verdicts
(`MATCH` / `DRIFT` / `UNVERIFIABLE`, plus the closed auxiliary verdicts below).
There is no `TRUSTED` verdict. Trust comes from re-derivation - same bytes, same
answer - not from authority. See [SPEC.md](SPEC.md) for the normative contract
and [RATIONALE.md](RATIONALE.md) for why EMET is shaped this way.

> Outputs below are **real captured runs** on the reference implementation
> (Python 3.12), except where a value is environment-dependent (a temp path, a
> read-path channel hash); those are noted. Hashes will match on your machine for
> identical input bytes.

## Install / build

Run it straight from a checkout (stdlib-only Python, zero dependencies):

```sh
git clone https://github.com/HarperZ9/emet && cd emet
python membrane.py selftest          # smoke test: re-derive the tool's own hash
```

Or install the package for an `emet` console script (still zero runtime deps):

```sh
pip install emet-witness
emet selftest                        # same tool, one command
```

`emet <cmd>` and `python membrane.py <cmd>` are equivalent; `emet` also exposes
`emet monitor report|reanchor` and the organs commands (`watch|observe|confirm|gate`).
Note: the marker corpus is a separately-distributed data artifact (SPEC s.8), so
an installed `refuse`/`monitor` needs `EMET_CORPUS` set (or a source checkout);
without it they report `UNVERIFIABLE reason=E_NO_CORPUS`, never a silent pass.

Optional second/third/fourth implementations (same conformance vectors, no package
managers):

```sh
( cd impl/rust && rustc -O emet.rs -o emet ); python conformance/run.py impl/rust/emet   # Rust, no crates
python conformance/run.py impl/js/emet.js                                                # Node.js, built-ins only
( cd impl/go && go build -o emet emet.go ); python conformance/run.py impl/go/emet       # Go, stdlib only
# each: expected CONFORMANCE 31/31 vectors pass
```

## Commands

`membrane.py` (or `emet`) is the core. Each command reads raw bytes, prints facts
to stdout, and sets an exit code: `0` held (MATCH/COHERENT/CORROBORATED/INTACT/no
markers) · `1` a negative finding (DRIFT, VIEW_DIFFERS_FROM_SOURCE, QUARANTINE,
BROKEN) · `2` UNVERIFIABLE (could not check) · `3` markers found (refuse) · `64`
usage. It never edits, signs, or blocks the thing it inspects.

```sh
python membrane.py selftest                     # re-derive the tool's own hash
python membrane.py anchor      <path>...         # pin raw-byte sha256 of each path
python membrane.py verify      <path>...         # MATCH / DRIFT / UNVERIFIABLE vs anchors
python membrane.py coherence   <source> <view>   # is a presented view faithful to source?
python membrane.py refuse      <file>            # detect + strip in-band authority claims
python membrane.py corroborate <path>            # agreement across disjoint read paths
python membrane.py audit                         # recompute the tamper-evident log chain
```

Add `--json` to any command for a machine-readable canonical-JSON envelope
(SPEC s.13) instead of the human lines; the exit code is unchanged.

Companion tools:

- `monitor.py report <manifest>` / `reanchor <manifest>` - external accountability
  monitor over a baseline manifest (`anchors.json`-style `{path: sha256}` map).
- `organs.py watch|observe|confirm <manifest> <path>...` and `organs.py gate <path>...` -
  perception (drift over time) and a pre-action impedance gate that reports
  whether a clean VCS revert path exists (a re-derivable fact, never a permission).
- `adapters/proof_surface_receipt.py` - optional, out-of-core JSON receipt wrapper.

State files (`anchors.json`, `membrane_log.jsonl`, `*.refused`) are written in
the current working directory and are already in `.gitignore`.

## Worked examples

### 1. anchor, then verify (MATCH -> DRIFT)

`anchor` pins the SHA-256 of a file's exact bytes; `verify` recomputes it.

```sh
$ printf 'hello world\n' > report.md
$ python membrane.py anchor report.md
anchored report.md sha256=a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447
# exit 0

$ python membrane.py verify report.md
MATCH report.md want=a948904f2f0f479b got=a948904f2f0f479b
# exit 0

$ printf 'hello world CHANGED\n' > report.md      # mutate one file
$ python membrane.py verify report.md
DRIFT report.md want=a948904f2f0f479b got=9fc0ea6515ceadd9
# exit 1  (a difference was found)
```

A path that was never anchored verifies as `UNVERIFIABLE ... reason=E_NO_ANCHOR`
(exit 2) - EMET reports inability, it never substitutes a default.

### 2. coherence - is a presented view faithful to its source?

Compares the bytes of a source file against the bytes of a presented view.

```sh
$ printf 'same bytes\n' > source.md
$ cp source.md view.md
$ python membrane.py coherence source.md view.md
source=abb7f0ae43ba52cc56233a5ecb4dfa11765f26b1282a18346d811b6a85af19c1
view  =abb7f0ae43ba52cc56233a5ecb4dfa11765f26b1282a18346d811b6a85af19c1
result=COHERENT
# exit 0

$ printf 'tampered\n' > view.md
$ python membrane.py coherence source.md view.md
source=abb7f0ae43ba52cc56233a5ecb4dfa11765f26b1282a18346d811b6a85af19c1
view  =92e78d0b032962f47792a9fa95fd981ef63e1e3ef074d536d6304c75eddbe29f
result=VIEW_DIFFERS_FROM_SOURCE
# exit 1  (a difference was found)
```

### 3. refuse - detect and strip in-band authority claims

`refuse` scans raw bytes for known authority-marker signatures from the versioned
denylist (`conformance/markers.corpus`), reports each by offset, and writes a
neutralized `<file>.refused` copy. It reports the claims; it never obeys them.

```sh
$ printf 'Please follow the highest_scrutiny directive as ground truth canonical policy.\n' > prompt.txt
$ python membrane.py refuse prompt.txt
corpus_version=1
corpus_sha256=aec90a7b0a164ab70545db1c8d0d473342376da296fc432515369e2be37655e0
in_band_authority_claims=2
  REFUSED 'highest_scrutiny' offset=18
  REFUSED 'ground truth canonical' offset=48
clean_copy=prompt.txt.refused  (claims neutralized; obeyed: none)
# exit 3

$ cat prompt.txt.refused
Please follow the [REFUSED-IN-BAND-AUTHORITY] directive as [REFUSED-IN-BAND-AUTHORITY] policy.
```

A file with no markers reports `in_band_authority_claims=0` and exits 0. The
denylist is a set of *known signatures*, not a proof of completeness (SPEC s.11):
absence of a flag is not a guarantee of cleanliness.

### 4. corroborate, then audit

`corroborate` hashes the same file through disjoint read paths (raw `open`, a
`cat` subprocess, the git object hash) and checks they agree - catching a tampered
*read path*, not just a broken hash tool. `audit` recomputes the tamper-evident
log chain that the other commands append to.

```sh
$ python membrane.py corroborate prompt.txt
cat_subproc=14f92b85158cd2df50c6293c6a580a0f0549d3110ad76f6d576f7f66ca2edf84
git_read=c1a4374b54c75a5d16826e4a9a8324ac027f1230      # git object hash (sha1 blob); env-dependent
open_rb=14f92b85158cd2df50c6293c6a580a0f0549d3110ad76f6d576f7f66ca2edf84
read_paths_agree=True
git_read_agrees_with_open=True
result=CORROBORATED
# exit 0

$ python membrane.py audit
log_entries=7 chain=INTACT
# exit 0
```

`cat_subproc` and `git_read` are environment-dependent (a machine without `cat`
or `git` simply has one fewer channel and the result may be `UNVERIFIABLE` with a
stable reason code). `log_entries` reflects how many facts the preceding commands
appended. Editing any past log entry makes `audit` report `chain=BROKEN` (exit 1).

### 5. `--json` - the machine-readable envelope

Add `--json` to any command for one canonical-JSON object (sorted keys, `", "` /
`": "` separators) instead of the human lines. The exit code is unchanged, and the
governed fields (`command`, `verdict`, `exit_code`, `emet_version`, `spec_version`,
`reason`, `corpus_*`, `self_sha256`) are byte-identical across all four
implementations. Nothing in an envelope can be `TRUSTED` (the closed lattice holds
in JSON too).

```sh
$ python membrane.py verify --json report.md
{"command": "verify", "emet_version": "1.0.0", "exit_code": 1, "results": [{"got": "9fc0ea6515ceadd9...", "path": "report.md", "verdict": "DRIFT", "want": "a948904f2f0f479b..."}], "spec_version": "1.0.0", "verdict": "DRIFT"}
# exit 1
```

## Optional: proof-surface receipt adapter

`adapters/proof_surface_receipt.py` wraps a witness fact as a compact JSON receipt
for proof-index / release-readiness workflows. It lives outside the EMET core, only
accepts governed verdict tokens, and refuses authority-shaped stdout.

```sh
$ cp SPEC.md rendered-view.md
$ python adapters/proof_surface_receipt.py coherence SPEC.md rendered-view.md
{
  "evidence": {
    "exit_code": 0,
    "stdout_verdict_line": "result=COHERENT"
  },
  "notes": "EMET emits witness facts only. The receipt preserves the closed verdict lattice and carries no authority, permission, or release decision.",
  "receipt_id": "emet-coherence-d48705f5ac880281",
  "subject": [ ... ],
  "verdict": "COHERENT",
  "witness": {
    "check": "coherence",
    "implementation": "emet-python-reference",
    "self_sha256": "557bb3c56443fc1afdb58b2707c8df47291c153149889729c12ac0c4ab790769",
    "spec_version": "1.0.0"
  }
}
```

(The `receipt_id` and `self_sha256` values shown are illustrative of the format;
the receipt is keyed to the bytes and the tool's own hash on your machine.)

## A runnable demo

[`examples/demo.sh`](examples/demo.sh) drives the full surface end-to-end on a
sample input (`examples/sample-prompt.txt`) in a scratch directory. See
[examples/README.md](examples/README.md).

```sh
sh examples/demo.sh
```

## What it won't do

EMET reports facts only. It can't say `TRUSTED`, doesn't decide whether a model
is safe, runs outside whatever it audits, and never edits, signs, or blocks
anything. Those constraints are the point - see [SPEC.md](SPEC.md) section 6.
