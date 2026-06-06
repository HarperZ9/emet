#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
attest.py -- EMET in-toto attestation adapter (OPTIONAL, out-of-core, stdlib-only).

Wraps an EMET verdict as an in-toto v1 Statement with an EMET predicate, so the
verdict is consumable by cosign, slsa-verifier, and Sigstore policy-controller
with zero EMET-specific code on their side.

Emits UNSIGNED JSON: EMET holds no key (SPEC boundaries 5 and 6). The OPERATOR
signs (for example cosign attest) and, if desired, uploads to a transparency log.
EMET attests; the operator actuates. This adapter lives outside the core (SPEC
section 10): the minimal-TCB guarantee covers membrane, organs, and monitor, not
this file.

The predicateType URL uses a placeholder domain (emet.dev). The project that
adopts EMET SHOULD host the predicate definition at a URL it controls.

Usage:
  python attest.py verify <path> <anchors.json>
  python attest.py coherence <source> <view>
  python attest.py corroborate <path>
"""
import os, sys, json, hashlib, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.join(os.path.dirname(HERE), "membrane.py")
SPEC_VERSION = "0.2.0-draft"
PREDICATE_TYPE = "https://emet.dev/attestation/coherence/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VERDICT_TOKENS = ["MATCH", "DRIFT", "UNVERIFIABLE", "COHERENT",
                  "VIEW_DIFFERS_FROM_SOURCE", "CORROBORATED",
                  "QUARANTINE_READ_PATH_DIVERGENCE"]

def sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def tool_version():
    p = subprocess.run([sys.executable, CORE, "selftest"], capture_output=True, text=True)
    for line in p.stdout.splitlines():
        if line.startswith("membrane_self_sha256="):
            return line.split("=", 1)[1]
    return "unknown"

def run_core(args, cwd=None):
    return subprocess.run([sys.executable, CORE] + args, cwd=cwd, capture_output=True, text=True)

def first_verdict(stdout):
    for line in stdout.splitlines():
        for tok in VERDICT_TOKENS:
            if tok in line:
                return tok
    return "UNVERIFIABLE"

def statement(subjects, check, verdict, evidence):
    return {
        "_type": STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "emet_spec_version": SPEC_VERSION,
            "emet_tool_version": tool_version(),
            "check": check,
            "verdict": verdict,
            "evidence": evidence,
            "signed": False,
            "note": "Unsigned EMET attestation. The operator signs and actuates; EMET holds no key and performs no action.",
        },
    }

def emit(st):
    print(json.dumps(st, indent=2, sort_keys=True))

def main():
    a = sys.argv
    if len(a) >= 4 and a[1] == "verify":
        path, anchors = a[2], a[3]
        cwd = os.path.dirname(os.path.abspath(anchors)) or "."
        p = run_core(["verify", os.path.abspath(path)], cwd=cwd)
        subj = [{"name": os.path.basename(path), "digest": {"sha256": sha256(path)}}]
        emit(statement(subj, "verify", first_verdict(p.stdout), {"exit_code": p.returncode}))
        sys.exit(0)
    if len(a) >= 4 and a[1] == "coherence":
        src, view = a[2], a[3]
        p = run_core(["coherence", os.path.abspath(src), os.path.abspath(view)])
        subj = [{"name": os.path.basename(src), "digest": {"sha256": sha256(src)}},
                {"name": os.path.basename(view), "digest": {"sha256": sha256(view)}}]
        emit(statement(subj, "coherence", first_verdict(p.stdout), {"exit_code": p.returncode}))
        sys.exit(0)
    if len(a) >= 3 and a[1] == "corroborate":
        path = a[2]
        p = run_core(["corroborate", os.path.abspath(path)])
        subj = [{"name": os.path.basename(path), "digest": {"sha256": sha256(path)}}]
        emit(statement(subj, "corroborate", first_verdict(p.stdout), {"exit_code": p.returncode}))
        sys.exit(0)
    print(__doc__)
    sys.exit(64)

if __name__ == "__main__":
    main()
