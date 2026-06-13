#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
proof_surface_receipt.py - EMET proof-surface receipt adapter.

Optional, out-of-core, stdlib-only adapter. It wraps EMET witness facts as a
small JSON receipt that tools such as repo-proof-index can summarize without
changing EMET's governed stdout or verdict lattice.

Usage:
  python proof_surface_receipt.py verify <path> <anchors.json>
  python proof_surface_receipt.py coherence <source> <view>
  python proof_surface_receipt.py corroborate <path>
"""
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORE = os.path.join(os.path.dirname(HERE), "membrane.py")
SPEC_VERSION = "0.2.0-draft"
VERDICT_TOKENS = [
    "MATCH",
    "DRIFT",
    "UNVERIFIABLE",
    "COHERENT",
    "VIEW_DIFFERS_FROM_SOURCE",
    "CORROBORATED",
    "QUARANTINE_READ_PATH_DIVERGENCE",
]


def sha256(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def run_core(args, cwd=None):
    return subprocess.run(
        [sys.executable, CORE] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def tool_version():
    result = run_core(["selftest"])
    for line in result.stdout.splitlines():
        if line.startswith("membrane_self_sha256="):
            return line.split("=", 1)[1]
    return "unknown"


def verdict_line(stdout):
    for line in stdout.splitlines():
        for token in VERDICT_TOKENS:
            if token in line:
                return token, line
    return "UNVERIFIABLE", ""


def subject(path):
    return {
        "name": os.path.basename(path),
        "digest": {"sha256": sha256(path)},
    }


def receipt_id(check, verdict, subjects):
    payload = json.dumps(
        {"check": check, "verdict": verdict, "subject": subjects},
        sort_keys=True,
    )
    return "emet-" + check + "-" + hashlib.sha256(payload.encode()).hexdigest()[:16]


def receipt(check, subjects, result):
    verdict, line = verdict_line(result.stdout)
    return {
        "receipt_id": receipt_id(check, verdict, subjects),
        "verdict": verdict,
        "witness": {
            "implementation": "emet-python-reference",
            "spec_version": SPEC_VERSION,
            "self_sha256": tool_version(),
            "check": check,
        },
        "subject": subjects,
        "evidence": {
            "exit_code": result.returncode,
            "stdout_verdict_line": line,
        },
        "notes": (
            "EMET emits witness facts only. The receipt preserves the closed "
            "verdict lattice and carries no authority, permission, or release "
            "decision."
        ),
    }


def emit(data):
    print(json.dumps(data, indent=2, sort_keys=True))


def main():
    args = sys.argv
    if len(args) >= 4 and args[1] == "verify":
        path, anchors = args[2], args[3]
        cwd = os.path.dirname(os.path.abspath(anchors)) or "."
        result = run_core(["verify", os.path.abspath(path)], cwd=cwd)
        emit(receipt("verify", [subject(path)], result))
        sys.exit(0)
    if len(args) >= 4 and args[1] == "coherence":
        source, view = args[2], args[3]
        result = run_core(["coherence", os.path.abspath(source), os.path.abspath(view)])
        emit(receipt("coherence", [subject(source), subject(view)], result))
        sys.exit(0)
    if len(args) >= 3 and args[1] == "corroborate":
        path = args[2]
        result = run_core(["corroborate", os.path.abspath(path)])
        emit(receipt("corroborate", [subject(path)], result))
        sys.exit(0)
    print(__doc__)
    sys.exit(64)


if __name__ == "__main__":
    main()
