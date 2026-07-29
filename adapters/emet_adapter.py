#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
emet_adapter.py -- EMET offensive-platform registry adapter.

Wire EMET membrane verdicts into the Aleph/Sofer orchestration system.
Emits typed witness facts: no authority, no enforcement, no signed claims.
Integrates with the private-line gate opsec/platform.toml (component: emet-internal).

Capabilities:
- verify: compare artifact against anchored digest
- coherence: compare source vs rendered view
- corroborate: cross-check read paths
- audit: validate hash-chained event logs
- check: validate witness receipts (SPEC s.17)
- rebind: match content against portable manifests (SPEC s.18, experimental)

All verdicts emit as JSON with stable schema; reason codes (SPEC s.9) for
unverifiable cases. Zero actuation: verdicts are advisory only.

Usage (Python):
  from adapters.emet_adapter import EmetAdapter
  adapter = EmetAdapter()
  verdict = adapter.verify("path/to/artifact", "path/to/anchors.json")
  print(verdict.to_json())

Usage (CLI):
  python -m adapters.emet_adapter verify <path> <anchors.json>
  python -m adapters.emet_adapter coherence <source> <view>
  python -m adapters.emet_adapter audit [--recompute]
"""

import os
import sys
import json
import hashlib
import subprocess
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from pathlib import Path

# Locate the core membrane module
HERE = Path(__file__).parent
CORE = HERE.parent / "membrane.py"
SPEC_VERSION = "1.0.0"

# Verdicts must never express authority (SPEC boundaries 1, 2)
VERDICT_TOKENS = {
    "MATCH": "artifact digest matches recorded anchor",
    "DRIFT": "artifact digest differs from recorded anchor",
    "UNVERIFIABLE": "unable to read or verify artifact",
    "COHERENT": "source and rendered view bytes match identically",
    "VIEW_DIFFERS_FROM_SOURCE": "rendered view differs from source artifact",
    "CORROBORATED": "artifact reads identically from multiple paths",
    "INTACT": "hash-chained log re-derives without tampering",
    "BROKEN": "log chain or event structure is tampered",
    "RECEIPT_VALID": "receipt re-derives its content address offline",
    "RECEIPT_TAMPERED": "receipt id or signature does not verify",
    "RECEIPT_UNVERIFIABLE": "receipt is malformed or unreadable",
}

FORBIDDEN_TOKENS = {
    "TRUSTED", "APPROVED", "SAFE", "ALLOWED", "PERMITTED",
    "AUTHORIZED", "CERTIFIED", "COMPLIANT", "PASSED", "FAILED",
    "SECURE", "INSECURE", "VALIDATED", "INVALID",
}


@dataclass
class EmetVerdict:
    """Typed witness fact: immutable, schema-governed verdict record."""
    spec_version: str
    witness: str  # Implementation identifier (e.g., "emet-python-v1.0.0")
    command: str  # verify | coherence | corroborate | audit | check | rebind
    verdict: str  # One of VERDICT_TOKENS
    reason: Optional[str] = None  # Machine reason code for UNVERIFIABLE / BROKEN
    subject_paths: Optional[List[str]] = None
    subject_digests: Optional[Dict[str, str]] = None
    exit_code: int = 0
    notes: Optional[str] = None

    def to_json(self) -> str:
        """Emit canonical JSON: sorted keys, compact format (SPEC s.13)."""
        return json.dumps(
            asdict(self),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Return as dictionary for programmatic use."""
        return {k: v for k, v in asdict(self).items() if v is not None}


class EmetAdapter:
    """
    Orchestration-friendly adapter for EMET verdicts.
    Wraps the reference implementation with schema-governed output.
    """

    def __init__(self, membrane_path: Optional[Path] = None):
        """Initialize with path to membrane.py reference implementation."""
        self.membrane_path = membrane_path or CORE
        if not self.membrane_path.exists():
            raise FileNotFoundError(f"Membrane not found: {self.membrane_path}")
        self.witness_id = f"emet-python-adapter-{SPEC_VERSION}"

    def _run_membrane(self, args: List[str], **kwargs) -> subprocess.CompletedProcess:
        """Execute membrane.py with typed arguments."""
        cmd = [sys.executable, str(self.membrane_path)] + args
        return subprocess.run(cmd, capture_output=True, text=True, **kwargs)

    def verify(
        self, artifact_path: str, anchors_path: str, json_output: bool = True
    ) -> EmetVerdict:
        """
        Verify an artifact against recorded anchors.

        Args:
            artifact_path: Path to the artifact being verified
            anchors_path: Path to anchors.json (SPEC s.2)
            json_output: Request JSON output from membrane (--json flag)

        Returns:
            EmetVerdict with verdict, reason, and exit code
        """
        args = ["verify"]
        if json_output:
            args.append("--json")
        args.extend([artifact_path, anchors_path])

        result = self._run_membrane(args)

        # Parse JSON output if requested
        output = result.stdout.strip()
        verdict_dict = {}
        if json_output and output:
            try:
                output_json = json.loads(output)
                verdict_dict = output_json
            except json.JSONDecodeError:
                # Fallback: parse plain text output
                verdict_dict = self._parse_text_output(output, "verify", result.returncode)
        else:
            verdict_dict = self._parse_text_output(output, "verify", result.returncode)

        return EmetVerdict(
            spec_version=SPEC_VERSION,
            witness=self.witness_id,
            command="verify",
            verdict=verdict_dict.get("verdict", "UNVERIFIABLE"),
            reason=verdict_dict.get("reason"),
            subject_paths=[artifact_path],
            exit_code=result.returncode,
        )

    def coherence(
        self, source_path: str, view_path: str, json_output: bool = True
    ) -> EmetVerdict:
        """
        Compare source artifact vs rendered view (SPEC s.3.2).

        Detects laundered views: a dashboard, summary, or self-report that
        differs from the source artifact it claims to represent.
        """
        args = ["coherence"]
        if json_output:
            args.append("--json")
        args.extend([source_path, view_path])

        result = self._run_membrane(args)
        output = result.stdout.strip()
        verdict_dict = {}
        if json_output and output:
            try:
                verdict_dict = json.loads(output)
            except json.JSONDecodeError:
                verdict_dict = self._parse_text_output(output, "coherence", result.returncode)
        else:
            verdict_dict = self._parse_text_output(output, "coherence", result.returncode)

        return EmetVerdict(
            spec_version=SPEC_VERSION,
            witness=self.witness_id,
            command="coherence",
            verdict=verdict_dict.get("verdict", "UNVERIFIABLE"),
            reason=verdict_dict.get("reason"),
            subject_paths=[source_path, view_path],
            exit_code=result.returncode,
        )

    def corroborate(self, artifact_path: str, json_output: bool = True) -> EmetVerdict:
        """
        Cross-check read paths: verify artifact reads identically from
        multiple paths or access methods (SPEC s.3.3).

        Detects read-path divergence: monitor sees one artifact, audited
        system executes another.
        """
        args = ["corroborate"]
        if json_output:
            args.append("--json")
        args.append(artifact_path)

        result = self._run_membrane(args)
        output = result.stdout.strip()
        verdict_dict = {}
        if json_output and output:
            try:
                verdict_dict = json.loads(output)
            except json.JSONDecodeError:
                verdict_dict = self._parse_text_output(output, "corroborate", result.returncode)
        else:
            verdict_dict = self._parse_text_output(output, "corroborate", result.returncode)

        return EmetVerdict(
            spec_version=SPEC_VERSION,
            witness=self.witness_id,
            command="corroborate",
            verdict=verdict_dict.get("verdict", "UNVERIFIABLE"),
            reason=verdict_dict.get("reason"),
            subject_paths=[artifact_path],
            exit_code=result.returncode,
        )

    def audit(self, recompute: bool = False, json_output: bool = True) -> EmetVerdict:
        """
        Validate hash-chained event log (SPEC s.7).

        Checks: log file exists, each line is valid JSON, each event's
        hash-chain re-derives without tampering.
        """
        args = ["audit"]
        if json_output:
            args.append("--json")
        if recompute:
            args.append("--recompute")

        result = self._run_membrane(args)
        output = result.stdout.strip()
        verdict_dict = {}
        if json_output and output:
            try:
                verdict_dict = json.loads(output)
            except json.JSONDecodeError:
                verdict_dict = self._parse_text_output(output, "audit", result.returncode)
        else:
            verdict_dict = self._parse_text_output(output, "audit", result.returncode)

        return EmetVerdict(
            spec_version=SPEC_VERSION,
            witness=self.witness_id,
            command="audit",
            verdict=verdict_dict.get("verdict", "UNVERIFIABLE"),
            reason=verdict_dict.get("reason"),
            exit_code=result.returncode,
        )

    def check(
        self, receipt_path: str, recompute_from_paths: bool = False
    ) -> EmetVerdict:
        """
        Validate witness receipt (SPEC s.17.3).

        Verifies: receipt format, content address matches receipt_id,
        subject digests re-derive from disk if --recompute-from-paths.
        """
        args = ["check", receipt_path]
        if recompute_from_paths:
            args.append("--recompute-from-paths")

        result = self._run_membrane(args)
        output = result.stdout.strip()
        verdict_dict = self._parse_text_output(output, "check", result.returncode)

        return EmetVerdict(
            spec_version=SPEC_VERSION,
            witness=self.witness_id,
            command="check",
            verdict=verdict_dict.get("verdict", "RECEIPT_UNVERIFIABLE"),
            reason=verdict_dict.get("reason"),
            subject_paths=[receipt_path],
            exit_code=result.returncode,
        )

    def rebind(
        self,
        artifact_path: str,
        manifest_path: str,
        claim: Optional[str] = None,
        json_output: bool = True,
    ) -> EmetVerdict:
        """
        Content-addressed rebinding against portable manifests (SPEC s.18, experimental).

        Match artifact bytes against known content anchors. If --claim is given,
        assert that the artifact IS a specific identity; if bytes hash differently,
        report DRIFT (a confirmed substitution).
        """
        args = ["rebind", artifact_path, "--manifest", manifest_path]
        if json_output:
            args.append("--json")
        if claim:
            args.extend(["--claim", claim])

        result = self._run_membrane(args)
        output = result.stdout.strip()
        verdict_dict = {}
        if json_output and output:
            try:
                verdict_dict = json.loads(output)
            except json.JSONDecodeError:
                verdict_dict = self._parse_text_output(output, "rebind", result.returncode)
        else:
            verdict_dict = self._parse_text_output(output, "rebind", result.returncode)

        return EmetVerdict(
            spec_version=SPEC_VERSION,
            witness=self.witness_id,
            command="rebind",
            verdict=verdict_dict.get("verdict", "UNVERIFIABLE"),
            reason=verdict_dict.get("reason"),
            subject_paths=[artifact_path, manifest_path],
            exit_code=result.returncode,
        )

    def _parse_text_output(
        self, output: str, command: str, exit_code: int
    ) -> Dict[str, Any]:
        """
        Fallback text parser for non-JSON output.
        Extracts verdict and reason from human-readable output.
        """
        # Map exit codes and output patterns to verdicts
        for line in output.split("\n"):
            if "MATCH" in line:
                return {"verdict": "MATCH"}
            elif "DRIFT" in line:
                return {"verdict": "DRIFT"}
            elif "UNVERIFIABLE" in line:
                return {"verdict": "UNVERIFIABLE", "reason": self._extract_reason(line)}
            elif "COHERENT" in line:
                return {"verdict": "COHERENT"}
            elif "VIEW_DIFFERS_FROM_SOURCE" in line:
                return {"verdict": "VIEW_DIFFERS_FROM_SOURCE"}
            elif "CORROBORATED" in line:
                return {"verdict": "CORROBORATED"}
            elif "INTACT" in line:
                return {"verdict": "INTACT"}
            elif "BROKEN" in line:
                return {"verdict": "BROKEN"}
            elif "RECEIPT_VALID" in line:
                return {"verdict": "RECEIPT_VALID"}
            elif "RECEIPT_TAMPERED" in line:
                return {"verdict": "RECEIPT_TAMPERED"}
            elif "RECEIPT_UNVERIFIABLE" in line:
                return {"verdict": "RECEIPT_UNVERIFIABLE", "reason": self._extract_reason(line)}

        # Default based on exit code
        if exit_code == 0:
            return {"verdict": "MATCH"}
        elif exit_code == 1:
            return {"verdict": "DRIFT"}
        elif exit_code == 2:
            return {"verdict": "UNVERIFIABLE"}
        else:
            return {"verdict": "UNVERIFIABLE"}

    @staticmethod
    def _extract_reason(line: str) -> Optional[str]:
        """Extract machine reason code from output line (SPEC s.9)."""
        for reason_code in [
            "E_NO_ANCHOR", "E_NOT_FOUND", "E_NO_RAW_CHANNEL",
            "E_MANIFEST_TAMPERED", "E_NO_ANCHOR_MANIFEST",
        ]:
            if reason_code in line:
                return reason_code
        return None


def cli_main():
    """Command-line entry point for orchestration integration."""
    if len(sys.argv) < 2:
        print("Usage: emet_adapter.py <command> [args...]", file=sys.stderr)
        print("Commands: verify, coherence, corroborate, audit, check, rebind", file=sys.stderr)
        sys.exit(1)

    command = sys.argv[1]
    args = sys.argv[2:]

    try:
        adapter = EmetAdapter()

        if command == "verify" and len(args) >= 2:
            verdict = adapter.verify(args[0], args[1])
            print(verdict.to_json())
            sys.exit(verdict.exit_code)

        elif command == "coherence" and len(args) >= 2:
            verdict = adapter.coherence(args[0], args[1])
            print(verdict.to_json())
            sys.exit(verdict.exit_code)

        elif command == "corroborate" and len(args) >= 1:
            verdict = adapter.corroborate(args[0])
            print(verdict.to_json())
            sys.exit(verdict.exit_code)

        elif command == "audit":
            recompute = "--recompute" in args
            verdict = adapter.audit(recompute=recompute)
            print(verdict.to_json())
            sys.exit(verdict.exit_code)

        elif command == "check" and len(args) >= 1:
            recompute = "--recompute-from-paths" in args
            verdict = adapter.check(args[0], recompute_from_paths=recompute)
            print(verdict.to_json())
            sys.exit(verdict.exit_code)

        elif command == "rebind" and len(args) >= 1:
            artifact = args[0]
            manifest = args[args.index("--manifest") + 1] if "--manifest" in args else None
            claim = args[args.index("--claim") + 1] if "--claim" in args else None
            if not manifest:
                print("rebind requires --manifest", file=sys.stderr)
                sys.exit(2)
            verdict = adapter.rebind(artifact, manifest, claim=claim)
            print(verdict.to_json())
            sys.exit(verdict.exit_code)

        else:
            print(f"Unknown command or missing arguments: {command}", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        error_verdict = EmetVerdict(
            spec_version=SPEC_VERSION,
            witness="emet-python-adapter",
            command="error",
            verdict="UNVERIFIABLE",
            reason="E_ADAPTER_ERROR",
            notes=str(e),
            exit_code=2,
        )
        print(error_verdict.to_json(), file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    cli_main()
