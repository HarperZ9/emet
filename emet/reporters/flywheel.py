#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Flywheel evaluation reporter.

This optional reporter turns a bounded Flywheel JSON report into two caller-
persisted byte artifacts and an EMET witness receipt over those bytes. EMET
witnesses artifact integrity only; it does not verify Flywheel scores, statuses,
incident conclusions, or semantic truth.
"""
import hashlib
import json
import math

from emet import report, witness_receipt

RAW_REPORT_FILENAME = "flywheel-evaluation.json"
RECORD_FILENAME = "flywheel-record.json"
RECORD_SCHEMA = "emet-flywheel-evaluation-record/v1"
MAX_BYTES = 16 * 1024 * 1024
MAX_DEPTH = 32
_KNOWN_SCHEMAS = {"flywheel.inspect-evidence/v1", "flywheel.incident-sim-command/v1"}
_INSPECT_STATUSES = {"started", "success", "cancelled", "error"}
_INSPECT_ASSESSMENTS = {"reported", "incomplete", "error"}
_INSPECT_SEMANTIC = {"UNVERIFIABLE"}
_INCIDENT_VERDICTS = {"MATCH", "DRIFT", "UNVERIFIABLE"}


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("E_DUPLICATE_KEY")
        out[key] = value
    return out


def _nonfinite(token):
    raise ValueError("E_NONFINITE_NUMBER")


def _finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("E_NONFINITE_NUMBER")
    return value


def _depth(value):
    max_depth = 0
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            max_depth = depth
        if max_depth > MAX_DEPTH:
            return max_depth
        if isinstance(item, dict):
            for child in item.values():
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            for child in item:
                stack.append((child, depth + 1))
    return max_depth


def _load(raw):
    if not isinstance(raw, bytes):
        raise ValueError("E_TYPE")
    if len(raw) > MAX_BYTES:
        raise ValueError("E_TOO_LARGE")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ValueError("E_UTF8") from exc
    try:
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_constant=_nonfinite, parse_float=_finite_float)
    except RecursionError as exc:
        raise ValueError("E_TOO_DEEP") from exc
    except ValueError as exc:
        if str(exc).startswith("E_"):
            raise
        raise ValueError("E_JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("E_TOP_LEVEL")
    if _depth(value) > MAX_DEPTH:
        raise ValueError("E_TOO_DEEP")
    return value


def _text(value):
    return isinstance(value, str) and bool(value)


def _enum(value, allowed):
    if not _text(value):
        raise ValueError("E_SHAPE")
    if value not in allowed:
        raise ValueError("E_ENUM")
    return value


def _string_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _inspect_projection(value):
    if not isinstance(value.get("producer"), dict):
        raise ValueError("E_SHAPE")
    if not isinstance(value.get("source"), dict):
        raise ValueError("E_SHAPE")
    if not isinstance(value.get("source_pointers"), list):
        raise ValueError("E_SHAPE")
    if not _string_list(value.get("does_not_prove")):
        raise ValueError("E_SHAPE")
    if not isinstance(value.get("invalidated"), bool):
        raise ValueError("E_SHAPE")
    reported_status = _enum(value.get("reported_status"), _INSPECT_STATUSES)
    assessment = _enum(value.get("assessment"), _INSPECT_ASSESSMENTS)
    semantic = _enum(value.get("semantic_verification"), _INSPECT_SEMANTIC)
    return {
        "reported_status": reported_status,
        "assessment": assessment,
        "semantic_verification": semantic,
        "invalidated": "true" if value["invalidated"] else "false",
    }


def _incident_projection(value):
    if not isinstance(value.get("sources"), dict):
        raise ValueError("E_SHAPE")
    if not isinstance(value.get("audit_packet"), dict):
        raise ValueError("E_SHAPE")
    if not _string_list(value.get("does_not_prove")):
        raise ValueError("E_SHAPE")
    evaluation = value.get("evaluation")
    if not isinstance(evaluation, dict):
        packet = value.get("audit_packet")
        evaluation = packet.get("evaluation") if isinstance(packet, dict) else None
    overall = evaluation.get("overall") if isinstance(evaluation, dict) else None
    verdict = overall.get("verdict") if isinstance(overall, dict) else None
    verdict = _enum(verdict, _INCIDENT_VERDICTS)
    return {"evaluation_overall_verdict": verdict}


def _projection(value):
    schema = value.get("schema")
    if not isinstance(schema, str):
        raise ValueError("E_SCHEMA")
    if schema not in _KNOWN_SCHEMAS:
        raise ValueError("E_SCHEMA")
    if schema == "flywheel.inspect-evidence/v1":
        return schema, _inspect_projection(value)
    return schema, _incident_projection(value)


def build_eval_record(raw):
    """Build a canonical-safe metadata record for exact raw Flywheel bytes."""
    value = _load(raw)
    producer_schema, producer_claims = _projection(value)
    return {
        "schema": RECORD_SCHEMA,
        "producer_schema": producer_schema,
        "source": {
            "algorithm": "sha256",
            "byte_length": len(raw),
            "sha256": _sha256(raw),
        },
        "producer_claims": producer_claims,
        "artifact_names": {
            "raw": RAW_REPORT_FILENAME,
            "record": RECORD_FILENAME,
        },
        "semantic_conclusions_verified_by_emet": "UNVERIFIED",
        "does_not_prove": [
            "Flywheel scorer correctness",
            "model quality or safety",
            "independent ground truth",
            "that reported actions actually executed",
        ],
    }


def mint_receipt(raw, now=None):
    """Return an EMET receipt and caller-persisted artifact bytes."""
    record = build_eval_record(raw)
    record_bytes = report.canonical(record).encode("utf-8")
    artifacts = {
        RAW_REPORT_FILENAME: raw,
        RECORD_FILENAME: record_bytes,
    }
    env = {
        "command": "anchor",
        "results": [
            {"path": RAW_REPORT_FILENAME, "sha256": _sha256(raw)},
            {"path": RECORD_FILENAME, "sha256": _sha256(record_bytes)},
        ],
    }
    receipt = witness_receipt.emit_receipt(env, now=now)
    return receipt, artifacts
