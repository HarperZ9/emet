#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Behavior proof for emet/reporters/flywheel.py.

Uses synthetic Flywheel-shaped JSON bytes only. The reporter never imports or
runs Flywheel, never executes a scorer, and never writes files itself. These
checks prove that EMET can bind exact raw Flywheel report bytes and a bounded
metadata projection with a portable witness receipt, while keeping semantic
claims outside EMET's receipt verdict.

Runs under `python -m pytest -q` AND as a plain `python test_reporter_flywheel.py`
because conformance CI runs behavior proofs as plain scripts, with no pytest.
"""
import hashlib
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from emet import report, witness_receipt  # noqa: E402
from emet.reporters import flywheel as fw  # noqa: E402

NOW = "2026-09-13T00:00:00Z"


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _inspect_report():
    return {
        "schema": "flywheel.inspect-evidence/v1",
        "producer": {"format": "inspect-json", "version": 2},
        "reported_status": "success",
        "assessment": "reported",
        "semantic_verification": "UNVERIFIABLE",
        "invalidated": False,
        "counts": {"total_samples": 2, "completed_samples": 2},
        "source": {"sha256": "a" * 64, "byte_length": 123},
        "source_pointers": [
            {"json_pointer": "/private",
             "source_value": "C:/private/operator/log.json"}
        ],
        "does_not_prove": ["semantic truth"],
    }


def _incident_command(verdict="MATCH"):
    return {
        "schema": "flywheel.incident-sim-command/v1",
        "evaluation": {"overall": {"verdict": verdict}},
        "audit_packet": {
            "evaluation": {"overall": {"verdict": verdict}},
            "source_values": [
                {"json_pointer": "/final_state",
                 "source_value": "private-source-value"}
            ],
        },
        "sources": {
            "task": {"sha256": "b" * 64, "byte_length": 100},
            "trace": {"sha256": "c" * 64, "byte_length": 120},
        },
        "does_not_prove": ["semantic truth"],
    }


def _write_artifacts(directory, artifacts):
    for name, data in artifacts.items():
        with open(os.path.join(directory, name), "wb") as handle:
            handle.write(data)


def _assert_error(raw, prefix):
    try:
        fw.build_eval_record(raw)
    except ValueError as exc:
        assert str(exc).startswith(prefix)
    else:
        raise AssertionError(prefix + " expected")


def test_inspect_record_is_bounded_projection_without_raw_source_values():
    raw = _bytes(_inspect_report())

    record = fw.build_eval_record(raw)
    record_bytes = report.canonical(record).encode("utf-8")

    assert record["schema"] == "emet-flywheel-evaluation-record/v1"
    assert record["producer_schema"] == "flywheel.inspect-evidence/v1"
    assert record["source"] == {
        "algorithm": "sha256",
        "byte_length": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    assert record["producer_claims"] == {
        "reported_status": "success",
        "assessment": "reported",
        "semantic_verification": "UNVERIFIABLE",
        "invalidated": "false",
    }
    assert record["semantic_conclusions_verified_by_emet"] == "UNVERIFIED"
    assert b"C:/private" not in record_bytes


def test_mint_receipt_addresses_raw_and_metadata_and_recomputes_valid():
    raw = _bytes(_inspect_report())

    with tempfile.TemporaryDirectory(prefix="emet_fw_") as tmp:
        receipt, artifacts = fw.mint_receipt(raw, now=NOW)
        _write_artifacts(tmp, artifacts)

        assert set(artifacts) == {fw.RAW_REPORT_FILENAME, fw.RECORD_FILENAME}
        assert artifacts[fw.RAW_REPORT_FILENAME] == raw
        assert receipt["verdict_record"] == []
        assert [row["path"] for row in receipt["subject"]] == [
            fw.RAW_REPORT_FILENAME, fw.RECORD_FILENAME]
        verdict, _ = witness_receipt.check_receipt(receipt, base_dir=tmp)
        assert verdict == "RECEIPT_VALID"
        verdict2, _ = witness_receipt.check_receipt(
            receipt, base_dir=tmp, recompute=True)
        assert verdict2 == "RECEIPT_VALID"


def test_changed_raw_artifact_tampers_and_missing_artifact_is_unverifiable():
    raw = _bytes(_inspect_report())

    with tempfile.TemporaryDirectory(prefix="emet_fw_") as tmp:
        receipt, artifacts = fw.mint_receipt(raw, now=NOW)
        _write_artifacts(tmp, artifacts)

        with open(os.path.join(tmp, fw.RAW_REPORT_FILENAME), "ab") as handle:
            handle.write(b"\n")
        verdict, _ = witness_receipt.check_receipt(
            receipt, base_dir=tmp, recompute=True)
        assert verdict == "RECEIPT_TAMPERED"

        _write_artifacts(tmp, artifacts)
        os.unlink(os.path.join(tmp, fw.RECORD_FILENAME))
        verdict2, _ = witness_receipt.check_receipt(
            receipt, base_dir=tmp, recompute=True)
        assert verdict2 == "RECEIPT_UNVERIFIABLE"


def test_wrong_state_drift_can_still_have_intact_integrity_witness():
    raw = _bytes(_incident_command("DRIFT"))

    with tempfile.TemporaryDirectory(prefix="emet_fw_") as tmp:
        receipt, artifacts = fw.mint_receipt(raw, now=NOW)
        _write_artifacts(tmp, artifacts)
        record = json.loads(artifacts[fw.RECORD_FILENAME].decode("utf-8"))

        assert record["producer_claims"] == {
            "evaluation_overall_verdict": "DRIFT"
        }
        assert record["semantic_conclusions_verified_by_emet"] == "UNVERIFIED"
        assert receipt["verdict_record"] == []
        verdict, _ = witness_receipt.check_receipt(
            receipt, base_dir=tmp, recompute=True)
        assert verdict == "RECEIPT_VALID"


def test_malformed_or_oversize_inputs_fail_boundedly():
    cases = [
        ("duplicate-key",
         b'{"schema":"flywheel.inspect-evidence/v1","schema":"x"}'),
        ("nonfinite",
         b'{"schema":"flywheel.inspect-evidence/v1","reported_status":NaN}'),
        ("unknown-schema", b'{"schema":"unknown"}'),
        ("too-deep", b'[' + (b'[' * 40) + (b']' * 40) + b']'),
        ("too-large", b' ' * (16 * 1024 * 1024 + 1)),
    ]
    for name, raw in cases:
        try:
            fw.build_eval_record(raw)
        except ValueError as exc:
            assert str(exc).startswith("E_"), name
        else:
            raise AssertionError(name + " should raise ValueError")


def test_unknown_producer_claims_are_rejected_not_projected():
    for field in ("reported_status", "assessment", "semantic_verification"):
        doc = _inspect_report()
        doc[field] = "private-source-value"
        _assert_error(_bytes(doc), "E_ENUM")

    _assert_error(_bytes(_incident_command("private-source-value")), "E_ENUM")


def test_non_string_schema_values_raise_bounded_schema_error():
    _assert_error(_bytes({"schema": []}), "E_SCHEMA")
    _assert_error(_bytes({"schema": {}}), "E_SCHEMA")


def test_large_exponent_number_is_rejected_before_projection():
    raw = (
        b'{"assessment":"reported","counts":{"bad":1e999},'
        b'"does_not_prove":[],"invalidated":false,'
        b'"producer":{},"reported_status":"success",'
        b'"schema":"flywheel.inspect-evidence/v1",'
        b'"semantic_verification":"UNVERIFIABLE",'
        b'"source":{},"source_pointers":[]}'
    )

    _assert_error(raw, "E_NONFINITE_NUMBER")


def test_receipt_and_metadata_do_not_copy_private_source_values():
    raw = _bytes(_incident_command("MATCH"))

    receipt, artifacts = fw.mint_receipt(raw, now=NOW)
    public_bytes = (
        report.canonical(receipt).encode("utf-8") + artifacts[fw.RECORD_FILENAME]
    )

    assert b"private-source-value" not in public_bytes


def _run_all():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("PASS " + fn.__name__)
    print("OK " + str(len(fns)) + " flywheel-reporter behavior proofs")


if __name__ == "__main__":
    _run_all()
