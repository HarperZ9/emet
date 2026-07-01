import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def test_browser_evidence_docs_keep_emet_as_witness_only():
    text = (ROOT / "docs" / "browser-evidence.md").read_text(encoding="utf-8")

    assert "project-telos.browser-evidence/v1" in text
    assert "emet anchor" in text
    assert "emet verify" in text
    assert "emet audit" in text
    assert "EMET does not control the browser" in text
    assert "MATCH" in text
    assert "DRIFT" in text
    assert "UNVERIFIABLE" in text


def test_browser_evidence_example_is_compact_anchor_receipt():
    data = json.loads((ROOT / "examples" / "browser-evidence-anchor.json").read_text(encoding="utf-8"))

    assert data["schema"] == "emet.browser-evidence-anchor/v1"
    assert data["source_schema"] == "project-telos.browser-evidence/v1"
    assert data["witness"] == "emet"
    assert data["commands"] == ["emet anchor browser-evidence.json", "emet verify browser-evidence.json",
                                "emet audit"]
