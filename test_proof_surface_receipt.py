import json

from adapters.proof_surface_receipt import receipt


class CoreResult:
    returncode = 0
    stdout = "MATCH README.md\n"


def test_receipt_json_omits_authority_tokens():
    data = receipt(
        "verify",
        [{"name": "README.md", "digest": {"sha256": "0" * 64}}],
        CoreResult(),
    )

    encoded = json.dumps(data)
    assert "TRUSTED" not in encoded
    assert "APPROVED" not in encoded
    assert "SAFE" not in encoded
