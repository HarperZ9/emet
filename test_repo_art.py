# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""The front-page artwork is a pure function of docs/art/emet.art.json.

A picture in a README is never diffed, so it drifts from the text silently.
tools/check_repo_art.py re-renders every drawing, compares the result against
what is committed, runs twelve other gates besides, then emits a receipt. This
asserts on that receipt the way the other root-level test scripts assert on
their own surfaces.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Named rather than counted, so a gate that quietly leaves the registry fails
# here instead of passing as a smaller green run.
GATES = (
    "spec.present",
    "art.matches_spec",
    "art.render_is_deterministic",
    "art.identity_per_repository",
    "art.seed_is_recorded",
    "art.no_local_paths_or_em_dashes",
    "art.spec_words_reach_the_drawing",
    "art.note_survives_the_wrapper",
    "art.return_edge_stays_on_its_row",
    "art.every_illustration_is_shown",
    "art.tagline_stays_inside_its_rule",
    "art.outcome_fits_its_box",
    "art.the_gate_can_fail",
)

DRAWINGS = (
    "docs/art/emet-header.svg",
    "docs/art/receipt-lane.svg",
    "docs/art/witness-lane.svg",
)


def receipt() -> dict:
    out = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "check_repo_art.py"), "--json"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise AssertionError(out.stderr or out.stdout)
    return json.loads(out.stdout)


class RepoArtTests(unittest.TestCase):
    def test_every_gate_passes_and_the_receipt_names_the_gate_it_ran(self) -> None:
        report = receipt()
        self.assertEqual(report["schema"], "emet.repo-art/v1")
        self.assertEqual(report["mode"], "check")
        by_name = {check["name"]: check for check in report["checks"]}
        for name in GATES:
            self.assertIn(name, by_name, name)
            self.assertEqual(by_name[name]["failures"], [], name)
        self.assertTrue(report["passed"])

    def test_both_diagrams_and_the_header_are_accounted_for(self) -> None:
        report = receipt()
        self.assertEqual(report["specs"], ["docs/art/emet.art.json"])
        self.assertEqual([o["file"] for o in report["outputs"]], list(DRAWINGS))
        for output in report["outputs"]:
            self.assertRegex(output["sha256"], re.compile(r"^[a-f0-9]{64}$"))
            self.assertGreater(output["bytes"], 0, output["file"])

    def test_a_gate_that_cannot_fail_is_not_a_gate(self) -> None:
        # Point the outcome-box check at a throwaway spec whose note is far too
        # wide for its box. It must say so, exactly once.
        probe = "\n".join((
            "import sys, json, tempfile, pathlib",
            "sys.path.insert(0, 'tools')",
            "import check_repo_art as gate",
            "d = pathlib.Path(tempfile.mkdtemp())",
            "box = {'label': 'L', 'note': 'ok', 'tone': 'none'}",
            "wide = {'label': 'L', 'note': 'n' * 80, 'tone': 'none'}",
            "spec = {'header': {'name': 'x', 'role': 'x', 'tagline': 'y', 'words': []},",
            "        'flows': [{'outcomes': [wide, box, box]}]}",
            "(d / 'bad.art.json').write_text(json.dumps(spec), encoding='utf-8')",
            "gate.ART = d",
            "print(len(gate.check_outcome_fits_its_box([])))",
        ))
        out = subprocess.run([sys.executable, "-c", probe], cwd=ROOT,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr or out.stdout)
        self.assertEqual(out.stdout.strip(), "1", "the outcome-box gate cannot fail")


if __name__ == "__main__":
    unittest.main()
