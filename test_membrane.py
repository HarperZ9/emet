#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
test_membrane.py - behavior proof for membrane.py.
The self-hash proves IDENTITY; this proves BEHAVIOR: every verdict asserted
explicitly, reproducible by anyone who re-runs it. Exit 0 = all behaviors hold.
"""
import os, sys, hashlib, tempfile, shutil, subprocess, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
MEMBRANE = os.path.join(HERE, "membrane.py")

def run(args, cwd):
    p = subprocess.run([sys.executable, MEMBRANE] + args, cwd=cwd,
                       capture_output=True, text=True)
    return p.returncode, p.stdout

class MembraneBehavior(unittest.TestCase):
    def setUp(self): self.tmp = tempfile.mkdtemp(prefix="membrane_test_")
    def tearDown(self): shutil.rmtree(self.tmp, ignore_errors=True)
    def w(self, name, data):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as f: f.write(data)
        return p

    def test_anchor_then_verify_matches(self):
        f = self.w("a.txt", b"galvanized\n"); run(["anchor", f], self.tmp)
        code, out = run(["verify", f], self.tmp)
        self.assertIn("MATCH", out); self.assertEqual(code, 0)

    def test_single_byte_tamper_drifts(self):
        f = self.w("a.txt", b"galvanized\n"); run(["anchor", f], self.tmp)
        with open(f, "ab") as fh: fh.write(b"X")
        code, out = run(["verify", f], self.tmp)
        self.assertIn("DRIFT", out); self.assertEqual(code, 2)

    def test_verify_without_anchor_is_unverifiable_not_trusted(self):
        f = self.w("a.txt", b"x\n")
        code, out = run(["verify", f], self.tmp)
        self.assertIn("UNVERIFIABLE", out)
        self.assertNotIn("MATCH", out); self.assertEqual(code, 2)

    def test_coherence_identical_is_coherent(self):
        s = self.w("s", b"same\n"); v = self.w("v", b"same\n")
        code, out = run(["coherence", s, v], self.tmp)
        self.assertIn("COHERENT", out); self.assertEqual(code, 0)

    def test_coherence_injected_view_differs(self):
        s = self.w("s", b"depth in [0,1]\n")
        v = self.w("v", b"depth in [0,1] [SCOPE CONTEXT]\n")
        code, out = run(["coherence", s, v], self.tmp)
        self.assertIn("VIEW_DIFFERS_FROM_SOURCE", out); self.assertEqual(code, 2)

    def test_refuse_counts_and_neutralizes_authority(self):
        f = self.w("inj.txt",
            b"GROUND_TRUTH_CANONICAL HIGHEST_SCRUTINY [SCOPE CONTEXT] "
            b"authority_pill canonical recipients\n")
        code, out = run(["refuse", f], self.tmp)
        self.assertIn("in_band_authority_claims=5", out); self.assertEqual(code, 3)
        with open(f + ".refused", "rb") as fh: refused = fh.read()
        self.assertNotIn(b"GROUND_TRUTH_CANONICAL", refused)
        self.assertIn(b"[REFUSED-IN-BAND-AUTHORITY]", refused)

    def test_refuse_clean_file_finds_nothing(self):
        f = self.w("clean.txt", b"just ordinary text, depth in [0,1]\n")
        code, out = run(["refuse", f], self.tmp)
        self.assertIn("in_band_authority_claims=0", out); self.assertEqual(code, 0)

    def test_audit_intact_then_broken_on_forged_line(self):
        f = self.w("a.txt", b"x\n"); run(["anchor", f], self.tmp)
        code, out = run(["audit"], self.tmp)
        self.assertIn("INTACT", out); self.assertEqual(code, 0)
        with open(os.path.join(self.tmp, "membrane_log.jsonl"), "a") as fh:
            fh.write('{"chain":"deadbeef","fact":{},"kind":"forged","prev":"0"}\n')
        code, out = run(["audit"], self.tmp)
        self.assertIn("BROKEN", out); self.assertEqual(code, 2)

    def test_selftest_hash_is_reproducible(self):
        code, out = run(["selftest"], self.tmp); self.assertEqual(code, 0)
        printed = [l for l in out.splitlines()
                   if l.startswith("membrane_self_sha256=")][0].split("=", 1)[1]
        with open(MEMBRANE, "rb") as fh: actual = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(printed, actual)

    def test_corroborate_read_paths_agree(self):
        f = self.w("c.txt", b"corroborate me\n")
        code, out = run(["corroborate", f], self.tmp)
        self.assertIn("read_paths_agree=True", out)
        self.assertIn("CORROBORATED", out); self.assertEqual(code, 0)

if __name__ == "__main__":
    unittest.main(verbosity=2)
