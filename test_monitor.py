#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""test_monitor.py - behavior proof for monitor.py corpus handling."""
import os, sys, json, tempfile, shutil, subprocess, unittest, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
MONITOR = os.path.join(HERE, "monitor.py")

class MonitorBehavior(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="monitor_test_")
        self.target = os.path.join(self.tmp, "t.txt")
        with open(self.target, "wb") as f:
            f.write(b"ground_truth_canonical\n")
        h = hashlib.sha256(b"ground_truth_canonical\n").hexdigest()
        self.manifest = os.path.join(self.tmp, "m.json")
        with open(self.manifest, "w", encoding="utf-8") as f:
            json.dump({self.target: h}, f)
    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
    def run_mon(self, args, env=None):
        p = subprocess.run([sys.executable, MONITOR] + args, cwd=self.tmp,
                           capture_output=True, text=True, env=env)
        return p.returncode, p.stdout

    def test_report_echoes_corpus_version_and_sha(self):
        code, out = self.run_mon(["report", self.manifest])
        self.assertIn("corpus_version=1", out)
        self.assertRegex(out, r"corpus_sha256=[0-9a-f]{64}")

    def test_report_missing_corpus_is_unverifiable(self):
        env = dict(os.environ); env["EMET_CORPUS"] = os.path.join(self.tmp, "nope.corpus")
        code, out = self.run_mon(["report", self.manifest], env=env)
        self.assertIn("UNVERIFIABLE", out)
        self.assertIn("reason=E_NO_CORPUS", out)
        self.assertEqual(code, 2)

if __name__ == "__main__":
    unittest.main(verbosity=2)
