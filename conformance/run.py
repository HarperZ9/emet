#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
run.py -- EMET conformance runner (language-agnostic).

Executes conformance/vectors.json against ANY implementation and reports PASS or
FAIL per vector. Exit 0 if and only if every vector passes.

A second, INDEPENDENT implementation passing these vectors is what DEMONSTRATES
re-derivability (SPEC.md section 12). The reference implementation passing them
proves internal consistency only.

Usage: python run.py [path-to-tool] [path-to-vectors.json]
  path-to-tool may be a .py script (run via this interpreter) OR any executable
  binary (run directly) -- so a Rust or Go build is tested the same way as Python.
"""
import os, sys, json, tempfile, shutil, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(HERE), "membrane.py"))
VECT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "vectors.json")
SUBCMDS = ("anchor", "verify", "coherence", "refuse", "corroborate", "audit", "selftest")

def invoke(tool):
    return [sys.executable, tool] if tool.endswith(".py") else [tool]

def main():
    spec = json.load(open(VECT, encoding="utf-8"))
    vectors = spec["vectors"]
    npass = 0
    for v in vectors:
        tmp = tempfile.mkdtemp(prefix="emet_conf_")
        try:
            for name, content in v.get("files", {}).items():
                with open(os.path.join(tmp, name), "w", encoding="utf-8", newline="") as fh:
                    fh.write(content)
            for name in v.get("anchor", []):
                subprocess.run(invoke(TOOL) + ["anchor", os.path.join(tmp, name)], cwd=tmp, capture_output=True)
            for name, extra in v.get("append", {}).items():
                with open(os.path.join(tmp, name), "a", encoding="utf-8", newline="") as fh:
                    fh.write(extra)
            args = [a if a in SUBCMDS else os.path.join(tmp, a) for a in v["run"]]
            p = subprocess.run(invoke(TOOL) + args, cwd=tmp, capture_output=True, text=True)
            ok = (v["expect_substr"] in p.stdout) and (p.returncode == v["expect_exit"])
            print(("PASS " if ok else "FAIL ") + v["id"] + " exit=" + str(p.returncode) + " want=" + str(v["expect_exit"]))
            if not ok:
                print("     stdout: " + p.stdout.strip().replace(chr(10), " / ")[:180])
            if ok:
                npass += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("CONFORMANCE " + str(npass) + "/" + str(len(vectors)) + " vectors pass")
    sys.exit(0 if npass == len(vectors) else 1)

if __name__ == "__main__":
    main()
