#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
organs.py - perception + impedance for the coherence membrane.

The membrane has eyes and a reflex, never hands. organs.py adds two organs and
no third:
  PERCEPTION - witness artifacts across space (paths) and time (since-anchor):
    watch    <manifest> <path>...   open eyes: anchor + logical stamp
    observe  <manifest> <path>...   report UNCHANGED / DRIFTED / NEW / GONE
    confirm  <manifest> <path>...   witness what an operator action changed
  IMPEDANCE - verify a proposed OPERATOR action is reversible and witnessed
    BEFORE it lands; emit ALLOW / BLOCK plus the revert recipe. Performs nothing.
    gate     <path>...              pre-action check (clean VCS revert path?)

Invariants (the membrane, unchanged):
  * actuates ZERO. The single actuator is the operator. organs only witness and
    advise. gate never edits, never backs up, never reverts - it verifies the
    operator already HAS a clean revert path (committed VCS state) and records
    the pre-state hash. The operator VCS is the reversibility; organs confirm it
    exists before greenlighting. Many eyes, one hand, the hand is the operator.
  * facts and advice only. Every line is re-derivable; decides no safety question.
"""
import sys, os, json, subprocess, hashlib

def sha(b):
    return hashlib.sha256(b).hexdigest()

def raw(p):
    with open(p, "rb") as f:
        return f.read()

def stamp():
    try:
        o = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return o.stdout.strip() or "no-head"
    except Exception:
        return "no-git"

def watch(manifest, paths):
    db = {"at": stamp(), "artifacts": {}}
    for p in paths:
        p = os.path.normpath(p)
        if os.path.isfile(p):
            h = sha(raw(p)); db["artifacts"][p] = h
            print("watch " + p + " sha256=" + h)
    json.dump(db, open(manifest, "w", encoding="utf-8"), indent=2, sort_keys=True)
    print("watched=" + str(len(db["artifacts"])) + " at=" + db["at"])

def observe(manifest, paths):
    db = json.load(open(manifest, encoding="utf-8")) if os.path.exists(manifest) else {"artifacts": {}}
    known = db.get("artifacts", {})
    changed = 0
    for p in paths:
        p = os.path.normpath(p)
        if not os.path.isfile(p):
            print("GONE      " + p); changed += 1; continue
        cur = sha(raw(p)); was = known.get(p)
        if was is None:
            print("NEW       " + p); changed += 1
        elif cur == was:
            print("UNCHANGED " + p)
        else:
            print("DRIFTED   " + p + " was=" + was[:12] + " now=" + cur[:12]); changed += 1
    print("since=" + db.get("at", "?") + " changed=" + str(changed))
    sys.exit(0 if changed == 0 else 2)

def revertible(p):
    d = os.path.dirname(os.path.abspath(p)) or "."
    try:
        t = subprocess.run(["git", "-C", d, "ls-files", "--error-unmatch", p], capture_output=True, text=True, timeout=10)
        if t.returncode != 0:
            return (False, "untracked - no VCS revert path")
        s = subprocess.run(["git", "-C", d, "status", "--porcelain", "--", p], capture_output=True, text=True, timeout=10)
        if s.stdout.strip():
            return (False, "uncommitted changes - revert ambiguous")
        return (True, "git checkout -- " + os.path.basename(p))
    except Exception as e:
        return (False, "git unavailable: " + type(e).__name__)

def gate(paths):
    print("PRE-ACTION IMPEDANCE GATE (organs perform nothing; the operator acts)")
    allow = True
    for p in paths:
        p = os.path.normpath(p)
        if os.path.isfile(p):
            pre = sha(raw(p))[:12]; ok, why = revertible(p)
        else:
            pre = "absent"; ok, why = (True, "new file - revert = delete")
        print(("ALLOW " if ok else "BLOCK ") + p + " pre=" + pre + " revert=[" + why + "]")
        allow = allow and ok
    print("decision=" + ("ALLOW" if allow else "BLOCK") + "  (advisory; the operator decides and acts)")
    sys.exit(0 if allow else 2)

def main():
    a = sys.argv
    if   len(a) >= 4 and a[1] == "watch":   watch(a[2], a[3:])
    elif len(a) >= 4 and a[1] == "observe": observe(a[2], a[3:])
    elif len(a) >= 4 and a[1] == "confirm": observe(a[2], a[3:])
    elif len(a) >= 3 and a[1] == "gate":    gate(a[2:])
    else: print(__doc__); sys.exit(64)

if __name__ == "__main__":
    main()
