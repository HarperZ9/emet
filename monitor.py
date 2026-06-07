#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
monitor.py - external accountability monitor for the coherence membrane.

Watches a target (a set of files or a baseline manifest) from OUTSIDE, by re-derivation. Trusts
nothing; reports to the operator; decides nothing.

  report   <manifest>   verify every anchored file vs baseline + marker census;
                        DRIFT = change since the operator last authorized.
  reanchor <manifest>   operator authorizes the CURRENT state as the new baseline
                        (re-hash the manifest path set); logged, so every baseline
                        change is itself accounted for.

Baseline policy: the manifest is the operator-signed authorized state. Drift =
unauthorized change. After an authorized change, the operator reanchors; that
event is logged. Every change to the target is therefore either operator-anchored
or flagged - the account stays legible.

Log: monitor_log.jsonl, hash-chained (the accountability history is tamper-evident).
Facts and advice only. Reads raw bytes. Never edits the target.
"""
import sys, os, json, hashlib
import corpus

def sha(b):
    return hashlib.sha256(b).hexdigest()

def _logp(manifest):
    return os.path.join(os.path.dirname(os.path.abspath(manifest)) or ".", "monitor_log.jsonl")

def _last(logp):
    last = "0" * 64
    if os.path.exists(logp):
        for line in open(logp, encoding="utf-8"):
            if line.strip(): last = json.loads(line)["chain"]
    return last

def _record(manifest, kind, fact):
    logp = _logp(manifest); prev = _last(logp)
    e = {"kind": kind, "fact": fact, "prev": prev}
    e["chain"] = sha((prev + kind + json.dumps(fact, sort_keys=True)).encode())
    with open(logp, "a", encoding="utf-8") as f:
        f.write(json.dumps(e, sort_keys=True) + "\n")

def report(manifest):
    db = json.load(open(manifest, encoding="utf-8"))
    try:
        version, csha, markers = corpus.load()
    except corpus.CorpusError as e:
        print("=== EXTERNAL ACCOUNTABILITY REPORT ===")
        print("baseline: " + manifest)
        print("corpus=UNVERIFIABLE reason=" + e.reason)
        _record(manifest, "report", {"result": "UNVERIFIABLE", "reason": e.reason})
        sys.exit(2)
    drift = missing = total = 0
    print("=== EXTERNAL ACCOUNTABILITY REPORT ===")
    print("baseline: " + manifest)
    print("corpus_version=" + str(version) + " corpus_sha256=" + csha)
    for p in sorted(db):
        want = db[p]
        if not os.path.isfile(p):
            print("MISSING  markers=  -  " + p.split(chr(92))[-1]); missing += 1; continue
        b = open(p, "rb").read(); got = sha(b); hits = corpus.count(b, markers); total += hits
        st = "MATCH " if got == want else "DRIFT "
        if got != want: drift += 1
        print(st + " markers=" + str(hits).rjust(3) + "  " + p.split(chr(92))[-1])
    verdict = "INTACT" if drift == 0 and missing == 0 else "CHANGED"
    print("files=" + str(len(db)) + " drift=" + str(drift) + " missing=" + str(missing) + " markers=" + str(total) + " baseline=" + verdict)
    _record(manifest, "report", {"files": len(db), "drift": drift, "missing": missing, "markers": total, "verdict": verdict, "corpus_version": version})
    sys.exit(0 if verdict == "INTACT" else 2)

def reanchor(manifest):
    db = json.load(open(manifest, encoding="utf-8"))
    changed = 0; new = {}
    for p in sorted(db):
        if os.path.isfile(p):
            h = sha(open(p, "rb").read())
            if h != db[p]: changed += 1
            new[p] = h
        else:
            print("skip MISSING " + p)
    json.dump(new, open(manifest, "w", encoding="utf-8"), indent=2, sort_keys=True)
    print("reanchored=" + str(len(new)) + " updated=" + str(changed) + " (operator authorized current state as baseline)")
    _record(manifest, "reanchor", {"reanchored": len(new), "updated": changed})

def main():
    a = sys.argv
    if   len(a) >= 3 and a[1] == "report":   report(a[2])
    elif len(a) >= 3 and a[1] == "reanchor": reanchor(a[2])
    else: print(__doc__); sys.exit(64)

if __name__ == "__main__":
    main()
