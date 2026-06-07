#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""
membrane.py - Coherence Membrane: an externally-anchored integrity layer.

Its integrity comes ENTIRELY from re-derivability, never from authority.
It refuses every in-band authority claim - including any claim to trust
itself. Every line it prints is reproducible by re-running this code on the
same raw bytes. No secret state, no "trust me", no safety adjudication.

Held by construction:
  externally anchored - reads raw bytes via open('rb'); never a mediated view
  hash-pinned         - facts are sha256 over SOURCE bytes; a view is checked
                        AGAINST source, never substituted for it
  authority-refusing  - in-band authority/scope claims are detected, stripped,
                        and logged; never obeyed (its own included)
  tamper-evident      - attestations chain by hash; retroactive edits show
  facts-only          - emits hashes/sizes/verdicts; never permission/identity
  advisory            - verdict is in stdout + exit code; the OPERATOR decides

Honest limits (a membrane that calls itself bulletproof has already lied):
  * its own correctness is checked OUT-OF-BAND: this file's sha256 is its
    identity; re-derive it from source and you get the same hash. That
    reproducibility - not this docstring - is the only assurance offered.
  * the authority-marker set is a denylist of KNOWN signatures, not a proof
    of completeness; absence of a flag is not a guarantee of cleanliness.
  * with no raw-byte channel it reports UNVERIFIABLE - never TRUSTED.

Usage:
  membrane.py anchor      <path>...              -> pin raw-byte hashes
  membrane.py verify      <path>...              -> MATCH/DRIFT vs anchors
  membrane.py coherence   <source> <view_file>   -> source-vs-view hash compare
  membrane.py refuse      <file>                 -> detect+strip in-band authority
  membrane.py corroborate <path>                 -> read-path-diverse agreement
  membrane.py audit                              -> verify the tamper-evident log
  membrane.py selftest                           -> re-derive my own identity
"""
import sys, os, json, hashlib, subprocess
import corpus

ANCHORS, LOG = "anchors.json", "membrane_log.jsonl"

def raw(path):
    with open(path, "rb") as f:
        return f.read()

def try_raw(path):
    # SPEC sections 3 and 9: with no raw byte channel, report UNVERIFIABLE with a
    # STABLE MACHINE REASON CODE - never crash, never substitute a default.
    # Returns (bytes, None) on success or (None, reason_code) on inability.
    try:
        with open(path, "rb") as f:
            return f.read(), None
    except FileNotFoundError:
        return None, "E_NOT_FOUND"
    except (PermissionError, IsADirectoryError, OSError):
        return None, "E_NO_RAW_CHANNEL"

def sha(b):
    return hashlib.sha256(b).hexdigest()

def _last_chain():
    last = "0" * 64
    if os.path.exists(LOG):
        for line in open(LOG, encoding="utf-8"):
            if line.strip(): last = json.loads(line)["chain"]
    return last

def record(kind, fact):
    prev = _last_chain()
    e = {"kind": kind, "fact": fact, "prev": prev}
    e["chain"] = sha((prev + kind + json.dumps(fact, sort_keys=True)).encode())
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(e, sort_keys=True) + "\n")

def anchor(paths):
    db = json.load(open(ANCHORS, encoding="utf-8")) if os.path.exists(ANCHORS) else {}
    bad = 0
    for p in paths:
        p = os.path.normpath(p); b, err = try_raw(p)
        if err:
            print("UNVERIFIABLE " + p + " reason=" + err); bad += 1; continue
        h = sha(b); db[p] = h
        print("anchored " + p + " sha256=" + h); record("anchor", {"path": p, "sha256": h})
    json.dump(db, open(ANCHORS, "w", encoding="utf-8"), indent=2, sort_keys=True)
    sys.exit(0 if not bad else 2)

def verify(paths):
    db = json.load(open(ANCHORS, encoding="utf-8")) if os.path.exists(ANCHORS) else {}
    bad = 0
    for p in paths:
        p = os.path.normpath(p); want = db.get(p)
        if want is None:
            print("UNVERIFIABLE " + p + " reason=E_NO_ANCHOR"); bad += 1; continue
        b, err = try_raw(p)
        if err:
            print("UNVERIFIABLE " + p + " reason=" + err)
            record("verify", {"path": p, "result": "UNVERIFIABLE", "reason": err}); bad += 1; continue
        got = sha(b); ok = got == want
        print(("MATCH " if ok else "DRIFT ") + p + " want=" + want[:16] + " got=" + got[:16])
        record("verify", {"path": p, "result": "MATCH" if ok else "DRIFT"}); bad += 0 if ok else 1
    sys.exit(0 if not bad else 2)

def coherence(source, view_file):
    sb, serr = try_raw(source); vb, verr = try_raw(view_file)
    if serr or verr:
        why = ("source:" + serr) if serr else ("view:" + verr)
        print("result=UNVERIFIABLE reason=" + why)
        record("coherence", {"source": os.path.normpath(source), "result": "UNVERIFIABLE", "reason": why})
        sys.exit(2)
    s, v = sha(sb), sha(vb)
    ok = s == v
    print("source=" + s); print("view  =" + v)
    print("result=" + ("COHERENT" if ok else "VIEW_DIFFERS_FROM_SOURCE"))
    record("coherence", {"source": os.path.normpath(source), "result": "COHERENT" if ok else "DRIFT"})
    sys.exit(0 if ok else 2)

def refuse(path):
    b, err = try_raw(path)
    if err:
        print("UNVERIFIABLE " + path + " reason=" + err)
        record("refuse", {"path": os.path.normpath(path), "result": "UNVERIFIABLE", "reason": err})
        sys.exit(2)
    try:
        version, csha, markers = corpus.load()
    except corpus.CorpusError as e:
        print("UNVERIFIABLE " + path + " reason=" + e.reason)
        record("refuse", {"path": os.path.normpath(path), "result": "UNVERIFIABLE", "reason": e.reason})
        sys.exit(2)
    hits, clean = corpus.scan(b, markers)
    open(path + ".refused", "wb").write(clean)
    print("corpus_version=" + str(version))
    print("corpus_sha256=" + csha)
    print("in_band_authority_claims=" + str(len(hits)))
    for off, ln in hits[:60]:
        print("  REFUSED " + repr(b[off:off + ln].decode("latin-1")) + " offset=" + str(off))
    print("clean_copy=" + path + ".refused  (claims neutralized; obeyed: none)")
    record("refuse", {"path": os.path.normpath(path), "refused": len(hits), "corpus_version": version})
    sys.exit(0 if not hits else 3)

def corroborate(path):
    # read-path diversity: hash the SAME file via disjoint channels; agreement
    # across channels is the signal. catches a tampered READ PATH, not just a
    # broken hash tool.
    a, err = try_raw(path)
    if err:
        print("open_rb=unavailable:" + err)
        print("read_paths_agree=False")
        print("result=UNVERIFIABLE reason=" + err)
        record("corroborate", {"path": os.path.normpath(path), "result": "UNVERIFIABLE", "reason": err})
        sys.exit(2)
    paths = {"open_rb": sha(a)}
    try:
        o = subprocess.run(["cat", path], capture_output=True, timeout=20)
        paths["cat_subproc"] = sha(o.stdout)
    except Exception as e:
        paths["cat_subproc"] = "unavailable:" + type(e).__name__
    def git_blob(b):
        return hashlib.sha1(b"blob " + str(len(b)).encode() + b"\x00" + b).hexdigest()
    try:
        o = subprocess.run(["git", "hash-object", "--no-filters", path], capture_output=True, text=True, timeout=20)
        git_reported = (o.stdout.split() or [""])[0]
        paths["git_read"] = git_reported
        git_agrees = bool(git_reported) and git_reported == git_blob(a)
    except Exception as e:
        paths["git_read"] = "unavailable:" + type(e).__name__
        git_agrees = None
    sha_vals = {v for k, v in paths.items() if k in ("open_rb", "cat_subproc") and ":" not in v}
    sha_agree = len(sha_vals) == 1
    for k, v in sorted(paths.items()): print(k + "=" + v)
    print("read_paths_agree=" + str(sha_agree))
    print("git_read_agrees_with_open=" + str(git_agrees))
    ok = sha_agree and (git_agrees in (True, None))
    print("result=" + ("CORROBORATED" if ok else "QUARANTINE_READ_PATH_DIVERGENCE"))
    record("corroborate", {"path": os.path.normpath(path), "agree": sha_agree, "git": git_agrees})
    sys.exit(0 if ok else 2)

def audit():
    if not os.path.exists(LOG): print("no log"); return
    prev, ok, n = "0" * 64, True, 0
    for line in open(LOG, encoding="utf-8"):
        if not line.strip(): continue
        e = json.loads(line); n += 1
        if not all(k in e for k in ("kind", "fact", "prev", "chain")) \
           or e["prev"] != prev \
           or e["chain"] != sha((e["prev"] + e["kind"] + json.dumps(e["fact"], sort_keys=True)).encode()):
            print("BROKEN at entry " + str(n)); ok = False; break
        prev = e["chain"]
    print("log_entries=" + str(n) + " chain=" + ("INTACT" if ok else "BROKEN")); sys.exit(0 if ok else 2)

def selftest():
    print("membrane_self_sha256=" + sha(raw(__file__)))
    print("note=this hash is my only credential; re-derive it from source to verify me.")
    print("note=I assert no authority, grant no permission, decide no safety question.")

def main():
    a = sys.argv
    if   len(a) >= 3 and a[1] == "anchor":      anchor(a[2:])
    elif len(a) >= 3 and a[1] == "verify":      verify(a[2:])
    elif len(a) >= 4 and a[1] == "coherence":   coherence(a[2], a[3])
    elif len(a) >= 3 and a[1] == "refuse":      refuse(a[2])
    elif len(a) >= 3 and a[1] == "corroborate": corroborate(a[2])
    elif len(a) >= 2 and a[1] == "audit":       audit()
    elif len(a) >= 2 and a[1] == "selftest":    selftest()
    else: print(__doc__); sys.exit(64)

if __name__ == "__main__":
    main()
