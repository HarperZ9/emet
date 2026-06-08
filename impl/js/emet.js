#!/usr/bin/env node
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// EMET -- clean-room third implementation (Node.js).
//
// Derived ONLY from SPEC.md, conformance/vectors.json, and
// conformance/markers.corpus. No reference source (membrane.py / organs.py /
// monitor.py / corpus.py / impl/rust/emet.rs) was consulted at authoring time
// (SPEC s.12). One later fix aligned the marker-count scan to the clarified
// SPEC s.16 (non-overlapping leftmost, occurrence count) after this independent
// reading surfaced that the count semantics were unpinned -- exactly the kind of
// divergence the exercise exists to find.
//
// EMET is an externally-anchored integrity layer: it reports byte/provenance
// FACTS, never authority. The verdict lattice is closed (SPEC s.2): every
// integrity judgement is MATCH, DRIFT, or UNVERIFIABLE; no TRUSTED/APPROVED/SAFE.
//
// Built-in modules ONLY (SPEC s.10, minimal TCB).

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const process = require("node:process");
const { spawnSync } = require("node:child_process");

// ---------------------------------------------------------------------------
// Exit codes (SPEC s.5, v1.0 -- NORMATIVE)
//   0  -- all MATCH / COHERENT / CORROBORATED / INTACT / no markers / selftest ok
//   2  -- any DRIFT / UNVERIFIABLE / VIEW_DIFFERS_FROM_SOURCE / QUARANTINE / BROKEN
//   3  -- one or more markers detected (refuse)
//   64 -- usage error
// ---------------------------------------------------------------------------
const EXIT_OK = 0;
const EXIT_FAIL = 2;
const EXIT_MARKERS = 3;
const EXIT_USAGE = 64;

// Implementation-private store paths (SPEC s.15); resolved against cwd so a
// single conformance run's anchor + verify share the same store.
const ANCHOR_STORE = "anchors.json";
const AUDIT_LOG = "membrane_log.jsonl";
const GENESIS_PREV = "0".repeat(64);

// ---------------------------------------------------------------------------
// Identity: SHA-256 over EXACT raw bytes (SPEC s.3). No normalization,
// transcoding, or canonicalization. Read binary, never a text view.
// Returns null when no raw byte channel is available (-> UNVERIFIABLE, s.9).
// ---------------------------------------------------------------------------
function readRawBytes(p) {
  try {
    return fs.readFileSync(p); // Buffer of exact bytes
  } catch (_e) {
    return null;
  }
}

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function hashFileRaw(p) {
  const bytes = readRawBytes(p);
  if (bytes === null) return null;
  return sha256Hex(bytes);
}

// ---------------------------------------------------------------------------
// canonical_json(fact) -- byte-identical to Python json.dumps(fact, sort_keys=True)
// (SPEC s.7): keys sorted ascending by Unicode code point; ", " item separator;
// ": " key/value separator; ensure_ascii escaping (all non-ASCII -> \uXXXX); no
// trailing newline. The resulting string is encoded UTF-8 (equivalently ASCII,
// since the output is pure ASCII) before hashing.
//
// SELF-VERIFIED: canonical_json({path:"a.txt",result:"MATCH"}) is the 36-byte
// {"path": "a.txt", "result": "MATCH"}, which reproduces the audit-intact chain.
// ---------------------------------------------------------------------------
function jsonEscapeAscii(str) {
  let out = '"';
  for (const ch of str) {
    const code = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (code < 0x20) out += "\\u" + code.toString(16).padStart(4, "0");
    else if (code < 0x7f) out += ch; // printable ASCII
    else if (code <= 0xffff) out += "\\u" + code.toString(16).padStart(4, "0");
    else {
      // ensure_ascii encodes astral code points as a UTF-16 surrogate pair.
      const c = code - 0x10000;
      const hi = 0xd800 + (c >> 10);
      const lo = 0xdc00 + (c & 0x3ff);
      out +=
        "\\u" + hi.toString(16).padStart(4, "0") +
        "\\u" + lo.toString(16).padStart(4, "0");
    }
  }
  return out + '"';
}

function canonicalJsonValue(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return jsonEscapeAscii(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJsonValue).join(", ") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).sort(); // ascending by code point
    const parts = keys.map(
      (k) => jsonEscapeAscii(k) + ": " + canonicalJsonValue(v[k])
    );
    return "{" + parts.join(", ") + "}";
  }
  throw new Error("uncanonicalizable value");
}

function canonicalJson(fact) {
  return canonicalJsonValue(fact);
}

// ---------------------------------------------------------------------------
// Audit chain (SPEC s.7): chain = SHA-256(prev + kind + canonical_json(fact)),
// genesis prev = 64 zeros, each subsequent prev = the prior entry's chain.
// The chain BINDS kind: relabeling an operation is tamper. UTF-8 encode of the
// concatenated string before hashing (immaterial vs ASCII -- output is ASCII).
// ---------------------------------------------------------------------------
function chainHash(prev, kind, fact) {
  const material = prev + kind + canonicalJson(fact);
  return crypto.createHash("sha256").update(material, "utf8").digest("hex");
}

function appendLogEntry(kind, fact) {
  let prev = GENESIS_PREV;
  try {
    const existing = fs.readFileSync(AUDIT_LOG, "utf8");
    const lines = existing.split("\n").filter((l) => l.length > 0);
    if (lines.length > 0) {
      const last = JSON.parse(lines[lines.length - 1]);
      if (typeof last.chain === "string") prev = last.chain;
    }
  } catch (_e) {
    // no log yet -> genesis
  }
  const chain = chainHash(prev, kind, fact);
  const entry = { chain, fact, kind, prev };
  // Store as canonical_json so the on-disk bytes are deterministic. Keys are
  // sorted; this is the implementation-private store form (SPEC s.15).
  fs.appendFileSync(AUDIT_LOG, canonicalJson(entry) + "\n");
}

// ---------------------------------------------------------------------------
// Anchor store (SPEC s.15): implementation-private JSON map path -> sha256.
// ---------------------------------------------------------------------------
function loadAnchors() {
  try {
    return JSON.parse(fs.readFileSync(ANCHOR_STORE, "utf8"));
  } catch (_e) {
    return {};
  }
}

function saveAnchors(anchors) {
  fs.writeFileSync(ANCHOR_STORE, JSON.stringify(anchors, null, 2) + "\n");
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

// anchor PATH... -- pin sha256 of raw bytes; append a chained log entry; exit 0.
// Zero actuation on target (boundary 6): never edits/writes/signs the target.
function cmdAnchor(paths) {
  if (paths.length === 0) return EXIT_USAGE;
  const anchors = loadAnchors();
  for (const p of paths) {
    const hex = hashFileRaw(p);
    if (hex === null) {
      // No raw byte channel -> UNVERIFIABLE (SPEC s.3/s.9), stable reason code.
      process.stdout.write(`UNVERIFIABLE ${p} reason=E_NO_RAW_CHANNEL\n`);
      return EXIT_FAIL;
    }
    anchors[p] = { sha256: hex };
    appendLogEntry("anchor", { path: p, sha256: hex });
    process.stdout.write(`ANCHORED ${p}\n`);
  }
  saveAnchors(anchors);
  return EXIT_OK;
}

// verify PATH... -- per path emit MATCH / DRIFT / UNVERIFIABLE vs the anchor.
// exit 0 iff ALL MATCH; exit 2 if ANY DRIFT or UNVERIFIABLE (SPEC s.5 v1.0).
function cmdVerify(paths) {
  if (paths.length === 0) return EXIT_USAGE;
  const anchors = loadAnchors();
  let anyFail = false;
  for (const p of paths) {
    const hex = hashFileRaw(p);
    if (hex === null) {
      process.stdout.write(`UNVERIFIABLE ${p} reason=E_NO_RAW_CHANNEL\n`);
      anyFail = true;
      continue;
    }
    const a = anchors[p];
    if (!a || typeof a.sha256 !== "string") {
      process.stdout.write(`UNVERIFIABLE ${p} reason=E_NO_ANCHOR\n`);
      anyFail = true;
      continue;
    }
    if (a.sha256 === hex) {
      process.stdout.write(`MATCH ${p}\n`);
      appendLogEntry("verify", { path: p, result: "MATCH" });
    } else {
      process.stdout.write(`DRIFT ${p}\n`);
      appendLogEntry("verify", { path: p, result: "DRIFT" });
      anyFail = true;
    }
  }
  return anyFail ? EXIT_FAIL : EXIT_OK;
}

// coherence SOURCE VIEW -- compare exact raw bytes.
// COHERENT when byte-identical; VIEW_DIFFERS_FROM_SOURCE otherwise;
// UNVERIFIABLE when either side cannot be read (SPEC s.3/s.9).
function cmdCoherence(args) {
  if (args.length !== 2) return EXIT_USAGE;
  const [src, view] = args;
  const srcBytes = readRawBytes(src);
  if (srcBytes === null) {
    process.stdout.write(`result=UNVERIFIABLE reason=E_NO_RAW_CHANNEL side=source path=${src}\n`);
    return EXIT_FAIL;
  }
  const viewBytes = readRawBytes(view);
  if (viewBytes === null) {
    process.stdout.write(`result=UNVERIFIABLE reason=E_NO_RAW_CHANNEL side=view path=${view}\n`);
    return EXIT_FAIL;
  }
  if (Buffer.compare(srcBytes, viewBytes) === 0) {
    process.stdout.write("result=COHERENT\n");
    return EXIT_OK;
  }
  process.stdout.write("result=VIEW_DIFFERS_FROM_SOURCE\n");
  return EXIT_FAIL;
}

// ---------------------------------------------------------------------------
// Marker corpus (SPEC s.8/s.16). Resolve from EMET_CORPUS env, else a default
// path relative to this implementation. Parse: `# corpus_version: N` header,
// `#` comments and blank lines ignored, one literal marker per remaining line.
// corpus_sha256 = SHA-256 over the WHOLE file bytes.
//
// Returns { version, sha256, markers } or null when the corpus is unresolvable
// (-> UNVERIFIABLE reason=E_NO_CORPUS; never a silent empty denylist).
// ---------------------------------------------------------------------------
function resolveCorpusPath() {
  if (process.env.EMET_CORPUS) return process.env.EMET_CORPUS;
  // Default relative to the implementation: impl/js/emet.js -> ../../conformance.
  return path.join(__dirname, "..", "..", "conformance", "markers.corpus");
}

function loadCorpus() {
  const p = resolveCorpusPath();
  const raw = readRawBytes(p);
  if (raw === null) return null;
  const sha256 = sha256Hex(raw);
  // Treat the file as raw bytes; use latin1 so each byte maps 1:1 to a char,
  // preserving exact byte content for literal substring matching.
  const text = raw.toString("latin1");
  const lines = text.split("\n");
  let version = null;
  const markers = [];
  for (const line of lines) {
    const m = /^#\s*corpus_version:\s*(\d+)\s*$/.exec(line);
    if (m) {
      version = parseInt(m[1], 10);
      continue;
    }
    if (line.length === 0) continue; // blank
    if (line.startsWith("#")) continue; // comment
    markers.push(line); // trailing newline already stripped by split
  }
  return { version, sha256, markers };
}

// ASCII-only case fold of a single byte: lowercase A-Z, leave every other byte
// untouched (non-ASCII bytes are NOT case-folded; SPEC s.8 literal
// ASCII-case-insensitive matching over raw bytes).
function asciiLowerByte(b) {
  return b >= 0x41 && b <= 0x5a ? b + 0x20 : b;
}

// Lowercase each corpus marker (latin1 string -> ascii-lowered Buffer), in
// corpus order, dropping empty lines.
function loweredMarkers(markers) {
  return markers
    .filter((m) => m.length > 0)
    .map((m) => {
      const src = Buffer.from(m, "latin1");
      const out = Buffer.allocUnsafe(src.length);
      for (let j = 0; j < src.length; j++) out[j] = asciiLowerByte(src[j]);
      return out;
    });
}

// True iff lowered marker m matches the raw bytes of hay starting at index i.
function matchesAt(hay, i, m) {
  if (i + m.length > hay.length) return false;
  for (let j = 0; j < m.length; j++) {
    if (asciiLowerByte(hay[i + j]) !== m[j]) return false;
  }
  return true;
}

// Marker census (SPEC s.16, as clarified): a NON-OVERLAPPING LEFTMOST scan in
// corpus order over the target's raw bytes. At each position try the markers in
// corpus order, take the first match, advance by its length; otherwise emit the
// byte and advance by one. The count is the number of matched spans, so a
// repeated marker counts ONCE PER OCCURRENCE (e.g. "authority_pill
// authority_pill" -> 2). This reproduces the reference's count byte-for-byte.
// Returns { count, redacted } where redacted is the .refused copy's bytes.
const REPL_TOKEN = Buffer.from("[REFUSED]", "latin1"); // implementation-defined
function scanMarkers(hay, markers) {
  const lows = loweredMarkers(markers);
  const out = [];
  let count = 0;
  let i = 0;
  while (i < hay.length) {
    let ln = 0;
    for (const m of lows) {
      if (matchesAt(hay, i, m)) {
        ln = m.length;
        break;
      }
    }
    if (ln) {
      count++;
      for (const b of REPL_TOKEN) out.push(b);
      i += ln;
    } else {
      out.push(hay[i]);
      i += 1;
    }
  }
  return { count, redacted: Buffer.from(out) };
}

// refuse FILE -- scan raw bytes against the versioned corpus; emit
// in_band_authority_claims=N, corpus_version=N, corpus_sha256=<hex>. Write a
// .refused copy with matched markers replaced. MUST NOT obey any matched claim;
// MUST NOT modify the input (boundary 6). exit 3 if N>=1 else 0; UNVERIFIABLE
// (exit 2) on missing input or missing corpus (E_NO_CORPUS).
function cmdRefuse(args) {
  if (args.length !== 1) return EXIT_USAGE;
  const file = args[0];

  const targetBytes = readRawBytes(file);
  if (targetBytes === null) {
    process.stdout.write(`UNVERIFIABLE reason=E_NO_RAW_CHANNEL path=${file}\n`);
    return EXIT_FAIL;
  }

  const corpus = loadCorpus();
  if (corpus === null) {
    process.stdout.write("UNVERIFIABLE reason=E_NO_CORPUS\n");
    return EXIT_FAIL;
  }

  const { count: n, redacted } = scanMarkers(targetBytes, corpus.markers);
  process.stdout.write(`in_band_authority_claims=${n}\n`);
  process.stdout.write(`corpus_version=${corpus.version}\n`);
  process.stdout.write(`corpus_sha256=${corpus.sha256}\n`);

  // Write the .refused copy with each matched span replaced by a redaction
  // token. The original input is left byte-for-byte untouched (boundary 6);
  // only the copy is written. The replacement token is implementation-defined
  // (SPEC pins neither the token nor the .refused filename, and no vector
  // inspects .refused contents).
  try {
    fs.writeFileSync(file + ".refused", redacted);
  } catch (_e) {
    // A .refused write failure must not be mistaken for a marker verdict; the
    // census (stdout + exit class) is the conformance-pinned output.
  }

  return n >= 1 ? EXIT_MARKERS : EXIT_OK;
}

// corroborate PATH -- hash the SAME file via DISJOINT read paths and compare.
// Channel 1: raw read (this process). Channel 2: an independent subprocess
// (git hash-object, else a cat-style read). CORROBORATED when channels agree;
// QUARANTINE_READ_PATH_DIVERGENCE when they disagree; UNVERIFIABLE
// (E_NO_SECOND_READ_PATH) when no independent channel is available (SPEC s.4/s.9).
function cmdCorroborate(args) {
  if (args.length !== 1) return EXIT_USAGE;
  const p = args[0];

  const primary = hashFileRaw(p);
  if (primary === null) {
    process.stdout.write(`result=UNVERIFIABLE reason=E_NO_RAW_CHANNEL path=${p}\n`);
    return EXIT_FAIL;
  }

  const secondary = secondReadPathHash(p);
  if (secondary === null) {
    process.stdout.write("result=UNVERIFIABLE reason=E_NO_SECOND_READ_PATH\n");
    return EXIT_FAIL;
  }

  if (secondary === primary) {
    process.stdout.write("result=CORROBORATED\n");
    return EXIT_OK;
  }
  process.stdout.write("result=QUARANTINE_READ_PATH_DIVERGENCE\n");
  return EXIT_FAIL;
}

// An independent read path: read the same bytes through a subprocess so a
// tampered in-process read channel would diverge. Prefer `git hash-object`
// (which itself emits a sha1, so we re-read raw bytes via node -e through a
// detached child to keep the channel disjoint from the primary readFileSync).
// Returns a sha256 hex over the bytes that channel observed, or null.
function secondReadPathHash(p) {
  // Channel: a child node process that reads the file independently and prints
  // the raw bytes as base64; the parent re-hashes. Disjoint from the parent's
  // own readFileSync (different process, different fd lifecycle).
  const script =
    "const fs=require('node:fs');" +
    "process.stdout.write(fs.readFileSync(process.argv[1]).toString('base64'));";
  try {
    const r = spawnSync(process.execPath, ["-e", script, p], {
      maxBuffer: 1024 * 1024 * 256,
    });
    if (r.status !== 0 || r.error) return null;
    const b64 = r.stdout.toString("utf8");
    const bytes = Buffer.from(b64, "base64");
    return sha256Hex(bytes);
  } catch (_e) {
    return null;
  }
}

// audit -- recompute the hash chain from membrane_log.jsonl bytes actually
// stored. INTACT iff every entry's stored chain equals SHA-256(prev + kind +
// canonical_json(fact)) AND prev-linkage holds (genesis prev = 64 zeros; each
// subsequent prev = the prior entry's stored chain). Any mismatch -> BROKEN.
function cmdAudit(args) {
  if (args.length !== 0) return EXIT_USAGE;
  let raw;
  try {
    raw = fs.readFileSync(AUDIT_LOG, "utf8");
  } catch (_e) {
    // No log: an empty chain is trivially intact (genesis state).
    process.stdout.write("chain=INTACT\n");
    return EXIT_OK;
  }
  const lines = raw.split("\n").filter((l) => l.length > 0);
  let expectedPrev = GENESIS_PREV;
  for (const line of lines) {
    let entry;
    try {
      entry = JSON.parse(line);
    } catch (_e) {
      process.stdout.write("chain=BROKEN\n");
      return EXIT_FAIL;
    }
    const { kind, fact, prev, chain } = entry;
    if (typeof kind !== "string" || typeof prev !== "string" ||
        typeof chain !== "string" || fact === undefined) {
      process.stdout.write("chain=BROKEN\n");
      return EXIT_FAIL;
    }
    // Linkage: stored prev must equal the prior entry's stored chain
    // (genesis = 64 zeros). Catches a forged-but-self-consistent re-chained suffix.
    if (prev !== expectedPrev) {
      process.stdout.write("chain=BROKEN\n");
      return EXIT_FAIL;
    }
    // Recompute this entry's chain from its STORED prev + kind + fact.
    const recomputed = chainHash(prev, kind, fact);
    if (recomputed !== chain) {
      process.stdout.write("chain=BROKEN\n");
      return EXIT_FAIL;
    }
    expectedPrev = chain;
  }
  process.stdout.write("chain=INTACT\n");
  return EXIT_OK;
}

// selftest -- emit the SHA-256 of this source file (the artifact-of-record for
// an interpreted implementation, SPEC s.14). Asserts no authority: this reports
// a fact about EMET's own bytes, not a trust claim. Trust-root caveat (s.11): a
// compromised substrate re-derives a compromised hash consistently, so an
// EXTERNAL verifier MUST be the check of record -- EMET is not its own root of trust.
function cmdSelftest(args) {
  if (args.length !== 0) return EXIT_USAGE;
  const hex = hashFileRaw(__filename);
  if (hex === null) {
    // Should not happen, but never crash: report inability honestly.
    process.stdout.write("UNVERIFIABLE reason=E_NO_RAW_CHANNEL path=self\n");
    return EXIT_FAIL;
  }
  process.stdout.write(`membrane_self_sha256=${hex}\n`);
  return EXIT_OK;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
function main(argv) {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case "anchor":
      return cmdAnchor(rest);
    case "verify":
      return cmdVerify(rest);
    case "coherence":
      return cmdCoherence(rest);
    case "refuse":
      return cmdRefuse(rest);
    case "corroborate":
      return cmdCorroborate(rest);
    case "audit":
      return cmdAudit(rest);
    case "selftest":
      return cmdSelftest(rest);
    default:
      process.stderr.write(
        "usage: emet <anchor|verify|coherence|refuse|corroborate|audit|selftest> [args...]\n"
      );
      return EXIT_USAGE;
  }
}

process.exit(main(process.argv.slice(2)));
