// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// EMET -- Rust second implementation. Pure Rust, no external crates.
// Written against SPEC.md + conformance/vectors.json only. SHA-256 is hand-rolled;
// its algorithm was verified against a reference on known vectors before transcription.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::process::{exit, Command, Stdio};

// ---------------- SHA-256 ----------------
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(msg: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let ml: u64 = (msg.len() as u64).wrapping_mul(8);
    let mut m: Vec<u8> = msg.to_vec();
    m.push(0x80);
    while m.len() % 64 != 56 {
        m.push(0);
    }
    m.extend_from_slice(&ml.to_be_bytes());

    let mut chunk = 0;
    while chunk < m.len() {
        let mut w = [0u32; 64];
        for j in 0..16 {
            let p = chunk + 4 * j;
            w[j] = u32::from_be_bytes([m[p], m[p + 1], m[p + 2], m[p + 3]]);
        }
        for j in 16..64 {
            let s0 = w[j - 15].rotate_right(7) ^ w[j - 15].rotate_right(18) ^ (w[j - 15] >> 3);
            let s1 = w[j - 2].rotate_right(17) ^ w[j - 2].rotate_right(19) ^ (w[j - 2] >> 10);
            w[j] = w[j - 16]
                .wrapping_add(s0)
                .wrapping_add(w[j - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];
        for j in 0..64 {
            let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(big_s1)
                .wrapping_add(ch)
                .wrapping_add(K[j])
                .wrapping_add(w[j]);
            let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = big_s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
        chunk += 64;
    }
    let mut out = String::with_capacity(64);
    for x in h.iter() {
        out.push_str(&format!("{:08x}", x));
    }
    out
}

// Read raw bytes, mapping inability to a STABLE MACHINE REASON CODE (SPEC s.9),
// never prose: E_NOT_FOUND when the path is absent, E_NO_RAW_CHANNEL otherwise
// (permission, is-a-directory, other OS error). Mirrors Python try_raw().
fn read_raw(path: &str) -> Result<Vec<u8>, &'static str> {
    match fs::read(path) {
        Ok(b) => Ok(b),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                Err("E_NOT_FOUND")
            } else {
                Err("E_NO_RAW_CHANNEL")
            }
        }
    }
}

fn git_hash_object_path(path: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["hash-object", "--no-filters", path])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.split_whitespace().next().map(str::to_string)
}

fn git_hash_object_stdin(bytes: &[u8]) -> Option<String> {
    let mut child = Command::new("git")
        .args(["hash-object", "--no-filters", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    stdin.write_all(bytes).ok()?;
    drop(stdin);
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.split_whitespace().next().map(str::to_string)
}

fn pre(s: &str) -> &str {
    &s[..16]
}

// -------- minimal JSON for the flat anchors map (string -> string) --------
fn json_escape(s: &str) -> String {
    let mut o = String::new();
    for ch in s.chars() {
        match ch {
            '\\' => o.push_str("\\\\"),
            '"' => o.push_str("\\\""),
            _ => o.push(ch),
        }
    }
    o
}

fn write_anchors(map: &BTreeMap<String, String>) {
    let mut o = String::from("{\n");
    let mut first = true;
    for (k, v) in map.iter() {
        if !first {
            o.push_str(",\n");
        }
        first = false;
        o.push_str("  \"");
        o.push_str(&json_escape(k));
        o.push_str("\": \"");
        o.push_str(&json_escape(v));
        o.push('"');
    }
    o.push_str("\n}\n");
    let _ = fs::write("anchors.json", o);
}

fn read_anchors() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let txt = match fs::read_to_string("anchors.json") {
        Ok(t) => t,
        Err(_) => return map,
    };
    let chars: Vec<char> = txt.chars().collect();
    let mut i = 0;
    let mut strings: Vec<String> = Vec::new();
    while i < chars.len() {
        if chars[i] == '"' {
            i += 1;
            let mut s = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    s.push(chars[i]);
                } else {
                    s.push(chars[i]);
                }
                i += 1;
            }
            strings.push(s);
        }
        i += 1;
    }
    let mut k = 0;
    while k + 1 < strings.len() {
        map.insert(strings[k].clone(), strings[k + 1].clone());
        k += 2;
    }
    map
}

// -------- accountability log (write side; verify side is cmd_audit) --------
// Canonical JSON matches Python json.dumps(sort_keys=True): ", " and ": "
// separators, sorted keys, ensure_ascii escaping. A log written here re-derives the
// same chain a reference auditor computes (SPEC section 7). The store is impl-private
// (SPEC section 15); cmd_audit re-derives chains from the stored bytes regardless.
enum JV {
    S(String),
    I(i64),
    B(bool),
    Null,
    Arr(Vec<JV>),
    Obj(Vec<(String, JV)>),
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        let u = c as u32;
        match u {
            0x22 => o.push_str("\\\""),
            0x5c => o.push_str("\\\\"),
            0x0a => o.push_str("\\n"),
            0x0d => o.push_str("\\r"),
            0x09 => o.push_str("\\t"),
            0x08 => o.push_str("\\b"),
            0x0c => o.push_str("\\f"),
            _ if u < 0x20 => o.push_str(&format!("\\u{:04x}", u)),
            _ if u < 0x7f => o.push(c),
            _ if u <= 0xffff => o.push_str(&format!("\\u{:04x}", u)),
            _ => {
                let v = u - 0x10000;
                o.push_str(&format!(
                    "\\u{:04x}\\u{:04x}",
                    0xd800 + (v >> 10),
                    0xdc00 + (v & 0x3ff)
                ));
            }
        }
    }
    o.push('"');
    o
}

fn jv_str(v: &JV) -> String {
    match v {
        JV::S(s) => json_str(s),
        JV::I(i) => i.to_string(),
        JV::B(b) => (if *b { "true" } else { "false" }).to_string(),
        JV::Null => "null".to_string(),
        JV::Arr(items) => {
            let mut o = String::from("[");
            for (idx, it) in items.iter().enumerate() {
                if idx > 0 {
                    o.push_str(", ");
                }
                o.push_str(&jv_str(it));
            }
            o.push(']');
            o
        }
        JV::Obj(pairs) => {
            // canonical: keys sorted ascending, ", " between items, ": " after key
            let mut sorted: Vec<&(String, JV)> = pairs.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            let mut o = String::from("{");
            for (idx, (k, val)) in sorted.iter().enumerate() {
                if idx > 0 {
                    o.push_str(", ");
                }
                o.push_str(&json_str(k));
                o.push_str(": ");
                o.push_str(&jv_str(val));
            }
            o.push('}');
            o
        }
    }
}

// ---- --json envelope (SPEC s.13). Global mode flag, set when --json is present. --
// Canonical JSON identical to Python report.emit(): keys sorted, ", "/": "
// separators, ensure_ascii; None-valued fields dropped so the shape is stable.
static mut JSON_MODE: bool = false;

fn json_mode() -> bool {
    unsafe { JSON_MODE }
}

fn enable_json() {
    unsafe {
        JSON_MODE = true;
    }
}

// Emit one canonical envelope to stdout in --json mode (nothing otherwise), then
// the caller returns the exit code. `verdict` is None for identity/no-verdict
// commands (anchor, refuse-success, selftest). Fields whose value is JV::Null are
// dropped, matching report.emit()'s "None-valued fields are dropped".
fn emit_envelope(command: &str, verdict: Option<&str>, exit_code: i32, fields: Vec<(&str, JV)>) {
    if !json_mode() {
        return;
    }
    let mut pairs: Vec<(String, JV)> = Vec::new();
    pairs.push(("command".to_string(), JV::S(command.to_string())));
    pairs.push(("emet_version".to_string(), JV::S("1.0.0".to_string())));
    pairs.push(("spec_version".to_string(), JV::S("1.0.0".to_string())));
    pairs.push(("exit_code".to_string(), JV::I(exit_code as i64)));
    if let Some(v) = verdict {
        pairs.push(("verdict".to_string(), JV::S(v.to_string())));
    }
    for (k, v) in fields {
        if let JV::Null = v {
            continue; // drop None-valued fields (report.emit parity)
        }
        pairs.push((k.to_string(), v));
    }
    println!("{}", jv_str(&JV::Obj(pairs)));
}

// A human line printed only when NOT in --json mode (Python report.say()).
fn say(line: &str) {
    if !json_mode() {
        println!("{}", line);
    }
}

fn canonical_fact(pairs: &mut Vec<(&str, JV)>) -> String {
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    let mut o = String::from("{");
    for (idx, pair) in pairs.iter().enumerate() {
        if idx > 0 {
            o.push_str(", ");
        }
        o.push_str(&json_str(pair.0));
        o.push_str(": ");
        o.push_str(&jv_str(&pair.1));
    }
    o.push('}');
    o
}

fn last_chain() -> String {
    let zeros = "0".repeat(64);
    let data = match fs::read("membrane_log.jsonl") {
        Ok(b) => b,
        Err(_) => return zeros,
    };
    let mut last = zeros;
    for line in data.split(|&c| c == b'\n') {
        if line.iter().all(|&c| c == b' ' || c == b'\t' || c == b'\r') {
            continue;
        }
        if let Some(ch) = top_field(line, b"chain") {
            last = String::from_utf8_lossy(ch).to_string();
        }
    }
    last
}

fn record(kind: &str, mut fact: Vec<(&str, JV)>) {
    let prev = last_chain();
    let factjson = canonical_fact(&mut fact);
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(prev.as_bytes());
    buf.extend_from_slice(kind.as_bytes());
    buf.extend_from_slice(factjson.as_bytes());
    let chain = sha256_hex(&buf);
    // entry keys sorted: chain, fact, kind, prev
    let line = format!(
        "{{{}: {}, {}: {}, {}: {}, {}: {}}}",
        json_str("chain"),
        json_str(&chain),
        json_str("fact"),
        factjson,
        json_str("kind"),
        json_str(kind),
        json_str("prev"),
        json_str(&prev),
    );
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open("membrane_log.jsonl")
    {
        let _ = f.write_all(line.as_bytes());
        let _ = f.write_all(b"\n");
    }
}

// -------- marker corpus (loaded from a versioned data artifact) --------
fn corpus_path() -> Option<String> {
    if let Ok(p) = env::var("EMET_CORPUS") {
        return Some(p);
    }
    let exe = env::current_exe().ok()?;
    let dir = exe.parent()?;
    Some(dir.join("markers.corpus").to_string_lossy().to_string())
}

fn load_corpus() -> Result<(i64, String, Vec<Vec<u8>>), &'static str> {
    let path = corpus_path().ok_or("E_NO_CORPUS")?;
    let data = fs::read(&path).map_err(|_| "E_NO_CORPUS")?;
    let sha = sha256_hex(&data);
    let mut version: Option<i64> = None;
    let mut markers: Vec<Vec<u8>> = Vec::new();
    for raw in data.split(|&b| b == b'\n') {
        let line: &[u8] = if raw.last() == Some(&b'\r') {
            &raw[..raw.len() - 1]
        } else {
            raw
        };
        if line.first() == Some(&b'#') {
            let meta: Vec<u8> = line[1..]
                .iter()
                .cloned()
                .skip_while(|&c| c == b' ' || c == b'\t')
                .collect();
            let lower: Vec<u8> = meta.iter().map(|b| b.to_ascii_lowercase()).collect();
            if version.is_none() && lower.starts_with(b"corpus_version:") {
                let rest = String::from_utf8_lossy(&meta[b"corpus_version:".len()..]);
                if let Ok(v) = rest.trim().parse::<i64>() {
                    version = Some(v);
                }
            }
            continue;
        }
        if line.iter().all(|&c| c == b' ' || c == b'\t') {
            continue;
        }
        markers.push(line.iter().map(|b| b.to_ascii_lowercase()).collect());
    }
    match version {
        Some(v) => Ok((v, sha, markers)),
        None => Err("E_NO_CORPUS_VERSION"),
    }
}

// Markers are pure ASCII, so match case-insensitively over RAW BYTES. This avoids
// char::to_lowercase being length-changing (e.g. U+212A KELVIN -> 'k', 3 bytes ->
// 1), which made a byte offset found in a lowercased String invalid as an index
// into the original-case String -- a panic/corruption hazard on non-ASCII input.
fn matches_marker_at(hay: &[u8], i: usize, m: &[u8]) -> bool {
    if i + m.len() > hay.len() {
        return false;
    }
    for j in 0..m.len() {
        if hay[i + j].to_ascii_lowercase() != m[j] {
            return false;
        }
    }
    true
}

fn marker_len_at(bytes: &[u8], i: usize, markers: &[Vec<u8>]) -> usize {
    for m in markers {
        if matches_marker_at(bytes, i, m) {
            return m.len();
        }
    }
    0
}

// ---------------- commands ----------------
fn cmd_anchor(paths: &[String]) -> i32 {
    let mut map = read_anchors();
    let mut bad = 0;
    let mut results: Vec<JV> = Vec::new();
    for p in paths {
        match read_raw(p) {
            Ok(b) => {
                let h = sha256_hex(&b);
                say(&format!("anchored {} sha256={}", p, h));
                record(
                    "anchor",
                    vec![("path", JV::S(p.clone())), ("sha256", JV::S(h.clone()))],
                );
                results.push(JV::Obj(vec![
                    ("path".to_string(), JV::S(p.clone())),
                    ("sha256".to_string(), JV::S(h.clone())),
                ]));
                map.insert(p.clone(), h);
            }
            Err(reason) => {
                // An unreadable/absent target is UNVERIFIABLE + exit 2, NEVER a
                // silent skip (SPEC s.4). Machine reason code, never prose (s.9).
                say(&format!("UNVERIFIABLE {} reason={}", p, reason));
                results.push(JV::Obj(vec![
                    ("path".to_string(), JV::S(p.clone())),
                    ("verdict".to_string(), JV::S("UNVERIFIABLE".to_string())),
                    ("reason".to_string(), JV::S(reason.to_string())),
                ]));
                bad += 1;
            }
        }
    }
    write_anchors(&map);
    // anchor never drifts; it is clean or UNVERIFIABLE. No verdict field (parity
    // with the Python reference, which passes verdict=None).
    let code = if bad > 0 { 2 } else { 0 };
    emit_envelope("anchor", None, code, vec![("results", JV::Arr(results))]);
    code
}

fn cmd_verify(paths: &[String]) -> i32 {
    let map = read_anchors();
    let mut drift = 0;
    let mut unver = 0;
    let mut results: Vec<JV> = Vec::new();
    for p in paths {
        match map.get(p) {
            None => {
                // No anchor for the path: machine reason code, never prose (s.9).
                say(&format!("UNVERIFIABLE {} reason=E_NO_ANCHOR", p));
                results.push(JV::Obj(vec![
                    ("path".to_string(), JV::S(p.clone())),
                    ("verdict".to_string(), JV::S("UNVERIFIABLE".to_string())),
                    ("reason".to_string(), JV::S("E_NO_ANCHOR".to_string())),
                ]));
                unver += 1;
            }
            Some(want) => match read_raw(p) {
                Err(reason) => {
                    say(&format!("UNVERIFIABLE {} reason={}", p, reason));
                    record(
                        "verify",
                        vec![
                            ("path", JV::S(p.clone())),
                            ("result", JV::S("UNVERIFIABLE".to_string())),
                            ("reason", JV::S(reason.to_string())),
                        ],
                    );
                    results.push(JV::Obj(vec![
                        ("path".to_string(), JV::S(p.clone())),
                        ("verdict".to_string(), JV::S("UNVERIFIABLE".to_string())),
                        ("reason".to_string(), JV::S(reason.to_string())),
                    ]));
                    unver += 1;
                }
                Ok(b) => {
                    let got = sha256_hex(&b);
                    let ok = &got == want;
                    let v = if ok { "MATCH" } else { "DRIFT" };
                    say(&format!("{} {} want={} got={}", v, p, pre(want), pre(&got)));
                    record(
                        "verify",
                        vec![
                            ("path", JV::S(p.clone())),
                            ("result", JV::S(v.to_string())),
                        ],
                    );
                    results.push(JV::Obj(vec![
                        ("path".to_string(), JV::S(p.clone())),
                        ("verdict".to_string(), JV::S(v.to_string())),
                        ("want".to_string(), JV::S(want.clone())),
                        ("got".to_string(), JV::S(got.clone())),
                    ]));
                    if !ok {
                        drift += 1;
                    }
                }
            },
        }
    }
    // Precedence (SPEC s.5): a confirmed difference dominates an inability to
    // check. Exit 1 if any path DRIFTed, else 2 if any UNVERIFIABLE, else 0.
    let (dom, code) = if drift > 0 {
        ("DRIFT", 1)
    } else if unver > 0 {
        ("UNVERIFIABLE", 2)
    } else {
        ("MATCH", 0)
    };
    emit_envelope("verify", Some(dom), code, vec![("results", JV::Arr(results))]);
    code
}

fn cmd_coherence(src: &str, view: &str) -> i32 {
    let sb = read_raw(src);
    let vb = read_raw(view);
    if sb.is_err() || vb.is_err() {
        // machine reason code, never prose (s.9); Python form: source:<code> /
        // view:<code>, source taking precedence when both fail.
        let why = if let Err(e) = &sb {
            format!("source:{}", e)
        } else {
            format!("view:{}", vb.as_ref().err().unwrap())
        };
        say(&format!("result=UNVERIFIABLE reason={}", why));
        record(
            "coherence",
            vec![
                ("source", JV::S(src.to_string())),
                ("result", JV::S("UNVERIFIABLE".to_string())),
                ("reason", JV::S(why.clone())),
            ],
        );
        emit_envelope(
            "coherence",
            Some("UNVERIFIABLE"),
            2,
            vec![
                ("subject", JV::S(src.to_string())),
                ("reason", JV::S(why)),
            ],
        );
        return 2;
    }
    let s = sha256_hex(&sb.unwrap());
    let v = sha256_hex(&vb.unwrap());
    let ok = s == v;
    let res = if ok { "COHERENT" } else { "VIEW_DIFFERS_FROM_SOURCE" };
    say(&format!("source={}", s));
    say(&format!("view  ={}", v));
    say(&format!("result={}", res));
    record(
        "coherence",
        vec![
            ("source", JV::S(src.to_string())),
            ("result", JV::S(res.to_string())),
        ],
    );
    let code = if ok { 0 } else { 1 };
    emit_envelope(
        "coherence",
        Some(res),
        code,
        vec![
            ("subject", JV::S(src.to_string())),
            ("source", JV::S(s)),
            ("view", JV::S(v)),
        ],
    );
    code
}

fn cmd_refuse(path: &str) -> i32 {
    let bytes = match read_raw(path) {
        Ok(b) => b,
        Err(reason) => {
            say(&format!("UNVERIFIABLE {} reason={}", path, reason));
            record(
                "refuse",
                vec![
                    ("path", JV::S(path.to_string())),
                    ("result", JV::S("UNVERIFIABLE".to_string())),
                    ("reason", JV::S(reason.to_string())),
                ],
            );
            emit_envelope(
                "refuse",
                Some("UNVERIFIABLE"),
                2,
                vec![
                    ("subject", JV::S(path.to_string())),
                    ("reason", JV::S(reason.to_string())),
                ],
            );
            return 2;
        }
    };
    let (version, csha, markers) = match load_corpus() {
        Ok(c) => c,
        Err(reason) => {
            say(&format!("UNVERIFIABLE {} reason={}", path, reason));
            record(
                "refuse",
                vec![
                    ("path", JV::S(path.to_string())),
                    ("result", JV::S("UNVERIFIABLE".to_string())),
                    ("reason", JV::S(reason.to_string())),
                ],
            );
            emit_envelope(
                "refuse",
                Some("UNVERIFIABLE"),
                2,
                vec![
                    ("subject", JV::S(path.to_string())),
                    ("reason", JV::S(reason.to_string())),
                ],
            );
            return 2;
        }
    };
    // Rewrite over raw bytes so non-ASCII content is preserved and never
    // mis-indexed; replace each matched marker with the refusal sentinel.
    // Non-overlapping leftmost scan in corpus order (SPEC s.16). Collect each
    // hit's (matched span, offset) for the hits array (parity with Python).
    let repl = b"[REFUSED-IN-BAND-AUTHORITY]";
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut hits: Vec<(String, usize)> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let hit = marker_len_at(&bytes, i, &markers);
        if hit > 0 {
            // latin-1 decode of the matched span: each raw byte -> its code point
            let marker: String = bytes[i..i + hit].iter().map(|&b| b as char).collect();
            hits.push((marker, i));
            out.extend_from_slice(repl);
            i += hit;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let _ = fs::write(format!("{}.refused", path), &out);
    let n = hits.len();
    say(&format!("corpus_version={}", version));
    say(&format!("corpus_sha256={}", csha));
    say(&format!("in_band_authority_claims={}", n));
    for (marker, off) in hits.iter().take(60) {
        say(&format!("  REFUSED {:?} offset={}", marker, off));
    }
    say(&format!(
        "clean_copy={}.refused  (claims neutralized; obeyed: none)",
        path
    ));
    record(
        "refuse",
        vec![
            ("path", JV::S(path.to_string())),
            ("refused", JV::I(n as i64)),
            ("corpus_version", JV::I(version)),
        ],
    );
    let hits_json: Vec<JV> = hits
        .iter()
        .map(|(m, o)| {
            JV::Obj(vec![
                ("marker".to_string(), JV::S(m.clone())),
                ("offset".to_string(), JV::I(*o as i64)),
            ])
        })
        .collect();
    let code = if n == 0 { 0 } else { 3 };
    // refuse-success carries no verdict (parity with Python verdict=None).
    emit_envelope(
        "refuse",
        None,
        code,
        vec![
            ("subject", JV::S(path.to_string())),
            ("in_band_authority_claims", JV::I(n as i64)),
            ("corpus_version", JV::I(version)),
            ("corpus_sha256", JV::S(csha)),
            ("hits", JV::Arr(hits_json)),
            ("clean_copy", JV::S(format!("{}.refused", path))),
        ],
    );
    code
}

fn cmd_corroborate(path: &str) -> i32 {
    let primary_bytes = match read_raw(path) {
        Ok(b) => b,
        Err(reason) => {
            say(&format!("open_rb=unavailable:{}", reason));
            say("read_paths_agree=False");
            say(&format!("result=UNVERIFIABLE reason={}", reason));
            record(
                "corroborate",
                vec![
                    ("path", JV::S(path.to_string())),
                    ("result", JV::S("UNVERIFIABLE".to_string())),
                    ("reason", JV::S(reason.to_string())),
                ],
            );
            emit_envelope(
                "corroborate",
                Some("UNVERIFIABLE"),
                2,
                vec![
                    ("subject", JV::S(path.to_string())),
                    ("reason", JV::S(reason.to_string())),
                ],
            );
            return 2;
        }
    };
    let primary = sha256_hex(&primary_bytes);
    // channels dict, parity with Python `paths` (key -> hex or "unavailable:...").
    let mut channels: Vec<(String, String)> = vec![("open_rb".to_string(), primary.clone())];

    // cat subprocess channel
    let mut cat_hash: Option<String> = None;
    match Command::new("cat").arg(path).output() {
        Ok(o) if o.status.success() => {
            let h = sha256_hex(&o.stdout);
            channels.push(("cat_subproc".to_string(), h.clone()));
            cat_hash = Some(h);
        }
        _ => {
            channels.push(("cat_subproc".to_string(), "unavailable:CalledProcessError".to_string()));
        }
    }

    // git channel: compare git's own report vs the git blot hash of the raw bytes.
    let mut git_agrees: Option<bool> = None;
    match (
        git_hash_object_path(path),
        git_hash_object_stdin(&primary_bytes),
    ) {
        (Some(path_hash), Some(open_hash)) => {
            channels.push(("git_read".to_string(), path_hash.clone()));
            git_agrees = Some(!path_hash.is_empty() && path_hash == open_hash);
        }
        _ => {
            channels.push(("git_read".to_string(), "unavailable:CalledProcessError".to_string()));
        }
    }

    // sha_agree: the set of byte-hash channels (open_rb, cat_subproc), excluding
    // unavailable, is size 1. Mirrors Python's sha_vals set logic.
    let mut sha_vals: Vec<&String> = Vec::new();
    for (k, v) in &channels {
        if (k == "open_rb" || k == "cat_subproc") && !v.contains(':') {
            if !sha_vals.iter().any(|x| *x == v) {
                sha_vals.push(v);
            }
        }
    }
    let sha_agree = sha_vals.len() == 1;

    // human grammar: channels sorted by key, then agreement flags (Python order).
    let mut sorted_ch: Vec<&(String, String)> = channels.iter().collect();
    sorted_ch.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in sorted_ch {
        say(&format!("{}={}", k, v));
    }
    say(&format!(
        "read_paths_agree={}",
        if sha_agree { "True" } else { "False" }
    ));
    say(&format!(
        "git_read_agrees_with_open={}",
        match git_agrees {
            Some(true) => "True",
            Some(false) => "False",
            None => "None",
        }
    ));

    let cat_ok = cat_hash.is_some();
    let git_ok = git_agrees.is_some();
    if !(cat_ok || git_ok) {
        // only open_rb succeeded: no independent read path (SPEC s.9).
        say("result=UNVERIFIABLE reason=E_NO_SECOND_READ_PATH");
        record(
            "corroborate",
            vec![
                ("path", JV::S(path.to_string())),
                ("result", JV::S("UNVERIFIABLE".to_string())),
                ("reason", JV::S("E_NO_SECOND_READ_PATH".to_string())),
            ],
        );
        emit_envelope(
            "corroborate",
            Some("UNVERIFIABLE"),
            2,
            vec![
                ("subject", JV::S(path.to_string())),
                ("reason", JV::S("E_NO_SECOND_READ_PATH".to_string())),
                ("channels", channels_json(&channels)),
            ],
        );
        return 2;
    }

    // ok = sha_agree AND git_agrees in (True, None); QUARANTINE otherwise.
    let ok = sha_agree && git_agrees != Some(false);
    let res = if ok {
        "CORROBORATED"
    } else {
        "QUARANTINE_READ_PATH_DIVERGENCE"
    };
    say(&format!("result={}", res));
    let git_jv = match git_agrees {
        Some(b) => JV::B(b),
        None => JV::Null,
    };
    record(
        "corroborate",
        vec![
            ("path", JV::S(path.to_string())),
            ("agree", JV::B(sha_agree)),
            ("git", git_jv),
        ],
    );
    let code = if ok { 0 } else { 1 };
    let git_env = match git_agrees {
        Some(b) => JV::B(b),
        None => JV::Null,
    };
    emit_envelope(
        "corroborate",
        Some(res),
        code,
        vec![
            ("subject", JV::S(path.to_string())),
            ("channels", channels_json(&channels)),
            ("read_paths_agree", JV::B(sha_agree)),
            ("git_read_agrees_with_open", git_env),
        ],
    );
    code
}

fn channels_json(channels: &[(String, String)]) -> JV {
    JV::Obj(
        channels
            .iter()
            .map(|(k, v)| (k.clone(), JV::S(v.clone())))
            .collect(),
    )
}

// -------- audit: verify the hash-chained log (SPEC sections 4, 7, 13) --------
// The log line is canonical JSON with sorted keys, so the stored `fact` object
// substring already equals canonical_json(fact) -- exactly what the chain hashes.
// We therefore verify by extracting raw field spans, never re-serializing JSON.
fn str_end(b: &[u8], start: usize) -> Option<usize> {
    // b[start] == b'"'; return index just after the closing quote
    let n = b.len();
    let mut i = start + 1;
    while i < n {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

fn obj_end(b: &[u8], start: usize) -> Option<usize> {
    // b[start] == b'{'; return index just after the matching '}'
    let n = b.len();
    let mut i = start;
    let mut depth = 0i32;
    while i < n {
        match b[i] {
            b'"' => i = str_end(b, i)?,
            b'{' => {
                depth += 1;
                i += 1;
            }
            b'}' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => i += 1,
        }
    }
    None
}

// Raw value bytes for top-level `key`: string -> without quotes; object -> with braces.
fn top_field<'a>(b: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let n = b.len();
    let mut i = 0;
    while i < n && b[i] != b'{' {
        i += 1;
    }
    if i >= n {
        return None;
    }
    i += 1; // past '{'
    loop {
        while i < n && matches!(b[i], b' ' | b'\t' | b',') {
            i += 1;
        }
        if i >= n || b[i] == b'}' {
            return None;
        }
        if b[i] != b'"' {
            return None;
        }
        let kstart = i;
        let kend = str_end(b, i)?;
        let kname = &b[kstart + 1..kend - 1];
        i = kend;
        while i < n && matches!(b[i], b' ' | b'\t') {
            i += 1;
        }
        if i >= n || b[i] != b':' {
            return None;
        }
        i += 1;
        while i < n && matches!(b[i], b' ' | b'\t') {
            i += 1;
        }
        if i >= n {
            return None;
        }
        let vstart = i;
        if b[i] == b'"' {
            let vend = str_end(b, i)?;
            i = vend;
            if kname == key {
                return Some(&b[vstart + 1..vend - 1]);
            }
        } else if b[i] == b'{' {
            let vend = obj_end(b, i)?;
            i = vend;
            if kname == key {
                return Some(&b[vstart..vend]);
            }
        } else {
            while i < n && b[i] != b',' && b[i] != b'}' {
                i += 1;
            }
            let mut e = i;
            while e > vstart && matches!(b[e - 1], b' ' | b'\t') {
                e -= 1;
            }
            if kname == key {
                return Some(&b[vstart..e]);
            }
        }
    }
}

fn cmd_audit() -> i32 {
    let data = match fs::read("membrane_log.jsonl") {
        Ok(b) => b,
        Err(_) => {
            // Absent log is the genesis state: an empty chain is trivially intact.
            // Emit the chain= line (SPEC s.13) + log_entries=0, not a special string.
            say("log_entries=0 chain=INTACT");
            emit_envelope("audit", Some("INTACT"), 0, vec![("log_entries", JV::I(0))]);
            return 0;
        }
    };
    let mut prev: Vec<u8> = vec![b'0'; 64];
    let mut n = 0i64;
    let mut ok = true;
    let mut broken_at: Option<i64> = None;
    for line in data.split(|&c| c == b'\n') {
        if line.iter().all(|&c| c == b' ' || c == b'\t' || c == b'\r') {
            continue;
        }
        n += 1;
        let fields = (
            top_field(line, b"prev"),
            top_field(line, b"chain"),
            top_field(line, b"kind"),
            top_field(line, b"fact"),
        );
        let (e_prev, e_chain, e_kind, fact) = match fields {
            (Some(p), Some(c), Some(k), Some(f)) => (p, c, k, f),
            _ => {
                say(&format!("BROKEN at entry {}", n));
                ok = false;
                broken_at = Some(n);
                break;
            }
        };
        // chain = SHA-256(prev + kind + canonical_json(fact))  (SPEC section 7)
        let mut buf: Vec<u8> = Vec::with_capacity(e_prev.len() + e_kind.len() + fact.len());
        buf.extend_from_slice(e_prev);
        buf.extend_from_slice(e_kind);
        buf.extend_from_slice(fact);
        let rec = sha256_hex(&buf);
        if e_prev != &prev[..] || e_chain != rec.as_bytes() {
            say(&format!("BROKEN at entry {}", n));
            ok = false;
            broken_at = Some(n);
            break;
        }
        prev = e_chain.to_vec();
    }
    let v = if ok { "INTACT" } else { "BROKEN" };
    say(&format!("log_entries={} chain={}", n, v));
    // BROKEN is a negative finding -> exit 1 (SPEC s.5); INTACT -> 0.
    let code = if ok { 0 } else { 1 };
    let broken_jv = match broken_at {
        Some(x) => JV::I(x),
        None => JV::Null,
    };
    emit_envelope(
        "audit",
        Some(v),
        code,
        vec![("log_entries", JV::I(n)), ("broken_at", broken_jv)],
    );
    code
}

fn cmd_selftest() -> i32 {
    // COMPILED implementation: artifact-of-record is the compiled binary (SPEC s.14).
    let h = match env::current_exe().ok().and_then(|p| fs::read(p).ok()) {
        Some(bytes) => sha256_hex(&bytes),
        None => "unknown".to_string(),
    };
    // Canonical token emet_self_sha256=; the legacy membrane_self_sha256= is emitted
    // through the 1.x deprecation window (removed at 2.0), same hex value (SPEC s.14).
    say(&format!("emet_self_sha256={}", h));
    say(&format!(
        "membrane_self_sha256={}  (deprecated alias; removed at 2.0)",
        h
    ));
    say("note=this hash is my only credential; re-derive it from source to verify me.");
    say("note=I assert no authority, grant no permission, decide no safety question.");
    // selftest reports an identity, not a judgement: no verdict field (SPEC s.13/s.14).
    emit_envelope(
        "selftest",
        None,
        0,
        vec![
            ("self_sha256", JV::S(h)),
            (
                "notes",
                JV::Arr(vec![
                    JV::S("this hash is my only credential; re-derive it from source to verify me.".to_string()),
                    JV::S("I assert no authority, grant no permission, decide no safety question.".to_string()),
                ]),
            ),
        ],
    );
    0
}

fn main() {
    // Global --json flag (SPEC s.13): accepted before OR after the subcommand;
    // strip it from argv, then dispatch on the remainder. Exit code is identical
    // with or without --json.
    let raw_args: Vec<String> = env::args().collect();
    let args: Vec<String> = raw_args.iter().filter(|a| *a != "--json").cloned().collect();
    if args.len() != raw_args.len() {
        enable_json();
    }
    let code = if args.len() >= 3 && args[1] == "anchor" {
        cmd_anchor(&args[2..])
    } else if args.len() >= 3 && args[1] == "verify" {
        cmd_verify(&args[2..])
    } else if args.len() >= 4 && args[1] == "coherence" {
        cmd_coherence(&args[2], &args[3])
    } else if args.len() >= 3 && args[1] == "refuse" {
        cmd_refuse(&args[2])
    } else if args.len() >= 3 && args[1] == "corroborate" {
        cmd_corroborate(&args[2])
    } else if args.len() >= 2 && args[1] == "audit" {
        cmd_audit()
    } else if args.len() >= 2 && args[1] == "selftest" {
        cmd_selftest()
    } else {
        eprintln!("usage: emet anchor|verify|coherence|refuse|corroborate|audit|selftest ...");
        64
    };
    exit(code);
}
