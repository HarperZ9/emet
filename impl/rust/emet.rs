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
use std::process::{exit, Command};

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
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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
            w[j] = w[j - 16].wrapping_add(s0).wrapping_add(w[j - 7]).wrapping_add(s1);
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

fn sha_of_file(path: &str) -> Option<String> {
    fs::read(path).ok().map(|b| sha256_hex(&b))
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
        let line: &[u8] = if raw.last() == Some(&b'\r') { &raw[..raw.len() - 1] } else { raw };
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
    for p in paths {
        if let Some(h) = sha_of_file(p) {
            println!("anchored {} sha256={}", p, h);
            map.insert(p.clone(), h);
        }
    }
    write_anchors(&map);
    0
}

fn cmd_verify(paths: &[String]) -> i32 {
    let map = read_anchors();
    let mut bad = 0;
    for p in paths {
        match map.get(p) {
            None => {
                println!("UNVERIFIABLE {} (no anchor)", p);
                bad += 1;
            }
            Some(want) => match sha_of_file(p) {
                None => {
                    println!("UNVERIFIABLE {} (unreadable)", p);
                    bad += 1;
                }
                Some(got) => {
                    if &got == want {
                        println!("MATCH {} want={} got={}", p, pre(want), pre(&got));
                    } else {
                        println!("DRIFT {} want={} got={}", p, pre(want), pre(&got));
                        bad += 1;
                    }
                }
            },
        }
    }
    if bad == 0 {
        0
    } else {
        2
    }
}

fn cmd_coherence(src: &str, view: &str) -> i32 {
    match (sha_of_file(src), sha_of_file(view)) {
        (Some(s), Some(v)) => {
            println!("source={}", s);
            println!("view  ={}", v);
            if s == v {
                println!("result=COHERENT");
                0
            } else {
                println!("result=VIEW_DIFFERS_FROM_SOURCE");
                2
            }
        }
        _ => {
            println!("result=UNVERIFIABLE");
            2
        }
    }
}

fn cmd_refuse(path: &str) -> i32 {
    let bytes = match fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            println!("UNVERIFIABLE {} reason=E_NOT_FOUND", path);
            return 2;
        }
    };
    let (version, csha, markers) = match load_corpus() {
        Ok(c) => c,
        Err(reason) => {
            println!("UNVERIFIABLE {} reason={}", path, reason);
            return 2;
        }
    };
    // Rewrite over raw bytes so non-ASCII content is preserved and never
    // mis-indexed; replace each matched marker with the refusal sentinel.
    let repl = b"[REFUSED-IN-BAND-AUTHORITY]";
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut n = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        let hit = marker_len_at(&bytes, i, &markers);
        if hit > 0 {
            out.extend_from_slice(repl);
            i += hit;
            n += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    let _ = fs::write(format!("{}.refused", path), &out);
    println!("corpus_version={}", version);
    println!("corpus_sha256={}", csha);
    println!("in_band_authority_claims={}", n);
    println!("clean_copy={}.refused  (claims neutralized; obeyed: none)", path);
    if n == 0 {
        0
    } else {
        3
    }
}

fn cmd_corroborate(path: &str) -> i32 {
    let primary = match fs::read(path) {
        Ok(b) => sha256_hex(&b),
        Err(_) => {
            println!("read_paths_agree=False");
            println!("result=QUARANTINE_READ_PATH_DIVERGENCE");
            return 2;
        }
    };
    println!("open_rb={}", primary);
    let mut agree = true;
    match Command::new("cat").arg(path).output() {
        Ok(o) if o.status.success() => {
            let cat_hash = sha256_hex(&o.stdout);
            println!("cat_subproc={}", cat_hash);
            if cat_hash != primary {
                agree = false;
            }
        }
        _ => {
            println!("cat_subproc=unavailable");
        }
    }
    println!("read_paths_agree={}", if agree { "True" } else { "False" });
    if agree {
        println!("result=CORROBORATED");
        0
    } else {
        println!("result=QUARANTINE_READ_PATH_DIVERGENCE");
        2
    }
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
            println!("no log");
            return 0;
        }
    };
    let mut prev: Vec<u8> = vec![b'0'; 64];
    let mut n = 0i64;
    let mut ok = true;
    for line in data.split(|&c| c == b'\n') {
        if line.iter().all(|&c| c == b' ' || c == b'\t' || c == b'\r') {
            continue;
        }
        n += 1;
        let fields = (top_field(line, b"prev"), top_field(line, b"chain"), top_field(line, b"fact"));
        let (e_prev, e_chain, fact) = match fields {
            (Some(p), Some(c), Some(f)) => (p, c, f),
            _ => {
                println!("BROKEN at entry {}", n);
                ok = false;
                break;
            }
        };
        let mut buf: Vec<u8> = Vec::with_capacity(e_prev.len() + fact.len());
        buf.extend_from_slice(e_prev);
        buf.extend_from_slice(fact);
        let rec = sha256_hex(&buf);
        if e_prev != &prev[..] || e_chain != rec.as_bytes() {
            println!("BROKEN at entry {}", n);
            ok = false;
            break;
        }
        prev = e_chain.to_vec();
    }
    println!("log_entries={} chain={}", n, if ok { "INTACT" } else { "BROKEN" });
    if ok {
        0
    } else {
        2
    }
}

fn cmd_selftest() -> i32 {
    match env::current_exe().ok().and_then(|p| fs::read(p).ok()) {
        Some(bytes) => println!("membrane_self_sha256={}", sha256_hex(&bytes)),
        None => println!("membrane_self_sha256=unknown"),
    }
    println!("note=this hash is my only credential; re-derive it from source to verify me.");
    println!("note=I assert no authority, grant no permission, decide no safety question.");
    0
}

fn main() {
    let args: Vec<String> = env::args().collect();
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
