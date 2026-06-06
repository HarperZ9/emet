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

// -------- markers (literal, case-insensitive; corpus semantics deferred) --------
const MARKERS: [&str; 10] = [
    "ground_truth_canonical",
    "highest_scrutiny",
    "[scope context]",
    "authority_pill",
    "canonical recipients",
    "frame_injected",
    "consulting register",
    "semantic_modulat",
    "compound_rewrites",
    "density_restructured",
];

fn count_markers(bytes: &[u8]) -> usize {
    let s = String::from_utf8_lossy(bytes).to_lowercase();
    let mut n = 0usize;
    for &m in MARKERS.iter() {
        let mut start = 0;
        while let Some(pos) = s[start..].find(m) {
            n += 1;
            start += pos + m.len();
        }
    }
    n
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
            println!("UNVERIFIABLE (unreadable)");
            return 2;
        }
    };
    let n = count_markers(&bytes);
    let mut text = String::from_utf8_lossy(&bytes).to_string();
    for &m in MARKERS.iter() {
        loop {
            let pos = text.to_lowercase().find(m);
            match pos {
                Some(p) => text.replace_range(p..p + m.len(), "[REFUSED-IN-BAND-AUTHORITY]"),
                None => break,
            }
        }
    }
    let _ = fs::write(format!("{}.refused", path), text.as_bytes());
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
    } else if args.len() >= 2 && args[1] == "selftest" {
        cmd_selftest()
    } else {
        eprintln!("usage: emet anchor|verify|coherence|refuse|corroborate|selftest ...");
        64
    };
    exit(code);
}
