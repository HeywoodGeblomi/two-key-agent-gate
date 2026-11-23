//! Hash-chained, append-only decision log (JSON lines).
//!
//! Each entry: {"body": {...}, "prev": <hex>, "hash": <hex>, "mac": <hex>}
//! hash = SHA-256( "rust_gate/log/v1\n" || prev || "\n" || canonical(body) )
//! mac  = HMAC-SHA256(key, hash)
//! The chain is publicly verifiable (anyone can recompute hashes, so any edit,
//! deletion or reordering breaks it after the edited point). The MAC lets the
//! key holder also detect a wholesale rewrite of the chain.

use crate::crypto::{ct_eq, hex, hmac_sha256, sha256};
use crate::json::{self, Value};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn entry_hash(prev: &str, body: &Value) -> String {
    let mut m = Vec::new();
    m.extend_from_slice(b"rust_gate/log/v1\n");
    m.extend_from_slice(prev.as_bytes());
    m.push(b'\n');
    m.extend_from_slice(body.to_canonical().as_bytes());
    hex(&sha256(&m))
}

pub struct DecisionLog {
    file: Option<File>,
    pub prev: String,
    pub count: u64,
    key: Vec<u8>,
}

impl DecisionLog {
    /// In-memory chain (no file). Used by tests and when no --log is given.
    pub fn memory(key: Vec<u8>) -> DecisionLog {
        DecisionLog { file: None, prev: GENESIS.into(), count: 0, key }
    }

    /// Open (or create) a log file. An existing file is fully verified first;
    /// a broken chain is an error (fail closed: refuse to extend it).
    pub fn open(path: &str, key: Vec<u8>) -> Result<DecisionLog, String> {
        let (prev, count) = match File::open(path) {
            Ok(f) => verify_reader(BufReader::new(f), Some(&key))?,
            Err(_) => (GENESIS.to_string(), 0),
        };
        let file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("open log: {}", e))?;
        Ok(DecisionLog { file: Some(file), prev, count, key })
    }

    pub fn append(&mut self, body: Value) -> Result<String, String> {
        let h = entry_hash(&self.prev, &body);
        let mac = hex(&hmac_sha256(&self.key, h.as_bytes()));
        let line = Value::Object(vec![
            ("body".into(), body),
            ("prev".into(), Value::String(self.prev.clone())),
            ("hash".into(), Value::String(h.clone())),
            ("mac".into(), Value::String(mac)),
        ])
        .to_canonical();
        if let Some(f) = self.file.as_mut() {
            f.write_all(line.as_bytes()).map_err(|e| format!("write log: {}", e))?;
            f.write_all(b"\n").map_err(|e| format!("write log: {}", e))?;
            f.flush().map_err(|e| format!("flush log: {}", e))?;
        }
        self.prev = h.clone();
        self.count += 1;
        Ok(h)
    }
}

/// Verify a whole log. Returns (last hash, entry count).
pub fn verify_reader<R: BufRead>(r: R, key: Option<&[u8]>) -> Result<(String, u64), String> {
    let mut prev = GENESIS.to_string();
    let mut n = 0u64;
    for (i, line) in r.lines().enumerate() {
        let line = line.map_err(|e| format!("read log: {}", e))?;
        if line.trim().is_empty() {
            return Err(format!("log line {}: empty line", i + 1));
        }
        let v = json::parse(&line).map_err(|e| format!("log line {}: {}", i + 1, e))?;
        let body = v.get("body").ok_or_else(|| format!("log line {}: missing body", i + 1))?;
        let p = v.get("prev").and_then(|x| x.as_str()).ok_or_else(|| format!("log line {}: missing prev", i + 1))?;
        let h = v.get("hash").and_then(|x| x.as_str()).ok_or_else(|| format!("log line {}: missing hash", i + 1))?;
        if p != prev {
            return Err(format!("log line {}: prev does not link to previous entry", i + 1));
        }
        if entry_hash(p, body) != h {
            return Err(format!("log line {}: hash mismatch (entry altered)", i + 1));
        }
        if let Some(k) = key {
            let mac = v.get("mac").and_then(|x| x.as_str()).ok_or_else(|| format!("log line {}: missing mac", i + 1))?;
            let expect = hex(&hmac_sha256(k, h.as_bytes()));
            if !ct_eq(expect.as_bytes(), mac.as_bytes()) {
                return Err(format!("log line {}: mac mismatch (wrong key or rewritten chain)", i + 1));
            }
        }
        prev = h.to_string();
        n += 1;
    }
    Ok((prev, n))
}
