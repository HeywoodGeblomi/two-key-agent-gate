//! two-key-gate CLI (JSON lines).
//!
//!   two-key-gate eval --policy P.json [--key-file K] [--log L.jsonl]
//!       stdin: one request per line; stdout: one decision per line.
//!   two-key-gate verify-log --log L.jsonl [--key-file K]
//!   two-key-gate redeem --key-file K
//!       stdin: {"seq":n,"token":"<hex>","call":{"tool":..,"args":{..}}} per line
//!   two-key-gate approve --key-file K
//!       Run by the user-facing UI only, never reachable by the model.
//!       stdin: {"seq":n,"token":"<pending hex>","call":{..},"approved":true|false}
//!       stdout: {"ok":true,"capability":{"seq":n,"token":"<hex>"}} on yes
//!   two-key-gate keygen --out K
//!
//! Key file: 64+ hex chars (32+ bytes). Without --key-file, eval uses a fresh
//! random key from /dev/urandom, so tokens are valid only for that process.
//! The key is never printed.

use two_key_gate::crypto::{hex, unhex};
use two_key_gate::gate::{parse_request, ApprovalDesk, Dispatcher, Gate};
use two_key_gate::json::{self, Value};
use two_key_gate::log::{verify_reader, DecisionLog};
use two_key_gate::policy::Policy;
use two_key_gate::service::{process_line, MAX_LINE};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::exit;

fn die(msg: &str) -> ! {
    eprintln!("rust_gate: {}", msg);
    exit(2)
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn load_key(path: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("read key file: {}", e)));
    let k = unhex(text.trim()).unwrap_or_else(|| die("key file must be hex"));
    if k.len() < 32 {
        die("key must be at least 32 bytes (64 hex chars)");
    }
    k
}

fn random_key() -> Vec<u8> {
    let mut k = vec![0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut k))
        .unwrap_or_else(|e| die(&format!("cannot read /dev/urandom: {}", e)));
    k
}

/// Read one line with a hard size cap. Returns None at EOF.
/// Ok(Err(..)) means the line was rejected (too long or not UTF-8).
fn read_capped<R: BufRead>(r: &mut R) -> Option<Result<String, String>> {
    let mut buf = Vec::new();
    let n = r.by_ref().take(MAX_LINE as u64 + 1).read_until(b'\n', &mut buf).unwrap_or(0);
    if n == 0 {
        return None;
    }
    if buf.len() > MAX_LINE && buf.last() != Some(&b'\n') {
        // Drain the rest of the oversized line.
        let mut sink = Vec::new();
        let _ = r.read_until(b'\n', &mut sink);
        return Some(Err("line exceeds maximum length".into()));
    }
    while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    Some(String::from_utf8(buf).map_err(|_| "line is not valid UTF-8".to_string()))
}

fn cmd_eval(args: &[String]) {
    let policy_path = arg_value(args, "--policy").unwrap_or_else(|| die("--policy is required"));
    let policy_text = std::fs::read_to_string(&policy_path).unwrap_or_else(|e| die(&format!("read policy: {}", e)));
    let policy = Policy::from_json(&policy_text).unwrap_or_else(|e| die(&format!("policy: {}", e)));
    let key = match arg_value(args, "--key-file") {
        Some(p) => load_key(&p),
        None => random_key(),
    };
    let mut log = match arg_value(args, "--log") {
        Some(p) => DecisionLog::open(&p, key.clone()).unwrap_or_else(|e| die(&format!("log: {}", e))),
        None => DecisionLog::memory(key.clone()),
    };
    let mut gate = Gate::new(policy, key).unwrap_or_else(|e| die(&e)).with_start_seq(log.count);
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    while let Some(line) = read_capped(&mut input) {
        let text = match line {
            Ok(t) => t,
            // Feed a guaranteed-invalid marker so the refusal is logged uniformly.
            Err(e) => format!("\u{0}{}", e),
        };
        if text.trim().is_empty() {
            continue;
        }
        match process_line(&mut gate, &mut log, &text) {
            Ok(o) => {
                writeln!(out, "{}", o).unwrap_or_else(|e| die(&format!("stdout: {}", e)));
            }
            Err(o) => {
                let _ = writeln!(out, "{}", o);
                die("decision log write failed; stopping (fail closed)");
            }
        }
    }
    let _ = out.flush();
}

fn cmd_verify_log(args: &[String]) {
    let path = arg_value(args, "--log").unwrap_or_else(|| die("--log is required"));
    let key = arg_value(args, "--key-file").map(|p| load_key(&p));
    let f = std::fs::File::open(&path).unwrap_or_else(|e| die(&format!("open log: {}", e)));
    match verify_reader(BufReader::new(f), key.as_deref()) {
        Ok((last, n)) => {
            println!("{}", Value::Object(vec![
                ("ok".into(), Value::Bool(true)),
                ("entries".into(), Value::Number(n as f64)),
                ("head".into(), Value::String(last)),
                ("mac_checked".into(), Value::Bool(key.is_some())),
            ]).to_compact());
        }
        Err(e) => {
            println!("{}", Value::Object(vec![("ok".into(), Value::Bool(false)), ("error".into(), Value::String(e))]).to_compact());
            exit(1);
        }
    }
}

fn cmd_redeem(args: &[String]) {
    let key = load_key(&arg_value(args, "--key-file").unwrap_or_else(|| die("--key-file is required")));
    let mut disp = Dispatcher::new(key);
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    while let Some(line) = read_capped(&mut input) {
        let res: Result<u64, String> = line.and_then(|t| {
            let v = json::parse(&t).map_err(|e| e.to_string())?;
            let seq = match v.get("seq") {
                Some(Value::Number(n)) if *n >= 0.0 && n.fract() == 0.0 && *n < 9.0e15 => *n as u64,
                _ => return Err("seq must be a non-negative integer".into()),
            };
            let token = v.get("token").and_then(|x| x.as_str()).ok_or("token must be a string")?;
            let call = v.get("call").ok_or("call is required")?;
            let req = parse_request(&Value::Object(vec![
                ("context".into(), Value::Array(vec![])),
                ("call".into(), call.clone()),
            ]))?;
            disp.redeem_hex(seq, &req.call, token)
        });
        let o = match res {
            Ok(seq) => Value::Object(vec![("ok".into(), Value::Bool(true)), ("seq".into(), Value::Number(seq as f64))]),
            Err(e) => Value::Object(vec![("ok".into(), Value::Bool(false)), ("error".into(), Value::String(e))]),
        };
        println!("{}", o.to_compact());
    }
}

fn cmd_approve(args: &[String]) {
    let key = load_key(&arg_value(args, "--key-file").unwrap_or_else(|| die("--key-file is required")));
    let mut desk = ApprovalDesk::new(key);
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    while let Some(line) = read_capped(&mut input) {
        let res = line.and_then(|t| {
            let v = json::parse(&t).map_err(|e| e.to_string())?;
            let seq = match v.get("seq") {
                Some(Value::Number(n)) if *n >= 0.0 && n.fract() == 0.0 && *n < 9.0e15 => *n as u64,
                _ => return Err("seq must be a non-negative integer".into()),
            };
            let token = v.get("token").and_then(|x| x.as_str()).ok_or("token must be a string")?;
            let yes = v.get("approved").and_then(|x| x.as_bool()).ok_or("approved must be a boolean")?;
            let call = v.get("call").ok_or("call is required")?;
            let req = parse_request(&Value::Object(vec![
                ("context".into(), Value::Array(vec![])),
                ("call".into(), call.clone()),
            ]))?;
            desk.approve_hex(seq, &req.call, token, yes)
        });
        let o = match res {
            Ok(cap) => Value::Object(vec![
                ("ok".into(), Value::Bool(true)),
                ("capability".into(), Value::Object(vec![
                    ("seq".into(), Value::Number(cap.seq() as f64)),
                    ("token".into(), Value::String(cap.token_hex())),
                ])),
            ]),
            Err(e) => Value::Object(vec![("ok".into(), Value::Bool(false)), ("error".into(), Value::String(e))]),
        };
        println!("{}", o.to_compact());
    }
}

fn cmd_keygen(args: &[String]) {
    let out = arg_value(args, "--out").unwrap_or_else(|| die("--out is required"));
    if std::path::Path::new(&out).exists() {
        die("refusing to overwrite an existing key file");
    }
    let k = random_key();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&out).unwrap_or_else(|e| die(&format!("create key file: {}", e)));
    f.write_all(hex(&k).as_bytes()).unwrap_or_else(|e| die(&format!("write key: {}", e)));
    eprintln!("rust_gate: wrote a new 32-byte key to {}", out);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("eval") => cmd_eval(&args[2..]),
        Some("verify-log") => cmd_verify_log(&args[2..]),
        Some("redeem") => cmd_redeem(&args[2..]),
        Some("approve") => cmd_approve(&args[2..]),
        Some("keygen") => cmd_keygen(&args[2..]),
        _ => die("usage: rust_gate <eval|verify-log|redeem|approve|keygen> [options]"),
    }
}
