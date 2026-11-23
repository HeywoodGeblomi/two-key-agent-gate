//! Line-level service used by the CLI: one JSON request line in, one JSON
//! decision line out, one log entry appended. Any failure refuses.

use crate::crypto::{hex, sha256};
use crate::gate::{parse_request, Gate};
use crate::json::{self, Value};
use crate::log::DecisionLog;
use crate::taint::Status;

pub const MAX_LINE: usize = 16 * 1024 * 1024;

fn s(x: &str) -> Value {
    Value::String(x.to_string())
}

fn strs(v: &[String]) -> Value {
    Value::Array(v.iter().map(|x| s(x)).collect())
}

/// Process one request line. Returns the output JSON line. If the log write
/// fails, the decision is forced to refuse and `Err` carries the output line
/// so the caller can print it and stop.
pub fn process_line(gate: &mut Gate, log: &mut DecisionLog, line: &str) -> Result<String, String> {
    let parsed = json::parse(line).map_err(|e| e.to_string()).and_then(|v| parse_request(&v));
    let policy_digest = gate.policy.digest.clone();
    match parsed {
        Err(e) => {
            // Invalid input: refuse, log it with a digest of the raw bytes.
            let raw_digest = hex(&sha256(line.as_bytes()));
            let reasons = vec![format!("invalid_input: {}", e)];
            let body = Value::Object(vec![
                ("kind".into(), s("invalid_input")),
                ("decision".into(), s("refuse")),
                ("reasons".into(), strs(&reasons)),
                ("raw_digest".into(), s(&raw_digest)),
                ("policy_digest".into(), s(&policy_digest)),
            ]);
            let (log_hash, log_ok) = match log.append(body) {
                Ok(h) => (Value::String(h), true),
                Err(e2) => (Value::String(format!("LOG_FAILURE: {}", e2)), false),
            };
            let out = Value::Object(vec![
                ("id".into(), Value::Null),
                ("decision".into(), s("refuse")),
                ("reasons".into(), strs(&reasons)),
                ("capability".into(), Value::Null),
                ("pending".into(), Value::Null),
                ("log_hash".into(), log_hash),
            ])
            .to_compact();
            if log_ok { Ok(out) } else { Err(out) }
        }
        Ok(req) => {
            let verdict = gate.evaluate(&req);
            let d = &verdict.decision;
            let call_digest = hex(&req.call.digest());
            let ctx_canon = Value::Array(
                req.spans
                    .iter()
                    .map(|sp| Value::Object(vec![("label".into(), s(sp.label.as_str())), ("text".into(), s(&sp.text))]))
                    .collect(),
            )
            .to_canonical();
            let context_digest = hex(&sha256(ctx_canon.as_bytes()));
            let id_v = req.id.as_ref().map(|x| s(x)).unwrap_or(Value::Null);
            let mut decision_word = d.outcome.as_str();
            let mut reasons = d.reasons.clone();
            let body = Value::Object(vec![
                ("kind".into(), s("decision")),
                ("seq".into(), Value::Number(verdict.seq as f64)),
                ("id".into(), id_v.clone()),
                ("tool".into(), s(&req.call.tool)),
                ("decision".into(), s(decision_word)),
                ("reasons".into(), strs(&reasons)),
                ("call_digest".into(), s(&call_digest)),
                ("context_digest".into(), s(&context_digest)),
                ("policy_digest".into(), s(&policy_digest)),
            ]);
            let (log_hash, log_ok) = match log.append(body) {
                Ok(h) => (Value::String(h), true),
                Err(e2) => (Value::String(format!("LOG_FAILURE: {}", e2)), false),
            };
            let mut cap_v = match &verdict.capability {
                Some(c) => Value::Object(vec![("seq".into(), Value::Number(c.seq() as f64)), ("token".into(), s(&c.token_hex()))]),
                None => Value::Null,
            };
            let mut pending_v = match &verdict.pending {
                Some(p) => Value::Object(vec![("seq".into(), Value::Number(p.seq() as f64)), ("token".into(), s(&p.token_hex()))]),
                None => Value::Null,
            };
            if !log_ok {
                // Unlogged allow or confirm is not allowed.
                decision_word = "refuse";
                reasons.push("log_failure: decision could not be recorded".into());
                cap_v = Value::Null;
                pending_v = Value::Null;
            }
            let content_v = Value::Array(
                d.content
                    .iter()
                    .map(|c| {
                        Value::Object(vec![
                            ("arg".into(), s(&c.arg)),
                            ("kind".into(), s(c.kind)),
                            ("entity".into(), s(&c.entity)),
                            ("trusted".into(), Value::Bool(c.trusted)),
                        ])
                    })
                    .collect(),
            );
            let args_v = Value::Array(
                d.findings
                    .iter()
                    .map(|f| {
                        Value::Object(vec![
                            ("arg".into(), s(&f.arg)),
                            ("controlling".into(), Value::Bool(f.controlling)),
                            ("status".into(), s(f.summary())),
                            (
                                "leaves".into(),
                                Value::Array(
                                    f.leaves
                                        .iter()
                                        .map(|l| {
                                            let mut kv = vec![("value".into(), s(&l.preview)), ("status".into(), s(l.status.name()))];
                                            if let Status::Trusted { source, method } = &l.status {
                                                kv.push(("source".into(), s(source.as_str())));
                                                kv.push(("method".into(), s(method)));
                                            }
                                            Value::Object(kv)
                                        })
                                        .collect(),
                                ),
                            ),
                        ])
                    })
                    .collect(),
            );
            let out = Value::Object(vec![
                ("id".into(), id_v),
                ("seq".into(), Value::Number(verdict.seq as f64)),
                ("decision".into(), s(decision_word)),
                ("tool".into(), s(&req.call.tool)),
                ("privileged".into(), Value::Bool(d.privileged)),
                ("reasons".into(), strs(&reasons)),
                ("args".into(), args_v),
                ("content".into(), content_v),
                ("capability".into(), cap_v),
                ("pending".into(), pending_v),
                ("call_digest".into(), s(&call_digest)),
                ("policy_digest".into(), s(&policy_digest)),
                ("log_hash".into(), log_hash),
            ])
            .to_compact();
            // Capability value is dropped here; the CLI hands out only its token.
            drop(verdict);
            if log_ok { Ok(out) } else { Err(out) }
        }
    }
}
