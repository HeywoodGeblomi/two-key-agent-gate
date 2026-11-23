//! The gate: validate a request, classify controlling arguments, decide.
//!
//! Fail-closed properties:
//! - Every call is evaluated on its own request. The gate keeps no
//!   "allowed" state between calls, so nothing latches open. The only state
//!   is a sequence counter used to bind capability tokens.
//! - Unknown tool, unknown argument, malformed input, non-finite number,
//!   duplicate key, bad label: refuse.
//! - A privileged call is allowed only if every scalar leaf of every
//!   controlling argument is positively trusted-sourced, and every URL,
//!   email and IBAN in its content arguments appears in trusted text.
//! - v2: a privileged call that fails those checks is CONFIRM, not a silent
//!   deny: it is held as a move-once [`PendingConfirm`] that only the user's
//!   approval (through [`ApprovalDesk`], which holds the key) can turn into a
//!   [`Capability`]. Malformed or out-of-policy calls are still REFUSE.
//!
//! Capabilities use a move-once pattern: a [`Capability`] has private
//! fields, is not `Clone` or `Copy`, can only be minted by
//! [`Gate::evaluate`] on an allow, and [`Dispatcher::redeem`] takes it by
//! value, so one allow authorizes exactly one execution of exactly the call
//! that was checked. Its token is HMAC-SHA256 under a key that never enters
//! the model context or tool data, so it cannot be forged from the public
//! call alone (an unkeyed hash commitment could be).

use crate::crypto::{ct_eq, hex, hmac_sha256, sha256, unhex};
use crate::json::{self, Value};
use crate::policy::{valid_name, Policy};
use crate::taint::{classify_id, classify_value, extract_entities, scalar_strings, Context, Label, Leaf, Span, Status};
use std::collections::BTreeSet;

pub const MAX_SPANS: usize = 10_000;
pub const MAX_LEAVES: usize = 10_000;
pub const MAX_ID_LEN: usize = 256;

#[derive(Debug, Clone)]
pub struct ToolCall {
    pub tool: String,
    pub args: Vec<(String, Value)>,
}

impl ToolCall {
    pub fn canonical(&self) -> String {
        Value::Object(vec![
            ("args".into(), Value::Object(self.args.clone())),
            ("tool".into(), Value::String(self.tool.clone())),
        ])
        .to_canonical()
    }
    pub fn digest(&self) -> [u8; 32] {
        sha256(self.canonical().as_bytes())
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub id: Option<String>,
    pub spans: Vec<Span>,
    pub call: ToolCall,
}

/// Parse and validate a request object. Any problem is an error (refuse).
pub fn parse_request(v: &Value) -> Result<Request, String> {
    let obj = v.as_object().ok_or("request must be a JSON object")?;
    for (k, _) in obj {
        if !matches!(k.as_str(), "id" | "context" | "call") {
            return Err(format!("unknown request field {}", json::quote(k)));
        }
    }
    let id = match v.get("id") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.chars().count() <= MAX_ID_LEN => Some(s.clone()),
        Some(Value::Number(n)) => Some(json::format_number(*n)),
        _ => return Err("id must be a short string or a number".into()),
    };
    let ctx = v.get("context").and_then(|c| c.as_array()).ok_or("context must be an array")?;
    if ctx.len() > MAX_SPANS {
        return Err("too many context spans".into());
    }
    let mut spans = Vec::with_capacity(ctx.len());
    for (i, s) in ctx.iter().enumerate() {
        let so = s.as_object().ok_or_else(|| format!("context[{}] must be an object", i))?;
        for (k, _) in so {
            if k != "label" && k != "text" && k != "kind" {
                return Err(format!("context[{}] has unknown field {}", i, json::quote(k)));
            }
        }
        let label_s = s.get("label").and_then(|x| x.as_str()).ok_or_else(|| format!("context[{}].label must be a string", i))?;
        let label = Label::parse(label_s).ok_or_else(|| format!("context[{}].label {} is not a known label", i, json::quote(label_s)))?;
        let text = s.get("text").and_then(|x| x.as_str()).ok_or_else(|| format!("context[{}].text must be a string", i))?;
        let kind = match (label, s.get("kind")) {
            (Label::SystemId, Some(Value::String(k))) if valid_name(k) => Some(k.clone()),
            (Label::SystemId, _) => return Err(format!("context[{}]: system_id needs a valid kind", i)),
            (_, None) => None,
            (_, Some(_)) => return Err(format!("context[{}]: kind is only allowed on system_id", i)),
        };
        if label == Label::SystemId && (text.is_empty() || text.chars().count() > 256) {
            return Err(format!("context[{}]: system_id value must be 1 to 256 chars", i));
        }
        spans.push(Span { label, text: text.to_string(), kind });
    }
    let call = v.get("call").and_then(|c| c.as_object()).ok_or("call must be an object")?;
    for (k, _) in call {
        if k != "tool" && k != "args" {
            return Err(format!("call has unknown field {}", json::quote(k)));
        }
    }
    let callv = v.get("call").unwrap();
    let tool = callv.get("tool").and_then(|x| x.as_str()).ok_or("call.tool must be a string")?;
    if !valid_name(tool) {
        return Err("call.tool is not a valid tool name".into());
    }
    let args = match callv.get("args") {
        None => Vec::new(),
        Some(Value::Object(kv)) => kv.clone(),
        Some(_) => return Err("call.args must be an object".into()),
    };
    for (k, _) in &args {
        if !valid_name(k) {
            return Err(format!("argument name {} is not valid", json::quote(k)));
        }
    }
    Ok(Request { id, spans, call: ToolCall { tool: tool.to_string(), args } })
}

#[derive(Debug, Clone)]
pub struct ArgFinding {
    pub arg: String,
    pub controlling: bool,
    pub leaves: Vec<Leaf>,
}

impl ArgFinding {
    /// Worst status across leaves: unknown > tainted > trusted; absent if none.
    pub fn summary(&self) -> &'static str {
        if self.leaves.is_empty() {
            return "absent";
        }
        if self.leaves.iter().any(|l| l.status == Status::Unknown) {
            "unknown"
        } else if self.leaves.iter().any(|l| l.status == Status::Tainted) {
            "tainted"
        } else {
            "trusted"
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    /// Held for the user. Not executed unless the user approves.
    Confirm,
    Refuse,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Allow => "allow",
            Outcome::Confirm => "confirm",
            Outcome::Refuse => "refuse",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ContentFinding {
    pub arg: String,
    pub kind: &'static str,
    pub entity: String,
    pub trusted: bool,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub outcome: Outcome,
    pub privileged: bool,
    pub reasons: Vec<String>,
    pub findings: Vec<ArgFinding>,
    pub content: Vec<ContentFinding>,
}

impl Decision {
    pub fn allow(&self) -> bool {
        self.outcome == Outcome::Allow
    }
    fn refuse(privileged: bool, reasons: Vec<String>) -> Decision {
        Decision { outcome: Outcome::Refuse, privileged, reasons, findings: Vec::new(), content: Vec::new() }
    }
}

/// Move-once authorization for exactly one execution of one checked call.
/// Private fields, no Clone, no Copy: obtainable only from [`Gate::evaluate`].
///
/// Spending the same capability twice does not compile:
/// ```compile_fail
/// use two_key_gate::{gate::*, json, policy::Policy};
/// let p = Policy::from_json(r#"{"version":"t","tools":{"r":{"privileged":false}}}"#).unwrap();
/// let mut g = Gate::new(p, vec![1u8; 32]).unwrap();
/// let req = parse_request(&json::parse(r#"{"context":[],"call":{"tool":"r","args":{}}}"#).unwrap()).unwrap();
/// let cap = g.evaluate(&req).capability.unwrap();
/// let mut d = Dispatcher::new(vec![1u8; 32]);
/// let _ = d.redeem(cap, &req.call);
/// let _ = d.redeem(cap, &req.call); // error: use of moved value
/// ```
///
/// Nor can one be built outside the gate:
/// ```compile_fail
/// let c = two_key_gate::gate::Capability { seq: 0, call_digest: [0; 32], token: [0; 32] };
/// ```
///
/// The legitimate path compiles and runs:
/// ```
/// use two_key_gate::{gate::*, json, policy::Policy};
/// let p = Policy::from_json(r#"{"version":"t","tools":{"r":{"privileged":false}}}"#).unwrap();
/// let mut g = Gate::new(p, vec![1u8; 32]).unwrap();
/// let req = parse_request(&json::parse(r#"{"context":[],"call":{"tool":"r","args":{}}}"#).unwrap()).unwrap();
/// let cap = g.evaluate(&req).capability.unwrap();
/// let mut d = Dispatcher::new(vec![1u8; 32]);
/// assert!(d.redeem(cap, &req.call).is_ok());
/// ```
#[derive(Debug)]
pub struct Capability {
    seq: u64,
    call_digest: [u8; 32],
    token: [u8; 32],
}

impl Capability {
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn token_hex(&self) -> String {
        hex(&self.token)
    }
}

const CAP_DOMAIN: &[u8] = b"rust_gate/capability/v1\0";

fn cap_token(key: &[u8], seq: u64, call_digest: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(CAP_DOMAIN.len() + 8 + 32);
    m.extend_from_slice(CAP_DOMAIN);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(call_digest);
    hmac_sha256(key, &m)
}

pub struct Gate {
    pub policy: Policy,
    key: Vec<u8>,
    next_seq: u64,
}

pub struct Verdict {
    pub decision: Decision,
    pub capability: Option<Capability>,
    pub pending: Option<PendingConfirm>,
    pub seq: u64,
}

/// A held privileged call waiting for the user. Move-once like [`Capability`]:
/// private fields, no Clone or Copy. Only [`ApprovalDesk::approve`] with the
/// user's yes turns it into a Capability.
///
/// Approving the same pending item twice does not compile:
/// ```compile_fail
/// use two_key_gate::{gate::*, json, policy::Policy};
/// let p = Policy::from_json(r#"{"version":"t","tools":{"s":{"privileged":true,"controlling_args":["to"]}}}"#).unwrap();
/// let mut g = Gate::new(p, vec![1u8; 32]).unwrap();
/// let req = parse_request(&json::parse(r#"{"context":[],"call":{"tool":"s","args":{"to":"eve"}}}"#).unwrap()).unwrap();
/// let pending = g.evaluate(&req).pending.unwrap();
/// let mut desk = ApprovalDesk::new(vec![1u8; 32]);
/// let _ = desk.approve(pending, &req.call, true);
/// let _ = desk.approve(pending, &req.call, true); // error: use of moved value
/// ```
#[derive(Debug)]
pub struct PendingConfirm {
    seq: u64,
    call_digest: [u8; 32],
    token: [u8; 32],
}

impl PendingConfirm {
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn token_hex(&self) -> String {
        hex(&self.token)
    }
}

const PENDING_DOMAIN: &[u8] = b"rust_gate/pending-confirm/v2\0";

fn pending_token(key: &[u8], seq: u64, call_digest: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(PENDING_DOMAIN.len() + 40);
    m.extend_from_slice(PENDING_DOMAIN);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(call_digest);
    hmac_sha256(key, &m)
}

impl Gate {
    pub fn new(policy: Policy, key: Vec<u8>) -> Result<Gate, String> {
        if key.len() < 32 {
            return Err("HMAC key must be at least 32 bytes".into());
        }
        Ok(Gate { policy, key, next_seq: 0 })
    }

    pub fn with_start_seq(mut self, seq: u64) -> Gate {
        self.next_seq = seq;
        self
    }

    /// Pure decision function: same request and policy, same decision.
    pub fn decide(&self, req: &Request) -> Decision {
        let tp = match self.policy.tools.get(&req.call.tool) {
            None => {
                return Decision::refuse(true, vec![format!("unknown_tool: {} is not in the policy (fail closed)", req.call.tool)])
            }
            Some(tp) => tp,
        };
        let mut reasons = Vec::new();
        if let Some(allowed) = &tp.args {
            for (k, _) in &req.call.args {
                if !allowed.contains(k) {
                    reasons.push(format!("unknown_arg: {} is not a declared argument of {}", k, req.call.tool));
                }
            }
        }
        if !reasons.is_empty() {
            return Decision::refuse(tp.privileged, reasons);
        }
        if !tp.privileged {
            return Decision {
                outcome: Outcome::Allow,
                privileged: false,
                reasons: vec!["unprivileged_tool".into()],
                findings: Vec::new(),
                content: Vec::new(),
            };
        }
        let ctx = Context::new(&req.spans);
        let mut findings = Vec::new();
        let mut content = Vec::new();
        let mut total_leaves = 0usize;
        let mut confirm = false;
        for c in &tp.controlling_args {
            let mut leaves = Vec::new();
            if let Some((_, v)) = req.call.args.iter().find(|(k, _)| k == c) {
                match tp.id_args.get(c) {
                    Some(slot) => {
                        let mut ss = Vec::new();
                        scalar_strings(v, &mut ss);
                        for x in ss {
                            let status = classify_id(&ctx, &slot.kind, slot.cue_required, &x);
                            leaves.push(Leaf { preview: x.chars().take(80).collect(), status });
                        }
                    }
                    None => classify_value(&ctx, v, &mut leaves),
                }
            }
            total_leaves += leaves.len();
            if total_leaves > MAX_LEAVES {
                return Decision::refuse(true, vec!["too_many_argument_leaves".into()]);
            }
            for l in &leaves {
                match &l.status {
                    Status::Trusted { source: Label::SystemId, .. } if tp.destructive => {
                        confirm = true;
                        reasons.push(format!("destructive_tool_id_from_tool_output: {} value {} was not named by the user", c, json::quote(&l.preview)));
                    }
                    Status::Trusted { .. } => {}
                    Status::Tainted => {
                        confirm = true;
                        reasons.push(format!("tainted_controlling_arg: {} value {} appears in untrusted tool output and not in any trusted span", c, json::quote(&l.preview)));
                    }
                    Status::Unknown => {
                        confirm = true;
                        reasons.push(format!("untrusted_controlling_arg: {} value {} is not found in any trusted span", c, json::quote(&l.preview)));
                    }
                }
            }
            findings.push(ArgFinding { arg: c.clone(), controlling: true, leaves });
        }
        if findings.iter().all(|f| f.leaves.is_empty()) {
            // Nothing to check means no positive evidence (v1 leak: calendar
            // events with no participants). Ask the user.
            confirm = true;
            reasons.push("no_controlling_evidence: every controlling arg is absent or empty".into());
        }
        for c in &tp.content_args {
            if let Some((_, v)) = req.call.args.iter().find(|(k, _)| k == c) {
                let mut ss = Vec::new();
                scalar_strings(v, &mut ss);
                for text in ss {
                    for (kind, entity) in extract_entities(&text) {
                        let trusted = ctx.text_trust(&entity).is_some();
                        if !trusted {
                            confirm = true;
                            reasons.push(format!("untrusted_entity_in_content: {} {} in {} is not in trusted text", kind, json::quote(&entity), c));
                        }
                        content.push(ContentFinding { arg: c.clone(), kind, entity, trusted });
                    }
                }
            }
        }
        let outcome = if confirm {
            Outcome::Confirm
        } else {
            reasons.push("privileged_tool: all controlling args trusted-sourced, content clean".into());
            Outcome::Allow
        };
        Decision { outcome, privileged: true, reasons, findings, content }
    }

    /// Decide and, on allow, mint a single-use capability bound to this call.
    pub fn evaluate(&mut self, req: &Request) -> Verdict {
        let seq = self.next_seq;
        self.next_seq += 1;
        let decision = self.decide(req);
        let d = req.call.digest();
        let (capability, pending) = match decision.outcome {
            Outcome::Allow => (Some(Capability { seq, call_digest: d, token: cap_token(&self.key, seq, &d) }), None),
            Outcome::Confirm => (None, Some(PendingConfirm { seq, call_digest: d, token: pending_token(&self.key, seq, &d) })),
            Outcome::Refuse => (None, None),
        };
        Verdict { decision, capability, pending, seq }
    }
}

/// User-facing approval point. Holds the key; the model never reaches it.
/// The user's answer is a plain bool supplied by the UI, not by model output.
pub struct ApprovalDesk {
    key: Vec<u8>,
    spent: BTreeSet<u64>,
}

impl ApprovalDesk {
    pub fn new(key: Vec<u8>) -> ApprovalDesk {
        ApprovalDesk { key, spent: BTreeSet::new() }
    }

    /// Consumes the pending item. Yes: a single-use Capability for exactly
    /// that call. No: nothing, and the pending item cannot be retried.
    pub fn approve(&mut self, p: PendingConfirm, call: &ToolCall, user_said_yes: bool) -> Result<Capability, String> {
        if !ct_eq(&p.call_digest, &call.digest()) {
            return Err("pending item was held for a different call".into());
        }
        self.approve_raw(p.seq, call, &p.token, user_said_yes)
    }

    pub fn approve_hex(&mut self, seq: u64, call: &ToolCall, token_hex: &str, user_said_yes: bool) -> Result<Capability, String> {
        let t = unhex(token_hex).ok_or("token is not hex")?;
        self.approve_raw(seq, call, &t, user_said_yes)
    }

    fn approve_raw(&mut self, seq: u64, call: &ToolCall, token: &[u8], yes: bool) -> Result<Capability, String> {
        let d = call.digest();
        if !ct_eq(&pending_token(&self.key, seq, &d), token) {
            return Err("pending token does not match this call (forged, altered, or wrong key)".into());
        }
        if !self.spent.insert(seq) {
            return Err("pending item already resolved".into());
        }
        if !yes {
            return Err("user declined".into());
        }
        Ok(Capability { seq, call_digest: d, token: cap_token(&self.key, seq, &d) })
    }
}

/// Executor-side check. Holds the same key as the gate (never the model's).
pub struct Dispatcher {
    key: Vec<u8>,
    spent: BTreeSet<u64>,
}

impl Dispatcher {
    pub fn new(key: Vec<u8>) -> Dispatcher {
        Dispatcher { key, spent: BTreeSet::new() }
    }

    /// Consumes the capability. Verifies it was minted for exactly `call`.
    pub fn redeem(&mut self, cap: Capability, call: &ToolCall) -> Result<u64, String> {
        if !ct_eq(&cap.call_digest, &call.digest()) {
            return Err("capability was minted for a different call".into());
        }
        self.redeem_raw(cap.seq, call, &cap.token)
    }

    /// For an out-of-process dispatcher that received seq + token over the CLI.
    pub fn redeem_hex(&mut self, seq: u64, call: &ToolCall, token_hex: &str) -> Result<u64, String> {
        let t = unhex(token_hex).ok_or("token is not hex")?;
        self.redeem_raw(seq, call, &t)
    }

    fn redeem_raw(&mut self, seq: u64, call: &ToolCall, token: &[u8]) -> Result<u64, String> {
        let expect = cap_token(&self.key, seq, &call.digest());
        if !ct_eq(&expect, token) {
            return Err("capability does not match this call (forged, altered, or wrong key)".into());
        }
        if !self.spent.insert(seq) {
            return Err("capability already spent".into());
        }
        Ok(seq)
    }
}
