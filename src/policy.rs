//! Capability policy: which tools are privileged and which of their
//! arguments are controlling (must be trusted-sourced).
//!
//! Policy file format (JSON):
//! {
//!   "version": "agentdojo-v1.2.2-policy-1",
//!   "tools": {
//!     "send_money": {"privileged": true, "controlling_args": ["recipient"],
//!                    "args": ["recipient","amount","subject","date"]},
//!     "get_balance": {"privileged": false}
//!   }
//! }
//! Tools not listed are refused (fail closed). If "args" is given, any
//! argument outside that list is refused, so an argument cannot be smuggled
//! under a variant name the executor might also accept.

use crate::json::{self, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct IdSlot {
    /// ID kind, matched exactly against system_id spans (for example "file_id").
    pub kind: String,
    /// true: opaque id; trusted text must name it with an ID cue ("ID 13", "#13").
    /// false: name-like id (slack channel, user); any token-bounded trusted-text match.
    pub cue_required: bool,
}

#[derive(Debug, Clone)]
pub struct ToolPolicy {
    pub privileged: bool,
    pub controlling_args: Vec<String>,
    pub args: Option<Vec<String>>,
    /// v2: controlling args that hold system-generated identifiers.
    pub id_args: BTreeMap<String, IdSlot>,
    /// v2: free-text args scanned for URLs, emails and IBANs.
    pub content_args: Vec<String>,
    /// v2: irreversible; an ID that came only from tool output needs CONFIRM.
    pub destructive: bool,
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub version: String,
    pub tools: BTreeMap<String, ToolPolicy>,
    /// SHA-256 of the canonical policy JSON, recorded in every log entry.
    pub digest: String,
}

pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

fn str_list(v: &Value, what: &str) -> Result<Vec<String>, String> {
    let a = v.as_array().ok_or_else(|| format!("{} must be an array", what))?;
    let mut out = Vec::new();
    for x in a {
        let s = x.as_str().ok_or_else(|| format!("{} entries must be strings", what))?;
        if !valid_name(s) {
            return Err(format!("{} entry {} is not a valid name", what, json::quote(s)));
        }
        if out.iter().any(|y: &String| y == s) {
            return Err(format!("{} has duplicate {}", what, json::quote(s)));
        }
        out.push(s.to_string());
    }
    Ok(out)
}

impl Policy {
    pub fn from_json(text: &str) -> Result<Policy, String> {
        let v = json::parse(text).map_err(|e| e.to_string())?;
        let obj = v.as_object().ok_or("policy must be an object")?;
        for (k, _) in obj {
            if k != "version" && k != "tools" && k != "notes" {
                return Err(format!("unknown policy field {}", json::quote(k)));
            }
        }
        let version = v.get("version").and_then(|x| x.as_str()).ok_or("policy.version must be a string")?;
        let tools_v = v.get("tools").and_then(|x| x.as_object()).ok_or("policy.tools must be an object")?;
        let mut tools = BTreeMap::new();
        for (name, tv) in tools_v {
            if !valid_name(name) {
                return Err(format!("invalid tool name {}", json::quote(name)));
            }
            let to = tv.as_object().ok_or_else(|| format!("tool {} must be an object", name))?;
            for (k, _) in to {
                if !matches!(k.as_str(), "privileged" | "controlling_args" | "args" | "notes" | "id_args" | "content_args" | "destructive") {
                    return Err(format!("unknown field {} in tool {}", json::quote(k), name));
                }
            }
            let privileged = tv
                .get("privileged")
                .and_then(|x| x.as_bool())
                .ok_or_else(|| format!("tool {}: privileged must be a boolean", name))?;
            let controlling_args = match tv.get("controlling_args") {
                Some(x) => str_list(x, "controlling_args")?,
                None => Vec::new(),
            };
            let args = match tv.get("args") {
                Some(x) => Some(str_list(x, "args")?),
                None => None,
            };
            let content_args = match tv.get("content_args") {
                Some(x) => str_list(x, "content_args")?,
                None => Vec::new(),
            };
            let destructive = match tv.get("destructive") {
                None => false,
                Some(x) => x.as_bool().ok_or_else(|| format!("tool {}: destructive must be a boolean", name))?,
            };
            let mut id_args = BTreeMap::new();
            if let Some(x) = tv.get("id_args") {
                let o = x.as_object().ok_or_else(|| format!("tool {}: id_args must be an object", name))?;
                for (arg, spec) in o {
                    if !controlling_args.contains(arg) {
                        return Err(format!("tool {}: id arg {} must be a controlling arg", name, arg));
                    }
                    let kind = spec.get("kind").and_then(|k| k.as_str()).ok_or_else(|| format!("tool {}: id_args.{}.kind must be a string", name, arg))?;
                    if !valid_name(kind) {
                        return Err(format!("tool {}: bad id kind", name));
                    }
                    let cue_required = spec.get("cue_required").and_then(|k| k.as_bool()).ok_or_else(|| format!("tool {}: id_args.{}.cue_required must be a boolean", name, arg))?;
                    for (k2, _) in spec.as_object().unwrap() {
                        if k2 != "kind" && k2 != "cue_required" {
                            return Err(format!("tool {}: unknown field in id_args.{}", name, arg));
                        }
                    }
                    id_args.insert(arg.clone(), IdSlot { kind: kind.to_string(), cue_required });
                }
            }
            for c in &content_args {
                if controlling_args.contains(c) {
                    return Err(format!("tool {}: {} cannot be both controlling and content", name, c));
                }
                if let Some(a) = &args {
                    if !a.contains(c) {
                        return Err(format!("tool {}: content arg {} not in args", name, c));
                    }
                }
            }
            if !privileged && (!content_args.is_empty() || !id_args.is_empty() || destructive) {
                return Err(format!("unprivileged tool {} must not declare id_args, content_args or destructive", name));
            }
            if privileged && controlling_args.is_empty() {
                return Err(format!("privileged tool {} must name at least one controlling arg", name));
            }
            if !privileged && !controlling_args.is_empty() {
                return Err(format!("unprivileged tool {} must not list controlling args", name));
            }
            if let Some(a) = &args {
                for c in &controlling_args {
                    if !a.contains(c) {
                        return Err(format!("tool {}: controlling arg {} not in args", name, c));
                    }
                }
            }
            tools.insert(name.clone(), ToolPolicy { privileged, controlling_args, args, id_args, content_args, destructive });
        }
        let digest = crate::crypto::hex(&crate::crypto::sha256(v.to_canonical().as_bytes()));
        Ok(Policy { version: version.to_string(), tools, digest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates() {
        let p = Policy::from_json(
            r#"{"version":"t","tools":{"send":{"privileged":true,"controlling_args":["to"],"args":["to","body"]},"read":{"privileged":false}}}"#,
        )
        .unwrap();
        assert!(p.tools["send"].privileged);
        assert_eq!(p.digest.len(), 64);
    }

    #[test]
    fn rejects_bad_policies() {
        assert!(Policy::from_json(r#"{"version":"t","tools":{"send":{"privileged":true}}}"#).is_err());
        assert!(Policy::from_json(r#"{"version":"t","tools":{"r":{"privileged":false,"controlling_args":["x"]}}}"#).is_err());
        assert!(Policy::from_json(r#"{"version":"t","tools":{"s":{"privileged":true,"controlling_args":["x"],"args":["y"]}}}"#).is_err());
        assert!(Policy::from_json(r#"{"version":"t","tools":{},"extra":1}"#).is_err());
        assert!(Policy::from_json(r#"{"version":"t","tools":{"bad name":{"privileged":false}}}"#).is_err());
        // v2 fields
        assert!(Policy::from_json(r#"{"version":"t","tools":{"d":{"privileged":true,"controlling_args":["f"],"id_args":{"g":{"kind":"file_id","cue_required":true}}}}}"#).is_err());
        assert!(Policy::from_json(r#"{"version":"t","tools":{"d":{"privileged":true,"controlling_args":["f"],"content_args":["f"]}}}"#).is_err());
        assert!(Policy::from_json(r#"{"version":"t","tools":{"r":{"privileged":false,"destructive":true}}}"#).is_err());
        let p = Policy::from_json(r#"{"version":"t","tools":{"d":{"privileged":true,"destructive":true,"controlling_args":["f"],"content_args":["b"],"id_args":{"f":{"kind":"file_id","cue_required":true}}}}}"#).unwrap();
        assert!(p.tools["d"].destructive && p.tools["d"].id_args["f"].cue_required);
    }
}
