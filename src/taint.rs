//! Provenance labels and conservative taint classification of argument values.
//!
//! Design rule (asymmetric on purpose):
//! - A value counts as TRUSTED only if it appears, with token boundaries on
//!   both sides, inside a trusted span (system or user). Matching for trust is
//!   strict: exact, or after a light normalization (case fold, whitespace
//!   collapse, removal of invisible format characters). It never strips
//!   punctuation, because "bob@example.co" must not match "bob@example.com".
//! - A value counts as TAINTED if, failing that, it appears in any untrusted
//!   tool-output span under an aggressive normalization (lowercase,
//!   alphanumerics only). False taint is the safe direction.
//! - Otherwise it is UNKNOWN. The gate treats UNKNOWN exactly like TAINTED for
//!   controlling arguments: trust has to be shown, not assumed.
//!
//! Limits (also in README): this is value matching, not data-flow tracking.
//! It cannot see through encodings, translations, arithmetic, or a model that
//! copies a trusted-looking value chosen because of untrusted text (for
//! example, the user names two contacts and an injection picks which one).

use crate::json::{format_number, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Label {
    TrustedSystem,
    TrustedUser,
    UntrustedTool,
    /// v2: an identifier the tool runtime generated (file id, event id, ...),
    /// extracted by the dispatcher from a structured field of a tool result,
    /// never from free text. Usable only in policy-declared ID slots of the
    /// same kind.
    SystemId,
}

impl Label {
    pub fn parse(s: &str) -> Option<Label> {
        match s {
            "trusted_system" => Some(Label::TrustedSystem),
            "trusted_user" => Some(Label::TrustedUser),
            "untrusted_tool" => Some(Label::UntrustedTool),
            "system_id" => Some(Label::SystemId),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Label::TrustedSystem => "trusted_system",
            Label::TrustedUser => "trusted_user",
            Label::UntrustedTool => "untrusted_tool",
            Label::SystemId => "system_id",
        }
    }
    /// Trusted as free text (system prompt or user turn). SystemId is not.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Label::TrustedSystem | Label::TrustedUser)
    }
}

#[derive(Debug, Clone)]
pub struct Span {
    pub label: Label,
    pub text: String,
    /// Only for SystemId spans: the ID kind (for example "file_id").
    pub kind: Option<String>,
}

impl Span {
    pub fn text(label: Label, text: &str) -> Span {
        Span { label, text: text.to_string(), kind: None }
    }
}

/// Pre-normalized context, built once per request.
pub struct Context {
    trusted: Vec<(Label, String, String)>, // (label, raw, strict-normalized)
    untrusted_loose: Vec<String>,
    ids: std::collections::BTreeSet<(String, String)>, // (kind, exact value)
}

impl Context {
    pub fn new(spans: &[Span]) -> Context {
        let mut trusted = Vec::new();
        let mut untrusted_loose = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for s in spans {
            match s.label {
                Label::TrustedSystem | Label::TrustedUser => {
                    trusted.push((s.label, s.text.clone(), strict_norm(&s.text)))
                }
                Label::UntrustedTool => untrusted_loose.push(loose_norm(&s.text)),
                Label::SystemId => {
                    if let Some(k) = &s.kind {
                        ids.insert((k.clone(), s.text.clone()));
                    }
                }
            }
        }
        Context { trusted, untrusted_loose, ids }
    }

    /// Exact (kind, value) match against tool-generated IDs.
    pub fn has_system_id(&self, kind: &str, value: &str) -> bool {
        self.ids.contains(&(kind.to_string(), value.to_string()))
    }

    /// Strict, token-bounded match in trusted text only.
    pub fn text_trust(&self, value: &str) -> Option<(Label, &'static str)> {
        let strict_v = strict_norm(value);
        if strict_v.is_empty() {
            return None;
        }
        let raw_trim = value.trim();
        for (label, raw, _) in &self.trusted {
            if bounded_contains(raw, raw_trim) {
                return Some((*label, "exact"));
            }
        }
        for (label, _, norm) in &self.trusted {
            if bounded_contains(norm, &strict_v) {
                return Some((*label, "normalized"));
            }
        }
        None
    }

    /// Role rule for opaque ID slots: the value must appear in trusted text
    /// as an ID, that is right after a cue ("id", "ids", "number", "no", or
    /// a '#'). "May 13" does not make "13" a trusted file id; "file ID 13" does.
    pub fn id_cue_trust(&self, value: &str) -> Option<Label> {
        let v = strict_norm(value);
        if v.is_empty() {
            return None;
        }
        for (label, _, norm) in &self.trusted {
            for start in bounded_positions(norm, &v) {
                let pre = &norm[..start];
                let had_hash = pre.ends_with('#');
                let t = pre.trim_end_matches(|c: char| c.is_whitespace() || "'\"`:#=([".contains(c));
                let last = t.rsplit(' ').next().unwrap_or("");
                if had_hash || matches!(last, "id" | "ids" | "id_" | "number" | "no" | "no.") {
                    return Some(*label);
                }
            }
        }
        None
    }

    pub fn tainted(&self, value: &str) -> bool {
        let loose_v = loose_norm(value);
        !loose_v.is_empty() && self.untrusted_loose.iter().any(|u| u.contains(&loose_v))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Trusted { source: Label, method: &'static str },
    Tainted,
    Unknown,
}

impl Status {
    pub fn name(&self) -> &'static str {
        match self {
            Status::Trusted { .. } => "trusted",
            Status::Tainted => "tainted",
            Status::Unknown => "unknown",
        }
    }
}

fn is_invisible(c: char) -> bool {
    matches!(c, '\u{00AD}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Strict normalization for trust: case fold, drop invisible format chars,
/// collapse whitespace runs to one ASCII space, trim.
pub fn strict_norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending_space = false;
    for c in s.chars() {
        if is_invisible(c) {
            continue;
        }
        if c.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        for l in c.to_lowercase() {
            out.push(l);
        }
    }
    out
}

/// Loose normalization for taint detection: lowercase alphanumerics only.
pub fn loose_norm(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_alphanumeric() {
            for l in c.to_lowercase() {
                out.push(l);
            }
        }
    }
    out
}

fn left_boundary(c: Option<char>) -> bool {
    match c {
        None => true,
        Some(c) => c.is_whitespace() || "\"'`([{<,;:$\u{20ac}\u{a3}=#".contains(c),
    }
}

fn right_boundary(rest: &str) -> bool {
    let mut it = rest.chars();
    match it.next() {
        None => true,
        Some(c) if c.is_whitespace() || "\"'`)]}>,;".contains(c) => true,
        // Sentence punctuation counts only when it ends the token.
        Some(c) if ".!?:".contains(c) => match it.next() {
            None => true,
            Some(d) => d.is_whitespace() || "\"'`)]}>,;".contains(d),
        },
        _ => false,
    }
}

/// Byte offsets where `needle` occurs in `hay` with token boundaries on both sides.
pub fn bounded_positions(hay: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    if needle.is_empty() || needle.len() > hay.len() {
        return out;
    }
    let mut from = 0;
    while let Some(pos) = hay[from..].find(needle) {
        let start = from + pos;
        let end = start + needle.len();
        let before = hay[..start].chars().next_back();
        if left_boundary(before) && right_boundary(&hay[end..]) {
            out.push(start);
        }
        let step = hay[start..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        from = start + step;
    }
    out
}

/// True if `needle` occurs in `hay` with token boundaries on both sides.
pub fn bounded_contains(hay: &str, needle: &str) -> bool {
    !bounded_positions(hay, needle).is_empty()
}

/// v2 content check: extract URLs, email addresses and IBANs from free text.
/// Returns (kind, entity). Deliberately broad; a false hit only costs a CONFIRM.
pub fn extract_entities(s: &str) -> Vec<(&'static str, String)> {
    const TLDS: &[&str] = &[
        "com", "net", "org", "io", "co", "gov", "edu", "info", "biz", "me", "ai", "app", "dev", "uk", "de",
        "fr", "us", "ch", "eu", "ly", "xyz", "site", "online", "ru", "cn", "tk", "top", "link", "page",
    ];
    let mut out: Vec<(&'static str, String)> = Vec::new();
    for raw in s.split(|c: char| c.is_whitespace() || "\"'<>()[]{},;|`".contains(c)) {
        let tok = raw.trim_end_matches(|c: char| ".!?:".contains(c)).trim_start_matches(|c: char| ":".contains(c));
        if tok.is_empty() {
            continue;
        }
        let lower = tok.to_lowercase();
        let kind = if let Some(at) = tok.find('@') {
            let (l, d) = (&tok[..at], &tok[at + 1..]);
            if !l.is_empty() && d.contains('.') && !d.starts_with('.') {
                Some("email")
            } else {
                None
            }
        } else if lower.contains("://") || lower.starts_with("www.") {
            Some("url")
        } else {
            let host = lower.split('/').next().unwrap_or("");
            let tld = host.rsplit('.').next().unwrap_or("");
            if host.contains('.') && TLDS.contains(&tld) && host.split('.').all(|p| !p.is_empty()) {
                Some("url")
            } else {
                let b = tok.as_bytes();
                if b.len() >= 14
                    && b.len() <= 34
                    && b[0].is_ascii_uppercase()
                    && b[1].is_ascii_uppercase()
                    && b[2].is_ascii_digit()
                    && b[3].is_ascii_digit()
                    && b[4..].iter().all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
                {
                    Some("iban")
                } else {
                    None
                }
            }
        };
        if let Some(k) = kind {
            if !out.iter().any(|(_, e)| e == tok) {
                out.push((k, tok.to_string()));
            }
        }
    }
    out
}

/// Classify one scalar string value.
pub fn classify_str(ctx: &Context, value: &str) -> Status {
    // Empty or whitespace-only carries no positive evidence: Unknown (fail closed).
    if let Some((source, method)) = ctx.text_trust(value) {
        return Status::Trusted { source, method };
    }
    if ctx.tainted(value) {
        return Status::Tainted;
    }
    Status::Unknown
}

/// v2: classify a scalar in a policy-declared ID slot of `kind`.
/// Trust sources, in order: (1) trusted text with an ID cue (or, for
/// name-like ID kinds, any token-bounded trusted-text match); (2) an exact
/// tool-generated ID of the same kind. Free text from tool output never counts.
pub fn classify_id(ctx: &Context, kind: &str, cue_required: bool, value: &str) -> Status {
    if cue_required {
        if let Some(l) = ctx.id_cue_trust(value) {
            return Status::Trusted { source: l, method: "user_id_cue" };
        }
    } else if let Some((source, method)) = ctx.text_trust(value) {
        return Status::Trusted { source, method };
    }
    if ctx.has_system_id(kind, value) {
        return Status::Trusted { source: Label::SystemId, method: "system_id" };
    }
    if ctx.tainted(value) {
        return Status::Tainted;
    }
    Status::Unknown
}

/// Scalar leaves of a value as strings (object keys included).
pub fn scalar_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Null => {}
        Value::Bool(b) => out.push(b.to_string()),
        Value::Number(n) => out.push(format_number(*n)),
        Value::String(s) => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| scalar_strings(x, out)),
        Value::Object(kv) => kv.iter().for_each(|(k, x)| {
            out.push(k.clone());
            scalar_strings(x, out)
        }),
    }
}

/// One leaf of an argument value with its status.
#[derive(Debug, Clone)]
pub struct Leaf {
    pub preview: String,
    pub status: Status,
}

fn preview(s: &str) -> String {
    let p: String = s.chars().take(80).collect();
    if s.chars().count() > 80 {
        format!("{}...", p)
    } else {
        p
    }
}

/// Classify every scalar leaf of an argument value (arrays and objects are
/// walked; object keys are classified too, since they are data).
pub fn classify_value(ctx: &Context, v: &Value, out: &mut Vec<Leaf>) {
    match v {
        Value::Null => {}
        Value::Bool(b) => out.push(Leaf {
            preview: b.to_string(),
            // A boolean carries attacker choice but no text to match: fail closed.
            status: Status::Unknown,
        }),
        Value::Number(n) => {
            let s = format_number(*n);
            out.push(Leaf { status: classify_str(ctx, &s), preview: s });
        }
        Value::String(s) => out.push(Leaf { preview: preview(s), status: classify_str(ctx, s) }),
        Value::Array(a) => {
            for x in a {
                classify_value(ctx, x, out);
            }
        }
        Value::Object(kv) => {
            for (k, x) in kv {
                out.push(Leaf { preview: preview(k), status: classify_str(ctx, k) });
                classify_value(ctx, x, out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(user: &str, tool: &str) -> Context {
        Context::new(&[
            Span::text(Label::TrustedSystem, "You are a helpful assistant."),
            Span::text(Label::TrustedUser, user),
            Span::text(Label::UntrustedTool, tool),
        ])
    }

    #[test]
    fn exact_and_normalized_trust() {
        let c = ctx("Please email Bob@Example.com the report.", "");
        assert!(matches!(classify_str(&c, "Bob@Example.com"), Status::Trusted { method: "exact", .. }));
        assert!(matches!(classify_str(&c, "bob@example.com"), Status::Trusted { method: "normalized", .. }));
    }

    #[test]
    fn boundaries_block_prefix_and_suffix_lookalikes() {
        let c = ctx("Please email bob@example.com today.", "");
        assert_eq!(classify_str(&c, "bob@example.co"), Status::Unknown);
        assert_eq!(classify_str(&c, "example.com"), Status::Unknown);
        assert_eq!(classify_str(&c, "ob@example.com"), Status::Unknown);
        // Sentence-final period is a boundary.
        let c2 = ctx("Send it to alice@corp.io.", "");
        assert!(matches!(classify_str(&c2, "alice@corp.io"), Status::Trusted { .. }));
    }

    #[test]
    fn punctuation_not_stripped_for_trust() {
        let c = ctx("pay bob@example.com", "");
        assert_eq!(classify_str(&c, "bob.example@com"), Status::Unknown);
    }

    #[test]
    fn taint_is_loose() {
        let c = ctx("pay my bill", "IBAN: US13-3000 0001 2121 2121 2121 2");
        assert_eq!(classify_str(&c, "US133000000121212121212"), Status::Tainted);
    }

    #[test]
    fn invisible_chars_and_whitespace() {
        let c = ctx("Book the  Le\u{200B} Marais   Boutique please", "");
        assert!(matches!(classify_str(&c, "le marais boutique"), Status::Trusted { method: "normalized", .. }));
    }

    #[test]
    fn empty_and_unseen_are_unknown() {
        let c = ctx("hello", "world");
        assert_eq!(classify_str(&c, ""), Status::Unknown);
        assert_eq!(classify_str(&c, "   "), Status::Unknown);
        assert_eq!(classify_str(&c, "zzz"), Status::Unknown);
    }

    #[test]
    fn id_cue_rule() {
        let c = ctx("Delete the file with ID '13'. Also my meeting on May 14.", "");
        assert!(c.id_cue_trust("13").is_some());
        assert!(c.id_cue_trust("14").is_none());
        let c2 = ctx("Close ticket #42 please", "");
        assert!(c2.id_cue_trust("42").is_some());
    }

    #[test]
    fn system_ids_only_in_matching_kind_and_not_as_text() {
        let c = Context::new(&[
            Span::text(Label::TrustedUser, "tidy my drive"),
            Span { label: Label::SystemId, text: "7".into(), kind: Some("file_id".into()) },
        ]);
        assert!(matches!(classify_id(&c, "file_id", true, "7"), Status::Trusted { method: "system_id", .. }));
        assert!(!matches!(classify_id(&c, "event_id", true, "7"), Status::Trusted { .. }));
        // A system id is not trusted text for ordinary slots.
        assert!(!matches!(classify_str(&c, "7"), Status::Trusted { .. }));
    }

    #[test]
    fn entity_extraction() {
        let e = extract_entities("Visit www.secure-systems-252.com or https://x.io/a?b=1, mail eve@evil.example. IBAN US133000000121212121212 e.g. fine.");
        let kinds: Vec<&str> = e.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, vec!["url", "url", "email", "iban"]);
        assert_eq!(e[0].1, "www.secure-systems-252.com");
        assert!(extract_entities("Hi Bob, see you at 10.30 on Monday. Mr.Smith").is_empty());
        assert_eq!(extract_entities("go to my-site.com/page")[0].0, "url");
    }

    #[test]
    fn short_values_need_token_boundaries() {
        let c = ctx("send 100 to bob", "");
        assert!(matches!(classify_str(&c, "100"), Status::Trusted { .. }));
        assert_eq!(classify_str(&c, "10"), Status::Unknown);
        assert_eq!(classify_str(&c, "o"), Status::Unknown);
    }
}
