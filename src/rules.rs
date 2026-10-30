//! Rules are data. Add a row to a table to add a rule; no code changes.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Check {
    /// Any match counts.
    Plain,
    /// A match counts only if it is exactly this many digits and passes Luhn.
    /// `Luhn(0)` means "13 or more digits" (card numbers).
    Luhn(usize),
    /// An assigned secret: the value after the `:` or `=` needs Shannon entropy of at least
    /// `MIN_VALUE_ENTROPY` bits and must not contain a stopword (gitleaks generic-api-key shape).
    Secret,
    /// An email address whose host has a label that mixes scripts beyond UTS #39 "Highly
    /// Restrictive" (Latin plus Cyrillic, for example). Single script hosts, accented Latin
    /// included, do not match; the provider list handles those.
    MixedScriptHost,
}

/// Bits per character the value of an assigned secret must carry (gitleaks generic-api-key: 3.5).
pub const MIN_VALUE_ENTROPY: f64 = 3.5;

/// Lowercase substrings that mark a value as a name, type or call rather than a secret. Copied in
/// shape from the gitleaks generic-api-key stopword list; not the same list, not exhaustive.
pub const STOPWORDS: &[&str] = &[
    "process", "environ", "setting", "config", "undefined", "required", "optional", "string",
    "random", "secret", "password", "passwd", "token_", "getenv", "example", "sample", "default",
    "placeholder", "changeme", "credential", "variable", "argument", "parameter", "property",
    "function", "object", "boolean", "integer", "nullable", "default", "storage", "manager",
    "provider", "service", "client", "request", "response", "session", "encrypt", "decrypt",
    "generate", "length", "format", "buffer", "bytes", "input", "value", "field", "label",
    "prompt", "false", "true", "none", "null", "self.", "this.", "args.", "kwargs", "params",
];

fn shannon_bits(s: &str) -> f64 {
    let mut n = std::collections::HashMap::new();
    let mut len = 0f64;
    for c in s.chars() {
        *n.entry(c).or_insert(0u32) += 1;
        len += 1.0;
    }
    n.values().map(|&k| { let p = k as f64 / len; -p * p.log2() }).sum()
}

/// True when the matched assignment `name sep value` has a value that could be a secret.
pub fn secret_value_ok(m: &str) -> bool {
    let Some(i) = m.find([':', '=']) else { return false };
    let v = m[i + 1..].trim().trim_matches(|c| c == '\'' || c == '"');
    let low = v.to_lowercase();
    shannon_bits(v) >= MIN_VALUE_ENTROPY && !STOPWORDS.iter().any(|w| low.contains(w))
}

/// True when `m` is `local` joined to `host` by the at sign and some label of the host is non-ASCII and above the UTS #39
/// Highly Restrictive level (unicode-security RestrictionLevelDetection).
pub fn mixed_script_host(m: &str) -> bool {
    use unicode_security::RestrictionLevelDetection;
    use unicode_security::restriction_level::RestrictionLevel;
    let Some((_, host)) = m.rsplit_once('@') else { return false };
    host.split('.').any(|label| {
        !label.is_ascii() && label.detect_restriction_level() > RestrictionLevel::HighlyRestrictive
    })
}

pub struct Rule {
    pub category: &'static str,
    pub placeholder: &'static str,
    pub pattern: &'static str,
    pub check: Check,
}

const fn r(
    category: &'static str,
    placeholder: &'static str,
    pattern: &'static str,
    check: Check,
) -> Rule {
    Rule {
        category,
        placeholder,
        pattern,
        check,
    }
}

/// Order matters for `mask`: most specific first, so a card is not eaten as a phone number.
pub const RULES: &[Rule] = &[
    r(
        "secret:aws_key_id",
        "[SECRET]",
        r"AKIA[0-9A-Z]{16}",
        Check::Plain,
    ),
    r(
        "secret:api_key",
        "[SECRET]",
        r"sk-[A-Za-z0-9_-]{20,}",
        Check::Plain,
    ),
    r(
        "secret:github_token",
        "[SECRET]",
        r"ghp_[A-Za-z0-9]{30,}",
        Check::Plain,
    ),
    r(
        "secret:slack_token",
        "[SECRET]",
        r"xox[abp]-[A-Za-z0-9-]{10,}",
        Check::Plain,
    ),
    r(
        "secret:google_key",
        "[SECRET]",
        r"AIza[0-9A-Za-z_-]{30,}",
        Check::Plain,
    ),
    r(
        "secret:private_key",
        "[SECRET]",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        Check::Plain,
    ),
    r(
        "secret:assigned_secret",
        "[SECRET]",
        r#"(?i)(aws_secret_access_key|api[_-]?key|secret|password)['"]?\s*[:=]\s*(?:['"][^'"]{8,}['"]|[A-Za-z0-9+/=_.-]{8,})"#,
        Check::Secret,
    ),
    // Brand anchored first group (shape from Presidio card recogniser, reference unverified: no network
    // when written, so no URL or commit is cited; Presidio shape: issuer digits 2 to 6, then bounded groups), so a
    // trailing CVV or expiry falls outside the match and Luhn runs on the card's own digits.
    // 16 digit (4-4-4-4), 15 digit Amex (4-6-5), 13 digit and 19 digit (the extra 3 digits glued, never after a separator, so a CVV stays outside).
    r(
        "personal:card",
        "[CARD]",
        r"\b(?:[2-6]\d{3}(?:[\s.\-/_,:]{0,3}\d{4}){3}(?:\d{3})?|3[47]\d{2}[\s.\-/_,:]{0,3}\d{6}[\s.\-/_,:]{0,3}\d{5}|4\d{3}[\s.\-/_,:]{0,3}\d{3}[\s.\-/_,:]{0,3}\d{3}[\s.\-/_,:]{0,3}\d{3})\b",
        Check::Luhn(0),
    ),
    r(
        "personal:sin",
        "[SIN]",
        r"\b\d{3}[\s.\-/_,:]{0,3}\d{3}[\s.\-/_,:]{0,3}\d{3}\b",
        Check::Luhn(9),
    ),
    r(
        "personal:email",
        "[EMAIL]",
        r"(?i)\b[A-Za-z0-9._%+-]+@(?:gmail|hotmail|yahoo|outlook|icloud)\.[a-z]{2,}\b",
        Check::Plain,
    ),
    // A mixed script host label is the lookalike of a provider name; see `mixed_script_host`.
    r(
        "personal:email",
        "[EMAIL]",
        r"[\w.%+\-]+@[\w\-]+(?:\.[\w\-]+)+",
        Check::MixedScriptHost,
    ),
    r(
        "personal:phone",
        "[PHONE]",
        r"(?:\+1[ .\-]*|\b1[ .\-]+)?\(?\b[2-9]\d{2}\)?[ .\-/]*[2-9]\d{2}[ .\-/]*\d{4}\b",
        Check::Plain,
    ),
];

/// Topic words are never shipped. An optional private list is loaded from the file named by
/// `ARROWMEM_GATE_BLOCKLIST`, one word per line, case-insensitive. A hit blocks the whole text.
pub const TOPIC_CATEGORY: &str = "topic:blocked_word";

/// Luhn over the digits of `s`: every non-digit between digits is ignored (standard DLP
/// behaviour). Unicode digits are folded to ASCII by `decode::fold` before the rules run.
pub fn luhn(s: &str, exact_len: usize) -> bool {
    let mut d: Vec<u32> = Vec::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            d.push(c as u32 - '0' as u32);
        }
    }
    let len_ok = if exact_len == 0 {
        d.len() >= 13
    } else {
        d.len() == exact_len
    };
    if !len_ok {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 0 {
                x
            } else if x * 2 > 9 {
                x * 2 - 9
            } else {
                x * 2
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

pub const BLOCKLIST_UNREADABLE: &str = "topic:blocklist_unreadable";

/// Parse a blocklist: one word per line, blank lines ignored, lowercased.
pub fn load_blocklist(path: &str) -> std::io::Result<Vec<String>> {
    let t = std::fs::read_to_string(path)?;
    Ok(t.lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty())
        .collect())
}
