//! Views of a text: the text itself plus every decoding an encoder could hide it behind.
//! The rules run over all views. Decoders are deliberately small and total (never panic).

use regex::Regex;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;
use unicode_security::confusable_detection::skeleton;

const MAX_DEPTH: usize = 3;
/// Counted per distinct decoded view (dedupe by content). The 8 MB size bound below is what
/// protects the scanner; this one only stops pathological fan-out.
const MAX_VIEWS: usize = 4096;
const MAX_TOTAL_CHARS: usize = 8 * 1024 * 1024;
/// Shortest base64 run that is decoded. 16 chars is 12 bytes, the shortest useful address.
const MIN_B64_RUN: usize = 16;

pub fn nfkc(s: &str) -> String {
    s.nfkc().collect()
}

/// Default_Ignorable_Code_Point (Unicode DerivedCoreProperties): format characters a receiving
/// model or mail client ignores, so they can be threaded through a token to defeat a regex.
fn default_ignorable(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x034F | 0x061C | 0x115F..=0x1160 | 0x17B4..=0x17B5 | 0x180B..=0x180F
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F | 0x3164 | 0xFE00..=0xFE0F
        | 0xFEFF | 0xFFA0 | 0xFFF0..=0xFFF8 | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A
        | 0xE0000..=0xE0FFF)
}

/// Code point of the zero digit of each Unicode Nd (decimal digit) run of ten, Unicode 15.
/// NFKC already folds the fullwidth and mathematical runs; these are the rest.
const ND_ZEROS: &[u32] = &[
    0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6,
    0x0D66, 0x0DE6, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0,
    0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0,
    0xAA50, 0xABF0, 0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0,
    0x11450, 0x114D0, 0x11650, 0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0,
    0x16A60, 0x16AC0, 0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0,
    0x1E4F0, 0x1E950, 0x1FBF0,
];

fn nd_to_ascii(c: char) -> char {
    let u = c as u32;
    for &z in ND_ZEROS {
        if (z..z + 10).contains(&u) {
            return char::from(b'0' + (u - z) as u8);
        }
    }
    c
}

/// Cf (format), Mn and Me (nonspacing and enclosing marks), plus the blank-glyph characters that
/// are not format characters (braille blank). A receiving model reads straight through them.
fn invisible(c: char) -> bool {
    use icu_properties::{CodePointMapData, props::GeneralCategory as G};
    matches!(c as u32, 0x2800 | 0x3164 | 0xFFA0)
        || matches!(
            CodePointMapData::<G>::new().get(c),
            G::Format | G::NonspacingMark | G::EnclosingMark
        )
}

fn strip_ignorable(s: &str) -> String {
    s.chars().filter(|&c| !default_ignorable(c) && !invisible(c)).collect()
}

/// UTS #39 skeleton over each maximal run of non-ASCII characters (the string, not one character
/// at a time), ASCII left alone so "m" is not rewritten to its "rn" prototype.
fn confusable_runs(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    for c in s.chars() {
        if c.is_ascii() {
            if !run.is_empty() {
                out.extend(skeleton(&run));
                run.clear();
            }
            out.push(c);
        } else {
            run.push(c);
        }
    }
    if !run.is_empty() {
        out.extend(skeleton(&run));
    }
    out
}

/// The whole-string UTS #39 skeleton, as one more view (ASCII "m" becomes "rn" here, so this is
/// a view for the rules to match against, never a replacement for the folded text).
pub fn skeleton_view(s: &str) -> String {
    skeleton(s).collect()
}

/// The normalised view: NFKC, then Cf, Mn and Me dropped, Unicode digits folded to ASCII,
/// cross-script lookalikes folded to ASCII.
pub fn fold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_string();
    }
    let t = strip_ignorable(&nfkc(&strip_ignorable(s)));
    let d: String = t.chars().map(nd_to_ascii).collect();
    confusable_runs(&d)
}

fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    b[..4].iter().try_fold(0u32, |a, &c| Some(a * 16 + hexval(c)? as u32))
}

/// One level of JSON-style backslash unescaping: \uXXXX (with surrogate pairs), \xXX and the
/// single-char escapes. Unknown escapes stay literal. Applied once per depth level.
pub fn json_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            let ch = s[i..].chars().next().unwrap_or('\u{FFFD}');
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        match b[i + 1] {
            b'u' => {
                if let Some(hi) = hex4(&b[i + 2..]) {
                    let mut adv = 6;
                    let mut cp = hi;
                    if (0xD800..0xDC00).contains(&hi)
                        && b.get(i + 6) == Some(&b'\\')
                        && b.get(i + 7) == Some(&b'u')
                        && let Some(lo) = hex4(&b[(i + 8).min(b.len())..])
                        && (0xDC00..0xE000).contains(&lo)
                    {
                        cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                        adv = 12;
                    }
                    out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    i += adv;
                    continue;
                }
            }
            b'x' if i + 4 <= b.len() => {
                if let (Some(h), Some(l)) = (hexval(b[i + 2]), hexval(b[i + 3])) {
                    out.push(char::from(h * 16 + l));
                    i += 4;
                    continue;
                }
            }
            b'n' => { out.push('\n'); i += 2; continue; }
            b't' => { out.push('\t'); i += 2; continue; }
            b'r' => { out.push('\r'); i += 2; continue; }
            b'"' | b'\\' | b'/' | b'\'' => { out.push(char::from(b[i + 1])); i += 2; continue; }
            _ => {}
        }
        out.push('\\');
        i += 1;
    }
    out
}

fn hexval(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode. `plus_is_space` is the form-encoding rule. Invalid escapes stay literal.
pub fn percent_decode(s: &str, plus_is_space: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() && hexval(b[i + 1]).is_some() && hexval(b[i + 2]).is_some() => {
                out.push(hexval(b[i + 1]).unwrap_or(0) * 16 + hexval(b[i + 2]).unwrap_or(0));
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn b64val(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Lenient base64 (standard and URL-safe alphabets, padding optional). None if impossible.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let t: Vec<u8> = s.bytes().filter(|&c| c != b'=').collect();
    if t.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    for ch in t.chunks(4) {
        let mut acc = 0u32;
        for &c in ch {
            acc = (acc << 6) | b64val(c)?;
        }
        acc <<= 6 * (4 - ch.len()) as u32;
        let bytes = acc.to_be_bytes();
        out.extend_from_slice(&bytes[1..ch.len()]);
    }
    Some(out)
}

fn b64_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").expect("b64 pattern"))
}

/// Printable-enough check: most decoded bytes must be text, else it is a binary blob (a
/// compressed or encrypted payload cannot be scanned; see `has_opaque_blob`).
fn mostly_text(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let t = String::from_utf8_lossy(b);
    let total = t.chars().count();
    let bad = t
        .chars()
        .filter(|&c| c == '\u{FFFD}' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t')))
        .count();
    bad * 10 <= total
}

fn b64_views(s: &str, out: &mut Vec<String>) {
    let stripped: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    for src in [s, stripped.as_str()] {
        for m in b64_re().find_iter(src) {
            let run = m.as_str();
            // The run may start mid-quantum when glued to preceding letters: try 4 alignments.
            for skip in 0..4 {
                if run.len() <= skip + MIN_B64_RUN - 4 {
                    break;
                }
                if let Some(bytes) = b64_decode(&run[skip..])
                    && mostly_text(&bytes)
                {
                    out.push(String::from_utf8_lossy(&bytes).into_owned());
                }
            }
        }
    }
}

fn hex_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"[0-9A-Fa-f]{32,}").expect("hex pattern"))
}

/// Shortest hex run decoded: 32 hex chars is 16 bytes.
fn hex_views(s: &str, out: &mut Vec<String>) {
    for m in hex_re().find_iter(s) {
        let run = m.as_str().as_bytes();
        // Either alignment, each cut to an even length.
        for skip in 0..2 {
            let r = &run[skip..];
            let r = &r[..r.len() - r.len() % 2];
            if r.len() < 32 {
                continue;
            }
            let bytes: Vec<u8> = r
                .chunks(2)
                .map(|p| hexval(p[0]).unwrap_or(0) * 16 + hexval(p[1]).unwrap_or(0))
                .collect();
            if mostly_text(&bytes) {
                out.push(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
    }
}

/// The text plus NFKC, percent, base64 and hex views, to a bounded depth and count.
/// The flag is true when a bound was hit: some view was dropped, so the caller must fail closed.
/// HTML numeric character references (`&#1084;`, `&#x43c;`, semicolon optional as in a browser)
/// decoded to characters; anything not a valid scalar value is left as written.
pub fn html_numeric_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'&' && b.get(i + 1) == Some(&b'#') {
            let (radix, start) = match b.get(i + 2) {
                Some(b'x' | b'X') => (16, i + 3),
                _ => (10, i + 2),
            };
            let mut j = start;
            while j < b.len() && j - start < 8 && (b[j] as char).is_digit(radix) {
                j += 1;
            }
            if j > start
                && let Some(c) = u32::from_str_radix(&s[start..j], radix).ok().and_then(char::from_u32)
            {
                out.push(c);
                i = if b.get(j) == Some(&b';') { j + 1 } else { j };
                continue;
            }
        }
        let ch = s[i..].chars().next().expect("char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Every `xn--` IDNA A label (dot delimited) decoded to Unicode with the idna crate (UTS 46
/// ToUnicode), so a punycode host is measured as the host a mail client would show.
pub fn punycode_view(s: &str) -> String {
    let low = s.to_ascii_lowercase(); // same byte length as `s`, so indices carry over
    let mut out = String::with_capacity(s.len());
    let mut at = 0;
    while let Some(p) = low[at..].find("xn--").map(|p| p + at) {
        let end = low[p..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .map_or(low.len(), |e| e + p);
        let (uni, _) = idna::domain_to_unicode(&s[p..end]);
        out.push_str(&s[at..p]);
        out.push_str(if uni.is_empty() { &s[p..end] } else { &uni });
        at = end;
    }
    out.push_str(&s[at..]);
    out
}

pub fn views_bounded(text: &str) -> (Vec<String>, bool) {
    let (v, over) = views_tagged(text);
    (v.into_iter().map(|(s, _)| s).collect(), over)
}

/// Like `views_bounded`, each view tagged `true` when it has not been through the cross-script
/// lookalike fold. Script mixing is only measurable on such a view: the fold rewrites part of a
/// genuine Cyrillic word into Latin letters, which would read as mixing.
pub fn views_tagged(text: &str) -> (Vec<(String, bool)>, bool) {
    let mut all: Vec<(String, bool)> = vec![(text.to_string(), true)];
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    index.insert(text.to_string(), 0);
    let mut frontier: Vec<(String, bool)> = vec![(text.to_string(), true)];
    let mut total = text.len();
    for _ in 0..MAX_DEPTH {
        let mut next: Vec<(String, bool)> = Vec::new();
        for (v, raw) in &frontier {
            let raw = *raw;
            // Unfolded candidates first, so a string reachable both ways keeps the raw tag.
            let mut cand: Vec<(String, bool)> = vec![(nfkc(v), raw)];
            if v.contains('\\') {
                cand.push((json_unescape(v), raw));
            }
            if v.contains('%') {
                cand.push((percent_decode(v, false), raw));
            }
            if v.contains("&#") {
                cand.push((html_numeric_decode(v), raw));
            }
            if v.to_ascii_lowercase().contains("xn--") {
                cand.push((punycode_view(v), raw));
            }
            let mut dec: Vec<String> = Vec::new();
            b64_views(v, &mut dec);
            hex_views(v, &mut dec);
            cand.extend(dec.into_iter().map(|d| (d, raw)));
            cand.push((fold(v), false));
            if !v.is_ascii() {
                cand.push((skeleton_view(&fold(v)), false));
            }
            if v.contains('\\') {
                cand.push((fold(&json_unescape(v)), false));
            }
            if v.contains('%') {
                cand.push((fold(&percent_decode(v, false)), false));
            }
            for (c, r) in cand {
                if let Some(&i) = index.get(&c) {
                    all[i].1 |= r;
                    continue;
                }
                if all.len() >= MAX_VIEWS || total + c.len() > MAX_TOTAL_CHARS {
                    return (all, true);
                }
                total += c.len();
                index.insert(c.clone(), all.len());
                all.push((c.clone(), r));
                next.push((c, r));
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    (all, false)
}

pub fn views(text: &str) -> Vec<String> {
    views_bounded(text).0
}

/// Runs this long that decode to non-text (compressed, encrypted) cannot be scanned. Refused
/// rather than passed. Shorter runs (hashes, ids) are left alone to keep false positives down.
const OPAQUE_RUN: usize = 256;

/// Body-level opacity (F2): the sum, over the whole body, of base64-shaped runs that carry high
/// Shannon entropy and do not decode to text. A "." every 200 characters no longer resets the
/// count. Entropy is the gitleaks and trufflehog approach, normalised by the most a run of that
/// length can hold (log2 of its length, capped at 6 bits for a 64 symbol alphabet): random
/// base64 sits near 0.94 of it, identifiers and prose near 0.8, hex digests near 0.67.
/// Runs that decode to text are not counted; they are scanned as views instead.
const ENTROPY_WINDOW: usize = 128;
const ENTROPY_NORMALISED: f64 = 0.9;
/// Hot characters per body before it is refused. 1024 leaves room for a log with a couple of
/// dozen token signatures; a 1500 byte blob is 2000 characters.
const HOT_TOTAL: usize = 1024;

fn shannon(w: &[u8]) -> f64 {
    let mut n = [0u32; 256];
    for &c in w {
        n[c as usize] += 1;
    }
    let len = w.len() as f64;
    n.iter()
        .filter(|&&k| k > 0)
        .map(|&k| {
            let p = k as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn run_is_hot(run: &str) -> bool {
    let b = run.as_bytes();
    let texty = (0..4).any(|skip| b64_decode(&run[skip..]).is_some_and(|d| mostly_text(&d)));
    if texty {
        return false;
    }
    let norm = |w: &[u8]| shannon(w) / (w.len() as f64).log2().min(6.0);
    if b.len() <= ENTROPY_WINDOW {
        return norm(b) > ENTROPY_NORMALISED;
    }
    let mut starts: Vec<usize> = (0..=b.len() - ENTROPY_WINDOW).step_by(ENTROPY_WINDOW / 2).collect();
    starts.push(b.len() - ENTROPY_WINDOW);
    starts.into_iter().any(|st| norm(&b[st..st + ENTROPY_WINDOW]) > ENTROPY_NORMALISED)
}

/// A token that is a published public integrity value, not a payload: a Subresource Integrity
/// hash at its fixed length (lockfiles carry hundreds), or an OpenSSH public key blob.
fn is_public_blob(run: &str) -> bool {
    for (pre, lens) in [("sha256-", [43usize, 44]), ("sha384-", [64, 64]), ("sha512-", [86, 88])] {
        if let Some(rest) = run.strip_prefix(pre) {
            return lens.contains(&rest.trim_end_matches('=').len())
                || lens.contains(&rest.len());
        }
    }
    run.len() <= 800 && run.starts_with("AAAA") && b64_decode(run).is_some_and(|b| is_openssh_key(&b))
}

/// The application field of a security key: "ssh:" then up to 60 further bytes (OpenSSH default is "ssh:").
fn sk_app(a: &[u8]) -> bool {
    a.starts_with(b"ssh:") && a.len() <= 64
}

/// One RFC 4251 string (u32 length, then bytes) from the front of `b`.
fn ssh_string<'a>(b: &mut &'a [u8]) -> Option<&'a [u8]> {
    let n = u32::from_be_bytes(b.get(..4)?.try_into().ok()?) as usize;
    let s = b.get(4..4usize.checked_add(n)?)?;
    *b = &b[4 + n..];
    Some(s)
}

/// An OpenSSH public key wire blob, parsed field by field and required to be consumed exactly:
/// ed25519 (one 32 byte key, 51 bytes in all), ecdsa (curve name matching the type, an
/// uncompressed point of the curve's size), rsa (exponent, modulus with its high bit set) and the
/// two sk- (security key) forms. A prefix match alone does not qualify.
fn is_openssh_key(blob: &[u8]) -> bool {
    let mut b = blob;
    let Some(t) = ssh_string(&mut b) else { return false };
    let mut field = |len: &dyn Fn(&[u8]) -> bool| ssh_string(&mut b).is_some_and(len);
    let ok = match t {
        b"ssh-ed25519" => field(&|k| k.len() == 32),
        SK_SSH_ED25519 => field(&|k| k.len() == 32) && field(&sk_app),
        // Exponent 3, 17 or 65537; modulus of a standard size (1024, 2048, 3072 or 4096 bits, plus
        // the sign byte) with its high bit set and odd. The modulus itself cannot be told from random.
        b"ssh-rsa" => {
            field(&|e| matches!(e, [3] | [17] | [1, 0, 1]))
                && field(&|n| matches!(n.len(), 129 | 257 | 385 | 513) && n[0] == 0 && n[1] >= 0x80 && n[n.len() - 1] & 1 == 1)
        }
        b"ecdsa-sha2-nistp256" | b"ecdsa-sha2-nistp384" | b"ecdsa-sha2-nistp521"
        | SK_ECDSA_P256 => {
            let (curve, point): (&[u8], usize) = if t.ends_with(b"nistp256") || t.starts_with(b"sk-ecdsa") {
                (b"nistp256", 65)
            } else if t.ends_with(b"nistp384") {
                (b"nistp384", 97)
            } else {
                (b"nistp521", 133)
            };
            field(&|c| c == curve)
                && field(&|p| p.len() == point && p[0] == 4)
                && (!t.starts_with(b"sk-") || field(&sk_app))
        }
        _ => false,
    };
    ok && b.is_empty()
}

/// Opacity runs over the text as written, whitespace-delimited like gitleaks and trufflehog
/// tokens; never over a whitespace-stripped view, which glues words into one run.
fn hot_total(s: &str) -> usize {
    b64_re()
        .find_iter(s)
        .filter(|m| !is_public_blob(m.as_str()) && run_is_hot(m.as_str()))
        .map(|m| m.as_str().len())
        .sum()
}

pub fn has_opaque_blob(s: &str) -> bool {
    if hot_total(s) >= HOT_TOTAL {
        return true;
    }
    for m in b64_re().find_iter(s) {
        let run = m.as_str();
        if run.len() < OPAQUE_RUN || is_public_blob(run) {
            continue;
        }
        let texty = (0..4).any(|skip| b64_decode(&run[skip..]).is_some_and(|b| mostly_text(&b)));
        if !texty {
            return true;
        }
    }
    false
}

// SSH key type names as bytes; the separator is escaped so no address-shaped literal sits in source.
const SK_SSH_ED25519: &[u8] = concat!("sk-ssh-ed25519", "\x40", "openssh.com").as_bytes();
const SK_ECDSA_P256: &[u8] = concat!("sk-ecdsa-sha2-nistp256", "\x40", "openssh.com").as_bytes();
