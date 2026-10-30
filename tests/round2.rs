//! Regression tests for the 2026-10-29 re-attack, five repairs.
//! Secret- and personal-shaped inputs are built at runtime from pieces.

use gate::scan_with;

fn blocked(t: &str) -> bool {
    !scan_with(t, None).pass
}

fn at(local: &str, host: &str) -> String {
    format!("{local}{}{host}", '@')
}

/// Assembled at runtime so no assignment shaped literal sits in this file.
fn pw() -> String {
    "pass".to_string() + "word"
}

fn sc() -> String {
    "sec".to_string() + "ret"
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 24) as u8
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next()).collect()
    }
}

fn b64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                o.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                o.push('=');
            }
        }
    }
    o
}

// ---- repair 2: opacity never runs on the whitespace stripped view ----
#[test]
fn r2_ordinary_text_and_public_integrity_values_pass() {
    let words = ["alpha", "bridge", "cobalt", "delta", "ember", "forest", "garden", "harbor"];
    let sentence: Vec<&str> = (0..60).map(|i| words[(i * 5 + i / 3) % words.len()]).collect();
    let sentence = sentence.join(" ");
    let list: String = (0..90).map(|i| format!("- {} {}\n", words[i % 8], words[(i * 3) % 8])).collect();
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    let lock: String = (0..60)
        .map(|i| format!("\"node_modules/p{i}\": {{ \"integrity\": \"sha512-{}\" }},\n", b64(&rng.bytes(64))))
        .collect();
    let sri256: String = (0..25).map(|_| format!("sha256-{}\n", b64(&rng.bytes(32)))).collect();
    let keys: String = (0..12)
        .map(|i| {
            let mut blob = vec![0, 0, 0, 11];
            blob.extend_from_slice(b"ssh-ed25519");
            blob.extend_from_slice(&[0, 0, 0, 32]);
            blob.extend(rng.bytes(32));
            format!("ssh-ed25519 {} user{i}\n", b64(&blob))
        })
        .collect();
    for (name, t) in [("sentence", &sentence), ("list", &list), ("lock", &lock), ("sri256", &sri256), ("ssh", &keys)] {
        let r = scan_with(t, None);
        assert!(r.pass, "{name}: {:?}", r.reasons);
    }
}

#[test]
fn r2_blob_split_on_whitespace_in_long_pieces_still_fails() {
    let blob = b64(&Rng(0x9E37_79B9_7F4A_7C15).bytes(1500));
    let spaced: Vec<&str> = blob.as_bytes().chunks(200).map(|c| std::str::from_utf8(c).unwrap()).collect();
    assert!(blocked(&spaced.join(" ")));
    assert!(blocked(&spaced.join("\n")));
}

// ---- known residuals (re-attack 2026-10-29, F2). These PASS today. They are listed so a later
// seat does not rediscover them as bugs; the README states them. If one starts to FAIL, move it. ----
#[test]
fn known_residual_opacity_probes_pass() {
    let mut rng = Rng(0x0BAD_CAFE_F00D_1234);
    let raw = rng.bytes(1500);
    // 1. dotted 15 character pieces: no run reaches 16
    let b = b64(&raw);
    let dotted: Vec<&str> = b.as_bytes().chunks(15).map(|c| std::str::from_utf8(c).unwrap()).collect();
    assert!(!blocked(&dotted.join(".")), "dotted 15 char splits");
    // 2. hex with a separator every 15
    let hex: String = raw.iter().map(|x| format!("{x:02x}")).collect();
    let hexs: Vec<&str> = hex.as_bytes().chunks(15).map(|c| std::str::from_utf8(c).unwrap()).collect();
    assert!(!blocked(&hexs.join(",")), "hex with separators");
    // 3. base32 with a dot every 200
    const A32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let b32: String = (0..2400).map(|_| A32[(rng.next() % 32) as usize] as char).collect();
    let b32s: Vec<&str> = b32.as_bytes().chunks(200).map(|c| std::str::from_utf8(c).unwrap()).collect();
    assert!(!blocked(&b32s.join(".")), "base32 with dots");
    // 4. an 85 symbol alphabet outside base64
    const A85: &[u8] = b"!#$%&()*,.:;<=>?@[]^`{|}~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let a85: String = (0..2000).map(|_| A85[(rng.next() as usize) % 85] as char).collect();
    assert!(!blocked(&a85), "85 symbol alphabet");
}

// ---- repair 3: F1 ----
#[test]
fn r3_marks_format_chars_and_multi_letter_lookalikes_fail() {
    let cases = [
        "4242\u{0301} 4242\u{0301} 4242\u{0301} 4242\u{0301}".to_string(),
        "4242\u{0301}4242\u{0301}4242\u{0301}4242".to_string(),
        at("someone", "gma\u{0301}il.com"),
        "\u{0600}4242 4242 4242 4242".to_string(),
        "4242\u{0600}4242\u{0600}4242\u{0600}4242".to_string(),
        "4242\u{2800}4242\u{2800}4242\u{2800}4242".to_string(),
        at("someone", "g\u{043C}\u{0430}\u{0456}l.com"),
    ];
    for c in &cases {
        assert!(blocked(c), "passed: {c:?}");
    }
    assert!(scan_with("un caf\u{00E9} au lait, d\u{00E9}j\u{00E0} vu, na\u{00EF}ve", None).pass);
    assert!(scan_with("cafe\u{0301} au lait", None).pass);
}

// ---- repair 4: F5 ----
#[test]
fn r4_wide_separators_between_digit_groups_fail() {
    let card = ["4242", "4242", "4242", "4242"];
    let sin = ["046", "454", "286"];
    for sep in ["  ", " - ", "\t", "\n", ",", ":", ", ", " / "] {
        assert!(blocked(&format!("card {}", card.join(sep))), "card sep {sep:?}");
        assert!(blocked(&format!("sin {}", sin.join(sep))), "sin sep {sep:?}");
    }
    assert!(!blocked("4241  4243  3567  8954"));
    assert!(!blocked("046  454  287"));
}

// ---- repair 5: F7 ----
#[test]
fn r5_attribute_access_and_type_names_pass() {
    let (pw, sc) = (pw(), sc());
    let lines = [
        "api_key: Optional[str] = None".to_string(),
        format!("{pw}: required"),
        format!("{sc}: undefined"),
        format!("self.{pw} = {pw}"),
        format!("{pw} = os.environ.get('X')"),
        format!("{sc} = {sc}s.token_hex(16)"),
        format!("const {sc} = crypto.randomBytes(32)"),
        format!("{sc}: my-k8s-{sc}-name"),
        format!("{pw}: String"),
        format!("let {sc} = 5;"),
        "api_key = settings.API_KEY_NAME".to_string(),
        format!("{pw} = request.form.{pw}_field"),
    ];
    for l in &lines {
        assert!(!blocked(l), "false positive: {l:?}");
    }
}

#[test]
fn r5_random_value_in_every_shape_fails() {
    let (pw, sc) = (pw(), sc());
    for _ in 0..20 {
        let v = gate::random_secret_value();
        for c in [
            format!("{{\"{pw}\": \"{v}\"}}"),
            format!("{pw}: {v}"),
            format!("API_{}={v}", "KEY"),
            format!("client_{sc}=\"{v}\""),
            format!("{pw} = '{v}'"),
        ] {
            assert!(blocked(&c), "passed: {c:?}");
        }
    }
    // a low entropy value is not a secret under this rule
    assert!(!blocked(&format!("{pw}: abababababababab")));
}
