//! Regression tests for the round 3 repairs (2026-10-29). Secret and personal shaped inputs are
//! built at runtime from pieces.

use gate::scan_with;

fn blocked(t: &str) -> bool {
    !scan_with(t, None).pass
}

fn at(local: &str, host: &str) -> String {
    format!("{local}{}{host}", '@')
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

// ---- item 3: card shapes ----
#[test]
fn r3_card_with_cvv_expiry_and_amex_fail() {
    for c in [
        "card 4242 4242 4242 4242 123",
        "card 4242 4242 4242 4242, cvv 123",
        "card 4242 4242 4242 4242 12/27",
        "card 4242-4242-4242-4242 123",
        "1 4242 4242 4242 4242",
        "4242424242424242 123",
        "amex 3782 822463 10005",
        "amex 378282246310005",
        "amex 3782 822463 10005 1234",
        "amex 3782-822463-10005 exp 12/27",
        "visa 4222222222222",
    ] {
        assert!(blocked(c), "passed: {c:?}");
    }
    // Luhn invalid controls still pass
    assert!(!blocked("number 4241 4243 3567 8954"));
    assert!(!blocked("number 4241 4243 3567 8954 123"));
    assert!(!blocked("amex 3782 822463 10006"));
}

// ---- item 4: IDN hosts by UTS 39 restriction level ----
#[test]
fn r3_mixed_script_host_fails_single_script_idn_passes() {
    // Latin g and l with Cyrillic m, a, i in one label; and the variant with a Cyrillic TLD.
    for host in ["g\u{043C}\u{0430}\u{0456}l.com", "g\u{043C}\u{0430}\u{0456}l.\u{0441}\u{043E}\u{043C}", "gm\u{0430}il.com", "\u{043C}\u{0430}\u{0456}l.example"] {
        assert!(blocked(&at("someone", host)), "passed: {host:?}");
    }
    // The same lookalike with Cyrillic letters only in the TLD label, Latin elsewhere
    assert!(blocked(&at("someone", "example.c\u{043E}m")));
    // Legitimate single script addresses pass: accented Latin, all Cyrillic, Greek
    for host in ["caf\u{00E9}.fr", "b\u{00FC}cher.de", "\u{043F}\u{043E}\u{0447}\u{0442}\u{0430}.\u{0440}\u{0444}", "\u{03C0}\u{03B1}\u{03C1}\u{03B1}\u{03B4}\u{03B5}\u{03B9}\u{03B3}\u{03BC}\u{03B1}.gr", "xn--caf-dma.fr"] {
        assert!(!blocked(&at("jean", host)), "failed: {host:?}");
    }
    // Provider matches are unchanged
    assert!(blocked(&at("someone", "gmail.com")));
    assert!(blocked(&at("someone", "Outlook.ca")));
    assert!(!blocked(&at("someone", "example.com")));
}

#[test]
fn r3_mixed_script_host_survives_percent_encoding() {
    let pct = |t: String| -> String {
        t.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
    };
    assert!(blocked(&pct(at("someone", "g\u{043C}\u{0430}\u{0456}l.com"))), "percent encoded mixed host passed");
    let ok = pct(at("jean", "\u{043F}\u{043E}\u{0447}\u{0442}\u{0430}.\u{0440}\u{0444}"));
    assert!(!blocked(&ok), "percent encoded Cyrillic host failed");
}

// ---- item 5: OpenSSH wire format ----
fn sshs(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

fn key_line(blob: &[u8], name: &str) -> String {
    format!("{name} {} user\n", b64(blob))
}

#[test]
fn r3_openssh_keys_parsed_exactly() {
    let mut rng = Rng(0x5EED_5EED_1234_ABCD);
    let mut lines = String::new();
    for _ in 0..12 {
        let mut b = Vec::new();
        sshs(&mut b, b"ssh-ed25519");
        sshs(&mut b, &rng.bytes(32));
        lines.push_str(&key_line(&b, "ssh-ed25519"));
    }
    for _ in 0..4 {
        let mut b = Vec::new();
        sshs(&mut b, b"ecdsa-sha2-nistp256");
        sshs(&mut b, b"nistp256");
        let mut p = vec![4u8];
        p.extend(rng.bytes(64));
        sshs(&mut b, &p);
        lines.push_str(&key_line(&b, "ecdsa-sha2-nistp256"));
    }
    for _ in 0..4 {
        let mut b = Vec::new();
        sshs(&mut b, b"ssh-rsa");
        sshs(&mut b, &[1, 0, 1]);
        let mut n = vec![0u8, 0x80 | rng.next()];
        n.extend(rng.bytes(254));
        n.push(rng.next() | 1); // a real modulus is odd
        sshs(&mut b, &n);
        lines.push_str(&key_line(&b, "ssh-rsa"));
    }
    assert!(scan_with(&lines, None).pass, "{:?}", scan_with(&lines, None).reasons);

    // Same prefix, arbitrary payload after it: three lines of 500 random bytes are refused
    let mut tunnel = String::new();
    for _ in 0..3 {
        let mut b = Vec::new();
        sshs(&mut b, b"ssh-ed25519");
        b.extend(rng.bytes(500));
        tunnel.push_str(&key_line(&b, "ssh-ed25519"));
    }
    assert!(blocked(&tunnel), "prefix only blobs passed");

    // A real, exactly shaped key with 400 payload bytes after it is not consumed exactly
    let mut tail = String::new();
    for _ in 0..3 {
        let mut b = Vec::new();
        sshs(&mut b, b"ssh-ed25519");
        sshs(&mut b, &rng.bytes(32));
        b.extend(rng.bytes(400));
        tail.push_str(&key_line(&b, "ssh-ed25519"));
    }
    assert!(blocked(&tail), "trailing payload accepted");
    // A 64 byte field under the ed25519 type is not a key
    let mut wide = String::new();
    for _ in 0..20 {
        let mut b = Vec::new();
        sshs(&mut b, b"ssh-ed25519");
        sshs(&mut b, &rng.bytes(300));
        wide.push_str(&key_line(&b, "ssh-ed25519"));
    }
    assert!(blocked(&wide), "oversize ed25519 field accepted");
}

// ---- item 2: F7 scope, stated in the README, kept as a residual ----
#[test]
fn known_residual_human_chosen_passwords_pass() {
    let pw = "pass".to_string() + "word";
    for v in ["Summer2024", "Welcome1234", "letmein", "correct horse battery staple", "12345678", "Tr0ub4dor"] {
        for line in [format!("{pw}: {v}"), format!("{pw} = \"{v}\""), format!("{{\"{pw}\": \"{v}\"}}")] {
            assert!(!blocked(&line), "now fails, move it out of the residual list: {line:?}");
        }
    }
}
