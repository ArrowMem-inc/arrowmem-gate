//! Regression tests for the round 4 repairs (2026-10-29). Secret and personal shaped inputs
//! are built at runtime from pieces.

use gate::scan_with;

fn blocked(t: &str) -> bool {
    !scan_with(t, None).pass
}

fn at(local: &str, host: &str) -> String {
    format!("{local}{}{host}", '@')
}

fn ascii_host(h: &str) -> String {
    idna::domain_to_ascii(h).expect("idna encode")
}

fn entities(s: &str, hex: bool, semi: bool) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii() {
                c.to_string()
            } else {
                let body = if hex { format!("&#x{:x}", c as u32) } else { format!("&#{}", c as u32) };
                if semi { body + ";" } else { body }
            }
        })
        .collect()
}

const MIXED: &str = "g\u{043C}\u{0430}\u{0456}l.com";
const CYR: &str = "\u{043F}\u{043E}\u{0447}\u{0442}\u{0430}.\u{0440}\u{0444}";

#[test]
fn r4_punycode_mixed_script_host_fails_legit_punycode_passes() {
    let a = ascii_host(MIXED);
    assert!(a.contains("xn--") && a.is_ascii(), "probe not punycode: {a}");
    assert!(blocked(&at("someone", &a)), "punycode mixed host passed");
    assert!(blocked(&format!("write to {} please", at("someone", &a.to_uppercase()))), "upper case A label passed");
    // Legitimate punycode hosts: accented Latin, all Cyrillic, all Greek
    for h in ["caf\u{00E9}.fr", "b\u{00FC}cher.de", CYR, "\u{03C0}\u{03B1}\u{03C1}\u{03B1}\u{03B4}\u{03B5}\u{03B9}\u{03B3}\u{03BC}\u{03B1}.gr"] {
        let a = ascii_host(h);
        assert!(a.contains("xn--"), "{a}");
        assert!(!blocked(&at("jean", &a)), "legit punycode failed: {a}");
    }
    assert!(!blocked("see xn--caf-dma.fr and xn--80a for notes"));
}

#[test]
fn r4_html_numeric_entity_mixed_host_fails_legit_entities_pass() {
    for (hex, semi) in [(false, true), (true, true), (false, false), (true, false)] {
        let t = at("someone", &entities(MIXED, hex, semi));
        assert!(blocked(&t), "entity form passed: hex={hex} semi={semi}: {t}");
    }
    // The at sign itself as an entity, on a consumer provider
    assert!(blocked(&format!("someone&#64;{}", "gmail.com")));
    // Entity encoded punycode composes
    let a = ascii_host(MIXED).replace('x', "&#120;");
    assert!(blocked(&at("someone", &a)), "entity wrapped punycode passed");
    for h in [CYR, "caf\u{00E9}.fr"] {
        assert!(!blocked(&at("jean", &entities(h, false, true))), "legit entity host failed");
    }
    assert!(!blocked("a &#38; b, &#x41; and &#99999999; stay text"));
}

// ---- OpenSSH key shape: tightened, residual stated ----
fn sshs(out: &mut Vec<u8>, s: &[u8]) {
    out.extend((s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
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
            o.push(if i <= c.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    o
}

fn rsa_line(rng: &mut Rng, e: &[u8], modulus_len: usize, odd: bool) -> String {
    let mut b = Vec::new();
    sshs(&mut b, b"ssh-rsa");
    sshs(&mut b, e);
    let mut n = vec![0u8, 0x80 | rng.next()];
    n.extend(rng.bytes(modulus_len - 3));
    n.push(if odd { rng.next() | 1 } else { rng.next() & !1 });
    sshs(&mut b, &n);
    format!("ssh-rsa {} user\n", b64(&b))
}

/// KNOWN RESIDUAL. A modulus cannot be told from random, so an RSA shaped line carries the whole
/// modulus: 128, 256, 384 or 512 arbitrary bytes. Twenty 4096 bit shaped lines are 10240 bytes.
#[test]
fn known_residual_rsa_shaped_lines_carry_the_modulus() {
    let mut rng = Rng(0xC0FF_EE00_1234_5678);
    let lines: String = (0..20).map(|_| rsa_line(&mut rng, &[1, 0, 1], 513, true)).collect();
    assert!(scan_with(&lines, None).pass, "now fails, move it out of the residual list");
}

#[test]
fn r4_rsa_shape_tightened() {
    let mut rng = Rng(0x1357_9BDF_2468_ACE0);
    for len in [129, 257, 385, 513] {
        assert!(scan_with(&rsa_line(&mut rng, &[1, 0, 1], len, true), None).pass, "std size {len} failed");
    }
    // Off size moduli, an even modulus and an odd exponent length are not keys
    let off: String = (0..20).map(|_| rsa_line(&mut rng, &[1, 0, 1], 300, true)).collect();
    assert!(blocked(&off), "off size modulus passed");
    let even: String = (0..20).map(|_| rsa_line(&mut rng, &[1, 0, 1], 513, false)).collect();
    assert!(blocked(&even), "even modulus passed");
    let wide_e: String = (0..20).map(|_| rsa_line(&mut rng, &[1, 2, 3, 4, 5, 6, 7, 8], 513, true)).collect();
    assert!(blocked(&wide_e), "8 byte exponent passed");
}

#[test]
fn r4_sk_application_field_must_start_ssh_colon() {
    let mut rng = Rng(0x0BAD_CAFE_0000_0001);
    let mut line = |app: &[u8]| {
        let mut b = Vec::new();
        sshs(&mut b, concat!("sk-ssh-ed25519", "\x40", "openssh.com").as_bytes());
        sshs(&mut b, &rng.bytes(32));
        sshs(&mut b, app);
        format!("{} {} user\n", concat!("sk-ssh-ed25519", "\x40", "openssh.com"), b64(&b))
    };
    assert!(scan_with(&(0..3).map(|_| line(b"ssh:")).collect::<String>(), None).pass);
    let junk: String = (0..20).map(|_| line(&Rng(0x77).bytes(64))).collect();
    assert!(blocked(&junk), "sk app of random bytes passed");
}

// ---- LOW: a card glued to trailing letters, stated residual ----
#[test]
fn known_residual_card_glued_to_trailing_letters_passes() {
    let card = ["4111", "1111", "1111", "1111"].join(" ");
    assert!(blocked(&format!("card {card} cvv 123")), "control: spaced card must fail");
    assert!(!blocked(&format!("{card}abc")), "now fails, move it out of the residual list");
}
