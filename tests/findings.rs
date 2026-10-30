//! Regression tests for the 2026-10-29 review, findings F1 to F11.
//! Secret- and personal-shaped inputs are built at runtime from pieces.

use gate::{ModelConfig, mask, proxy, scan_with};
use std::sync::{Arc, Mutex};

fn blocked(t: &str) -> bool {
    !scan_with(t, None).pass
}

fn at(local: &str, host: &str) -> String {
    format!("{local}{}{host}", '@')
}

fn xorshift_bytes(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn b64_bytes(b: &[u8]) -> String {
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

fn b64url(s: &str) -> String {
    b64_bytes(s.as_bytes()).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
}

fn proxy_to(up_url: String, model: Option<ModelConfig>) -> String {
    let server = proxy::bind("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    std::thread::spawn(move || proxy::run(&server, &up_url, model.as_ref()));
    format!("http://127.0.0.1:{port}")
}

fn code_of(r: Result<ureq::Response, ureq::Error>) -> u16 {
    match r {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(c, _)) => c,
        Err(e) => panic!("transport: {e}"),
    }
}

// ---- F1 ----
#[test]
fn f1_format_characters_and_homoglyphs_fail() {
    let cases = [
        format!("{} ", at("someone", "gm\u{200B}ail.com")),
        "4242\u{00AD}4242\u{00AD}4242\u{00AD}4242".to_string(),
        "705\u{2060}555\u{2060}0142".to_string(),
        at("someone", "gm\u{0430}il.com"),
        "046\u{200D}454\u{FEFF}286".to_string(),
    ];
    for c in &cases {
        assert!(blocked(c), "passed: {c:?}");
    }
    // the private blocklist matches on the same folded view
    assert!(gate::decode::fold("sec\u{200B}ret").contains("secret"));
    assert!(gate::decode::fold("s\u{0435}cret").contains("secret"));
    // unchanged benign text still passes
    assert!(scan_with("caf\u{00E9} au lait, fn main() {}", None).pass);
}

// ---- F2 ----
#[test]
fn f2_punctuated_random_blob_fails_but_prose_and_code_pass() {
    let blob = b64_bytes(&xorshift_bytes(1500));
    let split: Vec<&str> = blob.as_bytes().chunks(200).map(|c| std::str::from_utf8(c).unwrap()).collect();
    let punctuated = split.join(". ");
    let r = scan_with(&punctuated, None);
    assert!(!r.pass && r.reasons.contains(&"encoded:opaque_blob".to_string()), "{:?}", r.reasons);
    assert!(blocked(&blob));
    for benign in [
        include_str!("../src/proxy.rs"),
        include_str!("../src/decode.rs"),
        include_str!("../Cargo.lock"),
    ] {
        let r = scan_with(benign, None);
        assert!(r.pass, "false positive: {:?}", r.reasons);
    }
}

// ---- F3 ----
#[test]
fn f3_nested_json_escaped_argument_fails_as_json_and_as_text() {
    let up = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let up_url = format!("http://127.0.0.1:{}", up.server_addr().to_ip().unwrap().port());
    let hits = Arc::new(Mutex::new(0usize));
    let h = hits.clone();
    std::thread::spawn(move || {
        for r in up.incoming_requests() {
            *h.lock().unwrap() += 1;
            let _ = r.respond(tiny_http::Response::from_string("ok"));
        }
    });
    let base = proxy_to(up_url, None);
    let nested = r#"{"arguments":"{\"to\":\"someone\\u0040gmail.com\"}"}"#;
    assert_eq!(code_of(ureq::post(&base).set("Content-Type", "application/json").send_string(nested)), 403);
    let plain = r#"{\"to\":\"someone\\u0040gmail.com\"}"#;
    assert_eq!(code_of(ureq::post(&base).set("Content-Type", "text/plain").send_string(plain)), 403);
    assert_eq!(*hits.lock().unwrap(), 0);
    assert!(blocked(r"someone\x40gmail.com"));
    assert!(blocked(concat!("someone", "\x40", "gmail.com")));
}

// ---- F4 ----
#[test]
fn f4_a_slow_model_call_does_not_stall_a_rule_fail() {
    // model that answers BUSINESS after 3 s
    let m = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let m_url = format!("http://127.0.0.1:{}/v1/chat/completions", m.server_addr().to_ip().unwrap().port());
    std::thread::spawn(move || {
        for req in m.incoming_requests() {
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(3));
                let _ = req.respond(tiny_http::Response::from_string(
                    r#"{"choices":[{"message":{"content":"BUSINESS"}}]}"#,
                ));
            });
        }
    });
    let up = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let up_url = format!("http://127.0.0.1:{}", up.server_addr().to_ip().unwrap().port());
    std::thread::spawn(move || {
        for r in up.incoming_requests() {
            let _ = r.respond(tiny_http::Response::from_string("ok"));
        }
    });
    let base = proxy_to(up_url, Some(ModelConfig::new(&m_url)));
    let b1 = base.clone();
    let slow = std::thread::spawn(move || {
        code_of(ureq::post(&b1).set("Content-Type", "text/plain").send_string("fn main() {}"))
    });
    std::thread::sleep(std::time::Duration::from_millis(500));
    let t = std::time::Instant::now();
    let c = code_of(
        ureq::post(&base)
            .set("Content-Type", "text/plain")
            .send_string(&format!("write to {}", at("someone", "gmail.com"))),
    );
    let took = t.elapsed();
    assert_eq!(c, 403);
    assert!(took < std::time::Duration::from_secs(1), "stalled {took:?}");
    assert_eq!(slow.join().unwrap(), 200);
    // model path has a lower body cap
    let big = "a b ".repeat(80_000);
    assert_eq!(code_of(ureq::post(&base).set("Content-Type", "text/plain").send_string(&big)), 413);
}

#[test]
fn f4_total_model_budget_fails_closed() {
    let m = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let m_url = format!("http://127.0.0.1:{}/v1/chat/completions", m.server_addr().to_ip().unwrap().port());
    std::thread::spawn(move || {
        for req in m.incoming_requests() {
            std::thread::sleep(std::time::Duration::from_millis(400));
            let _ = req.respond(tiny_http::Response::from_string(
                r#"{"choices":[{"message":{"content":"BUSINESS"}}]}"#,
            ));
        }
    });
    let mut cfg = ModelConfig::new(&m_url);
    cfg.budget = std::time::Duration::from_millis(900);
    let text = "ab, cd. ".repeat(19_000); // 152k chars = 26 chunks of 400 ms
    let v = scan_with(&text, Some(&cfg));
    assert!(!v.pass && v.model_unreachable);
}

// ---- F5 ----
#[test]
fn f5_unicode_digits_and_odd_separators_fail() {
    let arabic: String = "4242 4242 4242 4242".chars().map(|c| match c.to_digit(10) {
        Some(d) => char::from_u32(0x0660 + d).unwrap(),
        None => c,
    }).collect();
    for c in [arabic.as_str(), "4242.4242.4242.4242", "046.454.286", "705/555/0142"] {
        assert!(blocked(c), "passed: {c:?}");
    }
    // a Luhn-invalid number with the same separators still passes
    assert!(!blocked("4241.4243.3567.8954"));
}

// ---- F6 ----
#[test]
fn f6_upstream_sees_authorization_path_and_no_host_or_cookie() {
    let up = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let up_port = up.server_addr().to_ip().unwrap().port();
    type Seen = Vec<(String, String, Vec<(String, String)>)>;
    let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(vec![]));
    let s2 = seen.clone();
    std::thread::spawn(move || {
        for r in up.incoming_requests() {
            let hs = r.headers().iter().map(|h| (h.field.to_string().to_lowercase(), h.value.to_string())).collect();
            s2.lock().unwrap().push((r.method().to_string(), r.url().to_string(), hs));
            let resp = tiny_http::Response::from_string("ok")
                .with_header(tiny_http::Header::from_bytes(&b"X-Request-Id"[..], &b"rid-9"[..]).unwrap())
                .with_header(tiny_http::Header::from_bytes(&b"Set-Cookie"[..], &b"a=b"[..]).unwrap());
            let _ = r.respond(resp);
        }
    });
    let base = proxy_to(format!("http://127.0.0.1:{up_port}/api"), None);
    let r = ureq::post(&format!("{base}/v1/chat?q=1"))
        .set("Content-Type", "text/plain")
        .set("Authorization", "Bearer testtoken")
        .set("Cookie", "sid=1")
        .set("X-Request-Id", "rid-1")
        .send_string("fn main() {}")
        .unwrap();
    assert_eq!(r.header("x-request-id"), Some("rid-9"));
    assert_eq!(r.header("set-cookie"), None);
    let got = seen.lock().unwrap().clone();
    let (_, url, hs) = &got[0];
    assert_eq!(url, "/api/v1/chat?q=1");
    let has = |k: &str, v: &str| hs.iter().any(|(a, b)| a == k && b == v);
    assert!(has("authorization", "Bearer testtoken") && has("x-request-id", "rid-1"));
    assert!(!hs.iter().any(|(a, _)| a == "cookie"));
    assert!(hs.iter().any(|(a, b)| a == "host" && b == &format!("127.0.0.1:{up_port}")));
    // dot segments (sent raw, so no client normalises them away) are refused
    for path in ["/a/../b", "/a/%2e%2e/b", "/a/%252e%252e/b", "http://evil/x"] {
        use std::io::{Read, Write};
        let mut c = std::net::TcpStream::connect(base.trim_start_matches("http://")).unwrap();
        write!(c, "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx").unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        assert!(out.starts_with("HTTP/1.1 400"), "{path}: {out}");
    }
    assert_eq!(seen.lock().unwrap().len(), 1);
}

// ---- F7 ----
#[test]
fn f7_assigned_secret_json_yaml_dotenv() {
    let pw = "pass".to_string() + "word";
    let val = gate::random_secret_value();
    for c in [
        format!("{{\"{pw}\": \"{val}\"}}"),
        format!("{pw}: {val}"),
        format!("API_{}={val}", "KEY"),
        format!("client_{}=\"{val}\"", "secret"),
        format!("{pw} = '{val}'"),
    ] {
        assert!(blocked(&c), "passed: {c:?}");
    }
    assert!(!blocked("password: String"));
    assert!(!blocked("let secret = 5;"));
}

// ---- F9 ----
#[test]
fn f9_timestamps_isbn_and_many_jwt_segments_pass() {
    for c in ["built at 1698765432", "ts 1698765432123", "isbn 9781234567897", "id 1234567890"] {
        assert!(!blocked(c), "false positive: {c:?}");
    }
    assert!(blocked("call 705-555-0142"));
    assert!(blocked("call (705) 555 0142"));
    assert!(blocked("call +1 705 555 0142"));
    // 200 distinct text-bearing base64 segments (unsigned JWT-like) are not "too many views"
    let seg = |i: usize| format!("{}.{}", b64url(&format!("{{\"alg\":\"none\",\"n\":{i}}}")), b64url(&format!("{{\"sub\":\"1234567890\",\"i\":{i},\"name\":\"nobody\"}}")));
    let log: Vec<String> = (0..200).map(seg).collect();
    let r = scan_with(&log.join("\n"), None);
    assert!(r.pass, "{:?}", r.reasons);
    // plus ten signed ones (43 character random signatures): 430 hot characters, under the bound
    let mut signed = log.clone();
    for i in 0..10u8 {
        signed.push(format!("{}.{}", seg(i as usize), b64_bytes(&xorshift_bytes(40 + i as usize)).trim_end_matches('=')));
    }
    let r = scan_with(&signed.join("\n"), None);
    assert!(r.pass, "{:?}", r.reasons);
}

// ---- F10 ----
#[test]
fn f10_mask_covers_encoded_and_hidden_hits() {
    let email = at("someone", "gmail.com");
    let enc = b64_bytes(format!("please mail {email} now").as_bytes());
    assert_eq!(mask(&format!("see {enc}")), gate::MASK_WITHHELD);
    // hidden behind format characters (a card; a hidden email host is now masked in place)
    assert_eq!(mask("4242\u{00AD}4242\u{00AD}4242\u{00AD}4242"), gate::MASK_WITHHELD);
    assert_eq!(mask(&format!("a {email} b")), "a [EMAIL] b");
}

// ---- F11 ----
#[test]
fn f11_content_fail_outranks_model_unreachable() {
    let dir = std::env::temp_dir().join(format!("amg-f11-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let clean = dir.join("clean.txt");
    let bad = dir.join("bad.txt");
    std::fs::write(&clean, "fn main() {}").unwrap();
    std::fs::write(&bad, format!("mail {}", at("someone", "gmail.com"))).unwrap();
    let run = |files: &[&std::path::Path]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_arrowmem-gate"))
            .arg("scan")
            .args(files)
            .env("ARROWMEM_GATE_URL", "http://127.0.0.1:1/v1/chat/completions")
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(run(&[&clean]), Some(3));
    assert_eq!(run(&[&clean, &bad]), Some(2));
    assert_eq!(run(&[&bad, &clean]), Some(2));
    let _ = std::fs::remove_dir_all(&dir);
}
