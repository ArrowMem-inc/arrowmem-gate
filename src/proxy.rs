//! Minimal gating proxy. Loopback listen only. PASS forwards the body; FAIL returns 403.

use crate::{ModelConfig, scan_with};
use std::io::Read;
use std::net::SocketAddr;

const MAX_BODY: u64 = 10 * 1024 * 1024;
/// With the model layer on, every body costs model time, so the cap is much lower.
const MAX_BODY_MODEL: u64 = 256 * 1024;
/// Worker threads sharing one listener. A slow model call holds one, not the whole proxy.
const WORKERS: usize = 4;
/// Request headers forwarded upstream. Never Host, Cookie or hop-by-hop headers.
const FORWARD_REQ: [&str; 4] = ["Authorization", "Content-Type", "Accept", "X-Request-Id"];
/// Upstream response headers passed back to the client.
const FORWARD_RESP: [&str; 4] = ["Content-Type", "Retry-After", "X-Request-Id", "WWW-Authenticate"];

pub fn bind(addr: &str) -> Result<tiny_http::Server, String> {
    let sa: SocketAddr = addr
        .parse()
        .map_err(|_| "listen address must be IP:PORT".to_string())?;
    if !sa.ip().is_loopback() {
        return Err("listen address is not loopback; refusing".into());
    }
    tiny_http::Server::http(sa).map_err(|e| e.to_string())
}

fn json_resp(code: u16, body: String) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let h = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
        .expect("static header");
    tiny_http::Response::from_string(body)
        .with_status_code(code)
        .with_header(h)
}

const ALLOWED_TYPES: [&str; 3] = [
    "text/plain",
    "application/json",
    "application/x-www-form-urlencoded",
];

/// Why a request was refused before scanning: (status, message). Messages carry no content.
pub type Refusal = (u16, &'static str);

fn collect_json(v: &serde_json::Value, out: &mut String) {
    match v {
        serde_json::Value::String(s) => {
            out.push_str(s);
            out.push('\n');
        }
        serde_json::Value::Array(a) => a.iter().for_each(|x| collect_json(x, out)),
        serde_json::Value::Object(m) => {
            for (k, x) in m {
                out.push_str(k);
                out.push('\n');
                collect_json(x, out);
            }
        }
        other => {
            out.push_str(&other.to_string());
            out.push('\n');
        }
    }
}

/// Decide what text to scan for a request, or refuse it. Refuses any Content-Encoding other
/// than identity, any Content-Type outside the allowlist, any charset other than UTF-8/ASCII,
/// invalid UTF-8 and invalid JSON. JSON string values and keys are scanned decoded; form
/// values are percent-decoded. The raw text is scanned too.
pub fn text_to_scan(
    content_type: Option<&str>,
    encodings: &[String],
    raw: &[u8],
) -> Result<String, Refusal> {
    if encodings
        .iter()
        .any(|e| !e.trim().is_empty() && !e.trim().eq_ignore_ascii_case("identity"))
    {
        return Err((415, "content-encoding not accepted"));
    }
    let ct = content_type.ok_or((415, "content-type required"))?;
    let mut parts = ct.split(';');
    let mime = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    if !ALLOWED_TYPES.contains(&mime.as_str()) {
        return Err((415, "content-type not accepted"));
    }
    for p in parts {
        if let Some((k, v)) = p.split_once('=')
            && k.trim().eq_ignore_ascii_case("charset")
        {
            let v = v.trim().trim_matches('"').to_ascii_lowercase();
            if v != "utf-8" && v != "utf8" && v != "us-ascii" {
                return Err((415, "charset not accepted"));
            }
        }
    }
    let text = std::str::from_utf8(raw).map_err(|_| (400, "body is not valid utf-8"))?;
    let mut scan = text.to_string();
    match mime.as_str() {
        "application/json" => {
            let v: serde_json::Value =
                serde_json::from_str(text).map_err(|_| (400, "body is not valid json"))?;
            scan.push('\n');
            collect_json(&v, &mut scan);
        }
        "application/x-www-form-urlencoded" => {
            scan.push('\n');
            for pair in text.split('&') {
                let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
                scan.push_str(&crate::decode::percent_decode(k, true));
                scan.push('\n');
                scan.push_str(&crate::decode::percent_decode(v, true));
                scan.push('\n');
            }
        }
        _ => {}
    }
    Ok(scan)
}

/// Client-facing categories: topic detail is collapsed to `blocked`, so the private list
/// cannot be probed word by word.
pub fn public_categories(reasons: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in reasons {
        let c = if r.starts_with("topic:") { "blocked" } else { r.as_str() };
        if !out.iter().any(|x| x == c) {
            out.push(c.to_string());
        }
    }
    out
}

/// Topic blocks per client within a window. Repeated blocks look like word-by-word probing
/// of the private list (the 403 vs 200 membership oracle), so they are logged loudly.
const TOPIC_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const TOPIC_WARN_AT: usize = 3;

#[derive(Default)]
pub struct TopicWatch {
    seen: std::collections::HashMap<std::net::IpAddr, Vec<std::time::Instant>>,
}

impl TopicWatch {
    /// Record a topic block; returns the count in the window once it reaches the warn level.
    pub fn record(&mut self, ip: std::net::IpAddr, now: std::time::Instant) -> Option<usize> {
        let v = self.seen.entry(ip).or_default();
        v.retain(|t| now.duration_since(*t) < TOPIC_WINDOW);
        v.push(now);
        (v.len() >= TOPIC_WARN_AT).then_some(v.len())
    }
}

/// The upstream URL for a client request: the client's path and query under the upstream base.
/// None when the path is not a plain absolute path (absolute-form, dot segments, controls).
pub fn upstream_target(base: &str, client_url: &str) -> Option<String> {
    if !client_url.starts_with('/')
        || client_url.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return None;
    }
    let path = client_url.split(['?', '#']).next().unwrap_or("");
    let dec = crate::decode::percent_decode(&crate::decode::percent_decode(path, false), false);
    if dec.split('/').any(|seg| seg == ".." || seg == ".") || dec.contains('\\') {
        return None;
    }
    if client_url == "/" {
        return Some(base.to_string());
    }
    Some(format!("{}{}", base.trim_end_matches('/'), client_url))
}

/// Serve until the server is dropped. Logs counts and verdicts only. `WORKERS` threads share
/// the listener (tiny_http's Server is Sync), so a client held in the model does not stall others.
pub fn run(server: &tiny_http::Server, upstream: &str, model: Option<&ModelConfig>) {
    if !crate::model::upstream_allowed(upstream) {
        eprintln!("proxy: upstream refused (https, or http to a loopback/private IP literal only)");
        return;
    }
    let watch = std::sync::Mutex::new(TopicWatch::default());
    let watch = &watch;
    std::thread::scope(|s| {
        for _ in 0..WORKERS {
            s.spawn(move || {
                while let Ok(req) = server.recv() {
                    handle(req, upstream, model, watch);
                }
            });
        }
    });
}

fn hdr(req: &tiny_http::Request, name: &str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.to_string())
}

fn handle(
    mut req: tiny_http::Request,
    upstream: &str,
    model: Option<&ModelConfig>,
    watch: &std::sync::Mutex<TopicWatch>,
) {
    if *req.method() != tiny_http::Method::Post {
        let _ = req.respond(json_resp(405, r#"{"error":"POST only"}"#.into()));
        return;
    }
    let cap = if model.is_some() { MAX_BODY_MODEL } else { MAX_BODY };
    let mut raw = Vec::new();
    let read = req.as_reader().take(cap + 1).read_to_end(&mut raw);
    if read.is_err() || raw.len() as u64 > cap {
        let _ = req.respond(json_resp(
            413,
            r#"{"error":"body unreadable or too large"}"#.into(),
        ));
        return;
    }
    let ctype_hdr = hdr(&req, "Content-Type");
    let encodings: Vec<String> = req
        .headers()
        .iter()
        .filter(|h| h.field.equiv("Content-Encoding"))
        .map(|h| h.value.to_string())
        .collect();
    let text = match text_to_scan(ctype_hdr.as_deref(), &encodings, &raw) {
        Ok(t) => t,
        Err((code, msg)) => {
            eprintln!("proxy refused status={code}");
            let _ = req.respond(json_resp(code, format!(r#"{{"error":"{msg}"}}"#)));
            return;
        }
    };
    let Some(target) = upstream_target(upstream, req.url()) else {
        let _ = req.respond(json_resp(400, r#"{"error":"path not accepted"}"#.into()));
        return;
    };
    let v = scan_with(&text, model);
    eprintln!(
        "proxy chars={} verdict={} reasons={}",
        text.chars().count(),
        if v.pass { "PASS" } else { "FAIL" },
        v.reasons.len()
    );
    if !v.pass {
        if v.reasons.iter().any(|r| r.starts_with("topic:"))
            && let Some(ip) = req.remote_addr().map(|a| a.ip())
            && let Some(n) = watch
                .lock()
                .ok()
                .and_then(|mut w| w.record(ip, std::time::Instant::now()))
        {
            eprintln!("proxy WARNING: {n} topic blocks from {ip} within 60s (possible probing of the blocklist)");
        }
        let cats = serde_json::to_string(&public_categories(&v.reasons)).unwrap_or_else(|_| "[]".into());
        let _ = req.respond(json_resp(
            403,
            format!(r#"{{"blocked":true,"categories":{cats}}}"#),
        ));
        return;
    }
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(std::time::Duration::from_secs(60))
        .build();
    let mut up = agent.post(&target);
    for name in FORWARD_REQ {
        if let Some(val) = hdr(&req, name) {
            up = up.set(name, &val);
        }
    }
    let (code, body, heads) = match up.send_bytes(&raw) {
        Ok(r) | Err(ureq::Error::Status(_, r)) => {
            let c = r.status();
            let heads: Vec<(&str, String)> = FORWARD_RESP
                .iter()
                .filter_map(|n| r.header(n).map(|v| (*n, v.to_string())))
                .collect();
            let mut b = Vec::new();
            let _ = r.into_reader().take(MAX_BODY).read_to_end(&mut b);
            (c, b, heads)
        }
        Err(_) => (502, br#"{"error":"upstream unreachable"}"#.to_vec(), Vec::new()),
    };
    let mut resp = tiny_http::Response::from_data(body).with_status_code(code);
    for (n, val) in heads {
        if let Ok(h) = tiny_http::Header::from_bytes(n.as_bytes(), val.as_bytes()) {
            resp.add_header(h);
        }
    }
    let _ = req.respond(resp);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_watch_warns_on_repeats_within_a_minute_only() {
        let ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        let t0 = std::time::Instant::now();
        let mut w = TopicWatch::default();
        assert_eq!(w.record(ip, t0), None);
        assert_eq!(w.record(ip, t0), None);
        assert_eq!(w.record(ip, t0), Some(3));
        // a minute later the window has emptied
        let later = t0 + std::time::Duration::from_secs(61);
        assert_eq!(w.record(ip, later), None);
    }
}
