use gate::{ModelConfig, model, proxy, scan_with};
use std::process::ExitCode;

const USAGE: &str = "usage:\n  arrowmem-gate scan [--model] FILE...\n  arrowmem-gate mask FILE\n  arrowmem-gate selftest [--model]\n  arrowmem-gate proxy --listen 127.0.0.1:PORT --upstream URL [--model]\n\n--model enables the local model layer (ARROWMEM_GATE_URL, default http://127.0.0.1:8080/v1/chat/completions).\nExit: 0 PASS, 2 FAIL, 3 model unreachable, 1 usage or IO error.";

fn model_cfg(on: bool) -> Option<ModelConfig> {
    if !on {
        return ModelConfig::from_env();
    }
    Some(ModelConfig::from_env().unwrap_or_else(|| ModelConfig::new(model::DEFAULT_URL)))
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let use_model = if let Some(i) = args.iter().position(|a| a == "--model") {
        args.remove(i);
        true
    } else {
        false
    };
    let cfg = model_cfg(use_model);
    match args.first().map(String::as_str) {
        Some("scan") if args.len() > 1 => cmd_scan(&args[1..], cfg.as_ref()),
        Some("mask") if args.len() == 2 => match std::fs::read(&args[1]) {
            Ok(b) => {
                print!("{}", gate::mask(&String::from_utf8_lossy(&b)));
                ExitCode::SUCCESS
            }
            Err(_) => ExitCode::from(1),
        },
        Some("selftest") => cmd_selftest(cfg.as_ref()),
        Some("proxy") => cmd_proxy(&args[1..], cfg),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(1)
        }
    }
}

fn cmd_scan(files: &[String], cfg: Option<&ModelConfig>) -> ExitCode {
    let (mut fail, mut unreachable, mut io) = (false, false, false);
    for (n, f) in files.iter().enumerate() {
        let Ok(b) = std::fs::read(f) else {
            eprintln!("file {} verdict=ERROR (unreadable)", n + 1);
            io = true;
            continue;
        };
        let text = String::from_utf8_lossy(&b);
        let v = scan_with(&text, cfg);
        // Counts and verdict only: no path, no content.
        eprintln!(
            "file {} chars={} verdict={} reasons={}",
            n + 1,
            text.chars().count(),
            if v.pass { "PASS" } else { "FAIL" },
            v.reasons.len()
        );
        if !v.pass {
            println!("file {}: FAIL {}", n + 1, v.reasons.join(","));
            if v.model_unreachable {
                unreachable = true;
            } else {
                fail = true;
            }
        }
    }
    // A content FAIL (2) outranks model unreachable (3), which outranks an IO error (1).
    ExitCode::from(if fail { 2 } else if unreachable { 3 } else { u8::from(io) })
}

fn cmd_selftest(cfg: Option<&ModelConfig>) -> ExitCode {
    let mut bad = 0;
    for (text, should_block) in gate::selftest_cases() {
        let got = !scan_with(&text, None).pass;
        println!(
            "{} rules {}",
            if got == should_block { "ok  " } else { "FAIL" },
            if got { "blocks" } else { "passes" }
        );
        bad += usize::from(got != should_block);
    }
    if let Some(c) = cfg {
        if !model::reachable(c) {
            println!("selftest: model NOT reachable");
            return ExitCode::from(3);
        }
        for (text, should_pass) in gate::model_selftest_cases() {
            let got = scan_with(text, Some(c)).pass;
            println!(
                "{} model {}",
                if got == should_pass { "ok  " } else { "FAIL" },
                if got { "PASS" } else { "FAIL" }
            );
            bad += usize::from(got != should_pass);
        }
    }
    println!(
        "selftest: {}",
        if bad == 0 {
            "PASS".to_string()
        } else {
            format!("FAIL ({bad})")
        }
    );
    ExitCode::from(u8::from(bad > 0) * 2)
}

fn cmd_proxy(a: &[String], cfg: Option<ModelConfig>) -> ExitCode {
    let get = |k: &str| {
        a.iter()
            .position(|x| x == k)
            .and_then(|i| a.get(i + 1))
            .cloned()
    };
    let (Some(listen), Some(upstream)) = (get("--listen"), get("--upstream")) else {
        eprintln!("{USAGE}");
        return ExitCode::from(1);
    };
    if !model::upstream_allowed(&upstream) {
        eprintln!("proxy: upstream must be https, or http to a loopback/private IP literal");
        return ExitCode::from(1);
    }
    match proxy::bind(&listen) {
        Ok(s) => {
            // The bound address, not the requested one: a caller that asked for port 0 reads the real port here.
            let bound = s.server_addr().to_ip().map_or_else(|| listen.clone(), |a| a.to_string());
            eprintln!("proxy listening on {bound}");
            proxy::run(&s, &upstream, cfg.as_ref());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("proxy: {e}");
            ExitCode::from(1)
        }
    }
}
