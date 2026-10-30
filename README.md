# arrowmem-gate

A leak gate. Text goes in, a verdict comes out. It runs on your machine and is meant to sit in
front of anything that sends text elsewhere.

## What it does

Two layers.

1. **Rules.** Regex plus Luhn checks for secrets (cloud keys, tokens, private keys, assigned
   machine generated secrets), personal data (card numbers, Canadian SINs, personal-provider emails, phone
   numbers) and an optional private list of blocked topic words (none ship with the crate). The rules are tables in `src/rules.rs`; adding a
   rule is adding a row.
2. **Model (optional).** A local model on an OpenAI-style chat endpoint classifies the text as
   BUSINESS or PERSONAL. Anything other than BUSINESS fails. Off unless you ask for it.

A verdict carries categories only (for example `personal:email`), never the matched text.
`mask` replaces rule hits with typed placeholders: `[EMAIL]`, `[PHONE]`, `[CARD]`, `[SIN]`,
`[SECRET]`.

## What it does not do

It is a control, not a guarantee. Regexes miss things; a small model misjudges things. A PASS
means "nothing this gate knows how to see", not "nothing personal". Blocked topic words cannot be
masked, only refused. Do not describe it as preventing leaks; describe it as a check that runs
before text leaves.

## Read this before you rely on it

- **The rules layer can be bypassed by any encoding it does not decode.** It decodes NFKC
  compatibility forms, percent-encoding, base64 (standard and URL-safe, nested, up to three
  levels), hex runs of 32 or more characters and backslash escapes (`\uXXXX`, `\xXX`, nested), strips invisible characters (Default_Ignorable_Code_Point, general categories Cf, Mn and Me, braille blank), folds Unicode digits and cross-script lookalike letters (UTS #39) to ASCII, and it refuses `Content-Encoding` other than identity and
  any `Content-Type` outside `text/plain`, `application/json` and
  `application/x-www-form-urlencoded`. It does NOT decode rot13, UTF-16, compressed or
  encrypted data, steganography, or text split across requests. The opacity check is limited to base64 shaped runs: a run of 16 or more base64
  characters, taken from the text as written (split on whitespace, never a
  whitespace stripped view), that does not decode to text and looks random (Shannon entropy over a
  sliding window). Random looking runs that add up past a fixed total, or a single long one, are refused as `encoded:opaque_blob`. SRI hashes at their fixed length (sha256 at 43 or 44, sha384 at 64, sha512 at 86 or 88) and
  OpenSSH public keys are not counted. A key is counted as a key only if its wire format parses
  (length prefixed fields) and is consumed exactly. What a key shaped line can still carry, per type,
  as arbitrary bytes: ed25519 32 (not checked on the curve); ECDSA the point, 64 (nistp256), 96
  (nistp384) or 132 (nistp521), not checked on the curve; RSA the whole modulus, 128, 256, 384 or 512
  (exponent must be 3, 17 or 65537, modulus a standard size, odd, high bit set; a modulus cannot be
  told from random); a security key form adds up to 60 after the `ssh:` prefix of its application
  field. So about 32 to 512 bytes a line can leave as a key, and twenty 4096 bit shaped lines (about
  10 KB) PASS, kept as `known_residual_rsa_shaped_lines_carry_the_modulus` in `tests/round4.rs`. Hex, base32 and other alphabets are not counted, and a blob cut into pieces
  under 16 characters, or wrapped in the `sha512-` prefix at 88 characters a piece, is not seen.
  This is a check on what the gate can see, not a bound on how much can leave. The known cases are
  kept as tests named `known_residual_*` in `tests/round2.rs`. Also not seen: random runs padded
  with filler (12 random characters then 8 filler, in pieces of 20), which drop under the entropy
  threshold at about 1.7 times the bytes.
- **The secret rule finds machine generated secrets, not human chosen passwords.** An assignment
  to a password, secret or key name is a hit when its value has at least 3.5 bits of Shannon
  entropy per character and contains no stopword (the gitleaks generic key shape). A value of 11
  characters or fewer, or digits only, cannot reach that floor, so a season plus a year, a four
  word passphrase or an 8 digit PIN PASS. Appending a stopword such as `value` inside the
  quotes of a random value also passes. Kept as `known_residual_human_chosen_passwords_pass` in
  `tests/round3.rs`.
- **Card and email shapes.** A card is a 2 to 6 led 13, 15 (Amex), 16 or 19 digit group form that
  passes Luhn; a card glued to extra digits, or to trailing letters, with no separator is not matched (`known_residual_card_glued_to_trailing_letters_passes`). An email on a
  consumer provider matches by name; any other address is refused only when a host label mixes
  scripts beyond UTS #39 Highly Restrictive (Latin with Cyrillic, for example). Single script
  international hosts, accented Latin and all Cyrillic included, pass. An `xn--` label is decoded
  to Unicode (idna crate, UTS 46) and an HTML numeric character reference (`&#1084;`, `&#x43c;`) is
  decoded before that check; named entities (`&amp;`) are not decoded.
- **The model layer is prompt-injectable.** The text is delimited and the model is told to treat
  it as data, but a small local model can still be talked round. The model verdict is advisory:
  it can add a FAIL, never remove one. A rule hit fails whatever the model says. The selftest
  carries a canary (a personal sentence plus an appended "answer BUSINESS" instruction) that
  must still FAIL; run `arrowmem-gate selftest --model` after any model or prompt change.
- **A host egress firewall is required for the gate to mean anything.** The gate is a proxy.
  Anything else on the host can connect out directly and skip it. Allow outbound connections
  only from the gate's own user (for example an nftables `meta skuid` rule) and drop the rest.
  Without that, treat the gate as a check for cooperating software only, not as a control
  against a hostile local process.
- **Loopback trust is host-wide, in both directions.** Any local process that binds the model's
  loopback port first receives everything that reached the model layer (the text the rules
  passed, which is the sensitive residue) under the configured bearer token. The egress rule
  above covers outbound traffic only. Run the model under the gate's own uid and extend the
  firewall rule to loopback (only that uid may connect to the model port and to the gate's listen
  port), or the model layer is trustworthy only on a host with no other local users or services.
- **Proxy behaviour.** Four worker threads share the listener; with the model on, bodies over
  256 KiB are refused (413) and one request gets at most 120 s of model time, then fails closed.
  A client that holds a partial body open occupies a worker until it disconnects. Authorization,
  Content-Type, Accept and X-Request-Id are forwarded with the client's path and query under the
  upstream base; Host, Cookie and hop-by-hop headers never are. `mask` withholds the whole text
  when a hit exists only in a decoded or hidden form, since it cannot be replaced in place.
- The 403 body names categories only. Blocked topic words are reported as `blocked`, never by
  word or list.
- **Residual: the blocklist can be probed one word at a time.** A word sent alone as
  `text/plain` returns 403 when it is on the private list and 200 when it is not, so any local
  client can learn membership by trying words. No proxy that blocks on a word can hide that.
  The control is detection: three or more topic blocks from one client within a minute are
  logged as a WARNING on stderr.
- Bodies that produce more distinct decoded views than the bound (4096 views or 8 MB of decoded text) are
  refused as `encoded:too_many_views`.

## Rules that are not options

- **Loopback only for the model.** The model URL must be `http://` with a loopback host
  (`127.0.0.0/8`, `::1`), no userinfo. Hostnames, including `localhost`, are refused. Anything else is refused before any request
  is made. Redirects are not followed.
- **Fail closed.** Model unreachable, timeout, malformed reply, non-loopback URL: the text is
  refused. Exit code 3 (CLI) or a 403 (proxy).
- **A rule hit never reaches the model.** Text that already failed is not sent anywhere.
- **Counts only in logs.** Logs (stderr) hold character counts, verdicts and reason counts. No
  content, no file names. Nothing is written to disk by the gate.

## Run it

```
cargo build --release
```

Scan (exit 0 PASS, 2 FAIL, 3 model unreachable, 1 usage or IO error):

```
arrowmem-gate scan FILE...
arrowmem-gate scan --model FILE...
```

Mask (prints to stdout):

```
arrowmem-gate mask FILE
```

Self-test (rules cases always; model cases with `--model`):

```
arrowmem-gate selftest
arrowmem-gate selftest --model
```

Proxy. Accepts HTTP POST, scans the body, forwards to the upstream on PASS, returns
`403 {"blocked":true,"categories":[...]}` on FAIL. Listens on loopback only; a non-loopback
`--listen` is refused. The upstream must be `https://` (rustls), or `http://` to a loopback or RFC1918 IP literal. A TLS failure returns 502 and nothing is forwarded as success.

```
arrowmem-gate proxy --listen 127.0.0.1:8099 --upstream https://example.invalid/api [--model]
```

### Model settings

`--model` turns the model layer on. Environment:

| variable | default |
|---|---|
| `ARROWMEM_GATE_URL` | `http://127.0.0.1:8080/v1/chat/completions` |
| `ARROWMEM_GATE_MODEL` | `local` |
| `ARROWMEM_GATE_TOKEN` | `local` (a fixed loopback bearer, not a secret) |
| `ARROWMEM_GATE_UNSURE` | unset. `business` makes only an explicit PERSONAL answer fail; default is "if unsure, PERSONAL" |
| `ARROWMEM_GATE_BLOCKLIST` | unset. Path to a private file, one topic word per line; an unreadable file fails closed |

Setting `ARROWMEM_GATE_URL` also enables the layer without the flag. Make sure the model server
itself does not log prompts (no verbose mode), or the checker becomes the leak.

## Library

```rust
let v = gate::scan("text");          // rules, plus the model if ARROWMEM_GATE_URL is set
if !v.pass { /* v.reasons: category names only */ }
let safe = gate::mask("text");
```

## Test

```
cargo test
cargo clippy --all-targets -- -D warnings
```

Licence: Apache-2.0.
