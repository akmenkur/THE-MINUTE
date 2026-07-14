//! THE MINUTE - server.
//! One static page, one JSON registry, one chain, one Bitcoin account.
//! Automates everything except the single human action: the REFUSE veto.
//!
//! Payment identification has two modes:
//!  - xpub (recommended): each claim gets its own derived address (/0/i),
//!    any amount >= price identifies it. No spending key on the server.
//!  - legacy: a shared address + a unique amount per claim.
//!
//! Flow: POST /api/claim reserves a future minute -> the poller watches the
//! address(es) on public Esplora APIs (read only) -> a confirmed payment
//! marks the claim paid -> after the veto window it is auto-engraved into
//! the blake3 chain + registry -> the page shows it live. The buyer follows
//! everything on /?c=<claim_id>.

mod affiliates;
mod mempool;
mod promo;
mod store;
mod validate;
mod xpub;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as AnyhowContext, Result};
use bitcoin::bip32::Xpub;
use serde::Deserialize;
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use affiliates::Affiliates;
use promo::Promo;
use store::{render_registry_json, verify_chain_file, ClaimStatus, RegistryEntry, Store};

const BODY_LIMIT: u64 = 8192;

/// The 1200x630 social-card image, baked into the binary so there is no
/// separate asset to deploy or lose. A crawler fetches it out-of-band.
const OG_IMAGE: &[u8] = include_bytes!("../og.png");
const FAVICON_SVG: &str = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='#0a0a0a'/><circle cx='16' cy='16' r='11' fill='none' stroke='#d4af37' stroke-width='2'/><line x1='16' y1='16' x2='11' y2='11' stroke='#f6e3a1' stroke-width='2.2' stroke-linecap='round'/><line x1='16' y1='16' x2='22' y2='9' stroke='#f6e3a1' stroke-width='2.2' stroke-linecap='round'/><circle cx='16' cy='16' r='1.7' fill='#f6e3a1'/></svg>";

fn default_esplora_apis() -> Vec<String> {
    vec![
        "https://mempool.space/api".to_owned(),
        "https://blockstream.info/api".to_owned(),
    ]
}
fn default_poll() -> u64 {
    60
}
fn default_expiry() -> u64 {
    72
}
fn default_auto_engrave() -> u64 {
    6
}
fn default_min_lead() -> u64 {
    4
}
fn default_xpub_start() -> u64 {
    1 // /0/0 is the merchant's own address: never assigned to a claim
}
fn default_rate_limit() -> usize {
    // Per IP, per hour, shared by claim creation and code redemption. Codes are
    // 60-bit single-use so they can't be brute-forced; keep this forgiving so a
    // buyer fixing a typo (or the merchant testing) is never wrongly blocked.
    30
}
fn default_affiliate_pct() -> u64 {
    25
}
fn default_payout_threshold() -> u64 {
    10_000
}
fn default_min_conf() -> u64 {
    1 // the 6h auto-engrave veto is the primary reorg defense; raise for high value
}
fn default_min_sources() -> usize {
    2 // require two independent Esplora sources to agree before a payment counts
}

#[derive(Deserialize, Clone)]
struct Config {
    btc_address: String,
    price_sats: u64,
    bind: String,
    data_dir: String,
    site_index: String,
    #[serde(default)]
    admin_token: String,
    #[serde(default = "default_esplora_apis")]
    esplora_apis: Vec<String>,
    #[serde(default = "default_poll")]
    poll_secs: u64,
    #[serde(default = "default_expiry")]
    claim_expiry_hours: u64,
    /// 0 = manual mode (every engraving needs the admin click).
    /// N > 0 = auto mode: a paid claim is engraved immediately, on the
    /// poll that confirms its payment (no veto window).
    #[serde(default = "default_auto_engrave")]
    auto_engrave_hours: u64,
    /// A future minute must be claimed at least N hours before it arrives,
    /// so every live moment had a moderation window. 0 disables.
    #[serde(default = "default_min_lead")]
    min_lead_hours: u64,
    /// Watch-only extended public key: each claim gets its own fresh
    /// address (/0/i). Empty = legacy unique-amount mode on btc_address.
    #[serde(default)]
    xpub: String,
    #[serde(default = "default_xpub_start")]
    xpub_start_index: u64,
    /// Claim creations allowed per IP per hour.
    #[serde(default = "default_rate_limit")]
    rate_limit_per_hour: usize,
    /// Direct affiliate commission, percent of each referred sale. 0 = off.
    #[serde(default = "default_affiliate_pct")]
    affiliate_pct: u64,
    /// Balances below this roll over to the next month (dust control).
    #[serde(default = "default_payout_threshold")]
    affiliate_payout_threshold_sats: u64,
    /// Confirmations required before a payment counts. 1 = one block. The
    /// auto-engrave veto (hours) is the real reorg defense; this is extra.
    #[serde(default = "default_min_conf")]
    min_confirmations: u64,
    /// Independent Esplora sources that must AGREE on the same paying tx before
    /// it counts, so one compromised/lying source cannot trigger a false
    /// engraving. Clamped to the number of configured sources; 1 = no consensus.
    #[serde(default = "default_min_sources")]
    min_sources: usize,
}

struct Ctx {
    cfg: Config,
    account: Option<Xpub>,
    store: Mutex<Store>,
    affiliates: Mutex<Affiliates>,
    rate: Mutex<HashMap<IpAddr, Vec<u64>>>,
    /// confirmed payments to the shared address matching NO claim (legacy
    /// mode, wrong amount sent): surfaced on the admin page, never ignored
    unmatched: Mutex<Vec<(String, u64)>>,
    /// Live confirmation depth of a seen-but-not-yet-final payment, keyed by
    /// claim id (0 = in the mempool, unconfirmed). The poller rebuilds it each
    /// cycle so the buyer can watch 0 -> 1 -> 2. Ephemeral (recomputed on the
    /// next poll after a restart); never gates the payment decision.
    confirmations: Mutex<HashMap<String, u64>>,
    /// Promo codes: each grants ONE free engraving. Single-use, burned on
    /// redemption. Only ever locked AFTER `store` (redeem holds store, then
    /// promo), so the two can never deadlock.
    promo: Mutex<Promo>,
    /// Referrer address -> IPs that registered it as their own reward. A
    /// purchase self-referred from the same IP earns no commission (a simple,
    /// evadable anti-self-referral heuristic). In-memory only (transient-IP
    /// policy), bounded by MAX_AFF_IP_ADDRS addresses x 8 IPs.
    aff_ips: Mutex<HashMap<String, HashSet<IpAddr>>>,
}

/// Cap on how many referrer addresses the same-IP heuristic remembers.
const MAX_AFF_IP_ADDRS: usize = 50_000;

impl Ctx {
    fn payments_open(&self) -> bool {
        self.account.is_some() || !self.cfg.btc_address.is_empty()
    }
    fn admin_enabled(&self) -> bool {
        self.cfg.admin_token.len() >= 16
    }
}

type Resp = Response<std::io::Cursor<Vec<u8>>>;

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970") // unrecoverable misconfiguration
        .as_secs()
}

/// Keep serving even if a handler panicked while holding a lock.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Constant-time comparison for the admin token.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("static header is valid")
}

fn body_resp(code: u16, ctype: &str, body: Vec<u8>) -> Resp {
    Response::from_data(body)
        .with_status_code(code)
        .with_header(header("Content-Type", ctype))
}

fn json_resp(code: u16, body: String) -> Resp {
    body_resp(code, "application/json; charset=utf-8", body.into_bytes())
        .with_header(header("Cache-Control", "no-store"))
}

fn html_resp(code: u16, body: String) -> Resp {
    body_resp(code, "text/html; charset=utf-8", body.into_bytes())
}

/// Display sats as trimmed BTC (0.00021 BTC).
fn fmt_btc(sats: u64) -> String {
    let s = format!("{:.8}", sats as f64 / 1e8);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    format!("{s} BTC")
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn read_body(rq: &mut Request) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    rq.as_reader()
        .take(BODY_LIMIT)
        .read_to_end(&mut buf)
        .context("read request body")?;
    Ok(buf)
}

fn form_get<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    body.split('&').find_map(|kv| {
        let mut it = kv.splitn(2, '=');
        match (it.next(), it.next()) {
            (Some(k), Some(v)) if k == key => Some(v),
            _ => None,
        }
    })
}

/// Real client IP: behind the local reverse proxy (Caddy/nginx), the
/// remote address is loopback and the LAST hop of X-Forwarded-For is the
/// one the proxy appended (client cannot forge it). Anywhere else, the
/// socket address is authoritative.
fn client_ip(rq: &Request) -> IpAddr {
    let remote = rq
        .remote_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([0u8, 0, 0, 0]));
    if remote.is_loopback() {
        for h in rq.headers() {
            if h.field.equiv("x-forwarded-for") {
                if let Some(last) = h.value.as_str().rsplit(',').next() {
                    if let Ok(ip) = last.trim().parse() {
                        return ip;
                    }
                }
            }
        }
    }
    remote
}

fn rate_limited(ctx: &Ctx, ip: IpAddr, now: u64) -> bool {
    let mut map = lock(&ctx.rate);
    let hits = map.entry(ip).or_default();
    hits.retain(|t| *t + 3600 > now);
    if hits.len() >= ctx.cfg.rate_limit_per_hour {
        return true;
    }
    hits.push(now);
    false
}

/// Drop rate-limiter entries whose 1-hour window has fully expired, so the
/// map stays bounded to IPs active in the last hour instead of growing by one
/// entry per IP that ever posted (unbounded memory over the server's life).
fn prune_rate(map: &mut HashMap<IpAddr, Vec<u64>>, now: u64) {
    map.retain(|_, hits| {
        hits.retain(|t| *t + 3600 > now);
        !hits.is_empty()
    });
}

fn handle_index(ctx: &Ctx) -> Resp {
    match std::fs::read(&ctx.cfg.site_index) {
        Ok(bytes) => body_resp(200, "text/html; charset=utf-8", bytes),
        Err(e) => {
            eprintln!("[error] site index {}: {e}", ctx.cfg.site_index);
            html_resp(500, "site file missing".to_owned())
        }
    }
}

/// HTML-attribute-safe AND ASCII-safe encoding of an attacker-controlled value
/// for a DOUBLE-QUOTED content="..." meta attribute. Escapes & < > " ' (so the
/// value can never close the attribute or open a tag) AND folds every non-ASCII
/// scalar to a decimal numeric reference (&#N;), keeping the served page 100%
/// ASCII. INVARIANT: safe ONLY inside a double-quoted attribute - esc does not
/// escape space, = or /, so an unquoted attribute would reopen breakout.
fn meta_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if (c as u32) >= 0x20 && (c as u32) < 0x7f => out.push(c),
            c => out.push_str(&format!("&#{};", c as u32)),
        }
    }
    out
}

/// Value of `key` in a `&`-separated query string, or None.
fn query_get<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let mut it = kv.splitn(2, '=');
        match (it.next(), it.next()) {
            (Some(k), Some(v)) if k == key => Some(v),
            _ => None,
        }
    })
}

/// Decode only %XX escapes and '+' -> space; enough to restore a minute id
/// whose ':' arrived as %3A.
fn percent_decode_ascii(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = |c: u8| (c as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// "12:00 UTC, 1 January 2030" from a canonical minute id (already validated).
fn pretty_minute(min: &str) -> String {
    let g = |r: std::ops::Range<usize>| min.get(r).unwrap_or("");
    let mo: usize = g(5..7).parse().unwrap_or(1);
    let name = MONTHS.get(mo.saturating_sub(1)).copied().unwrap_or("");
    let day = g(8..10).trim_start_matches('0');
    format!(
        "{}:{} UTC, {} {} {}",
        g(11..13),
        g(14..16),
        if day.is_empty() { "0" } else { day },
        name,
        g(0..4)
    )
}

/// Coarsest human interval: "in 3 years" / "in 5 days" / "in under a minute".
fn until_human(secs: u64) -> String {
    if secs < 60 {
        return "in under a minute".to_owned();
    }
    let (n, unit) = if secs >= 365 * 86400 {
        (secs / (365 * 86400), "year")
    } else if secs >= 86400 {
        (secs / 86400, "day")
    } else if secs >= 3600 {
        (secs / 3600, "hour")
    } else {
        (secs / 60, "minute")
    };
    format!("in {} {}{}", n, unit, if n == 1 { "" } else { "s" })
}

/// The homepage, with per-minute social-card meta tags when ?s=<minute> names a
/// real minute. Crawlers do not run JS, so the SERVER injects the tags. Rule IV
/// holds BY CONSTRUCTION: a sealed (future) minute's words are never read. Any
/// bad input or anchor drift falls safe to the generic page (never a 500).
fn handle_share(ctx: &Ctx, url: &str) -> Resp {
    let Some(query) = url.split('?').nth(1) else {
        return handle_index(ctx); // plain homepage: fast raw path
    };
    let Some(raw) = query_get(query, "s") else {
        return handle_index(ctx);
    };
    let min = percent_decode_ascii(raw);
    let Some(epoch) = validate::minute_id_to_epoch(&min) else {
        return handle_index(ctx); // malformed / impossible minute
    };
    let Ok(page) = std::fs::read_to_string(&ctx.cfg.site_index) else {
        return handle_index(ctx);
    };
    let now = epoch_now();
    let entry = { lock(&ctx.store).registry.get(&min).cloned() };
    let pretty = pretty_minute(&min);
    let (title, desc, alt) = match entry {
        None => (
            format!("An unclaimed minute - {pretty}"),
            format!("{pretty} belongs to no one yet. Claim this minute of forever and write the words the world will read the moment it arrives. One minute, one owner, once."),
            format!("THE MINUTE - an unclaimed minute of forever, {pretty}"),
        ),
        Some(e) if epoch > now as i64 => {
            // SEALED FUTURE: e.msg is NEVER read here (Rule IV by construction).
            let name = if e.name.is_empty() { "Anonymous" } else { &e.name };
            let u = until_human((epoch as u64).saturating_sub(now));
            (
                format!("{name} owns {pretty}"),
                format!("{name} has sealed words into this minute. They stay hidden until it arrives {u} - then hold this page live, in gold, for sixty seconds. Once, forever."),
                format!("THE MINUTE - a sealed minute owned by {name}, arriving {u}"),
            )
        }
        Some(e) => {
            let name = if e.name.is_empty() { "Anonymous" } else { &e.name };
            (
                format!("{name} - {pretty}"),
                format!("\"{}\" - {name}. This minute arrived, held the world for sixty seconds, and now rests forever in the ledger.", e.msg),
                format!("THE MINUTE - {name}'s minute, engraved forever"),
            )
        }
    };
    let d = meta_attr(&desc);
    let t = meta_attr(&title);
    let a = meta_attr(&alt);
    let share_url = meta_attr(&format!("https://minuteofforever.com/?s={min}"));
    // Replace each dynamic tag's full static line. A missing/duplicated anchor
    // (a future edit) falls safe to the generic page - never a half-injected head.
    let reps: [(&str, String); 8] = [
        ("<meta name=\"description\" content=\"Every minute - past and future - can belong to exactly one human, forever. Write your words into your minute. When it arrives, they hold this page for its entire minute, live, once.\">",
         format!("<meta name=\"description\" content=\"{d}\">")),
        ("<meta property=\"og:url\" content=\"https://minuteofforever.com/\">",
         format!("<meta property=\"og:url\" content=\"{share_url}\">")),
        ("<meta property=\"og:title\" content=\"THE MINUTE - Own one minute of forever\">",
         format!("<meta property=\"og:title\" content=\"{t}\">")),
        ("<meta property=\"og:description\" content=\"One minute. One owner. Forever. When your minute arrives, your words hold this instant of the world for sixty seconds.\">",
         format!("<meta property=\"og:description\" content=\"{d}\">")),
        ("<meta property=\"og:image:alt\" content=\"THE MINUTE - a golden clock on black, own one minute of forever\">",
         format!("<meta property=\"og:image:alt\" content=\"{a}\">")),
        ("<meta name=\"twitter:title\" content=\"THE MINUTE - Own one minute of forever\">",
         format!("<meta name=\"twitter:title\" content=\"{t}\">")),
        ("<meta name=\"twitter:description\" content=\"One minute. One owner. Forever. When your minute arrives, your words hold this instant of the world for sixty seconds.\">",
         format!("<meta name=\"twitter:description\" content=\"{d}\">")),
        ("<meta name=\"twitter:image:alt\" content=\"THE MINUTE - a golden clock on black, own one minute of forever\">",
         format!("<meta name=\"twitter:image:alt\" content=\"{a}\">")),
    ];
    let mut out = page;
    for (anchor, rep) in &reps {
        if out.matches(anchor).count() != 1 {
            return handle_index(ctx);
        }
        out = out.replacen(anchor, rep, 1);
    }
    if !out.is_ascii() {
        return handle_index(ctx); // never break the ASCII invariant
    }
    body_resp(200, "text/html; charset=utf-8", out.into_bytes())
        .with_header(header("Cache-Control", "public, max-age=300"))
}

/// The social-card image (1200x630 PNG), baked into the binary.
fn handle_og_image() -> Resp {
    body_resp(200, "image/png", OG_IMAGE.to_vec())
        .with_header(header("Cache-Control", "public, max-age=86400"))
}

/// favicon: served as a real file at a stable URL so search engines (Google)
/// can fetch it; the same clock icon that index.html carries as a data-URI.
fn handle_favicon() -> Resp {
    body_resp(200, "image/svg+xml", FAVICON_SVG.as_bytes().to_vec())
        .with_header(header("Cache-Control", "public, max-age=604800"))
}

fn handle_registry(ctx: &Ctx) -> Result<Resp> {
    // clone the registry under the lock, serialize OUTSIDE it (never block the
    // store lock / payment poller behind a public unauthenticated GET).
    let registry = { lock(&ctx.store).registry.clone() };
    let body = render_registry_json(&registry, epoch_now())?;
    Ok(json_resp(200, body))
}

fn handle_health(ctx: &Ctx) -> Resp {
    // any free codes left? once all are spent, the field vanishes client-side.
    let promo_open = {
        let p = lock(&ctx.promo);
        p.total() > p.used()
    };
    json_resp(
        200,
        json!({
            "ok": true,
            "now": epoch_now(),
            "payments_open": ctx.payments_open(),
            "auto_engrave_hours": ctx.cfg.auto_engrave_hours,
            "min_lead_hours": ctx.cfg.min_lead_hours,
            "affiliate_pct": ctx.cfg.affiliate_pct,
            "promo_open": promo_open,
        })
        .to_string(),
    )
}

/// The raw cryptographic ledger, one JSON entry per line. Public:
/// anyone can download it and verify every link (minute-server verify).
fn handle_chain_file(ctx: &Ctx) -> Resp {
    let path = Path::new(&ctx.cfg.data_dir).join("chain.jsonl");
    let bytes = std::fs::read(&path).unwrap_or_default(); // empty chain = empty file
    body_resp(200, "application/x-ndjson; charset=utf-8", bytes)
        .with_header(header("Cache-Control", "no-store"))
}

fn handle_chain_tip(ctx: &Ctx) -> Resp {
    let st = lock(&ctx.store);
    let tip = if st.chain_len == 0 {
        Value::Null
    } else {
        Value::String(st.chain_tip.clone())
    };
    json_resp(
        200,
        json!({ "entries": st.chain_len, "tip": tip }).to_string(),
    )
}

/// Anchor proofs (OpenTimestamps) made public: anyone can download a
/// dated chain snapshot + its .ots and verify, against Bitcoin itself,
/// that the whole history existed at that date.
fn handle_anchors_list(ctx: &Ctx) -> Resp {
    let dir = Path::new(&ctx.cfg.data_dir).join("anchors");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    json_resp(
        200,
        serde_json::to_string(&files).unwrap_or_else(|_| "[]".to_owned()),
    )
}

fn handle_anchor_file(ctx: &Ctx, name: &str) -> Resp {
    // strict allowlist: traversal impossible by construction
    let clean = !name.is_empty()
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_');
    if !clean {
        return json_resp(404, json!({ "error": "not found" }).to_string());
    }
    let path = Path::new(&ctx.cfg.data_dir).join("anchors").join(name);
    match std::fs::read(&path) {
        Ok(bytes) => body_resp(200, "application/octet-stream", bytes),
        Err(_) => json_resp(404, json!({ "error": "not found" }).to_string()),
    }
}

/// Canonical mainnet Bitcoin address, or None. Used for affiliate links
/// and reward addresses: anything else is silently not an affiliate.
fn valid_btc_address(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > 100 {
        return None;
    }
    s.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
        .ok()?
        .require_network(bitcoin::Network::Bitcoin)
        .ok()
        .map(|a| a.to_string())
}

/// Engrave a paid claim, then accrue affiliate commissions on this real,
/// completed sale. An accrual failure never blocks the engraving: the
/// chain is the ledger of record, and the error is logged loudly.
fn engrave_with_commissions(ctx: &Ctx, st: &mut Store, claim_id: &str, now: u64) -> Result<String> {
    let minute = st.engrave(claim_id, now)?;
    if let Some(c) = st.claims.get(claim_id) {
        let mut aff = lock(&ctx.affiliates);
        match aff.on_sale(c, ctx.cfg.affiliate_pct, now) {
            Ok(lines) => {
                for l in lines {
                    eprintln!("[affiliate] {l}");
                }
            }
            Err(e) => eprintln!("[affiliate] ACCRUAL ERROR claim {claim_id}: {e:#}"),
        }
    }
    Ok(minute)
}

/// The public, provable affiliate ledger.
fn handle_affiliates_json(ctx: &Ctx) -> Resp {
    let aff = lock(&ctx.affiliates);
    json_resp(
        200,
        aff.public_json(
            ctx.cfg.affiliate_pct,
            ctx.cfg.affiliate_payout_threshold_sats,
        ),
    )
}

/// Set the buyer's reward address on their claim (the claim id is the
/// unguessable credential). This is how a buyer becomes an affiliate.
fn handle_reward(rq: &mut Request, ctx: &Ctx, id: &str) -> Result<Resp> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(json_resp(
            404,
            json!({ "error": "unknown claim" }).to_string(),
        ));
    }
    let body = read_body(rq)?;
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return Ok(json_resp(
            400,
            json!({ "error": "invalid json" }).to_string(),
        ));
    };
    let raw = v.get("address").and_then(Value::as_str).unwrap_or("");
    let Some(addr) = valid_btc_address(raw) else {
        return Ok(json_resp(
            400,
            json!({ "error": "not a valid mainnet Bitcoin address" }).to_string(),
        ));
    };
    let mut st = lock(&ctx.store);
    if !st.claims.contains_key(id) {
        return Ok(json_resp(
            404,
            json!({ "error": "unknown claim" }).to_string(),
        ));
    }
    st.set_refs(id, None, Some(addr.clone()))?;
    // If this claim was itself referred, the buyer is now recruited by that
    // referrer: record the upline edge (set-once) so the buyer's own future
    // sales pay the right chain, even before this purchase is engraved.
    let refby = st.claims.get(id).and_then(|c| c.referred_by.clone());
    drop(st);
    if let Some(refby) = refby {
        let mut aff = lock(&ctx.affiliates);
        if let Err(e) = aff.link_recruit(&addr, &refby, epoch_now()) {
            eprintln!("[affiliate] link_recruit failed on claim {id}: {e:#}");
        }
    }
    // Remember which IPs claim this address as their own reward, so a later
    // purchase self-referred from the same IP earns no commission.
    {
        let ip = client_ip(rq);
        let mut m = lock(&ctx.aff_ips);
        if m.len() < MAX_AFF_IP_ADDRS || m.contains_key(&addr) {
            let set = m.entry(addr.clone()).or_default();
            if set.len() < 8 {
                set.insert(ip);
            }
        }
    }
    eprintln!("[affiliate] reward address set on claim {id}");
    Ok(json_resp(
        200,
        json!({ "reward_address": addr }).to_string(),
    ))
}

/// Escape a string into a JS single-quoted literal that can never break
/// out of its script block (no quote, no backslash, no "</script>", and
/// every non-ASCII char as \uXXXX so the snapshot stays pure ASCII).
fn js_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '<' => out.push_str("\\x3C"),
            c if (c as u32) >= 0x20 && (c as u32) < 0x7f => out.push(c),
            c => {
                let mut buf = [0u16; 2];
                for u in c.encode_utf16(&mut buf) {
                    out.push_str(&format!("\\u{u:04x}"));
                }
            }
        }
    }
    out
}

/// Standard base64 (dependency-free). Used to embed the exact bytes of the
/// chain into the snapshot while keeping the file 100% ASCII.
fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// The monument in ONE self-contained file: the page with the full public
/// registry embedded (Rule IV holds: words of minutes still to come are
/// sealed - only name and live flag appear). Every owner keeps a copy:
/// the monument replicates through the very people it certifies, and the
/// chain (plus its Bitcoin anchors) decides what is authentic.
fn build_monument_snapshot(
    page: &str,
    registry: &BTreeMap<String, RegistryEntry>,
    chain_len: u64,
    chain_tip: &str,
    chain_jsonl: &[u8],
    now: u64,
) -> Result<String> {
    const DOCTYPE: &str = "<!DOCTYPE html>";
    const MARK: &str = "const REGISTRY = {";
    if !page.starts_with(DOCTYPE) {
        anyhow::bail!("site index does not start with the doctype");
    }
    if page.matches(MARK).count() != 1 {
        anyhow::bail!("site index has no unique registry marker");
    }
    if page.matches("</body>").count() != 1 {
        anyhow::bail!("site index has no unique </body>");
    }
    let mut entries = String::new();
    for (minute, e) in registry {
        let arrived = validate::minute_id_to_epoch(minute)
            .map(|epoch| epoch <= now as i64)
            .unwrap_or(false);
        let msg = if arrived {
            format!("'{}'", js_escape(&e.msg))
        } else {
            "null".to_owned()
        };
        entries.push_str(&format!(
            "\n  '{}': {{ name: '{}', msg: {}, live: {} }},",
            js_escape(minute),
            js_escape(&e.name),
            msg,
            e.live
        ));
    }
    let stamp = validate::epoch_to_minute_id(now as i64).unwrap_or_default();
    let tip = if chain_len == 0 {
        "genesis (no engraving sealed yet)".to_owned()
    } else {
        chain_tip.to_owned()
    };
    let comment = format!(
        "{DOCTYPE}\n<!--\nTHE MINUTE - MONUMENT SNAPSHOT (self-contained, works offline forever)\n\
         Snapshot minute (UTC): {stamp}\nEngravings sealed in the chain: {}\n\
         Chain tip (blake3): {tip}\n\
         Words of minutes that had not yet arrived stay sealed: not in this file.\n\
         THE FULL CRYPTOGRAPHIC CHAIN IS EMBEDDED BELOW (script id=embedded-chain,\n\
         base64). This file verifies itself with NO server, forever:\n\
         - decode the embedded chain to chain.jsonl, run: minute-server verify chain.jsonl\n\
         - recompute blake3 of each shown message, match its sealed commitment\n\
         Cross-check the date, with no trust in us, against Bitcoin itself via the\n\
         OpenTimestamps proofs (/anchors on the living monument, or your own copy).\n\
         Any single holder of this file can republish the monument. The chain\n\
         decides what is authentic - not the publisher, not any server.\n-->",
        chain_len
    );
    // the full chain, exact bytes, base64 (ASCII, never executed, id-addressable)
    let chain_block = format!(
        "<script type=\"application/x-ndjson-base64\" id=\"embedded-chain\">{}</script>\n</body>",
        base64_encode(chain_jsonl)
    );
    let out = page.replacen(DOCTYPE, &comment, 1);
    let out = out.replacen(MARK, &format!("{MARK}{entries}"), 1);
    Ok(out.replacen("</body>", &chain_block, 1))
}

/// One copy per owner: the snapshot is offered to every buyer, and to
/// anyone else who wants to hold the monument.
fn handle_monument(ctx: &Ctx) -> Resp {
    let page = match std::fs::read_to_string(&ctx.cfg.site_index) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[error] site index {}: {e}", ctx.cfg.site_index);
            return html_resp(500, "site file missing".to_owned());
        }
    };
    let chain_path = Path::new(&ctx.cfg.data_dir).join("chain.jsonl");
    // Clone the small registry index under the lock, then do the heavy disk
    // read + base64 encode OUTSIDE it. Holding the store lock across blocking
    // I/O let a flood of /monument.html requests starve claim creation AND the
    // payment poller (which needs the same lock). A momentary chain/registry
    // skew is harmless: the embedded self-verifier tolerates it.
    let (registry, chain_len, chain_tip) = {
        let st = lock(&ctx.store);
        (st.registry.clone(), st.chain_len, st.chain_tip.clone())
    };
    let chain_bytes = std::fs::read(&chain_path).unwrap_or_default();
    let snap = build_monument_snapshot(
        &page,
        &registry,
        chain_len,
        &chain_tip,
        &chain_bytes,
        epoch_now(),
    );
    match snap {
        Ok(body) => html_resp(200, body).with_header(header("Cache-Control", "no-store")),
        Err(e) => {
            eprintln!("[error] monument snapshot: {e:#}");
            html_resp(500, "snapshot unavailable".to_owned())
        }
    }
}

fn handle_new_claim(rq: &mut Request, ctx: &Ctx) -> Result<Resp> {
    if !ctx.payments_open() {
        return Ok(json_resp(
            503,
            json!({ "error": "payments are not open yet" }).to_string(),
        ));
    }
    let now = epoch_now();
    let ip = client_ip(rq);
    if rate_limited(ctx, ip, now) {
        return Ok(json_resp(
            429,
            json!({ "error": "too many claims from this address, try again later" }).to_string(),
        ));
    }
    let body = read_body(rq)?;
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return Ok(json_resp(
            400,
            json!({ "error": "invalid json" }).to_string(),
        ));
    };
    let minute = v.get("minute").and_then(Value::as_str).unwrap_or("");
    let name = v.get("name").and_then(Value::as_str).unwrap_or("");
    let msg = v.get("msg").and_then(Value::as_str).unwrap_or("");
    // affiliate data: invalid addresses are dropped, never block a sale
    let referred_by = v
        .get("ref")
        .and_then(Value::as_str)
        .and_then(valid_btc_address);
    let reward_address = v
        .get("reward_address")
        .and_then(Value::as_str)
        .and_then(valid_btc_address);
    let expiry = ctx.cfg.claim_expiry_hours * 3600;
    // same-IP self-referral guard: if the buyer's IP is one that registered
    // this referrer address as its own reward, drop the referral (no commission).
    let referred_by = referred_by.filter(|r| {
        let same_ip = lock(&ctx.aff_ips)
            .get(r)
            .is_some_and(|ips| ips.contains(&ip));
        if same_ip {
            eprintln!("[affiliate] same-IP self-referral dropped ({r})");
        }
        !same_ip
    });
    let created = {
        let mut st = lock(&ctx.store);
        // derive the dedicated address under the same lock that assigns the
        // index, so two concurrent claims can never share an address
        let derived = match &ctx.account {
            Some(acct) => {
                let idx = st.next_addr_index(ctx.cfg.xpub_start_index);
                match u32::try_from(idx)
                    .ok()
                    .and_then(|i| xpub::derive_address(acct, i).ok())
                {
                    Some(addr) => Some((addr, idx)),
                    None => {
                        return Ok(json_resp(
                            500,
                            json!({ "error": "address derivation failed" }).to_string(),
                        ))
                    }
                }
            }
            None => None,
        };
        match st.new_claim(
            minute,
            name,
            msg,
            ctx.cfg.price_sats,
            now,
            expiry,
            ctx.cfg.min_lead_hours * 3600,
            derived,
        ) {
            Ok(c) => {
                st.set_refs(&c.id, referred_by, reward_address)?;
                Ok(c)
            }
            Err(e) => Err(e),
        }
    };
    // the chain tip at claim time: a custody link for the claim note
    let chain_tip = {
        let st = lock(&ctx.store);
        if st.chain_len == 0 {
            Value::Null
        } else {
            Value::String(st.chain_tip.clone())
        }
    };
    match created {
        Ok(c) => {
            eprintln!(
                "[claim] {} minute={} amount={} addr={} expires={}",
                c.id,
                c.minute,
                c.amount_sats,
                c.address.as_deref().unwrap_or("(shared)"),
                c.expires_epoch
            );
            let pay_to = c
                .address
                .clone()
                .unwrap_or_else(|| ctx.cfg.btc_address.clone());
            Ok(json_resp(
                200,
                json!({
                    "claim_id": c.id,
                    "minute": c.minute,
                    "pay_to": pay_to,
                    "amount_sats": c.amount_sats,
                    "exact_amount": ctx.account.is_none(),
                    "chain_tip": chain_tip,
                    "expires_epoch": c.expires_epoch,
                })
                .to_string(),
            ))
        }
        Err(e) => Ok(json_resp(
            409,
            json!({ "error": e.to_string() }).to_string(),
        )),
    }
}

fn handle_claim_status(ctx: &Ctx, id: &str) -> Resp {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return json_resp(404, json!({ "error": "unknown claim" }).to_string());
    }
    // read the live confirmation depth before locking the store (the poller
    // never holds both locks, so there is no ordering hazard either way).
    let confirmations = lock(&ctx.confirmations).get(id).copied();
    let st = lock(&ctx.store);
    match st.claims.get(id) {
        Some(c) => {
            let pay_to = c
                .address
                .clone()
                .unwrap_or_else(|| ctx.cfg.btc_address.clone());
            json_resp(
                200,
                json!({
                    "status": c.status.as_str(),
                    "minute": c.minute,
                    "amount_sats": c.amount_sats,
                    "pay_to": pay_to,
                    "exact_amount": c.address.is_none(),
                    "reward_address": c.reward_address,
                    "confirmations": confirmations,
                    "min_confirmations": ctx.cfg.min_confirmations,
                })
                .to_string(),
            )
        }
        None => json_resp(404, json!({ "error": "unknown claim" }).to_string()),
    }
}

/// Redeem a promo code: ONE free engraving, no Bitcoin paid. The code is burned
/// (single-use) before the claim is comped and engraved. Engraving goes through
/// engrave() directly, so NO affiliate commission accrues (a gift is not a
/// sale). Rate-limited per IP. Runs under the store lock, locking promo INSIDE
/// it, so check + burn + engrave are atomic and the two locks never deadlock
/// (the order is always store-then-promo, and promo is locked nowhere else).
fn handle_redeem(rq: &mut Request, ctx: &Ctx, id: &str) -> Result<Resp> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(json_resp(
            404,
            json!({ "error": "unknown claim" }).to_string(),
        ));
    }
    let now = epoch_now();
    let ip = client_ip(rq);
    if rate_limited(ctx, ip, now) {
        return Ok(json_resp(
            429,
            json!({ "error": "too many attempts, try again later" }).to_string(),
        ));
    }
    let body = read_body(rq)?;
    let Ok(v) = serde_json::from_slice::<Value>(&body) else {
        return Ok(json_resp(
            400,
            json!({ "error": "invalid json" }).to_string(),
        ));
    };
    let code = v
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    if code.is_empty() {
        return Ok(json_resp(
            400,
            json!({ "error": "enter a code" }).to_string(),
        ));
    }
    let mut st = lock(&ctx.store);
    // the claim must exist, still await payment, and its minute still be
    // engraveable - all checked BEFORE the code is burned, so a doomed
    // redemption never wastes an influencer's code.
    match st.claims.get(id) {
        None => {
            return Ok(json_resp(
                404,
                json!({ "error": "unknown claim" }).to_string(),
            ))
        }
        Some(c) => {
            if c.status != ClaimStatus::AwaitingPayment {
                return Ok(json_resp(
                    409,
                    json!({ "error": "this claim is no longer open" }).to_string(),
                ));
            }
            if st.registry.contains_key(&c.minute) {
                return Ok(json_resp(
                    409,
                    json!({ "error": "this minute is already engraved" }).to_string(),
                ));
            }
            match validate::minute_id_to_epoch(&c.minute) {
                Some(e) if e + 60 > now as i64 => {}
                _ => {
                    return Ok(json_resp(
                        409,
                        json!({ "error": "this minute has already passed" }).to_string(),
                    ))
                }
            }
        }
    }
    // burn the code (single-use, persisted) now that the claim can engrave.
    if let Err(e) = lock(&ctx.promo).redeem(&code, id, now) {
        return Ok(json_resp(
            400,
            json!({ "error": e.to_string() }).to_string(),
        ));
    }
    if let Err(e) = st.mark_paid(id, "comp", now) {
        return Ok(json_resp(
            409,
            json!({ "error": e.to_string() }).to_string(),
        ));
    }
    match st.engrave(id, now) {
        Ok(minute) => {
            eprintln!("[promo] free engrave claim={id} minute={minute}");
            Ok(json_resp(
                200,
                json!({ "status": "engraved", "minute": minute }).to_string(),
            ))
        }
        Err(e) => {
            eprintln!("[promo] engrave after redeem failed for {id}: {e:#}");
            Ok(json_resp(
                500,
                json!({ "error": "the engraving failed" }).to_string(),
            ))
        }
    }
}

fn admin_page(ctx: &Ctx, token: &str, notice: &str) -> Resp {
    let st = lock(&ctx.store);
    let now = epoch_now();
    let mut paid: Vec<_> = st
        .claims
        .values()
        .filter(|c| c.status == ClaimStatus::Paid)
        .collect();
    paid.sort_by_key(|c| c.paid_epoch.unwrap_or(0));
    let awaiting = st
        .claims
        .values()
        .filter(|c| c.status == ClaimStatus::AwaitingPayment && c.expires_epoch > now)
        .count();
    let engraved = st.registry.len();

    let mut rows = String::new();
    for c in &paid {
        let sched = if ctx.cfg.auto_engrave_hours == 0 {
            "manual mode".to_owned()
        } else {
            "auto-engraves on payment".to_owned()
        };
        rows.push_str(&format!(
            "<li><div class=\"lid\">{} - {} - txid {} - {}</div>\
             <div class=\"lmsg\">\"{}\"</div><div class=\"lname\">{}</div>\
             <form method=\"post\" action=\"/admin/{}\">\
             <input type=\"hidden\" name=\"claim_id\" value=\"{}\">\
             <button name=\"action\" value=\"engrave\">ENGRAVE NOW</button> \
             <button name=\"action\" value=\"refuse\" class=\"refuse\">REFUSE</button>\
             </form></li>",
            esc(&c.minute),
            fmt_btc(c.amount_sats),
            esc(c.txid.as_deref().unwrap_or("?")),
            esc(&sched),
            esc(&c.msg),
            esc(if c.name.is_empty() {
                "Anonymous"
            } else {
                &c.name
            }),
            esc(token),
            esc(&c.id),
        ));
    }
    let paid_block = if paid.is_empty() {
        "<p class=\"dim\">No paid claim waits for your decision.</p>".to_owned()
    } else {
        format!("<ul>{rows}</ul>")
    };
    let stray_list = lock(&ctx.unmatched);
    let stray_block = if stray_list.is_empty() {
        String::new()
    } else {
        let mut srows = String::new();
        for (txid, sats) in stray_list.iter() {
            srows.push_str(&format!(
                "<li><div class=\"lid\">{} - txid {}</div></li>",
                fmt_btc(*sats),
                esc(txid)
            ));
        }
        format!("<h1>Unmatched payments - wrong amount sent?</h1><ul>{srows}</ul>")
    };
    let aff = lock(&ctx.affiliates);
    let pending = aff.pending(ctx.cfg.affiliate_payout_threshold_sats);
    let payouts_done = aff.payouts.len();
    drop(aff);
    let aff_block = if pending.is_empty() {
        format!(
            "<h1>Affiliates</h1><p class=\"dim\">No payout due (threshold {}, {} payout(s) recorded, ledger: /affiliates.json).</p>",
            fmt_btc(ctx.cfg.affiliate_payout_threshold_sats),
            payouts_done
        )
    } else {
        let mut arows = String::new();
        let mut total = 0u64;
        for (addr, sats) in &pending {
            total += sats;
            arows.push_str(&format!(
                "<li><div class=\"lid\">{} - {}</div></li>",
                esc(addr),
                fmt_btc(*sats)
            ));
        }
        // freeze what is displayed into the form: record_payout marks EXACTLY
        // this, so a commission accruing after you send the batch tx stays
        // pending instead of being wrongly marked paid.
        let snapshot: String = pending
            .iter()
            .map(|(a, s)| format!("{a}:{s}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "<h1>Affiliates - payouts due</h1><ul>{arows}</ul>\
             <p>TOTAL {} for {} address(es). Send ONE batch transaction in Sparrow, then paste its txid:</p>\
             <form method=\"post\" action=\"/admin/{}\">\
             <input type=\"hidden\" name=\"outputs\" value=\"{}\">\
             <input type=\"text\" name=\"txid\" placeholder=\"payout txid\" size=\"66\">\
             <button name=\"action\" value=\"payout\">MARK PAYOUTS PAID</button></form>",
            fmt_btc(total),
            pending.len(),
            esc(token),
            esc(&snapshot)
        )
    };
    let (promo_free, promo_total) = {
        let p = lock(&ctx.promo);
        (p.total().saturating_sub(p.used()), p.total())
    };
    let comped = st
        .claims
        .values()
        .filter(|c| c.txid.as_deref() == Some("comp") && c.status == ClaimStatus::Engraved)
        .count();
    let tip_short = if st.chain_len == 0 {
        "genesis".to_owned()
    } else {
        st.chain_tip.chars().take(12).collect::<String>()
    };
    let health_block = format!(
        "<p class=\"dim\">Chain: {} entries, tip {} - Promo: {} free of {} ({} free engravings redeemed) - <a href=\"/anchors\">anchors</a></p>",
        st.chain_len,
        esc(&tip_short),
        promo_free,
        promo_total,
        comped
    );
    let notice_block = if notice.is_empty() {
        String::new()
    } else {
        format!("<p class=\"notice\">{}</p>", esc(notice))
    };
    let body = format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"robots\" content=\"noindex\">\
         <title>THE MINUTE - admin</title><style>\
         body{{background:#050505;color:#cdc6b4;font-family:Helvetica,Arial,sans-serif;\
         max-width:720px;margin:0 auto;padding:40px 24px}}\
         h1{{color:#e3c169;font-size:16px;letter-spacing:.3em;text-transform:uppercase}}\
         .dim{{color:#948d7c}}.notice{{color:#e3c169}}a{{color:#e3c169}}\
         ul{{list-style:none;padding:0}}li{{border-top:1px solid #242019;padding:16px 0}}\
         .lid{{font-size:12px;color:#948d7c}}.lmsg{{font-style:italic;margin:6px 0}}\
         .lname{{font-size:12px;color:#948d7c;text-transform:uppercase;\
         letter-spacing:.15em;margin-bottom:8px}}\
         button{{background:none;border:1px solid #8a7223;color:#e3c169;\
         padding:8px 14px;letter-spacing:.2em;cursor:pointer}}\
         button.refuse{{border-color:#5c3a3a;color:#b05c5c}}\
         </style></head><body><h1>The Minute - Admin</h1>\
         {notice_block}\
         <p class=\"dim\">{awaiting} awaiting payment - {} paid to decide - {engraved} engraved</p>\
         {health_block}\
         {stray_block}\
         <h1>Paid - auto-engraves after the veto window</h1>{paid_block}\
         {aff_block}\
         </body></html>",
        paid.len(),
    );
    html_resp(200, body)
}

/// Parse the admin payout snapshot "addr:sats,addr:sats" back into a map.
/// Only well-formed entries with a valid address and a positive amount
/// survive; anything malformed is silently dropped (fail closed).
fn parse_payout_snapshot(s: &str) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        if let Some((addr, sats)) = part.split_once(':') {
            if let (Some(a), Ok(v)) = (valid_btc_address(addr), sats.parse::<u64>()) {
                if v > 0 {
                    m.insert(a, v);
                }
            }
        }
    }
    m
}

fn handle_admin(rq: &mut Request, ctx: &Ctx, method: &Method, token: &str) -> Result<Resp> {
    if !ctx.admin_enabled() || !ct_eq(token, &ctx.cfg.admin_token) {
        return Ok(html_resp(404, "not found".to_owned()));
    }
    match method {
        Method::Get => Ok(admin_page(ctx, token, "")),
        Method::Post => {
            let body = read_body(rq)?;
            let body = String::from_utf8_lossy(&body).into_owned();
            let claim_id = form_get(&body, "claim_id").unwrap_or("").to_owned();
            let action = form_get(&body, "action").unwrap_or("");
            let now = epoch_now();
            let outcome = {
                let mut st = lock(&ctx.store);
                match action {
                    "engrave" => engrave_with_commissions(ctx, &mut st, &claim_id, now)
                        .map(|s| format!("engraved {s}")),
                    "refuse" => st
                        .refuse(&claim_id, now)
                        .map(|_| format!("refused {claim_id} (refund manually via the txid)")),
                    "payout" => {
                        let txid = form_get(&body, "txid").unwrap_or("").trim().to_owned();
                        // record EXACTLY the snapshot the admin page showed and
                        // the merchant paid, not a fresh recompute of pending.
                        let snapshot =
                            parse_payout_snapshot(form_get(&body, "outputs").unwrap_or(""));
                        drop(st);
                        let mut aff = lock(&ctx.affiliates);
                        aff.record_payout(&txid, &snapshot, now).map(|(total, n)| {
                            format!(
                                "payout recorded: {} to {n} address(es), txid {txid}",
                                fmt_btc(total)
                            )
                        })
                    }
                    _ => Err(anyhow::anyhow!("unknown action")),
                }
            };
            let notice = match outcome {
                Ok(n) => {
                    eprintln!("[admin] {n}");
                    n
                }
                Err(e) => format!("error: {e}"),
            };
            Ok(admin_page(ctx, token, &notice))
        }
        _ => Ok(html_resp(405, "method not allowed".to_owned())),
    }
}

/// robots.txt: let crawlers in, keep /admin and /api out, point to the sitemap.
fn handle_robots() -> Resp {
    let body = "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/\n\nSitemap: https://minuteofforever.com/sitemap.xml\n";
    body_resp(200, "text/plain; charset=utf-8", body.as_bytes().to_vec())
}

/// sitemap.xml: the public pages, so search engines discover the site.
fn handle_sitemap() -> Resp {
    let urls = [
        "https://minuteofforever.com/",
        "https://minuteofforever.com/?ledger",
        "https://minuteofforever.com/?affiliates",
        "https://minuteofforever.com/?faq",
        "https://minuteofforever.com/?terms",
        "https://minuteofforever.com/?privacy",
    ];
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for u in urls {
        body.push_str("<url><loc>");
        body.push_str(u);
        body.push_str("</loc></url>\n");
    }
    body.push_str("</urlset>\n");
    body_resp(200, "application/xml; charset=utf-8", body.into_bytes())
}

fn route(rq: &mut Request, ctx: &Ctx) -> Result<Resp> {
    let method = rq.method().clone();
    let url = rq.url().to_owned();
    let path = url.split('?').next().unwrap_or("").to_owned();
    match (&method, path.as_str()) {
        (Method::Get, "/") => Ok(handle_share(ctx, &url)),
        (Method::Get, "/og.png") => Ok(handle_og_image()),
        (Method::Get, "/favicon.ico") => Ok(handle_favicon()),
        (Method::Get, "/favicon.svg") => Ok(handle_favicon()),
        (Method::Get, "/robots.txt") => Ok(handle_robots()),
        (Method::Get, "/sitemap.xml") => Ok(handle_sitemap()),
        (Method::Get, "/monument.html") => Ok(handle_monument(ctx)),
        (Method::Get, "/registry.json") => handle_registry(ctx),
        (Method::Get, "/chain.jsonl") => Ok(handle_chain_file(ctx)),
        (Method::Get, "/api/chain/tip") => Ok(handle_chain_tip(ctx)),
        (Method::Get, "/anchors") => Ok(handle_anchors_list(ctx)),
        (Method::Get, p) if p.starts_with("/anchors/") => {
            Ok(handle_anchor_file(ctx, &p["/anchors/".len()..]))
        }
        (Method::Get, "/api/health") => Ok(handle_health(ctx)),
        (Method::Get, "/affiliates.json") => Ok(handle_affiliates_json(ctx)),
        (Method::Post, "/api/claim") => handle_new_claim(rq, ctx),
        (Method::Post, p) if p.starts_with("/api/claim/") && p.ends_with("/reward") => {
            // strip both ends safely: "/api/claim/reward" (no id) yields "" -> 404.
            // Never an inverted slice (start > end), which would panic the thread.
            let id = p
                .strip_prefix("/api/claim/")
                .and_then(|s| s.strip_suffix("/reward"))
                .unwrap_or("");
            handle_reward(rq, ctx, id)
        }
        (Method::Post, p) if p.starts_with("/api/claim/") && p.ends_with("/redeem") => {
            let id = p
                .strip_prefix("/api/claim/")
                .and_then(|s| s.strip_suffix("/redeem"))
                .unwrap_or("");
            handle_redeem(rq, ctx, id)
        }
        (Method::Get, p) if p.starts_with("/api/claim/") => {
            Ok(handle_claim_status(ctx, &p["/api/claim/".len()..]))
        }
        (_, p) if p.starts_with("/admin/") => {
            let token = &p["/admin/".len()..];
            handle_admin(rq, ctx, &method, token)
        }
        _ => Ok(json_resp(404, json!({ "error": "not found" }).to_string())),
    }
}

fn handle(mut rq: Request, ctx: &Ctx) {
    let path = rq.url().to_owned();
    // a panic inside any handler must NEVER take the server down: catch it,
    // answer 500, keep serving. Mutexes recover from poisoning (see lock()).
    let routed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| route(&mut rq, ctx)));
    let resp = match routed {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            eprintln!("[error] {path}: {e:#}");
            json_resp(500, json!({ "error": "internal" }).to_string())
        }
        Err(_) => {
            eprintln!("[panic] {path}: handler panicked, answered 500");
            json_resp(500, json!({ "error": "internal" }).to_string())
        }
    };
    if let Err(e) = rq.respond(resp) {
        eprintln!("[error] respond {path}: {e}");
    }
}

/// Fetch an address's transactions AND the best-block height from the first
/// healthy Esplora source (both from the SAME source, so confirmation depth is
/// measured consistently). Tip 0 = unknown -> callers requiring depth >= 2 fail
/// closed.
/// Fetch (txs, tip) from EVERY configured Esplora source. Failing sources are
/// skipped (logged), not fatal. The basis for multi-source payment consensus.
fn fetch_all_sources(ctx: &Ctx, address: &str) -> Vec<(Vec<Value>, u64)> {
    let mut out = Vec::new();
    for base in &ctx.cfg.esplora_apis {
        match mempool::fetch_address_txs(base, address, 10) {
            Ok(txs) => {
                let tip = mempool::fetch_tip_height(base).unwrap_or_else(|e| {
                    eprintln!("[poll] tip height from {base} failed: {e:#}");
                    0
                });
                out.push((txs, tip));
            }
            Err(e) => eprintln!("[poll] source {base} failed for {address}: {e:#}"),
        }
    }
    out
}

/// Consensus txid + deepest confirmation depth for `amount` at `address`
/// across pre-fetched sources. A txid is returned ONLY if at least `need`
/// sources independently report the SAME paying tx with >= `min_conf`
/// confirmations - so one compromised source cannot trigger a false engraving.
/// `depth` is the max any source reports for a matching payment (0 = mempool),
/// used only for the buyer's live 0->1->2 counter (informational, 1 source ok).
fn consensus_payment(
    sources: &[(Vec<Value>, u64)],
    address: &str,
    amount: u64,
    at_least: bool,
    min_conf: u64,
    need: usize,
) -> (Option<String>, Option<u64>) {
    let mut votes: HashMap<String, usize> = HashMap::new();
    let mut best_depth: Option<u64> = None;
    for (txs, tip) in sources {
        if let Some(d) = mempool::payment_depth(txs, address, amount, *tip, at_least) {
            best_depth = Some(best_depth.map_or(d, |b| b.max(d)));
        }
        let txid = if at_least {
            mempool::find_payment_to(txs, address, amount, *tip, min_conf)
        } else {
            mempool::find_confirmed_payment(txs, address, amount, *tip, min_conf)
        };
        if let Some(t) = txid {
            *votes.entry(t).or_insert(0) += 1;
        }
    }
    let consensus = votes
        .into_iter()
        .find(|(_, n)| *n >= need.max(1))
        .map(|(t, _)| t);
    (consensus, best_depth)
}

/// One poll cycle: expire overdue claims, auto-engrave what is due, then
/// look for payments (per-address in xpub mode, shared address in legacy).
fn poll_once(ctx: &Ctx) {
    let now = epoch_now();
    // keep the rate-limiter map bounded: evict IPs whose window fully expired.
    prune_rate(&mut lock(&ctx.rate), now);
    let pending = {
        let mut st = lock(&ctx.store);
        if let Err(e) = st.mark_expired(now) {
            eprintln!("[poll] expiry persist error: {e:#}");
        }
        // keep claims.json bounded: drop expired-past-revive and old refused
        match st.prune_terminal(now) {
            Ok(n) if n > 0 => eprintln!("[poll] pruned {n} terminal claim(s)"),
            Ok(_) => {}
            Err(e) => eprintln!("[poll] prune persist error: {e:#}"),
        }
        st.pending_for_matching(now)
    };

    // automatic engraving runs UNCONDITIONALLY (a lone paid claim must
    // engrave even when no other payment is awaited)
    if ctx.cfg.auto_engrave_hours > 0 {
        // instant: engrave on the poll that confirms payment (no veto window)
        let due = {
            let st = lock(&ctx.store);
            st.auto_engrave_due(now, 0)
        };
        for id in due {
            let mut st = lock(&ctx.store);
            match engrave_with_commissions(ctx, &mut st, &id, now) {
                Ok(minute) => eprintln!("[auto-engrave] claim={id} minute={minute}"),
                Err(e) => eprintln!("[auto-engrave] {id}: {e:#}"),
            }
        }
    }

    // xpub mode: each claim has its own dedicated address
    let xpub_pending: Vec<(String, u64, String)> = pending
        .iter()
        .filter_map(|(id, amt, addr)| addr.clone().map(|a| (id.clone(), *amt, a)))
        .collect();
    // Live confirmation depth per claim, rebuilt fresh each cycle so the buyer
    // watches 0 -> 1 -> 2. xpub and legacy claims are disjoint sets of ids.
    // a payment counts only when `need` independent sources agree on its txid.
    let need = ctx
        .cfg
        .min_sources
        .clamp(1, ctx.cfg.esplora_apis.len().max(1));
    let mut confs: HashMap<String, u64> = HashMap::new();
    for (id, amount, addr) in xpub_pending {
        let sources = fetch_all_sources(ctx, &addr);
        let (txid, depth) = consensus_payment(
            &sources,
            &addr,
            amount,
            true,
            ctx.cfg.min_confirmations,
            need,
        );
        if let Some(d) = depth {
            confs.insert(id.clone(), d);
        }
        if let Some(txid) = txid {
            let mut st = lock(&ctx.store);
            match st.mark_paid(&id, &txid, now) {
                Ok(()) => {
                    eprintln!("[paid] claim={id} txid={txid} addr={addr} ({need}-source consensus)")
                }
                Err(e) => eprintln!("[poll] mark paid {id}: {e:#}"),
            }
        }
    }
    // publish the xpub depths now; the legacy branch below may early-return.
    *lock(&ctx.confirmations) = confs;

    // legacy mode: shared address, unique amount identifies the claim
    let legacy: Vec<(String, u64)> = pending
        .iter()
        .filter(|(_, _, addr)| addr.is_none())
        .map(|(id, amt, _)| (id.clone(), *amt))
        .collect();
    if legacy.is_empty() || ctx.cfg.btc_address.is_empty() {
        return;
    }
    let sources = fetch_all_sources(ctx, &ctx.cfg.btc_address);
    if sources.is_empty() {
        eprintln!("[poll] all payment sources failed for shared address");
        return;
    }
    let pending_amounts: HashSet<u64> = legacy.iter().map(|(_, a)| *a).collect();
    // txids already tied to a claim: never let an old payment satisfy a new
    // claim that reuses the same amount (fail closed; it surfaces as a stray).
    let used_txids: HashSet<String> = {
        let st = lock(&ctx.store);
        st.claims.values().filter_map(|c| c.txid.clone()).collect()
    };
    for (id, amount) in legacy {
        let (txid, depth) = consensus_payment(
            &sources,
            &ctx.cfg.btc_address,
            amount,
            false,
            ctx.cfg.min_confirmations,
            need,
        );
        if let Some(d) = depth {
            lock(&ctx.confirmations).insert(id.clone(), d);
        }
        if let Some(txid) = txid {
            if used_txids.contains(&txid) {
                continue; // this confirmed payment already credited another claim
            }
            let mut st = lock(&ctx.store);
            match st.mark_paid(&id, &txid, now) {
                Ok(()) => eprintln!("[paid] claim={id} txid={txid} amount={amount}"),
                Err(e) => eprintln!("[poll] mark paid {id}: {e:#}"),
            }
        }
    }
    // confirmed payments matching no expected amount: keep them visible
    // (a buyer who sent the wrong amount must not vanish into silence)
    let known: HashSet<String> = {
        let st = lock(&ctx.store);
        st.claims.values().filter_map(|c| c.txid.clone()).collect()
    };
    // one source is enough to surface a wrong-amount payment (informational)
    let (txs, _) = &sources[0];
    let mut stray = Vec::new();
    for tx in txs {
        let confirmed = tx
            .pointer("/status/confirmed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !confirmed {
            continue;
        }
        let Some(txid) = tx.get("txid").and_then(Value::as_str) else {
            continue;
        };
        if known.contains(txid) {
            continue;
        }
        let Some(vouts) = tx.get("vout").and_then(Value::as_array) else {
            continue;
        };
        for v in vouts {
            if v.get("scriptpubkey_address").and_then(Value::as_str)
                == Some(ctx.cfg.btc_address.as_str())
            {
                if let Some(val) = v.get("value").and_then(Value::as_u64) {
                    if !pending_amounts.contains(&val) {
                        stray.push((txid.to_owned(), val));
                    }
                }
            }
        }
    }
    stray.truncate(50);
    *lock(&ctx.unmatched) = stray;
}

fn poller(ctx: Arc<Ctx>) {
    loop {
        thread::sleep(Duration::from_secs(ctx.cfg.poll_secs));
        // A panic in one cycle must NEVER kill the poller thread: that would
        // silently stop all payment detection while the server keeps serving.
        // Catch it, log, and run the next cycle (mutexes recover from poison).
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll_once(&ctx))).is_err() {
            eprintln!("[poll] cycle panicked; recovered, continuing next cycle");
        }
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    // `minute-server derive <xpub> <count>`: print the first receive
    // addresses of an xpub - lets the merchant verify they are his own.
    if first.as_deref() == Some("derive") {
        let key = args
            .next()
            .context("usage: minute-server derive <xpub> <count>")?;
        let count: u32 = args
            .next()
            .unwrap_or_else(|| "5".to_owned())
            .parse()
            .context("count must be a number")?;
        let parsed = xpub::parse_xpub(&key)?;
        for i in 0..count {
            println!("/0/{}  {}", i, xpub::derive_address(&parsed, i)?);
        }
        return Ok(());
    }
    // `minute-server verify [chain.jsonl]`: anyone can audit the ledger.
    if first.as_deref() == Some("verify") {
        let path = args.next().unwrap_or_else(|| "data/chain.jsonl".to_owned());
        match verify_chain_file(Path::new(&path)) {
            Ok((n, tip)) => {
                println!("CHAIN OK: {n} entries, tip {tip}");
                return Ok(());
            }
            Err(e) => {
                eprintln!("CHAIN BROKEN: {e:#}");
                std::process::exit(1);
            }
        }
    }
    // `minute-server payouts [config.json]`: the monthly list, one batch tx.
    if first.as_deref() == Some("payouts") {
        let config_path = args.next().unwrap_or_else(|| "config.json".to_owned());
        let cfg: Config = serde_json::from_slice(
            &std::fs::read(&config_path).with_context(|| format!("read {config_path}"))?,
        )
        .with_context(|| format!("parse {config_path}"))?;
        let aff = Affiliates::load(Path::new(&cfg.data_dir))?;
        let pending = aff.pending(cfg.affiliate_payout_threshold_sats);
        if pending.is_empty() {
            println!(
                "no payout due (threshold {} sats)",
                cfg.affiliate_payout_threshold_sats
            );
            return Ok(());
        }
        let mut total = 0u64;
        for (addr, sats) in &pending {
            total += sats;
            println!("{addr} {sats} sats ({:.8} BTC)", *sats as f64 / 1e8);
        }
        println!(
            "TOTAL {} address(es), {total} sats - send ONE batch tx in Sparrow, then record the txid on /admin",
            pending.len()
        );
        return Ok(());
    }
    // `minute-server gencodes <n> [config.json]`: mint n single-use free-engraving
    // codes to hand to influencers. Each is printed ONCE - store them safely.
    if first.as_deref() == Some("gencodes") {
        let n: usize = args
            .next()
            .context("usage: minute-server gencodes <n> [config.json]")?
            .parse()
            .context("count must be a positive number")?;
        let config_path = args.next().unwrap_or_else(|| "config.json".to_owned());
        let cfg: Config = serde_json::from_slice(
            &std::fs::read(&config_path).with_context(|| format!("read {config_path}"))?,
        )
        .with_context(|| format!("parse {config_path}"))?;
        let mut promo = Promo::load(Path::new(&cfg.data_dir))?;
        let codes = promo.generate(n, epoch_now())?;
        eprintln!(
            "[gencodes] {} code(s) minted - each = ONE free engraving (single-use):",
            codes.len()
        );
        for c in &codes {
            println!("{}", promo::display(c));
        }
        return Ok(());
    }
    // `minute-server codes [config.json]`: list every code and whether it is spent.
    if first.as_deref() == Some("codes") {
        let config_path = args.next().unwrap_or_else(|| "config.json".to_owned());
        let cfg: Config = serde_json::from_slice(
            &std::fs::read(&config_path).with_context(|| format!("read {config_path}"))?,
        )
        .with_context(|| format!("parse {config_path}"))?;
        let promo = Promo::load(Path::new(&cfg.data_dir))?;
        for (code, used) in promo.listing() {
            println!("{}  {}", code, if used { "USED" } else { "free" });
        }
        eprintln!("[codes] {} used / {} total", promo.used(), promo.total());
        return Ok(());
    }
    let config_path = first.unwrap_or_else(|| "config.json".to_owned());
    let cfg: Config = serde_json::from_slice(
        &std::fs::read(&config_path).with_context(|| format!("read {config_path}"))?,
    )
    .with_context(|| format!("parse {config_path}"))?;

    let account = if cfg.xpub.is_empty() {
        None
    } else {
        Some(xpub::parse_xpub(&cfg.xpub).context("config xpub")?)
    };

    if account.is_none() && cfg.btc_address.is_empty() {
        eprintln!("[warn] no xpub and no btc_address: payments are CLOSED (page says so honestly)");
    }
    if let Some(acct) = &account {
        let sample = xpub::derive_address(acct, cfg.xpub_start_index as u32)
            .context("cannot derive from xpub")?;
        eprintln!(
            "[start] xpub mode: first claim address /0/{} = {}",
            cfg.xpub_start_index, sample
        );
    }
    if cfg.admin_token.len() < 16 {
        eprintln!("[warn] admin_token shorter than 16 chars: admin is DISABLED");
    }

    if cfg.affiliate_pct > 90 {
        eprintln!("[warn] affiliate_pct exceeds 90% of each sale: check the config");
    }
    let affiliates = Affiliates::load(Path::new(&cfg.data_dir))?;
    eprintln!(
        "[start] affiliates: {} address(es) accrued, {} payout(s) recorded",
        affiliates.accrued.len(),
        affiliates.payouts.len()
    );
    let store = Store::load(Path::new(&cfg.data_dir))?;
    eprintln!(
        "[start] {} engraved minutes, {} claims on file, chain tip {}",
        store.registry.len(),
        store.claims.len(),
        if store.chain_len == 0 {
            "genesis (empty)".to_owned()
        } else {
            store.chain_tip.clone()
        }
    );
    let promo = Promo::load(Path::new(&cfg.data_dir))?;
    eprintln!(
        "[start] promo codes: {} free / {} total",
        promo.total() - promo.used(),
        promo.total()
    );

    let bind = cfg.bind.clone();
    let payments_live = account.is_some() || !cfg.btc_address.is_empty();
    let ctx = Arc::new(Ctx {
        cfg,
        account,
        store: Mutex::new(store),
        affiliates: Mutex::new(affiliates),
        rate: Mutex::new(HashMap::new()),
        unmatched: Mutex::new(Vec::new()),
        confirmations: Mutex::new(HashMap::new()),
        promo: Mutex::new(promo),
        aff_ips: Mutex::new(HashMap::new()),
    });

    if payments_live {
        let pctx = Arc::clone(&ctx);
        thread::spawn(move || poller(pctx));
    }

    let server = Server::http(&bind).map_err(|e| anyhow::anyhow!("bind {bind}: {e}"))?;
    let server = Arc::new(server);
    eprintln!("[start] listening on http://{bind}");

    let mut workers = Vec::new();
    for _ in 0..3 {
        let srv = Arc::clone(&server);
        let wctx = Arc::clone(&ctx);
        workers.push(thread::spawn(move || loop {
            match srv.recv() {
                Ok(rq) => handle(rq, &wctx),
                Err(e) => eprintln!("[error] recv: {e}"),
            }
        }));
    }
    loop {
        match server.recv() {
            Ok(rq) => handle(rq, &ctx),
            Err(e) => eprintln!("[error] recv: {e}"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn src_tx(addr: &str, val: u64, txid: &str) -> serde_json::Value {
        serde_json::json!({ "txid": txid, "status": {"confirmed": true, "block_height": 100},
                 "vout": [{"scriptpubkey_address": addr, "value": val}] })
    }

    #[test]
    fn consensus_needs_sources_to_agree() {
        let a = "bc1qtarget";
        // both sources confirm the SAME txid -> consensus at need=2
        let agree = vec![
            (vec![src_tx(a, 21042, "deadbeef")], 100u64),
            (vec![src_tx(a, 21042, "deadbeef")], 100u64),
        ];
        assert_eq!(
            consensus_payment(&agree, a, 21042, false, 1, 2)
                .0
                .as_deref(),
            Some("deadbeef")
        );
        // only ONE source sees it -> no consensus at need=2 (fail closed)
        let one = vec![
            (vec![src_tx(a, 21042, "deadbeef")], 100u64),
            (vec![], 100u64),
        ];
        assert_eq!(consensus_payment(&one, a, 21042, false, 1, 2).0, None);
        // a lying source proposes a DIFFERENT txid -> it can never win alone
        let lie = vec![
            (vec![src_tx(a, 21042, "real0000")], 100u64),
            (vec![src_tx(a, 21042, "fake1111")], 100u64),
        ];
        assert_eq!(consensus_payment(&lie, a, 21042, false, 1, 2).0, None);
        // need=1 accepts a single source (consensus disabled)
        assert_eq!(
            consensus_payment(&one, a, 21042, false, 1, 1).0.as_deref(),
            Some("deadbeef")
        );
        // depth is still reported from any source, for the live 0->1->2 counter
        assert_eq!(consensus_payment(&one, a, 21042, false, 1, 2).1, Some(1));
    }

    const PAGE: &str = "<!DOCTYPE html>\n<html><head><title>t</title></head>\
                        <body>\n<script>\nconst REGISTRY = {\n};\n</script>\n</body></html>\n";

    fn tmp_store(tag: &str) -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!("minute-main-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::load(&dir).expect("load empty store");
        (dir, store)
    }

    #[test]
    fn prune_rate_bounds_the_map() {
        use std::collections::HashMap;
        let mut map: HashMap<IpAddr, Vec<u64>> = HashMap::new();
        let now = 100_000u64;
        let ip_a = IpAddr::from([1, 1, 1, 1]);
        let ip_b = IpAddr::from([2, 2, 2, 2]);
        // A has only expired hits (all > 1h old), B has a recent one
        map.insert(ip_a, vec![now - 4000, now - 3601]);
        map.insert(ip_b, vec![now - 10]);
        prune_rate(&mut map, now);
        assert!(!map.contains_key(&ip_a), "fully-expired IP must be evicted");
        assert_eq!(map.get(&ip_b).map(|v| v.len()), Some(1));
        // an entry that becomes empty after pruning old timestamps is removed
        let ip_c = IpAddr::from([3, 3, 3, 3]);
        map.insert(ip_c, vec![now - 5000]);
        prune_rate(&mut map, now);
        assert!(!map.contains_key(&ip_c));
    }

    #[test]
    fn meta_attr_is_xss_and_ascii_safe() {
        // cannot close a double-quoted attribute or open a tag
        assert_eq!(
            meta_attr("a\"><script>alert(1)</script>"),
            "a&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(meta_attr("\" onmouseover=x"), "&quot; onmouseover=x");
        assert_eq!(meta_attr("a & b"), "a &amp; b");
        assert_eq!(meta_attr("it's"), "it&#39;s");
        // non-ASCII folds to decimal numeric refs, output stays ASCII
        assert_eq!(meta_attr("caf\u{e9}"), "caf&#233;");
        assert_eq!(meta_attr("\u{4e2d}"), "&#20013;");
        assert_eq!(meta_attr("\u{1f600}"), "&#128512;");
        for s in ["plain", "caf\u{e9} \"<x>\"", "\u{1f4a5}emoji"] {
            assert!(meta_attr(s).is_ascii());
        }
    }

    #[test]
    fn pretty_and_until() {
        assert_eq!(
            pretty_minute("2030-01-01T12:00Z"),
            "12:00 UTC, 1 January 2030"
        );
        assert_eq!(
            pretty_minute("2028-12-25T09:05Z"),
            "09:05 UTC, 25 December 2028"
        );
        assert_eq!(until_human(30), "in under a minute");
        assert_eq!(until_human(90), "in 1 minute");
        assert_eq!(until_human(3 * 60), "in 3 minutes");
        assert_eq!(until_human(3600), "in 1 hour");
        assert_eq!(until_human(2 * 86400), "in 2 days");
        assert_eq!(until_human(400 * 86400), "in 1 year");
        assert_eq!(until_human(800 * 86400), "in 2 years");
    }

    #[test]
    fn query_and_percent_decode() {
        assert_eq!(
            query_get("s=2030-01-01T12:00Z", "s"),
            Some("2030-01-01T12:00Z")
        );
        assert_eq!(query_get("r=abc&s=x&z=1", "s"), Some("x"));
        assert_eq!(query_get("r=abc", "s"), None);
        assert_eq!(
            percent_decode_ascii("2030-01-01T12%3A00Z"),
            "2030-01-01T12:00Z"
        );
        assert_eq!(percent_decode_ascii("a+b"), "a b");
        assert_eq!(percent_decode_ascii("nochange"), "nochange");
        assert_eq!(percent_decode_ascii("%zz"), "%zz"); // bad escape left as-is
    }

    #[test]
    fn btc_address_validation() {
        // real mainnet addresses accepted, canonical form returned
        assert_eq!(
            valid_btc_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").as_deref(),
            Some("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
        );
        assert_eq!(
            valid_btc_address("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu").as_deref(),
            Some("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
        );
        // testnet, garbage, oversized: refused
        assert_eq!(
            valid_btc_address("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pz3cppk"),
            None
        );
        assert_eq!(valid_btc_address("notanaddress"), None);
        assert_eq!(valid_btc_address(""), None);
        assert_eq!(valid_btc_address(&"b".repeat(101)), None);
    }

    fn base64_decode_for_test(s: &str) -> Vec<u8> {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let idx = |c: u8| T.iter().position(|&t| t == c).unwrap() as u32;
        let clean: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
        let mut out = Vec::new();
        for chunk in clean.chunks(4) {
            let mut n = 0u32;
            for (i, &c) in chunk.iter().enumerate() {
                n |= idx(c) << (18 - 6 * i);
            }
            out.push((n >> 16) as u8);
            if chunk.len() > 2 {
                out.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                out.push(n as u8);
            }
        }
        out
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // roundtrip on bytes with a non-ASCII payload (chain names can be UTF-8)
        let raw = "line one\n{\"name\":\"caf\u{e9}\"}\n".as_bytes();
        assert_eq!(base64_decode_for_test(&base64_encode(raw)), raw);
    }

    #[test]
    fn js_escape_neutralizes_breakouts() {
        assert_eq!(js_escape("it's"), "it\\'s");
        assert_eq!(js_escape("a\\b"), "a\\\\b");
        assert_eq!(js_escape("</script>"), "\\x3C/script>");
        assert_eq!(js_escape("caf\u{e9}"), "caf\\u00e9");
        assert_eq!(js_escape("ok plain"), "ok plain");
    }

    #[test]
    fn monument_snapshot_embeds_arrived_and_seals_future() {
        let (dir, mut st) = tmp_store("snap");
        let now = 1_767_225_600u64; // 2026-01-01T00:00Z
        let a = st
            .new_claim(
                "2026-01-02T00:00Z",
                "A",
                "Arrived words.",
                21000,
                now,
                3600,
                0,
                None,
            )
            .expect("claim a");
        st.mark_paid(&a.id, "tx-a", now).expect("paid a");
        st.engrave(&a.id, now).expect("engrave a");
        let b = st
            .new_claim(
                "2030-01-01T00:00Z",
                "B",
                "Still sealed words.",
                21000,
                now,
                3600,
                0,
                None,
            )
            .expect("claim b");
        st.mark_paid(&b.id, "tx-b", now).expect("paid b");
        st.engrave(&b.id, now).expect("engrave b");
        let later = now + 2 * 86400; // 2026-01-03: A has arrived, B still to come
                                     // the real chain bytes, as served, embedded into the file
        let chain = std::fs::read(dir.join("chain.jsonl")).expect("chain bytes");
        let snap = build_monument_snapshot(
            PAGE,
            &st.registry,
            st.chain_len,
            &st.chain_tip,
            &chain,
            later,
        )
        .expect("snapshot");
        assert!(snap.contains("MONUMENT SNAPSHOT"));
        assert!(snap.contains("Arrived words."));
        assert!(!snap.contains("Still sealed words.")); // Rule IV holds in the file
        assert!(snap.contains("msg: null, live: true"));
        assert!(snap.contains(&st.chain_tip));
        assert!(snap.contains("Snapshot minute (UTC): 2026-01-03T00:00Z"));
        assert!(snap.contains("Engravings sealed in the chain: 2"));
        assert!(snap.is_ascii());
        // the FULL chain is embedded and decodes back to the exact bytes:
        // one file verifies itself offline, no server
        let b64 = snap
            .split("id=\"embedded-chain\">")
            .nth(1)
            .and_then(|s| s.split("</script>").next())
            .expect("embedded chain block");
        assert_eq!(base64_decode_for_test(b64), chain);
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn monument_snapshot_refuses_bad_page() {
        let (dir, st) = tmp_store("badpage");
        assert!(build_monument_snapshot(
            "<html>no marker</html>",
            &st.registry,
            st.chain_len,
            &st.chain_tip,
            b"",
            0
        )
        .is_err());
        let twice = "<!DOCTYPE html>\nconst REGISTRY = {\nconst REGISTRY = {\n</body></body>";
        assert!(
            build_monument_snapshot(twice, &st.registry, st.chain_len, &st.chain_tip, b"", 0)
                .is_err()
        );
        // a page with no </body> is refused (the chain would have nowhere to go)
        let nobody = "<!DOCTYPE html>\nconst REGISTRY = {\n};";
        assert!(
            build_monument_snapshot(nobody, &st.registry, st.chain_len, &st.chain_tip, b"", 0)
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
