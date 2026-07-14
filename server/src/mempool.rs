//! Read-only Bitcoin payment detection through the public mempool.space API.
//! The server never holds keys or funds: it only reads the public address.

use anyhow::{Context, Result};
use serde_json::Value;

/// Confirmations of a transaction given the current best-block height.
/// 0 = unconfirmed. A confirmed tx whose height (or the tip) is unknown counts
/// as exactly 1 (the minimum), so a caller requiring >= 2 fails closed until it
/// can measure real depth.
pub fn tx_confirmations(tx: &Value, tip_height: u64) -> u64 {
    let confirmed = tx
        .pointer("/status/confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !confirmed {
        return 0;
    }
    match tx.pointer("/status/block_height").and_then(Value::as_u64) {
        Some(h) if tip_height >= h => tip_height - h + 1,
        _ => 1,
    }
}

/// Find a transaction paying exactly `amount_sats` to `address` with at least
/// `min_conf` confirmations (legacy mode).
pub fn find_confirmed_payment(
    txs: &[Value],
    address: &str,
    amount_sats: u64,
    tip_height: u64,
    min_conf: u64,
) -> Option<String> {
    for tx in txs {
        if tx_confirmations(tx, tip_height) < min_conf {
            continue;
        }
        let Some(vouts) = tx.get("vout").and_then(Value::as_array) else {
            continue;
        };
        for v in vouts {
            let addr = v.get("scriptpubkey_address").and_then(Value::as_str);
            let val = v.get("value").and_then(Value::as_u64);
            if addr == Some(address) && val == Some(amount_sats) {
                return tx.get("txid").and_then(Value::as_str).map(str::to_owned);
            }
        }
    }
    None
}

/// Find a transaction paying AT LEAST `min_sats` to `address` with at least
/// `min_conf` confirmations (xpub mode: the dedicated address is the id).
pub fn find_payment_to(
    txs: &[Value],
    address: &str,
    min_sats: u64,
    tip_height: u64,
    min_conf: u64,
) -> Option<String> {
    for tx in txs {
        if tx_confirmations(tx, tip_height) < min_conf {
            continue;
        }
        let Some(vouts) = tx.get("vout").and_then(Value::as_array) else {
            continue;
        };
        for v in vouts {
            let addr = v.get("scriptpubkey_address").and_then(Value::as_str);
            let val = v.get("value").and_then(Value::as_u64);
            if addr == Some(address) && val.map(|s| s >= min_sats).unwrap_or(false) {
                return tx.get("txid").and_then(Value::as_str).map(str::to_owned);
            }
        }
    }
    None
}

/// Confirmation depth of the DEEPEST transaction paying `address` with a value
/// satisfying the mode (`>= sats` when `at_least`, exact `== sats` otherwise),
/// regardless of any minimum. `None` = no matching payment seen yet; `Some(0)`
/// = seen only in the mempool (unconfirmed); `Some(n)` = confirmed n blocks
/// deep. Lets the buyer watch 0 -> 1 -> 2 while a payment matures, without
/// affecting the payment DECISION (which still requires `min_conf`).
pub fn payment_depth(
    txs: &[Value],
    address: &str,
    sats: u64,
    tip_height: u64,
    at_least: bool,
) -> Option<u64> {
    let mut best: Option<u64> = None;
    for tx in txs {
        let Some(vouts) = tx.get("vout").and_then(Value::as_array) else {
            continue;
        };
        let hit = vouts.iter().any(|v| {
            let addr = v.get("scriptpubkey_address").and_then(Value::as_str);
            let val = v.get("value").and_then(Value::as_u64);
            addr == Some(address)
                && val
                    .map(|s| if at_least { s >= sats } else { s == sats })
                    .unwrap_or(false)
        });
        if hit {
            let d = tx_confirmations(tx, tip_height);
            best = Some(best.map_or(d, |b| b.max(d)));
        }
    }
    best
}

/// Current best-block height from an Esplora source (GET /blocks/tip/height,
/// a plain integer). Used to measure confirmation depth.
pub fn fetch_tip_height(api_base: &str) -> Result<u64> {
    let body = ureq::get(&format!("{api_base}/blocks/tip/height"))
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .context("tip height request failed")?
        .into_string()
        .context("tip height response unreadable")?;
    body.trim()
        .parse::<u64>()
        .context("tip height not an integer")
}

/// Fetch the address transactions, following chain pagination.
/// mempool.space serves the newest transactions first.
pub fn fetch_address_txs(api_base: &str, address: &str, max_pages: usize) -> Result<Vec<Value>> {
    let mut all = Vec::new();
    let mut url = format!("{api_base}/address/{address}/txs");
    for _ in 0..max_pages {
        let resp: Value = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(20))
            .call()
            .context("mempool request failed")?
            .into_json()
            .context("mempool response is not json")?;
        let Some(arr) = resp.as_array() else {
            break;
        };
        if arr.is_empty() {
            break;
        }
        let page_len = arr.len();
        let last_txid = arr
            .last()
            .and_then(|t| t.get("txid"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        all.extend(arr.iter().cloned());
        // chain pages hold 25 transactions; a short page is the last one
        if page_len < 25 {
            break;
        }
        match last_txid {
            Some(t) => url = format!("{api_base}/address/{address}/txs/chain/{t}"),
            None => break,
        }
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canned() -> Vec<Value> {
        vec![
            json!({
                "txid": "aaa111",
                "status": { "confirmed": false },
                "vout": [
                    { "scriptpubkey_address": "bc1qtarget", "value": 21042 }
                ]
            }),
            json!({
                "txid": "bbb222",
                "status": { "confirmed": true },
                "vout": [
                    { "scriptpubkey_address": "bc1qother", "value": 21042 },
                    { "scriptpubkey_address": "bc1qtarget", "value": 5000 }
                ]
            }),
            json!({
                "txid": "ccc333",
                "status": { "confirmed": true },
                "vout": [
                    { "scriptpubkey_address": "bc1qtarget", "value": 21042 }
                ]
            }),
        ]
    }

    #[test]
    fn matches_confirmed_exact_amount_only() {
        let txs = canned();
        // exact amount on the right address, confirmed -> ccc333 (not the
        // unconfirmed aaa111, not the wrong-address output of bbb222)
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qtarget", 21042, 0, 1).as_deref(),
            Some("ccc333")
        );
    }

    #[test]
    fn ignores_wrong_amount_and_address() {
        let txs = canned();
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qtarget", 21043, 0, 1),
            None
        );
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qnobody", 21042, 0, 1),
            None
        );
    }

    #[test]
    fn tolerates_malformed_entries() {
        let txs = vec![json!({}), json!({"txid": "x", "vout": "not-an-array"})];
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qtarget", 21042, 0, 1),
            None
        );
    }

    #[test]
    fn confirmation_depth_is_enforced() {
        // a confirmed tx at block 100, tip at 100 = 1 conf; tip 101 = 2 confs
        let txs = vec![json!({
            "txid": "deep",
            "status": { "confirmed": true, "block_height": 100 },
            "vout": [ { "scriptpubkey_address": "bc1qtarget", "value": 21042 } ]
        })];
        // 1 conf available: passes min_conf 1, fails min_conf 2
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qtarget", 21042, 100, 1).as_deref(),
            Some("deep")
        );
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qtarget", 21042, 100, 2),
            None
        );
        // one more block: now 2 confs, passes min_conf 2
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qtarget", 21042, 101, 2).as_deref(),
            Some("deep")
        );
        // unknown tip (0) with a demand of 2 fails closed
        assert_eq!(
            find_confirmed_payment(&txs, "bc1qtarget", 21042, 0, 2),
            None
        );
        // xpub matcher honors depth too
        assert_eq!(
            find_payment_to(&txs, "bc1qtarget", 21000, 101, 2).as_deref(),
            Some("deep")
        );
        assert_eq!(find_payment_to(&txs, "bc1qtarget", 21000, 100, 2), None);
    }

    #[test]
    fn payment_depth_tracks_the_deepest_match() {
        // seen only in the mempool -> depth 0 (payment noticed, 0 confirmations)
        let pool = vec![json!({
            "txid": "m", "status": { "confirmed": false },
            "vout": [ { "scriptpubkey_address": "bc1qtarget", "value": 21042 } ]
        })];
        assert_eq!(
            payment_depth(&pool, "bc1qtarget", 21042, 999, false),
            Some(0)
        );
        // no matching output at all -> None (nothing to show the buyer yet)
        assert_eq!(payment_depth(&pool, "bc1qtarget", 21043, 999, false), None);
        // a shallow mempool copy and a deeper confirmation: the deepest wins
        let both = vec![
            json!({ "txid": "shallow", "status": { "confirmed": false },
                    "vout": [ { "scriptpubkey_address": "bc1qtarget", "value": 21042 } ] }),
            json!({ "txid": "deep", "status": { "confirmed": true, "block_height": 100 },
                    "vout": [ { "scriptpubkey_address": "bc1qtarget", "value": 21042 } ] }),
        ];
        // confirmed at block 100, tip 102 -> 3 confs; beats the mempool copy's 0
        assert_eq!(
            payment_depth(&both, "bc1qtarget", 21042, 102, false),
            Some(3)
        );
        // xpub mode counts any value >= the price; legacy needs the exact value
        assert_eq!(
            payment_depth(&both, "bc1qtarget", 21000, 102, true),
            Some(3)
        );
        assert_eq!(payment_depth(&both, "bc1qtarget", 21043, 102, false), None);
    }
}
