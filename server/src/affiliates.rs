//! Affiliate ledger: THE CHAIN OF HANDS.
//! Any Bitcoin address is a referral link (?r=addr). Commissions accrue ONLY
//! from real, completed sales (engraved claims) - never from recruitment - so
//! total outflow is bounded by real revenue forever, and no minimum purchase or
//! fee is ever required to be an affiliate.
//!
//! Each confirmed sale pays AT MOST 35% of the price: `direct_pct` (25%) to the
//! address that referred the buyer (the seller), plus a 10% network pool split
//! across the seller's nearest upline sponsors, up to four levels deep and
//! degressive by how many uplines exist: 1 upline pays [10]; 2 pay [6,4]; 3 pay
//! [5,3,2]; 4+ pay [4,3,2,1] (level 5 and above earn nothing). The project keeps
//! the rest (at least 65%, or 75% when the seller has no upline).
//!
//! The upline graph (addr -> who recruited it) is built ONLY from real referred
//! purchases: `addr` is recruited by `sponsor` the first time a buyer sets their
//! own reward address `addr` on a claim referred by `sponsor`. Set-once and
//! cycle-guarded, so the chain stays a tree no one can forge or hijack.
//! Append-only ledger (affiliates.jsonl); payouts carry their Bitcoin txid and
//! are published, so anyone can verify every payment on-chain.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::Claim;

/// Max upline levels paid on one sale. Cost ceiling = direct_pct + 10%.
const MAX_UPLINES: usize = 4;

/// The 10% network pool split, by how many upline sponsors the seller has.
/// Each row sums to 10; index 0 is the nearest upline. This is the definitive
/// economic rule - fixed, not configurable.
fn network_split(uplines: usize) -> &'static [u64] {
    match uplines {
        0 => &[],
        1 => &[10],
        2 => &[6, 4],
        3 => &[5, 3, 2],
        _ => &[4, 3, 2, 1],
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    Accrual {
        ts: u64,
        addr: String,
        sats: u64,
        claim_id: String,
    },
    Payout {
        ts: u64,
        txid: String,
        outputs: BTreeMap<String, u64>,
    },
    /// `addr` was recruited by `sponsor` (set-once; the first sponsor wins).
    Sponsor {
        ts: u64,
        addr: String,
        sponsor: String,
    },
}

pub struct PayoutRecord {
    pub ts: u64,
    pub txid: String,
    pub total: u64,
    pub outputs: BTreeMap<String, u64>,
}

pub struct Affiliates {
    path: PathBuf,
    pub accrued: BTreeMap<String, u64>,
    pub paid: BTreeMap<String, u64>,
    pub payouts: Vec<PayoutRecord>,
    seen: HashSet<String>,
    /// addr -> its immediate upline (who recruited it). Set-once, cycle-free.
    sponsor: BTreeMap<String, String>,
}

impl Affiliates {
    pub fn load(dir: &Path) -> Result<Affiliates> {
        fs::create_dir_all(dir)
            .with_context(|| format!("cannot create data dir {}", dir.display()))?;
        let mut a = Affiliates {
            path: dir.join("affiliates.jsonl"),
            accrued: BTreeMap::new(),
            paid: BTreeMap::new(),
            payouts: Vec::new(),
            seen: HashSet::new(),
            sponsor: BTreeMap::new(),
        };
        if a.path.exists() {
            let raw = fs::read_to_string(&a.path)
                .with_context(|| format!("read {}", a.path.display()))?;
            let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
            for (i, line) in lines.iter().enumerate() {
                let is_last = i + 1 == lines.len();
                match serde_json::from_str::<Event>(line) {
                    Ok(ev) => a.apply(ev),
                    // A torn/truncated FINAL line is a crash mid-append: that
                    // event was never committed. Drop it, keep the rest. An
                    // earlier bad line is real corruption -> refuse to start.
                    Err(err) if is_last => {
                        eprintln!(
                            "[affiliates] dropping incomplete final line (torn append): {err}"
                        );
                        break;
                    }
                    Err(err) => bail!("affiliates line {} unreadable: {err}", i + 1),
                }
            }
        }
        Ok(a)
    }

    /// One synced write for all events of one action: no partial accrual.
    fn append_events(&self, events: &[Event]) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let mut buf = String::new();
        for e in events {
            buf.push_str(&serde_json::to_string(e).context("serialize affiliate event")?);
            buf.push('\n');
        }
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open {}", self.path.display()))?;
        f.write_all(buf.as_bytes())
            .context("append affiliate events")?;
        f.sync_all().context("sync affiliates")?;
        Ok(())
    }

    fn apply(&mut self, ev: Event) {
        match ev {
            Event::Accrual {
                addr,
                sats,
                claim_id,
                ..
            } => {
                *self.accrued.entry(addr).or_insert(0) += sats;
                self.seen.insert(claim_id);
            }
            Event::Payout { ts, txid, outputs } => {
                let total = outputs.values().sum();
                for (addr, sats) in &outputs {
                    *self.paid.entry(addr.clone()).or_insert(0) += sats;
                }
                self.payouts.push(PayoutRecord {
                    ts,
                    txid,
                    total,
                    outputs,
                });
            }
            Event::Sponsor { addr, sponsor, .. } => {
                // first sponsor wins - a relationship, once set, is permanent
                self.sponsor.entry(addr).or_insert(sponsor);
            }
        }
    }

    /// The nearest distinct upline sponsors above `start`, up to `MAX_UPLINES`.
    /// Distinct-only + a visited set make cycles and repeats impossible to pay.
    fn uplines(&self, start: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        visited.insert(start.to_owned());
        let mut cur = start.to_owned();
        while chain.len() < MAX_UPLINES {
            match self.sponsor.get(&cur) {
                Some(up) if !visited.contains(up) => {
                    visited.insert(up.clone());
                    chain.push(up.clone());
                    cur = up.clone();
                }
                _ => break,
            }
        }
        chain
    }

    /// Record that `addr` was recruited by `sponsor`: set-once (first sponsor
    /// wins), never self, and cycle-guarded so the upline graph stays a tree.
    /// Idempotent and safe to call from anywhere the relationship is observed.
    pub fn link_recruit(&mut self, addr: &str, sponsor: &str, now: u64) -> Result<()> {
        if addr.is_empty() || sponsor.is_empty() || addr == sponsor {
            return Ok(());
        }
        if self.sponsor.contains_key(addr) {
            return Ok(()); // already has a sponsor: permanent
        }
        // reject if `sponsor` is already downstream of `addr` (would form a loop)
        let mut cur = sponsor.to_owned();
        let mut guard = 0usize;
        while let Some(up) = self.sponsor.get(&cur) {
            if up == addr {
                return Ok(());
            }
            cur = up.clone();
            guard += 1;
            if guard > 100_000 {
                break;
            }
        }
        let ev = Event::Sponsor {
            ts: now,
            addr: addr.to_owned(),
            sponsor: sponsor.to_owned(),
        };
        self.append_events(std::slice::from_ref(&ev))?;
        self.apply(ev);
        Ok(())
    }

    /// Commission for ONE completed sale (an engraved claim): `direct_pct` to
    /// the direct referrer, plus the 10% network pool up that referrer's upline
    /// (up to 4 levels, degressive). Idempotent per claim. Also records the
    /// buyer's own upline edge (set-once), so the buyer's future sales pay the
    /// right chain even if they register their reward address only now.
    pub fn on_sale(&mut self, c: &Claim, direct_pct: u64, now: u64) -> Result<Vec<String>> {
        // The buyer (their reward address) is recruited by whoever referred THIS
        // purchase. Record it first, set-once, before the idempotency gate so the
        // edge survives even a re-processed claim.
        if let (Some(buyer), Some(refby)) = (c.reward_address.as_deref(), c.referred_by.as_deref())
        {
            self.link_recruit(buyer, refby, now)?;
        }
        if self.seen.contains(&c.id) {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        let mut log = Vec::new();
        if let Some(direct) = &c.referred_by {
            // Self-referral is not a sale: a buyer must not earn on their own
            // purchase by naming their own reward address as referrer.
            if c.reward_address.as_deref() == Some(direct.as_str()) {
                log.push(format!("self-referral ignored (claim {})", c.id));
            } else {
                let s1 = c.amount_sats * direct_pct / 100;
                if s1 > 0 {
                    events.push(Event::Accrual {
                        ts: now,
                        addr: direct.clone(),
                        sats: s1,
                        claim_id: c.id.clone(),
                    });
                    log.push(format!(
                        "direct {s1} sats ({direct_pct}%) -> {direct} (claim {})",
                        c.id
                    ));
                }
                // walk the direct seller's upline for the 10% network pool
                let ups = self.uplines(direct);
                for (up, &pct) in ups.iter().zip(network_split(ups.len())) {
                    // the buyer can never earn on their own purchase, even via chain
                    if c.reward_address.as_deref() == Some(up.as_str()) {
                        continue;
                    }
                    let s = c.amount_sats * pct / 100;
                    if s > 0 {
                        events.push(Event::Accrual {
                            ts: now,
                            addr: up.clone(),
                            sats: s,
                            claim_id: c.id.clone(),
                        });
                        log.push(format!(
                            "network {s} sats ({pct}%) -> {up} (claim {})",
                            c.id
                        ));
                    }
                }
            }
        }
        self.append_events(&events)?;
        let had_accrual = !events.is_empty();
        for e in events {
            self.apply(e);
        }
        if !had_accrual {
            self.seen.insert(c.id.clone());
        }
        Ok(log)
    }

    /// Balances due, at or above the payout threshold.
    pub fn pending(&self, threshold: u64) -> Vec<(String, u64)> {
        self.accrued
            .iter()
            .filter_map(|(a, acc)| {
                let due = acc.saturating_sub(self.paid.get(a).copied().unwrap_or(0));
                if due > 0 && due >= threshold {
                    Some((a.clone(), due))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Record the batch payment: every balance in the paid snapshot is marked
    /// paid under this Bitcoin txid, published for anyone to verify on-chain.
    pub fn record_payout(
        &mut self,
        txid: &str,
        snapshot: &BTreeMap<String, u64>,
        now: u64,
    ) -> Result<(u64, usize)> {
        let txid = txid.to_lowercase();
        if txid.len() != 64 || !txid.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("txid must be 64 hex characters");
        }
        if self.payouts.iter().any(|p| p.txid == txid) {
            bail!("this txid is already recorded");
        }
        // Record EXACTLY the snapshot the merchant saw and paid - never a fresh
        // recompute. A commission that accrued AFTER the batch tx was sent must
        // stay pending, not be silently marked paid. Each amount is capped at
        // the address's current balance so a payout can never over-credit.
        let mut outputs: BTreeMap<String, u64> = BTreeMap::new();
        for (addr, &sats) in snapshot {
            let due = self
                .accrued
                .get(addr)
                .copied()
                .unwrap_or(0)
                .saturating_sub(self.paid.get(addr).copied().unwrap_or(0));
            let pay = sats.min(due);
            if pay > 0 {
                outputs.insert(addr.clone(), pay);
            }
        }
        if outputs.is_empty() {
            bail!("no payout due");
        }
        let total: u64 = outputs.values().sum();
        let n = outputs.len();
        let ev = Event::Payout {
            ts: now,
            txid,
            outputs,
        };
        self.append_events(std::slice::from_ref(&ev))?;
        self.apply(ev);
        Ok((total, n))
    }

    /// The public, provable ledger: the fixed rules + per-address balances +
    /// payout txids (verifiable on Bitcoin by anyone). The upline GRAPH is never
    /// disclosed - only balances and proofs are public.
    pub fn public_json(&self, direct_pct: u64, threshold: u64) -> String {
        let mut affs = serde_json::Map::new();
        for (addr, acc) in &self.accrued {
            let acc = *acc;
            let paid = self.paid.get(addr).copied().unwrap_or(0);
            let mut o = serde_json::Map::new();
            o.insert("accrued_sats".to_owned(), acc.into());
            o.insert("paid_sats".to_owned(), paid.into());
            o.insert("pending_sats".to_owned(), acc.saturating_sub(paid).into());
            affs.insert(addr.clone(), o.into());
        }
        let payouts: Vec<Value> = self
            .payouts
            .iter()
            .map(|p| {
                serde_json::json!({
                    "ts": p.ts,
                    "txid": p.txid,
                    "total_sats": p.total,
                    "outputs": p.outputs,
                })
            })
            .collect();
        serde_json::json!({
            "direct_pct": direct_pct,
            "network_pct": 10,
            "network_split": {
                "1": network_split(1),
                "2": network_split(2),
                "3": network_split(3),
                "4+": network_split(4),
            },
            "max_upline_levels": MAX_UPLINES,
            "payout_threshold_sats": threshold,
            "affiliates": affs,
            "payouts": payouts,
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::ClaimStatus;

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("minute-aff-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn claim(id: &str, refb: Option<&str>, rew: Option<&str>) -> Claim {
        Claim {
            id: id.to_owned(),
            minute: "2030-01-01T00:00Z".to_owned(),
            name: String::new(),
            msg: "Words.".to_owned(),
            amount_sats: 21000,
            created_epoch: 0,
            expires_epoch: 0,
            status: ClaimStatus::Engraved,
            address: None,
            addr_index: None,
            referred_by: refb.map(str::to_owned),
            reward_address: rew.map(str::to_owned),
            txid: None,
            paid_epoch: None,
            decided_epoch: None,
        }
    }

    #[test]
    fn direct_only_when_no_upline() {
        let dir = tmp_dir("direct");
        let mut a = Affiliates::load(&dir).expect("load");
        // A refers a buyer with no upline above A: A earns 25%, nobody else.
        a.on_sale(&claim("c1", Some("A"), None), 25, 100)
            .expect("sale");
        assert_eq!(a.accrued.get("A"), Some(&5250));
        assert_eq!(a.accrued.len(), 1);
        // idempotent per claim
        a.on_sale(&claim("c1", Some("A"), None), 25, 200)
            .expect("repeat");
        assert_eq!(a.accrued.get("A"), Some(&5250));
        // no ref at all: nothing accrues
        a.on_sale(&claim("c0", None, None), 25, 300)
            .expect("no ref");
        assert_eq!(a.accrued.len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multilevel_matches_spec_exactly() {
        // The definitive example from the spec: chain A -> B -> C -> D -> E -> F -> G
        // (A recruited B, B recruited C, ... F recruited G).
        let dir = tmp_dir("mlm");
        let mut a = Affiliates::load(&dir).expect("load");
        for (x, sp) in [
            ("B", "A"),
            ("C", "B"),
            ("D", "C"),
            ("E", "D"),
            ("F", "E"),
            ("G", "F"),
        ] {
            a.link_recruit(x, sp, 0).expect("link");
        }

        // G generates a sale: G 25%, F 4%, E 3%, D 2%, C 1%, B and A nothing.
        a.on_sale(&claim("s_g", Some("G"), None), 25, 100)
            .expect("G sale");
        assert_eq!(a.accrued.get("G"), Some(&5250)); // 25%
        assert_eq!(a.accrued.get("F"), Some(&840)); // 4%
        assert_eq!(a.accrued.get("E"), Some(&630)); // 3%
        assert_eq!(a.accrued.get("D"), Some(&420)); // 2%
        assert_eq!(a.accrued.get("C"), Some(&210)); // 1%
        assert_eq!(a.accrued.get("B"), None); // level 5: nothing
        assert_eq!(a.accrued.get("A"), None); // level 6: nothing
                                              // total cost never exceeds 35% (7350 of 21000)
        let cost: u64 = ["G", "F", "E", "D", "C"]
            .iter()
            .map(|k| a.accrued.get(*k).copied().unwrap_or(0))
            .sum();
        assert_eq!(cost, 7350);

        // B generates a sale: B 25%, A 10% (A is B's only upline).
        a.on_sale(&claim("s_b", Some("B"), None), 25, 200)
            .expect("B sale");
        assert_eq!(a.accrued.get("B"), Some(&5250)); // 25%
        assert_eq!(a.accrued.get("A"), Some(&2100)); // 10%
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn network_pool_by_depth() {
        let dir = tmp_dir("depth");
        let mut a = Affiliates::load(&dir).expect("load");
        // A -> B -> C -> D
        for (x, sp) in [("B", "A"), ("C", "B"), ("D", "C")] {
            a.link_recruit(x, sp, 0).expect("link");
        }
        // Seller C has 2 uplines (B, A) -> 25 / 6 / 4
        a.on_sale(&claim("sc", Some("C"), None), 25, 100)
            .expect("C");
        assert_eq!(a.accrued.get("C"), Some(&5250)); // 25%
        assert_eq!(a.accrued.get("B"), Some(&1260)); // 6%
        assert_eq!(a.accrued.get("A"), Some(&840)); // 4%
                                                    // Seller D has 3 uplines (C, B, A) -> 25 / 5 / 3 / 2
        a.on_sale(&claim("sd", Some("D"), None), 25, 200)
            .expect("D");
        assert_eq!(a.accrued.get("D"), Some(&5250)); // 25%
        assert_eq!(a.accrued.get("C"), Some(&(5250 + 1050))); // +5%
        assert_eq!(a.accrued.get("B"), Some(&(1260 + 630))); // +3%
        assert_eq!(a.accrued.get("A"), Some(&(840 + 420))); // +2%
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sponsor_is_set_once_and_from_real_purchase() {
        let dir = tmp_dir("edge");
        let mut a = Affiliates::load(&dir).expect("load");
        // B buys via A's link and registers reward=B -> B recruited by A.
        a.on_sale(&claim("cb", Some("A"), Some("B")), 25, 100)
            .expect("B buys");
        assert_eq!(a.accrued.get("A"), Some(&5250)); // A earns 25% on B's purchase
                                                     // A later tries to be re-parented under Z: first sponsor wins, ignored.
        a.on_sale(&claim("cb2", Some("Z"), Some("B")), 25, 150)
            .expect("reparent attempt");
        // Now C buys via B's link: B 25%, and B's upline A gets 10%.
        a.on_sale(&claim("cc", Some("B"), Some("C")), 25, 200)
            .expect("C buys");
        assert_eq!(a.accrued.get("B"), Some(&5250)); // 25% direct
        assert_eq!(a.accrued.get("A"), Some(&(5250 + 2100))); // +10% network, NOT Z
        assert_eq!(a.accrued.get("Z"), Some(&5250)); // Z only got its own direct sale
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn cycles_and_self_are_refused() {
        let dir = tmp_dir("cycle");
        let mut a = Affiliates::load(&dir).expect("load");
        a.link_recruit("A", "A", 0).expect("self"); // self ignored
        assert!(!a.sponsor.contains_key("A"));
        a.link_recruit("B", "A", 0).expect("b<-a");
        a.link_recruit("C", "B", 0).expect("c<-b");
        a.link_recruit("A", "C", 0).expect("would-be cycle A<-C"); // A upstream of C
        assert!(!a.sponsor.contains_key("A")); // refused, no loop
                                               // C selling pays C 25%, B 6%, A 4% (2 uplines) - never loops back to C
        a.on_sale(&claim("s", Some("C"), None), 25, 100)
            .expect("sale");
        assert_eq!(a.accrued.get("C"), Some(&5250));
        assert_eq!(a.accrued.get("B"), Some(&1260));
        assert_eq!(a.accrued.get("A"), Some(&840));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn self_referral_earns_nothing() {
        let dir = tmp_dir("self");
        let mut a = Affiliates::load(&dir).expect("load");
        // buyer named their OWN reward address as referrer: NO commission
        a.on_sale(&claim("c1", Some("A"), Some("A")), 25, 100)
            .expect("sale");
        assert!(!a.accrued.contains_key("A"));
        assert_eq!(a.accrued.len(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn payout_snapshot_and_persistence() {
        let dir = tmp_dir("pay");
        let mut a = Affiliates::load(&dir).expect("load");
        a.link_recruit("B", "A", 0).expect("link");
        a.on_sale(&claim("c1", Some("B"), None), 25, 100)
            .expect("sale"); // B 5250, A 2100
                             // pending honors the threshold
        assert_eq!(a.pending(10000).len(), 0);
        assert_eq!(a.pending(2000).len(), 2);
        // snapshot payout: a commission accrued AFTER the snapshot stays pending
        let snap: BTreeMap<String, u64> = a.pending(0).into_iter().collect();
        a.on_sale(&claim("c2", Some("B"), None), 25, 150)
            .expect("sale2"); // B now 10500
        assert!(a.record_payout("nothex", &snap, 200).is_err());
        let (total, n) = a
            .record_payout(&"ab".repeat(32), &snap, 200)
            .expect("payout");
        assert_eq!((total, n), (7350, 2)); // 5250 (B) + 2100 (A)
                                           // c2 accrued AFTER the snapshot, so both its commissions stay pending:
                                           // B's 5250 (direct) and A's 2100 (network) - never silently marked paid.
        assert_eq!(
            a.pending(0),
            vec![("A".to_owned(), 2100), ("B".to_owned(), 5250)]
        );
        assert!(a.record_payout(&"ab".repeat(32), &snap, 300).is_err()); // dup txid
                                                                         // persistence roundtrip: balances, payouts AND the upline graph survive
        let b = Affiliates::load(&dir).expect("reload");
        assert_eq!(b.accrued, a.accrued);
        assert_eq!(b.paid, a.paid);
        assert_eq!(b.payouts.len(), 1);
        assert_eq!(b.sponsor.get("B"), Some(&"A".to_owned()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn public_json_is_provable() {
        let dir = tmp_dir("json");
        let mut a = Affiliates::load(&dir).expect("load");
        a.on_sale(&claim("c1", Some("A"), Some("B")), 25, 100)
            .expect("sale");
        let j = a.public_json(25, 10000);
        assert!(j.contains("\"direct_pct\":25"));
        assert!(j.contains("\"network_pct\":10"));
        assert!(j.contains("\"accrued_sats\":5250"));
        // the recruitment graph is NOT disclosed publicly
        assert!(!j.contains("sponsor"));
        assert!(!j.contains("recruited_by"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_tolerates_torn_final_line() {
        let dir = tmp_dir("torn");
        {
            let mut a = Affiliates::load(&dir).expect("load");
            a.on_sale(&claim("c1", Some("A"), None), 25, 100)
                .expect("s1");
            a.on_sale(&claim("c2", Some("B"), None), 25, 200)
                .expect("s2");
        }
        let path = dir.join("affiliates.jsonl");
        // append a torn (truncated, unparseable) final line, as a crash would
        let mut raw = fs::read_to_string(&path).expect("read");
        raw.push_str("{\"kind\":\"accrual\",\"ts\":1,\"addr\":\"C\",\"sa");
        fs::write(&path, &raw).expect("write torn");
        let re = Affiliates::load(&dir).expect("tolerates torn final line");
        assert_eq!(re.accrued.get("A"), Some(&5250));
        assert_eq!(re.accrued.get("B"), Some(&5250));
        assert!(!re.accrued.contains_key("C")); // torn event dropped
                                                // a torn line in the MIDDLE is real corruption -> refuse
        let mut bad = fs::read_to_string(&path).unwrap();
        bad = bad.replacen('\n', "\nGARBAGE-NOT-JSON\n", 1);
        fs::write(&path, bad).expect("write mid corruption");
        assert!(Affiliates::load(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
