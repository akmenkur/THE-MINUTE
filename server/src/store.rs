//! Persistent state: claims and the public registry.
//! Plain JSON files, atomic writes (tmp + rename). The registry is the
//! monument itself: append only, never edited, never deleted (Rule II).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::validate;

/// A claim that was paid can still be matched this long after expiry:
/// money received is always honored (never swallowed).
pub const REVIVE_SECS: u64 = 7 * 86400;

/// Hard ceiling on outstanding unpaid reservations, independent of the
/// per-IP rate limit (which IPv6 /64 rotation can defeat). Blocks a mass
/// minute-reservation grief that would deny/extort real buyers.
pub const MAX_OPEN_CLAIMS: usize = 20_000;

/// A refused claim is kept this long (for the buyer's status link + refund
/// trace) then pruned, so the claims map cannot grow without bound.
pub const REFUSED_KEEP_SECS: u64 = 30 * 86400;

#[derive(Serialize, Deserialize, Clone)]
pub struct RegistryEntry {
    pub name: String,
    pub msg: String,
    pub live: bool,
}

/// All zeros: the `prev` of the first chain entry.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One link of the cryptographic ledger (`chain.jsonl`, one JSON per line).
/// `hash` = blake3 of the entry serialized without its `hash` field.
/// Each engraving seals the previous one: altering any line breaks every
/// hash after it. Rule II ("never altered") becomes verifiable by anyone.
///
/// Commit-reveal (Rule IV): the chain carries `msg_hash` = blake3 of the
/// words, never the words themselves. The words become public through
/// registry.json only once their minute has arrived; auditors can then
/// recompute blake3(msg) and match it against the sealed commitment.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChainEntry {
    pub seq: u64,
    pub prev: String,
    pub minute: String,
    pub name: String,
    pub msg_hash: String,
    pub live: bool,
    pub ts: u64,
    pub hash: String,
}

#[derive(Serialize)]
struct ChainPreimage<'a> {
    seq: u64,
    prev: &'a str,
    minute: &'a str,
    name: &'a str,
    msg_hash: &'a str,
    live: bool,
    ts: u64,
}

/// The public commitment to a message: blake3 of its exact bytes.
pub fn msg_commitment(msg: &str) -> String {
    blake3::hash(msg.as_bytes()).to_hex().to_string()
}

fn chain_entry_hash(
    seq: u64,
    prev: &str,
    minute: &str,
    name: &str,
    msg_hash: &str,
    live: bool,
    ts: u64,
) -> Result<String> {
    let pre = ChainPreimage {
        seq,
        prev,
        minute,
        name,
        msg_hash,
        live,
        ts,
    };
    let bytes = serde_json::to_vec(&pre).context("serialize chain preimage")?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Read and verify the whole chain, genesis to tip.
/// A missing file is a valid empty chain. Any broken link is an error.
pub fn read_chain(path: &Path) -> Result<Vec<ChainEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let mut prev = GENESIS_PREV.to_owned();
    let mut seq = 0u64;
    let mut out = Vec::new();
    let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    for (i, line) in lines.iter().enumerate() {
        let is_last = i + 1 == lines.len();
        let e: ChainEntry = match serde_json::from_str(line) {
            Ok(e) => e,
            // A torn/truncated FINAL line is a crash mid-append: the entry was
            // never committed. Drop it (the paid claim stays Paid and engraves
            // again). Any EARLIER unreadable line is real corruption -> bail.
            Err(err) if is_last => {
                eprintln!("[chain] dropping incomplete final line (torn append): {err}");
                break;
            }
            Err(err) => bail!("chain line {} unreadable: {err}", i + 1),
        };
        if e.seq != seq + 1 {
            bail!("chain line {}: seq {} expected {}", i + 1, e.seq, seq + 1);
        }
        if e.prev != prev {
            bail!("chain line {}: prev hash mismatch", i + 1);
        }
        let h = chain_entry_hash(
            e.seq,
            &e.prev,
            &e.minute,
            &e.name,
            &e.msg_hash,
            e.live,
            e.ts,
        )?;
        if h != e.hash {
            bail!("chain line {}: hash mismatch (entry altered)", i + 1);
        }
        prev = e.hash.clone();
        seq = e.seq;
        out.push(e);
    }
    Ok(out)
}

/// Verify a chain file. Returns (entries, tip hash).
pub fn verify_chain_file(path: &Path) -> Result<(u64, String)> {
    let chain = read_chain(path)?;
    Ok(match chain.last() {
        Some(e) => (e.seq, e.hash.clone()),
        None => (0, GENESIS_PREV.to_owned()),
    })
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    AwaitingPayment,
    Paid,
    Engraved,
    Refused,
    Expired,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimStatus::AwaitingPayment => "awaiting_payment",
            ClaimStatus::Paid => "paid",
            ClaimStatus::Engraved => "engraved",
            ClaimStatus::Refused => "refused",
            ClaimStatus::Expired => "expired",
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Claim {
    pub id: String,
    pub minute: String,
    pub name: String,
    pub msg: String,
    pub amount_sats: u64,
    pub created_epoch: u64,
    pub expires_epoch: u64,
    pub status: ClaimStatus,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub addr_index: Option<u64>,
    /// Affiliate link that brought this buyer (a Bitcoin address).
    #[serde(default)]
    pub referred_by: Option<String>,
    /// The buyer's own address for referral rewards (their affiliate id).
    #[serde(default)]
    pub reward_address: Option<String>,
    pub txid: Option<String>,
    pub paid_epoch: Option<u64>,
    pub decided_epoch: Option<u64>,
}

impl Claim {
    /// Does this claim block its minute from being claimed by someone else?
    fn blocks(&self, now: u64) -> bool {
        match self.status {
            ClaimStatus::AwaitingPayment => self.expires_epoch > now,
            ClaimStatus::Paid | ClaimStatus::Engraved => true,
            ClaimStatus::Refused | ClaimStatus::Expired => false,
        }
    }

    /// Is this claim still eligible for payment matching?
    fn matchable(&self, now: u64) -> bool {
        match self.status {
            ClaimStatus::AwaitingPayment => true,
            ClaimStatus::Expired => now < self.expires_epoch + REVIVE_SECS,
            _ => false,
        }
    }
}

pub struct Store {
    dir: PathBuf,
    pub claims: HashMap<String, Claim>,
    pub registry: BTreeMap<String, RegistryEntry>,
    pub chain_len: u64,
    pub chain_tip: String,
}

fn random_hex(bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; bytes];
    getrandom::getrandom(&mut buf).context("csprng unavailable")?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// Public registry JSON (Rule IV enforced HERE): the words of a minute that
/// has not fully arrived are NOT serialized - only name, live and sealed:true.
/// A free function so handlers can clone the registry under the store lock and
/// render OUTSIDE the lock (never blocking claim creation or the poller).
pub fn render_registry_json(
    registry: &BTreeMap<String, RegistryEntry>,
    now: u64,
) -> Result<String> {
    let mut out = serde_json::Map::new();
    for (minute, e) in registry {
        let arrived = validate::minute_id_to_epoch(minute)
            .map(|epoch| epoch <= now as i64)
            .unwrap_or(false);
        let v = if arrived {
            serde_json::json!({ "name": e.name, "msg": e.msg, "live": e.live })
        } else {
            serde_json::json!({ "name": e.name, "live": e.live, "sealed": true })
        };
        out.insert(minute.clone(), v);
    }
    serde_json::to_string_pretty(&out).context("serialize registry")
}

impl Store {
    pub fn load(dir: &Path) -> Result<Store> {
        fs::create_dir_all(dir)
            .with_context(|| format!("cannot create data dir {}", dir.display()))?;
        let claims_path = dir.join("claims.json");
        let registry_path = dir.join("registry.json");
        let claims: HashMap<String, Claim> = if claims_path.exists() {
            serde_json::from_slice(&fs::read(&claims_path).context("read claims.json")?)
                .context("parse claims.json")?
        } else {
            HashMap::new()
        };
        let registry: BTreeMap<String, RegistryEntry> = if registry_path.exists() {
            serde_json::from_slice(&fs::read(&registry_path).context("read registry.json")?)
                .context("parse registry.json")?
        } else {
            BTreeMap::new()
        };
        // The chain is the ledger of record: refuse to start on corruption,
        // rebuild the registry index from the chain if the two diverge.
        let chain =
            read_chain(&dir.join("chain.jsonl")).context("chain.jsonl integrity failure")?;
        let (chain_len, chain_tip) = match chain.last() {
            Some(e) => (e.seq, e.hash.clone()),
            None => (0, GENESIS_PREV.to_owned()),
        };
        // Self-heal a crash DURING engrave: engrave appends the chain, THEN
        // persists the registry (words), THEN the claim status. A crash in
        // between leaves the chain one (or more) ahead. Recover each missing
        // registry entry from its paying claim's words, verified against the
        // sealed commitment, and mark that claim engraved. If the words are
        // unrecoverable, refuse to start (genuine corruption / bad restore).
        let mut registry = registry;
        let mut claims = claims;
        let mut healed = false;
        for e in &chain {
            if registry.contains_key(&e.minute) {
                continue;
            }
            let cid = claims
                .iter()
                .find(|(_, c)| {
                    c.minute == e.minute
                        && matches!(c.status, ClaimStatus::Paid | ClaimStatus::Engraved)
                        && msg_commitment(&c.msg) == e.msg_hash
                })
                .map(|(id, _)| id.clone());
            match cid {
                Some(id) => {
                    let c = claims.get_mut(&id).expect("just located this claim");
                    c.status = ClaimStatus::Engraved;
                    registry.insert(
                        e.minute.clone(),
                        RegistryEntry {
                            name: c.name.clone(),
                            msg: c.msg.clone(),
                            live: e.live,
                        },
                    );
                    healed = true;
                    eprintln!(
                        "[recover] healed registry for {} from its claim (crash during engrave)",
                        e.minute
                    );
                }
                None => bail!(
                    "chain entry {} has no recoverable words: restore data dir from backup",
                    e.minute
                ),
            }
        }
        // Invariant must now hold exactly (also catches registry-ahead corruption).
        if chain.len() != registry.len() {
            bail!(
                "registry ({}) diverges from chain ({}): restore data dir from backup",
                registry.len(),
                chain.len()
            );
        }
        for e in &chain {
            let Some(r) = registry.get(&e.minute) else {
                bail!("chain entry {} missing from registry", e.minute);
            };
            if msg_commitment(&r.msg) != e.msg_hash {
                bail!(
                    "registry words for {} do not match the sealed commitment",
                    e.minute
                );
            }
        }
        let store = Store {
            dir: dir.to_path_buf(),
            claims,
            registry,
            chain_len,
            chain_tip,
        };
        if healed {
            store.persist_registry()?;
            store.persist_claims()?;
        }
        Ok(store)
    }

    /// Append one sealed entry to the cryptographic ledger.
    fn append_chain(
        &mut self,
        minute: &str,
        name: &str,
        msg_hash: &str,
        live: bool,
        ts: u64,
    ) -> Result<()> {
        let seq = self.chain_len + 1;
        let hash = chain_entry_hash(seq, &self.chain_tip, minute, name, msg_hash, live, ts)?;
        let entry = ChainEntry {
            seq,
            prev: self.chain_tip.clone(),
            minute: minute.to_owned(),
            name: name.to_owned(),
            msg_hash: msg_hash.to_owned(),
            live,
            ts,
            hash: hash.clone(),
        };
        let mut line = serde_json::to_string(&entry).context("serialize chain entry")?;
        line.push('\n');
        let path = self.dir.join("chain.jsonl");
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        f.write_all(line.as_bytes()).context("append chain entry")?;
        f.sync_all().context("sync chain")?;
        self.chain_len = seq;
        self.chain_tip = hash;
        Ok(())
    }

    fn write_atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let tmp = self.dir.join(format!("{name}.tmp"));
        let dst = self.dir.join(name);
        // Flush the data to disk BEFORE the rename, so a power loss can never
        // leave a renamed-but-empty file (atomic AND durable, like the chain).
        {
            let mut f =
                fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            f.write_all(bytes)
                .with_context(|| format!("write {}", tmp.display()))?;
            f.sync_all()
                .with_context(|| format!("sync {}", tmp.display()))?;
        }
        fs::rename(&tmp, &dst).with_context(|| format!("rename to {}", dst.display()))?;
        // fsync the directory so the rename entry itself survives a power loss.
        if let Ok(d) = fs::File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    fn persist_claims(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.claims).context("serialize claims")?;
        self.write_atomic("claims.json", &bytes)
    }

    fn persist_registry(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.registry).context("serialize registry")?;
        self.write_atomic("registry.json", &bytes)
    }

    fn minute_blocked(&self, minute: &str, now: u64) -> bool {
        self.registry.contains_key(minute)
            || self
                .claims
                .values()
                .any(|c| c.minute == minute && c.blocks(now))
    }

    /// Next unused derivation index (never reused, even across refusals).
    pub fn next_addr_index(&self, start: u64) -> u64 {
        self.claims
            .values()
            .filter_map(|c| c.addr_index)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0)
            .max(start)
    }

    /// Unique payable amount: price + suffix in 1..=999 sats, unique among
    /// all claims still eligible for matching. The amount IS the claim id
    /// on the blockchain side.
    fn unique_amount(&self, price_sats: u64, now: u64) -> Result<u64> {
        for _ in 0..500 {
            let mut b = [0u8; 2];
            getrandom::getrandom(&mut b).context("csprng unavailable")?;
            let r = u16::from_le_bytes(b);
            // reject the top of the range so 1..=999 is uniform (no modulo bias)
            if r >= 64935 {
                continue; // 64935 = 65 * 999
            }
            let suffix = (r % 999 + 1) as u64;
            let amount = price_sats + suffix;
            let collision = self.claims.values().any(|c| {
                c.amount_sats == amount && (c.matchable(now) || c.status == ClaimStatus::Paid)
            });
            if !collision {
                return Ok(amount);
            }
        }
        bail!("no unique amount available, try again later");
    }

    // 8 args: the three policy knobs (price, expiry, lead) will move into a
    // ClaimPolicy struct when premium pricing lands; not worth the churn yet.
    #[allow(clippy::too_many_arguments)]
    pub fn new_claim(
        &mut self,
        minute: &str,
        name: &str,
        msg: &str,
        price_sats: u64,
        now: u64,
        expiry_secs: u64,
        min_lead_secs: u64,
        derived: Option<(String, u64)>,
    ) -> Result<Claim> {
        let Some(epoch) = validate::minute_id_to_epoch(minute) else {
            bail!("that minute does not exist");
        };
        // the past cannot be bought: only minutes still to come (Rule VII)
        if epoch <= now as i64 {
            bail!("that minute has already passed: the past cannot be bought");
        }
        // every live moment must have had its moderation window (Rule VI)
        if min_lead_secs > 0 && (epoch as u64) < now + min_lead_secs {
            bail!(
                "this minute arrives too soon: future minutes must be claimed at least {} hours before they arrive",
                min_lead_secs / 3600
            );
        }
        let name = validate::validate_name(name).map_err(anyhow::Error::msg)?;
        let msg = validate::validate_message(msg).map_err(anyhow::Error::msg)?;
        if self.minute_blocked(minute, now) {
            bail!("this minute is already owned or reserved by a pending claim");
        }
        let open = self
            .claims
            .values()
            .filter(|c| c.status == ClaimStatus::AwaitingPayment && c.expires_epoch > now)
            .count();
        if open >= MAX_OPEN_CLAIMS {
            bail!("reservation capacity reached, try again in a moment");
        }
        let amount_sats = if derived.is_some() {
            price_sats // the dedicated address identifies the payment
        } else {
            self.unique_amount(price_sats, now)?
        };
        let (address, addr_index) = match derived {
            Some((a, i)) => (Some(a), Some(i)),
            None => (None, None),
        };
        let claim = Claim {
            id: random_hex(16)?,
            minute: minute.to_owned(),
            name,
            msg,
            amount_sats,
            address,
            addr_index,
            referred_by: None,
            reward_address: None,
            created_epoch: now,
            expires_epoch: now + expiry_secs,
            status: ClaimStatus::AwaitingPayment,
            txid: None,
            paid_epoch: None,
            decided_epoch: None,
        };
        self.claims.insert(claim.id.clone(), claim.clone());
        self.persist_claims()?;
        Ok(claim)
    }

    /// Attach referral data to a claim (addresses validated upstream).
    /// Each field only ever moves from None to Some or Some to Some.
    pub fn set_refs(
        &mut self,
        claim_id: &str,
        referred_by: Option<String>,
        reward_address: Option<String>,
    ) -> Result<()> {
        let c = self
            .claims
            .get_mut(claim_id)
            .with_context(|| format!("unknown claim {claim_id}"))?;
        if referred_by.is_none() && reward_address.is_none() {
            return Ok(());
        }
        if referred_by.is_some() {
            c.referred_by = referred_by;
        }
        if reward_address.is_some() {
            c.reward_address = reward_address;
        }
        self.persist_claims()
    }

    /// Prune terminal claims so the map/file cannot grow without bound:
    /// expired ones past their revive window, refused ones past their keep
    /// window. Paid/Engraved/Awaiting are always kept (real sales + the
    /// buyer's live status link). Returns how many were removed.
    pub fn prune_terminal(&mut self, now: u64) -> Result<usize> {
        let before = self.claims.len();
        self.claims.retain(|_, c| match c.status {
            ClaimStatus::Expired => now < c.expires_epoch + REVIVE_SECS,
            ClaimStatus::Refused => now < c.decided_epoch.unwrap_or(now) + REFUSED_KEEP_SECS,
            _ => true,
        });
        let removed = before - self.claims.len();
        if removed > 0 {
            self.persist_claims()?;
        }
        Ok(removed)
    }

    /// Mark overdue awaiting claims as expired. Returns how many changed.
    pub fn mark_expired(&mut self, now: u64) -> Result<usize> {
        let mut changed = 0;
        for c in self.claims.values_mut() {
            if c.status == ClaimStatus::AwaitingPayment && c.expires_epoch <= now {
                c.status = ClaimStatus::Expired;
                changed += 1;
            }
        }
        if changed > 0 {
            self.persist_claims()?;
        }
        Ok(changed)
    }

    /// Claims to check against the chain: (id, expected sats, dedicated address).
    pub fn pending_for_matching(&self, now: u64) -> Vec<(String, u64, Option<String>)> {
        self.claims
            .values()
            .filter(|c| c.matchable(now))
            .map(|c| (c.id.clone(), c.amount_sats, c.address.clone()))
            .collect()
    }

    pub fn mark_paid(&mut self, claim_id: &str, txid: &str, now: u64) -> Result<()> {
        let c = self
            .claims
            .get_mut(claim_id)
            .with_context(|| format!("unknown claim {claim_id}"))?;
        if c.status != ClaimStatus::AwaitingPayment && c.status != ClaimStatus::Expired {
            bail!("claim {claim_id} not awaiting payment");
        }
        c.status = ClaimStatus::Paid;
        c.txid = Some(txid.to_owned());
        c.paid_epoch = Some(now);
        self.persist_claims()
    }

    /// Paid claims ready for automatic engraving: the veto window (grace)
    /// has elapsed, or a FUTURE minute arrives within 30 minutes (a late
    /// payment must never miss its live moment). A minute already fully
    /// passed is gone forever: never engraved (refuse + refund).
    pub fn auto_engrave_due(&self, now: u64, grace_secs: u64) -> Vec<String> {
        self.claims
            .values()
            .filter(|c| c.status == ClaimStatus::Paid)
            // minute already engraved by another claim (revive race): leave it
            // for manual refuse+refund, never retry (no per-cycle error spam).
            .filter(|c| !self.registry.contains_key(&c.minute))
            .filter(|c| {
                let epoch = validate::minute_id_to_epoch(&c.minute).unwrap_or(i64::MIN);
                // a minute that has fully passed is gone: never engraved,
                // the claim stays visible for refuse + manual refund
                if epoch + 60 <= now as i64 {
                    return false;
                }
                let paid = c.paid_epoch.unwrap_or(now);
                let grace_over = now >= paid + grace_secs;
                let imminent = epoch > now as i64 && (epoch as u64) <= now + 1800;
                // Even an imminent minute keeps a minimum human-veto floor
                // after payment: a payment confirming too late to leave that
                // window is refused+refunded rather than engraved unreviewed.
                let veto_floor = grace_secs.min(1800);
                let veto_elapsed = now >= paid + veto_floor;
                (grace_over || imminent) && veto_elapsed
            })
            .map(|c| c.id.clone())
            .collect()
    }

    /// The one human action left: engrave early, or refuse during the grace window.
    pub fn engrave(&mut self, claim_id: &str, now: u64) -> Result<String> {
        let c = self
            .claims
            .get(claim_id)
            .with_context(|| format!("unknown claim {claim_id}"))?
            .clone();
        if c.status != ClaimStatus::Paid {
            bail!("claim {claim_id} is not paid");
        }
        if self.registry.contains_key(&c.minute) {
            bail!("minute {} already engraved", c.minute);
        }
        let epoch = validate::minute_id_to_epoch(&c.minute)
            .with_context(|| format!("claim {claim_id} has invalid minute"))?;
        if epoch + 60 <= now as i64 {
            bail!(
                "minute {} has already passed: it is gone, refuse and refund",
                c.minute
            );
        }
        let live = true; // only living minutes are ever engraved
                         // chain first: if this fails, nothing else moves (no divergence)
        self.append_chain(&c.minute, &c.name, &msg_commitment(&c.msg), live, now)?;
        self.registry.insert(
            c.minute.clone(),
            RegistryEntry {
                name: c.name.clone(),
                msg: c.msg.clone(),
                live,
            },
        );
        self.persist_registry()?;
        if let Some(cm) = self.claims.get_mut(claim_id) {
            cm.status = ClaimStatus::Engraved;
            cm.decided_epoch = Some(now);
        }
        self.persist_claims()?;
        Ok(c.minute)
    }

    /// Refuse a paid claim (Rule VI). Refund is manual, via the txid inputs.
    pub fn refuse(&mut self, claim_id: &str, now: u64) -> Result<()> {
        let c = self
            .claims
            .get_mut(claim_id)
            .with_context(|| format!("unknown claim {claim_id}"))?;
        if c.status != ClaimStatus::Paid {
            bail!("claim {claim_id} is not paid");
        }
        c.status = ClaimStatus::Refused;
        c.decided_epoch = Some(now);
        self.persist_claims()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_store() -> (PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!(
            "minute-store-test-{}",
            random_hex(8).expect("csprng in tests")
        ));
        let store = Store::load(&dir).expect("load empty store");
        (dir, store)
    }

    #[test]
    fn full_lifecycle() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64; // 2026-01-01
        let claim = store
            .new_claim(
                "2030-01-01T00:00Z",
                "Jean",
                "We were here.",
                21000,
                now,
                72 * 3600,
                0,
                None,
            )
            .expect("new claim");
        assert!(claim.amount_sats > 21000 && claim.amount_sats <= 21999);
        assert_eq!(claim.status, ClaimStatus::AwaitingPayment);

        // same minute is reserved
        assert!(store
            .new_claim(
                "2030-01-01T00:00Z",
                "",
                "Other words.",
                21000,
                now,
                72 * 3600,
                0,
                None
            )
            .is_err());
        // invalid minute rejected
        assert!(store
            .new_claim("2027-02-29T00:00Z", "", "x", 21000, now, 72 * 3600, 0, None)
            .is_err());

        // cannot engrave before payment
        assert!(store.engrave(&claim.id, now).is_err());

        store
            .mark_paid(&claim.id, "txid-test", now + 60)
            .expect("mark paid");
        let minute = store.engrave(&claim.id, now + 120).expect("engrave");
        assert_eq!(minute, "2030-01-01T00:00Z");
        let entry = store.registry.get(&minute).expect("registry entry");
        assert!(entry.live); // engraved before the minute arrived
        assert_eq!(entry.msg, "We were here.");

        // double engrave impossible
        assert!(store.engrave(&claim.id, now + 180).is_err());

        // persistence roundtrip
        let reloaded = Store::load(&dir).expect("reload");
        assert_eq!(reloaded.registry.len(), 1);
        assert_eq!(
            reloaded.claims.get(&claim.id).map(|c| c.status),
            Some(ClaimStatus::Engraved)
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn expiry_and_revive() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        let claim = store
            .new_claim(
                "2031-06-15T12:00Z",
                "",
                "Past due.",
                21000,
                now,
                3600,
                0,
                None,
            )
            .expect("new claim");
        assert_eq!(store.mark_expired(now + 3601).expect("expire"), 1);
        // expired frees the minute
        assert!(store
            .new_claim(
                "2031-06-15T12:00Z",
                "",
                "Second try.",
                21000,
                now + 3700,
                3600,
                0,
                None
            )
            .is_ok());
        // but the expired claim is still matchable inside the revive window
        let pending = store.pending_for_matching(now + 3700);
        assert!(pending.iter().any(|(id, _, _)| id == &claim.id));
        // and no longer after the window
        let pending = store.pending_for_matching(now + 3600 + REVIVE_SECS + 1);
        assert!(!pending.iter().any(|(id, _, _)| id == &claim.id));

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn chain_lifecycle_and_tamper() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        for minute in ["2035-01-01T00:00Z", "2035-01-01T00:01Z"] {
            let c = store
                .new_claim(minute, "A", "Chain test.", 21000, now, 3600, 0, None)
                .expect("claim");
            store.mark_paid(&c.id, "tx", now).expect("paid");
            store.engrave(&c.id, now).expect("engrave");
        }
        let path = dir.join("chain.jsonl");
        let (n, tip) = verify_chain_file(&path).expect("verify ok");
        assert_eq!(n, 2);
        assert_eq!(tip, store.chain_tip);
        assert_eq!(store.chain_len, 2);

        // reload rebuilds identical state
        let re = Store::load(&dir).expect("reload");
        assert_eq!(re.chain_len, 2);
        assert_eq!(re.chain_tip, tip);
        assert_eq!(re.registry.len(), 2);

        // commit-reveal: the public chain never contains the words themselves
        let raw = fs::read_to_string(&path).expect("read chain");
        assert!(!raw.contains("Chain test."));

        // losing registry.json is RECOVERABLE: the words live in the claims and
        // are verified against the chain commitments, so load heals instead of
        // refusing (a crash during engrave leaves exactly this state).
        let claims_backup = fs::read(dir.join("claims.json")).expect("backup claims");
        fs::remove_file(dir.join("registry.json")).expect("drop registry");
        let healed = Store::load(&dir).expect("heals registry from claims");
        assert_eq!(healed.registry.len(), 2);
        assert_eq!(
            healed
                .registry
                .get("2035-01-01T00:00Z")
                .map(|e| e.msg.as_str()),
            Some("Chain test.")
        );
        // but if the words are ALSO gone (no claims), it cannot heal -> refuse
        fs::remove_file(dir.join("registry.json")).ok(); // heal re-created it
        fs::write(dir.join("claims.json"), b"{}").expect("wipe claims");
        assert!(Store::load(&dir).is_err());
        fs::write(dir.join("claims.json"), &claims_backup).expect("restore claims");
        assert!(Store::load(&dir).is_ok());

        // tamper: alter one NON-last chain entry -> hash mismatch, start refused
        let raw = fs::read_to_string(&path).expect("re-read chain");
        let bad = raw.replacen("\"name\":\"A\"", "\"name\":\"B\"", 1);
        fs::write(&path, bad).expect("write tampered");
        assert!(verify_chain_file(&path).is_err());
        assert!(Store::load(&dir).is_err());

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn recovers_from_crash_during_engrave() {
        // Simulate a crash BETWEEN the chain append and the registry persist:
        // the chain is one ahead of the registry. load must heal from the claim.
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        let c = store
            .new_claim(
                "2036-02-02T02:02Z",
                "Heal",
                "Recover me.",
                21000,
                now,
                3600,
                0,
                None,
            )
            .expect("claim");
        store.mark_paid(&c.id, "tx", now).expect("paid");
        store.engrave(&c.id, now).expect("engrave");
        drop(store);
        // roll the registry back to empty (as if persist_registry never ran)
        fs::write(dir.join("registry.json"), b"{}").expect("roll back registry");
        // and the claim back to Paid (as if the final persist_claims never ran)
        let mut claims: HashMap<String, Claim> =
            serde_json::from_slice(&fs::read(dir.join("claims.json")).unwrap()).unwrap();
        claims.get_mut(&c.id).unwrap().status = ClaimStatus::Paid;
        fs::write(
            dir.join("claims.json"),
            serde_json::to_vec(&claims).unwrap(),
        )
        .unwrap();
        // load heals: registry rebuilt from the claim, claim marked engraved
        let re = Store::load(&dir).expect("heals");
        assert_eq!(re.registry.len(), 1);
        assert_eq!(
            re.registry.get("2036-02-02T02:02Z").map(|e| e.msg.as_str()),
            Some("Recover me.")
        );
        assert_eq!(
            re.claims.get(&c.id).map(|c| c.status),
            Some(ClaimStatus::Engraved)
        );
        // and the heal was persisted (a second load is clean, no re-heal)
        assert!(Store::load(&dir).is_ok());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn read_chain_tolerates_torn_final_line() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        for m in ["2037-03-03T03:03Z", "2037-03-03T03:04Z"] {
            let c = store
                .new_claim(m, "T", "Torn test.", 21000, now, 3600, 0, None)
                .expect("claim");
            store.mark_paid(&c.id, "tx", now).expect("paid");
            store.engrave(&c.id, now).expect("engrave");
        }
        let path = dir.join("chain.jsonl");
        let mut raw = fs::read_to_string(&path).expect("read");
        // append a torn (truncated, unparseable) final line, as a crash would
        raw.push_str("{\"seq\":3,\"prev\":\"ab\",\"minu");
        fs::write(&path, &raw).expect("write torn");
        // read_chain drops the torn final line and keeps the 2 valid entries
        let chain = read_chain(&path).expect("tolerates torn final line");
        assert_eq!(chain.len(), 2);
        // a torn line in the MIDDLE is real corruption -> bail
        let mut bad = fs::read_to_string(&path).unwrap();
        bad = bad.replacen('\n', "\nGARBAGE-NOT-JSON\n", 1);
        fs::write(&path, bad).expect("write mid corruption");
        assert!(read_chain(&path).is_err());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn lead_time_and_auto_engrave() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64; // 2026-01-01T00:00Z
                                    // une minute future a moins de 12 h est refusee
        assert!(store
            .new_claim(
                "2026-01-01T06:00Z",
                "",
                "Too soon.",
                21000,
                now,
                3600,
                12 * 3600,
                None
            )
            .is_err());
        // le passe ne s'achete pas, meme sans lead
        assert!(store
            .new_claim(
                "2001-01-01T00:00Z",
                "",
                "Memorial.",
                21000,
                now,
                3600,
                0,
                None
            )
            .is_err());
        // la minute courante non plus (elle est deja en train d'arriver)
        assert!(store
            .new_claim("2026-01-01T00:00Z", "", "Now.", 21000, now, 3600, 0, None)
            .is_err());
        // au-dela du lead: accepte
        let c = store
            .new_claim(
                "2026-01-02T00:00Z",
                "",
                "Fine.",
                21000,
                now,
                3600,
                12 * 3600,
                None,
            )
            .expect("claim ok");
        store.mark_paid(&c.id, "tx", now).expect("paid");
        // grace de 6 h pas ecoulee, minute pas imminente -> rien a graver
        assert!(store.auto_engrave_due(now + 3600, 6 * 3600).is_empty());
        // grace ecoulee -> du
        let due = store.auto_engrave_due(now + 6 * 3600 + 1, 6 * 3600);
        assert_eq!(due, vec![c.id.clone()]);
        // arrivee imminente (<30 min) -> du meme si la grace n'est pas ecoulee
        let due = store.auto_engrave_due(86400 + 1_767_225_600 - 900, 6 * 3600);
        assert_eq!(due, vec![c.id.clone()]);
        // minute entierement passee -> JAMAIS gravee automatiquement
        let after = 1_767_225_600 + 86400 + 61;
        assert!(store.auto_engrave_due(after, 6 * 3600).is_empty());
        // ni manuellement
        assert!(store.engrave(&c.id, after).is_err());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn revive_race_never_reengraves_or_spams() {
        // A reserves a minute, lets it expire; B takes the same minute and
        // engraves it; A pays late (revive window) and becomes Paid. The
        // already-engraved minute must NEVER be auto-engraved again, and never
        // returned by auto_engrave_due (no per-cycle error spam).
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        let a = store
            .new_claim(
                "2035-09-09T09:09Z",
                "A",
                "First.",
                21000,
                now,
                3600,
                0,
                None,
            )
            .expect("claim a");
        assert_eq!(store.mark_expired(now + 3601).expect("expire"), 1);
        let b = store
            .new_claim(
                "2035-09-09T09:09Z",
                "B",
                "Second.",
                21000,
                now + 3700,
                3600,
                0,
                None,
            )
            .expect("claim b");
        store.mark_paid(&b.id, "tx-b", now + 3700).expect("paid b");
        store.engrave(&b.id, now + 3700).expect("engrave b");
        // A pays late, inside the revive window
        store.mark_paid(&a.id, "tx-a", now + 3800).expect("paid a");
        assert_eq!(
            store.claims.get(&a.id).map(|c| c.status),
            Some(ClaimStatus::Paid)
        );
        // the engraved minute is NOT returned for auto-engraving
        let due = store.auto_engrave_due(now + 100000, 6 * 3600);
        assert!(!due.contains(&a.id));
        // and an explicit engrave of A bails (minute already taken)
        assert!(store.engrave(&a.id, now + 3900).is_err());
        // the registry still holds exactly B's words (no re-engrave)
        assert_eq!(
            store
                .registry
                .get("2035-09-09T09:09Z")
                .map(|e| e.msg.as_str()),
            Some("Second.")
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn registry_seals_future_words() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        let c = store
            .new_claim(
                "2035-05-05T05:05Z",
                "Seal",
                "Hidden words.",
                21000,
                now,
                3600,
                0,
                None,
            )
            .expect("claim");
        store.mark_paid(&c.id, "tx", now).expect("paid");
        store.engrave(&c.id, now).expect("engrave");

        // before the minute arrives: no words anywhere public
        let future_view = render_registry_json(&store.registry, now).expect("json");
        assert!(!future_view.contains("Hidden words."));
        assert!(future_view.contains("\"sealed\": true"));

        // once the minute has arrived: the words are public and match the seal
        let arrived = validate::minute_id_to_epoch("2035-05-05T05:05Z").expect("epoch") as u64;
        let arrived_view = render_registry_json(&store.registry, arrived).expect("json");
        assert!(arrived_view.contains("Hidden words."));
        assert_eq!(
            msg_commitment("Hidden words."),
            read_chain(&dir.join("chain.jsonl")).expect("chain")[0].msg_hash
        );

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn refs_attach_and_persist() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        let c = store
            .new_claim("2032-02-02T02:02Z", "", "Ref.", 21000, now, 3600, 0, None)
            .expect("claim");
        store
            .set_refs(&c.id, Some("bc1qAAA".to_owned()), None)
            .expect("set ref");
        store
            .set_refs(&c.id, None, Some("bc1qBBB".to_owned()))
            .expect("set reward");
        let re = Store::load(&dir).expect("reload");
        let rc = re.claims.get(&c.id).expect("claim back");
        assert_eq!(rc.referred_by.as_deref(), Some("bc1qAAA"));
        assert_eq!(rc.reward_address.as_deref(), Some("bc1qBBB"));
        assert!(store.set_refs("unknown", None, None).is_err());
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn unique_amounts() {
        let (dir, mut store) = tmp_store();
        let now = 1_767_225_600u64;
        let a = store
            .new_claim("2032-01-01T00:01Z", "", "One.", 21000, now, 3600, 0, None)
            .expect("claim a");
        let b = store
            .new_claim("2032-01-01T00:02Z", "", "Two.", 21000, now, 3600, 0, None)
            .expect("claim b");
        assert_ne!(a.amount_sats, b.amount_sats);

        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
