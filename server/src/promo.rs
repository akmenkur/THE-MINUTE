//! Promo codes: one code grants ONE free engraving (a comped claim) with no
//! Bitcoin paid. Codes are unguessable (60 bits of CSPRNG entropy), single-use,
//! validated on the SERVER only, and burned on redemption. Append-only ledger
//! (promo.jsonl): an Issue event per generated code, a Redeem event when one is
//! spent - so the live set and who spent each code is fully reconstructable and
//! crash-safe (a torn final line is dropped, like the other ledgers).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Crockford base32 without I, L, O, U: no character a human can confuse.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Event {
    Issue {
        ts: u64,
        code: String,
    },
    Redeem {
        ts: u64,
        code: String,
        claim_id: String,
    },
}

pub struct Promo {
    path: PathBuf,
    /// canonical code -> Some((claim_id, ts)) once spent, None while live.
    codes: HashMap<String, Option<(String, u64)>>,
}

impl Promo {
    pub fn load(dir: &Path) -> Result<Promo> {
        fs::create_dir_all(dir)
            .with_context(|| format!("cannot create data dir {}", dir.display()))?;
        let mut p = Promo {
            path: dir.join("promo.jsonl"),
            codes: HashMap::new(),
        };
        if p.path.exists() {
            let raw = fs::read_to_string(&p.path)
                .with_context(|| format!("read {}", p.path.display()))?;
            let lines: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
            for (i, line) in lines.iter().enumerate() {
                let is_last = i + 1 == lines.len();
                match serde_json::from_str::<Event>(line) {
                    Ok(ev) => p.apply(ev),
                    // A torn/truncated FINAL line is a crash mid-append: that
                    // event never committed. Drop it, keep the rest. An earlier
                    // bad line is real corruption -> refuse to start.
                    Err(err) if is_last => {
                        eprintln!("[promo] dropping incomplete final line (torn append): {err}");
                        break;
                    }
                    Err(err) => bail!("promo line {} unreadable: {err}", i + 1),
                }
            }
        }
        Ok(p)
    }

    fn apply(&mut self, ev: Event) {
        match ev {
            Event::Issue { code, .. } => {
                self.codes.entry(code).or_insert(None);
            }
            Event::Redeem { ts, code, claim_id } => {
                if let Some(slot) = self.codes.get_mut(&code) {
                    if slot.is_none() {
                        *slot = Some((claim_id, ts));
                    }
                }
            }
        }
    }

    fn append(&self, ev: &Event) -> Result<()> {
        let mut line = serde_json::to_string(ev).context("serialize promo event")?;
        line.push('\n');
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("open {}", self.path.display()))?;
        f.write_all(line.as_bytes())
            .with_context(|| format!("append {}", self.path.display()))?;
        f.sync_all().ok();
        Ok(())
    }

    /// Generate `n` fresh, unique, unguessable codes; persist and return them
    /// (canonical 12-char form - use `display` for the readable grouped form).
    pub fn generate(&mut self, n: usize, ts: u64) -> Result<Vec<String>> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            let code = loop {
                let c = fresh_code()?;
                if !self.codes.contains_key(&c) {
                    break c;
                }
            };
            let ev = Event::Issue {
                ts,
                code: code.clone(),
            };
            self.append(&ev)?;
            self.apply(ev);
            out.push(code);
        }
        Ok(out)
    }

    /// Burn a code for a claim. Fails (spending nothing) if the code is unknown
    /// or already used. The burn is persisted before Ok returns, so a crash can
    /// never resurrect a spent code.
    pub fn redeem(&mut self, input: &str, claim_id: &str, ts: u64) -> Result<()> {
        let code = normalize(input);
        match self.codes.get(&code) {
            None => bail!("this code is not valid"),
            Some(Some(_)) => bail!("this code has already been used"),
            Some(None) => {}
        }
        let ev = Event::Redeem {
            ts,
            code,
            claim_id: claim_id.to_owned(),
        };
        self.append(&ev)?;
        self.apply(ev);
        Ok(())
    }

    pub fn total(&self) -> usize {
        self.codes.len()
    }

    pub fn used(&self) -> usize {
        self.codes.values().filter(|v| v.is_some()).count()
    }

    /// (readable code, spent?) sorted, for the admin CLI listing.
    pub fn listing(&self) -> Vec<(String, bool)> {
        let mut v: Vec<(String, bool)> = self
            .codes
            .iter()
            .map(|(k, v)| (display(k), v.is_some()))
            .collect();
        v.sort();
        v
    }
}

/// A fresh 12-char code (canonical, no separators). 12 x 5 bits = 60 bits of
/// entropy: single-use + rate-limiting makes guessing hopeless. Each byte maps
/// with `% 32`; 256 is a multiple of 32, so there is NO modulo bias.
fn fresh_code() -> Result<String> {
    let mut raw = [0u8; 12];
    getrandom::getrandom(&mut raw).context("csprng unavailable")?;
    Ok(raw
        .iter()
        .map(|b| ALPHABET[(*b as usize) % 32] as char)
        .collect())
}

/// Normalize typed input to the canonical form: uppercase, drop separators and
/// spaces, and fold the Crockford look-alikes (I/L -> 1, O -> 0).
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            u => u,
        })
        .collect()
}

/// Group the canonical code for humans: XXXX-XXXX-XXXX.
pub fn display(code: &str) -> String {
    if code.len() == 12 {
        format!("{}-{}-{}", &code[0..4], &code[4..8], &code[8..12])
    } else {
        code.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "minute-promo-test-{}",
            fresh_code().expect("csprng in tests")
        ))
    }

    #[test]
    fn generates_unique_codes_of_the_right_shape() {
        let dir = tmp_dir();
        let mut p = Promo::load(&dir).expect("load");
        let codes = p.generate(100, 1_800_000_000).expect("gen");
        assert_eq!(codes.len(), 100);
        // all distinct
        let set: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(set.len(), 100);
        // canonical shape: 12 chars, all in the alphabet
        for c in &codes {
            assert_eq!(c.len(), 12);
            assert!(c.bytes().all(|b| ALPHABET.contains(&b)));
        }
        assert_eq!(p.total(), 100);
        assert_eq!(p.used(), 0);
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn redeem_is_single_use_and_validated() {
        let dir = tmp_dir();
        let mut p = Promo::load(&dir).expect("load");
        let code = p.generate(1, 1_800_000_000).expect("gen").pop().unwrap();
        // unknown code fails, spends nothing
        assert!(p.redeem("NOTACODE0000", "c1", 1).is_err());
        assert_eq!(p.used(), 0);
        // valid: first redemption succeeds
        assert!(p.redeem(&code, "claim-a", 2).is_ok());
        assert_eq!(p.used(), 1);
        // second redemption of the same code fails (single-use)
        assert!(p.redeem(&code, "claim-b", 3).is_err());
        assert_eq!(p.used(), 1);
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn accepts_dashed_lowercase_and_lookalikes() {
        let dir = tmp_dir();
        let mut p = Promo::load(&dir).expect("load");
        let code = p.generate(1, 1).expect("gen").pop().unwrap();
        // display form (with dashes), lowercased, still redeems
        let typed = display(&code).to_lowercase();
        assert!(p.redeem(&typed, "claim", 1).is_ok());
        // look-alikes fold both cases: O -> 0, I/L -> 1; separators drop
        assert_eq!(normalize("O-o-I-i-L-l"), "001111");
        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn survives_reload_from_disk() {
        let dir = tmp_dir();
        let code = {
            let mut p = Promo::load(&dir).expect("load");
            let c = p.generate(3, 5).expect("gen").pop().unwrap();
            p.redeem(&c, "claim-x", 6).expect("redeem");
            c
        };
        // a fresh load replays the ledger: same counts, same spent code
        let p2 = Promo::load(&dir).expect("reload");
        assert_eq!(p2.total(), 3);
        assert_eq!(p2.used(), 1);
        let mut p2 = p2;
        assert!(p2.redeem(&code, "again", 7).is_err()); // still burned
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
