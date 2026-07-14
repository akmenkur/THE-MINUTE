//! Watch-only BIP84 address derivation from the merchant's xpub.
//! An xpub can SEE addresses, never spend: no spending key ever touches
//! the server. Each claim receives its own fresh address (path /0/i).

use anyhow::{bail, Context, Result};
use bitcoin::base58;
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, CompressedPublicKey, Network};

/// Accept a standard `xpub...` or a SLIP-132 `zpub...` (same key material,
/// different version bytes - Sparrow offers both).
pub fn parse_xpub(s: &str) -> Result<Xpub> {
    let s = s.trim();
    if s.starts_with("xpub") {
        return s.parse::<Xpub>().context("invalid xpub");
    }
    if s.starts_with("zpub") {
        let mut raw = base58::decode_check(s).context("invalid zpub encoding")?;
        if raw.len() != 78 {
            bail!("invalid zpub length");
        }
        raw[0..4].copy_from_slice(&[0x04, 0x88, 0xB2, 0x1E]); // xpub version bytes
        return base58::encode_check(&raw)
            .parse::<Xpub>()
            .context("invalid zpub payload");
    }
    bail!("unsupported extended key (expected xpub... or zpub...)");
}

/// External receive address `index` of the account: path /0/index, P2WPKH.
pub fn derive_address(xpub: &Xpub, index: u32) -> Result<String> {
    let secp = Secp256k1::verification_only();
    let child = xpub
        .derive_pub(
            &secp,
            &[
                ChildNumber::from_normal_idx(0).expect("0 is a valid child index"),
                ChildNumber::from_normal_idx(index).context("index out of range")?,
            ],
        )
        .context("derivation failed")?;
    let pk = CompressedPublicKey(child.public_key);
    Ok(Address::p2wpkh(&pk, Network::Bitcoin).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Official BIP84 test vectors (mnemonic "abandon ... about").
    const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn bip84_vectors() {
        let xpub = parse_xpub(BIP84_ZPUB).expect("parse zpub");
        assert_eq!(
            derive_address(&xpub, 0).expect("derive 0"),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        assert_eq!(
            derive_address(&xpub, 1).expect("derive 1"),
            "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_xpub("xpubGARBAGE").is_err());
        assert!(parse_xpub("zpubGARBAGE").is_err());
        assert!(parse_xpub("ypub000").is_err());
        assert!(parse_xpub("").is_err());
    }
}
