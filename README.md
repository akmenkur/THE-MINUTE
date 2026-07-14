# THE MINUTE

**Own one minute of the future. Write it. Keep it forever.**
Live at **[minuteofforever.com](https://minuteofforever.com)**.

Every minute still to come, until the year 2126, can belong to exactly one
person. Only one, forever. You write up to 108 characters into your minute.
When it arrives, your words take over the whole page, live, for sixty seconds,
once, for everyone watching. Then they rest, permanently, in a public ledger
that is cryptographically chained and anchored into the Bitcoin blockchain.

Not a promise. **Proof.**

---

## How it works

1. **Claim a minute.** Pick any future UTC minute, write your words and a name.
   The server reserves it and gives you a unique Bitcoin amount to send.
2. **Pay in Bitcoin.** The first confirmed payment wins the minute. No coin, no
   token, no smart contract. Just a payment and an append-only ledger.
3. **It gets engraved.** Your entry is sealed into a hash chain: every engraving
   `blake3`-seals the one before it, so no entry can be altered or re-ordered
   without breaking every seal after it.
4. **It goes live.** When the minute arrives, the words hold the page for sixty
   seconds. Future minutes stay **sealed** (only a hash is public) until then.
5. **It's proven.** The chain is public and periodically anchored into Bitcoin,
   so its existence at a point in time is provable independently of this site.

Each ledger card shows **when** the words were sealed, so a future message is
provably written *before* its minute arrives.

## The proof model

- **`/chain.jsonl`**: the full, public, append-only ledger. Anyone can download
  it and re-verify every `blake3` seal without trusting the website.
- **Bitcoin anchoring**: the chain tip is timestamped on Bitcoin
  ([OpenTimestamps](https://opentimestamps.org/)); the proof is published.
- **Self-sealing site**: the page carries a `sha256` of its own source, itself
  timestamped on Bitcoin, and re-checks it in your browser (green means
  authentic, red means modified). See the footer.

## Affiliates (the chain of hands)

Any Bitcoin address is a referral link (`?r=<address>`). No signup, no purchase
required to participate. A confirmed sale pays:

- **25%** to the direct referrer, plus
- a **10% network pool** across that referrer's nearest upline sponsors, up to
  four levels deep (10 / 6-4 / 5-3-2 / 4-3-2-1), at most **35%** of the sale.

Commissions accrue only from **real, completed sales** (never from recruitment),
so total outflow is bounded by real revenue. Payouts are made in Bitcoin and
each is published with its transaction id on the public Affiliate Ledger.

## Architecture

- **`index.html`**: one static, self-contained page (100% ASCII). All dynamic
  text is injected via `textContent`; the live clock is a canvas dial.
- **`server/`**: a small Rust server (`tiny_http`), dependency-light. It reads
  the page from disk, watches mempool/Esplora for payments, engraves paid
  claims into the chain, and serves `chain.jsonl`, `registry.json`,
  `affiliates.json`, `robots.txt`, `sitemap.xml`, and a private `/admin`.

## Run your own instance

```bash
cd server
cp config.example.json config.json     # then fill in YOUR values
#   xpub         : your watch-only extended public key (unique address per claim)
#   btc_address  : OR a single receiving address
#   admin_token  : a long random secret for /admin
cargo build --release
./target/release/minute-server config.json
```

Full production notes (systemd, Caddy/HTTPS, promo codes, Bitcoin anchoring
cron) are in [`server/deploy/DEPLOY.md`](server/deploy/DEPLOY.md).

**Never commit `config.json`.** It holds your secrets. `.gitignore` already
excludes it; publish only `config.example.json`.

## License

**Source-available**, not open source. You may read, learn from, and adapt the
code for a genuinely different product, but **not** to run a competing
"own a unit of time" service. See [`LICENSE`](LICENSE). (Not legal advice.)
