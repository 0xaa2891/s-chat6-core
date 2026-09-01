# s//chat6 core

**Private 1:1 messaging — no accounts, no servers, no phone numbers.**

End-to-end encrypted messaging for one-to-one conversations over Tor. Each
relationship gets its own cryptographic persona, its own v3 onion service,
and its own session state. Contacts are added via a one-time QR in person, or a
pairing code passed over another channel (e.g. DMs).
There is no signup, directory, cloud inbox, or push provider.

- **Crypto** — libsignal PQXDH + Double Ratchet + SPQR (post-quantum hybrid)
- **Transport** — Tor v3 onion services, one per contact
- **Store** — SQLCipher; chat rows are cryptographically erased after 24 h

## What this is

**This repository is the core, not an app.** `schat-core` is one Rust
library — protocol, transport, store, media — with a frozen UniFFI surface
so any client (Android, iOS, desktop) binds the same API. `schat-cli` is a
headless reference client that drives the entire library. There is no GUI
yet; the Android client is the next milestone.

Status: **alpha, not independently audited.** Try it, break it — don't rely
on it for high-stakes communication yet.

## What the core can do today

Pair in person via QR or remotely via a typed code, then over Tor:
text, edits and deletes with tombstones, read receipts, typing and
presence (RAM-only), chunked attachments with media hygiene (EXIF strip /
re-encode), sticker packs, profiles, per-relationship policy negotiation,
and catch-up resync after offline windows. The vault locks, unlocks, and
panic-wipes; a kill switch cuts all network traffic. Everything above is
reachable from `schat-cli` (`pair`, `send`, `edit`, `attach`, `sticker`,
`lock`, `panic-wipe`, …) and from the UniFFI surface.

## Documentation

API docs are generated from the source:

```bash
cargo doc --workspace --no-deps --open
```

UniFFI bindings (Kotlin, Python, …): `just ffi-kotlin` / `just ffi-python`.

## Build & test

```bash
cargo test --workspace          # full suite
cargo run -p schat-cli -- ping  # headless smoke check
```

## Pair via code

One-time exchange. Remotely, the inviter sends a code; the accepter types it in:

```bash
schat-cli pair --data-dir alice --offer   # prints code: …
schat-cli pair --data-dir bob --code <CODE>
schat-cli pair --data-dir alice --accept-request
```

In person, scan a QR instead: `--offer --out qr.png` and `--accept qr.png`.

## License

[AGPLv3](LICENSE) — required for libsignal compatibility.
