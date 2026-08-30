# s//chat6

**Private 1:1 messaging — no accounts, no servers, no phone numbers.**

End-to-end encrypted messenger for one-to-one conversations over Tor. Each
relationship gets its own cryptographic persona, its own v3 onion service,
and its own session state. Contacts are added in person (QR / pairing code).
There is no signup, directory, cloud inbox, or push provider.

- **Crypto** — libsignal PQXDH + Double Ratchet + SPQR (post-quantum hybrid)
- **Transport** — Tor v3 onion services, one per contact
- **Store** — SQLCipher; chat rows are cryptographically erased after 24 h
- **Core** — one Rust library (`schat-core`) with a frozen UniFFI surface;
  any client (Android, iOS, desktop, CLI) binds the same API

## Build & test

```bash
cargo test --workspace          # full suite
cargo run -p schat-cli -- ping  # headless smoke check
```

## Pair via code

One-time, in person. The inviter shows a code; the accepter types it:

```bash
schat-cli pair --data-dir alice --offer   # prints code: …
schat-cli pair --data-dir bob --code <CODE>
schat-cli pair --data-dir alice --accept-request
```

Same ceremony, camera instead of keyboard: `--offer --out qr.png` and
`--accept qr.png`.

API docs: `cargo doc --workspace --no-deps --open`
UniFFI bindings (Kotlin, Python, …): `just ffi-kotlin` / `just ffi-python`

## License

[AGPLv3](LICENSE) — required for libsignal compatibility.
