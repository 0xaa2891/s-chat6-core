# Security policy

Please report vulnerabilities in s//chat6 **privately**. Do not open a public GitHub issue for a security bug.

## Contact

Email **[0xaa2891@proton.me](mailto:0xaa2891@proton.me)**.

We do not yet publish a project PGP key. Until one is listed here, send the report in plaintext email and we will arrange a better channel if the issue is sensitive.

## Scope

In scope:

- The s//chat6 messenger (Rust core, reference Android client, wire protocol, pairing, vault lock/unlock primitives, Tor transport integration).
- Cryptographic design and implementation in this repository.
- Build and release artifacts that we publish (APKs, signed tags) once they exist.

Out of scope:

- A dishonest or compromised peer retaining plaintext they already received.
- Screenshots or a second camera pointed at the screen.
- Physical bit-level flash recovery after cryptographic erasure.
- A global passive adversary with unlimited observation of the Tor network.
- Issues solely in third-party software we consume (Tor, libsignal, SQLCipher) that do not involve our integration — report those upstream as well, and copy us if our usage makes them exploitable.

## What to include

A report is most useful if it has:

- Affected version or commit (or “current `main`”).
- Impact (who can do what, under what assumptions).
- Steps to reproduce, or a proof-of-concept against a local/testnet instance — **not** against the live Tor network as a demo.
- Whether you have already disclosed it elsewhere.

## Response

We will acknowledge receipt as soon as we can and say whether we consider the report in scope. There is no bug bounty. Coordinated disclosure is preferred: we will work with you on a fix and a public advisory when a release exists.

## Supported versions

No general-availability release has shipped. Treat current development snapshots as **unsupported for production**; still report issues — this is the right time to find them.
