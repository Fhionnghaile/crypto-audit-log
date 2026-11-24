# Verifiable audit log (Merkle tree + Ed25519)

<!-- at-a-glance -->
> **An append-only log where any change to a past entry is cryptographically detectable in O(log n).**  
> **Result:** 4 exhaustive suites — inclusion for every leaf to n=24, consistency for every (m,n), forged-checkpoint rejection.  
> **Reproduce:** `pytest -q`  
> ![CI](https://github.com/fhionnghaile/crypto-audit-log/actions/workflows/ci.yml/badge.svg) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Fhionnghaile/crypto-audit-log/badge)](https://scorecard.dev/viewer/?uri=github.com/Fhionnghaile/crypto-audit-log)
>
> **What this is worth:** Lets you *prove* to a regulator, auditor or court that your records were never altered — not just assert it.


A tamper-evident, append-only log where any entry is provable against a **signed root** - and any
rewrite of history is detectable. **RFC 6962** (Certificate Transparency) Merkle construction;
primitives from `hashlib`/`cryptography` (you compose, you don't roll your own).

## Guarantees
- **Inclusion proof** (O(log n)): entry *e* is under checkpoint root *R*.
- **Consistency proof**: checkpoint N+1 is an append-only extension of N - no entry was changed or removed.
- **Signed checkpoints**: the root is signed (Ed25519); a forged root fails.

## Test it
```bash
pip install -e ".[dev]" && PYTHONPATH=src pytest -q
python -m auditlog.cli    # demo: append, checkpoint, prove, tamper->fail
```
The suite is **exhaustive** - it verifies inclusion for *every* entry of every tree up to size 24,
consistency for *every* (m, n) pair, proof length is logarithmic, and every tamper/forgery is rejected.

## What it does *not* do
Timestamping authority, gossip/witnessing (to stop split-view), or at-rest encryption - a Merkle log
proves *integrity and append-only-ness*, not confidentiality. Stated plainly because that honesty is
the point.

## License
MIT.

## Key decisions

- A Merkle tree (RFC 6962), not a hash-chain — logarithmic inclusion and consistency proofs that catch silent edits.
- Domain-separated hashing to resist second-preimage attacks.
- Ed25519-signed checkpoints a third party trusts without replaying the log.

## Scope & limits

- Integrity, not confidentiality — it proves a record is unaltered, not that it is secret.
- Checkpoint custody and publication is the operator's trust root.

