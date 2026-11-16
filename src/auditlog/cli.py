"""Tiny demo CLI: append, checkpoint, prove, tamper->fail."""
from __future__ import annotations
import sys
from .log import AuditLog, verify_checkpoint
from . import merkle

def demo() -> int:
    log = AuditLog(bytes(range(32)))
    for msg in ["login alice", "grant admin", "delete record 42", "export data"]:
        log.append(msg.encode())
    cp = log.checkpoint()
    print(f"appended {cp.tree_size} entries; root={cp.root.hex()[:16]}...")
    print("checkpoint signature verifies:", verify_checkpoint(cp, log.public_key))
    proof = log.inclusion_proof(2)
    ok = merkle.verify_inclusion(merkle.leaf_hash(log.entries[2]), 2, cp.tree_size, proof, cp.root)
    print(f"inclusion proof for entry 2 ({len(proof)} hashes) verifies:", ok)
    tampered = merkle.verify_inclusion(merkle.leaf_hash(b"delete record 7"), 2, cp.tree_size, proof, cp.root)
    print("tampered entry verifies (should be False):", tampered)
    return 0

if __name__ == "__main__":
    sys.exit(demo())
