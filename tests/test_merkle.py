import os, math
from auditlog import merkle
from auditlog.log import AuditLog, verify_checkpoint

def leaves(n):
    return [f"entry-{i}".encode() for i in range(n)]

def test_inclusion_exhaustive_and_tamper():
    for n in range(1, 25):
        L = leaves(n)
        root = merkle.merkle_root(L)
        for m in range(n):
            proof = merkle.inclusion_proof(L, m)
            assert merkle.verify_inclusion(merkle.leaf_hash(L[m]), m, n, proof, root)
            # tamper the entry -> leaf hash changes -> verification fails
            bad = merkle.leaf_hash(L[m] + b"!")
            assert not merkle.verify_inclusion(bad, m, n, proof, root)

def test_proof_is_logarithmic():
    for n in [2, 16, 256, 1024]:
        L = leaves(n)
        assert len(merkle.inclusion_proof(L, n // 2)) <= math.ceil(math.log2(n)) + 1

def test_consistency_exhaustive_and_rewrite_fails():
    for n in range(2, 20):
        L = leaves(n)
        new_root = merkle.merkle_root(L)
        for m in range(1, n + 1):
            old_root = merkle.merkle_root(L[:m])
            proof = merkle.consistency_proof(L, m)
            assert merkle.verify_consistency(m, n, proof, old_root, new_root)
            # a rewritten history (different old root) must fail
            if m >= 1:
                forged = merkle.merkle_root(L[:m - 1] + [b"rewritten"]) if m >= 1 else old_root
                assert not merkle.verify_consistency(m, n, proof, forged, new_root)

def test_signed_checkpoints():
    log = AuditLog(bytes(range(32)))
    for i in range(10):
        log.append(f"event {i}".encode())
    cp = log.checkpoint()
    assert verify_checkpoint(cp, log.public_key)
    # forged root fails
    forged = type(cp)(cp.tree_size, bytes(32), cp.signature)
    assert not verify_checkpoint(forged, log.public_key)
    # wrong key fails
    other = AuditLog(bytes(range(1, 33)))
    assert not verify_checkpoint(cp, other.public_key)
