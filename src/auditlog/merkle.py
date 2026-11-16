"""RFC 6962 (Certificate Transparency) Merkle tree: inclusion + consistency proofs.

Primitives (SHA-256) come from hashlib; only the tree/proofs are composed here -
the whole point of the showcase is *composing* vetted primitives, not rolling your own.
"""
from __future__ import annotations
import hashlib

def _sha(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def leaf_hash(data: bytes) -> bytes:
    return _sha(b"\x00" + data)

def node_hash(left: bytes, right: bytes) -> bytes:
    return _sha(b"\x01" + left + right)

def _k(n: int) -> int:
    """Largest power of two strictly less than n."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k

def merkle_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return _sha(b"")
    if n == 1:
        return leaf_hash(leaves[0])
    k = _k(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))

def inclusion_proof(leaves: list[bytes], m: int) -> list[bytes]:
    n = len(leaves)
    if not 0 <= m < n:
        raise IndexError("m out of range")
    if n == 1:
        return []
    k = _k(n)
    if m < k:
        return inclusion_proof(leaves[:k], m) + [merkle_root(leaves[k:])]
    return inclusion_proof(leaves[k:], m - k) + [merkle_root(leaves[:k])]

def verify_inclusion(leaf: bytes, m: int, n: int, proof: list[bytes], root: bytes) -> bool:
    if not 0 <= m < n:
        return False
    fn, sn = m, n - 1
    r = leaf
    for sibling in proof:
        if (fn & 1) or fn == sn:
            r = node_hash(sibling, r)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, sibling)
        fn >>= 1
        sn >>= 1
    return fn == 0 and r == root

def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_root(leaves)]
    k = _k(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_root(leaves[:k])]

def consistency_proof(leaves: list[bytes], m: int) -> list[bytes]:
    n = len(leaves)
    if not 0 < m <= n:
        raise ValueError("require 0 < m <= n")
    if m == n:
        return []
    return _subproof(m, leaves, True)

def _is_pow2(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0

def verify_consistency(m: int, n: int, proof: list[bytes], old_root: bytes, new_root: bytes) -> bool:
    if m == 0:
        return True
    if m > n:
        return False
    if m == n:
        return proof == [] and old_root == new_root
    p = list(proof)
    if _is_pow2(m):
        p = [old_root] + p
    if not p:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while fn != 0 and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fn == 0 and fr == old_root and sr == new_root
