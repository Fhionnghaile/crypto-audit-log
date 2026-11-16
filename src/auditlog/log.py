"""Append-only audit log with Ed25519-signed Merkle checkpoints."""
from __future__ import annotations
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from . import merkle

@dataclass(frozen=True)
class Checkpoint:
    tree_size: int
    root: bytes
    signature: bytes   # Ed25519 over (tree_size || root)

    def signed_bytes(self) -> bytes:
        return self.tree_size.to_bytes(8, "big") + self.root

class AuditLog:
    def __init__(self, signing_seed: bytes):
        if len(signing_seed) != 32:
            raise ValueError("seed must be 32 bytes")
        self._sk = Ed25519PrivateKey.from_private_bytes(signing_seed)
        self.entries: list[bytes] = []

    @property
    def public_key(self) -> bytes:
        return self._sk.public_key().public_bytes_raw()

    def append(self, data: bytes) -> int:
        self.entries.append(data)
        return len(self.entries) - 1

    def root(self) -> bytes:
        return merkle.merkle_root(self.entries)

    def checkpoint(self) -> Checkpoint:
        size, root = len(self.entries), self.root()
        sig = self._sk.sign(size.to_bytes(8, "big") + root)
        return Checkpoint(size, root, sig)

    def inclusion_proof(self, m: int) -> list[bytes]:
        return merkle.inclusion_proof(self.entries, m)

    def consistency_proof(self, m: int) -> list[bytes]:
        return merkle.consistency_proof(self.entries, m)

def verify_checkpoint(cp: Checkpoint, public_key: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(cp.signature, cp.signed_bytes())
        return True
    except Exception:
        return False
