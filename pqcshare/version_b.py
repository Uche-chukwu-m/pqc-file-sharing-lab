"""Version B v1: the rough draft's ML-KEM-768 + HKDF + AES-256-GCM design (Act 2).

Kept as the teammate wrote it, unsigned, to show the gap that v2 closes: the
seal proves a package was not modified, but not who made it. Anyone holding the
recipient's public key can build a valid package. See signed_package.py.

Package: 4-byte length | KEM ciphertext | 12-byte nonce | ciphertext + 16-byte tag
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .suites import get_suite


def derive_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"pqc-cloud-file-sharing-lab-v1").derive(shared_secret)


def encrypt(data: bytes, recipient_public_key: bytes) -> bytes:
    kem_ct, shared_secret = get_suite("pq").encaps(recipient_public_key)
    nonce = os.urandom(12)
    encrypted = AESGCM(derive_key(shared_secret)).encrypt(nonce, data, None)
    return len(kem_ct).to_bytes(4, "big") + kem_ct + nonce + encrypted


def decrypt(package: bytes, recipient_secret_key: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag (or ValueError) if anything was changed."""
    n = int.from_bytes(package[:4], "big")
    kem_ct = package[4:4 + n]
    nonce = package[4 + n:16 + n]
    ciphertext = package[16 + n:]
    shared_secret = get_suite("pq").decaps(recipient_secret_key, kem_ct)
    return AESGCM(derive_key(shared_secret)).decrypt(nonce, ciphertext, None)


def encrypt_for_recipient(source, package_file, recipient_public_key: bytes) -> None:
    Path(package_file).write_bytes(encrypt(Path(source).read_bytes(), recipient_public_key))


def decrypt_for_recipient(package_file, output_file, recipient_secret_key: bytes) -> None:
    Path(output_file).write_bytes(decrypt(Path(package_file).read_bytes(), recipient_secret_key))
