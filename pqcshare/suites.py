"""Crypto suites: the same package code runs with post-quantum or classical keys.

Keeping everything else identical makes the Week 4 benchmark a fair comparison:
only the key exchange and the signature algorithm change.

  pq        = ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204)
  classical = X25519 + Ed25519 (today's common choice)

X25519 is wrapped to look like a KEM: "encapsulate" makes a fresh ephemeral key
pair, and its public key is the ciphertext.
"""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from ._oqs import oqs

_RAW = (serialization.Encoding.Raw, serialization.PublicFormat.Raw)
_RAW_PRIV = (serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def _check_len(name: str, value: bytes, expected: int) -> None:
    # liboqs-python silently zero-pads short inputs, so check lengths ourselves.
    if len(value) != expected:
        raise ValueError(f"{name} must be {expected} bytes, got {len(value)}")


class PostQuantumSuite:
    name = "pq"
    kem_alg = "ML-KEM-768"
    sig_alg = "ML-DSA-65"

    def __init__(self):
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            self.kem_pk_len = kem.details["length_public_key"]
            self.kem_ct_len = kem.details["length_ciphertext"]
        with oqs.Signature(self.sig_alg) as sig:
            self.sig_pk_len = sig.details["length_public_key"]

    def kem_keygen(self) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            pk = kem.generate_keypair()
            return pk, kem.export_secret_key()

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        _check_len("KEM public key", pk, self.kem_pk_len)
        with oqs.KeyEncapsulation(self.kem_alg) as kem:
            return kem.encap_secret(pk)

    def decaps(self, sk: bytes, kem_ct: bytes) -> bytes:
        _check_len("KEM ciphertext", kem_ct, self.kem_ct_len)
        with oqs.KeyEncapsulation(self.kem_alg, secret_key=sk) as kem:
            return kem.decap_secret(kem_ct)

    def sig_keygen(self) -> tuple[bytes, bytes]:
        with oqs.Signature(self.sig_alg) as sig:
            pk = sig.generate_keypair()
            return pk, sig.export_secret_key()

    def sign(self, sk: bytes, message: bytes) -> bytes:
        with oqs.Signature(self.sig_alg, secret_key=sk) as sig:
            return sig.sign(message)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        if len(pk) != self.sig_pk_len:
            return False
        with oqs.Signature(self.sig_alg) as sig:
            return sig.verify(message, signature, pk)


class ClassicalSuite:
    name = "classical"
    kem_alg = "X25519"
    sig_alg = "Ed25519"

    def kem_keygen(self) -> tuple[bytes, bytes]:
        sk = X25519PrivateKey.generate()
        return sk.public_key().public_bytes(*_RAW), sk.private_bytes(*_RAW_PRIV)

    def encaps(self, pk: bytes) -> tuple[bytes, bytes]:
        _check_len("KEM public key", pk, 32)
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(pk))
        return ephemeral.public_key().public_bytes(*_RAW), shared

    def decaps(self, sk: bytes, kem_ct: bytes) -> bytes:
        _check_len("KEM ciphertext", kem_ct, 32)
        return X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(kem_ct))

    def sig_keygen(self) -> tuple[bytes, bytes]:
        sk = Ed25519PrivateKey.generate()
        return sk.public_key().public_bytes(*_RAW), sk.private_bytes(*_RAW_PRIV)

    def sign(self, sk: bytes, message: bytes) -> bytes:
        return Ed25519PrivateKey.from_private_bytes(sk).sign(message)

    def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(pk).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False


_SUITES = {}


def get_suite(name: str):
    if name not in ("pq", "classical"):
        raise ValueError(f"unknown suite {name!r}")
    if name not in _SUITES:
        _SUITES[name] = PostQuantumSuite() if name == "pq" else ClassicalSuite()
    return _SUITES[name]
