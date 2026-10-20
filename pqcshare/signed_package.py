"""Version B v2: ML-KEM + AES-256-GCM + ML-DSA signed packages (Acts 2 and 3).

Package layout (every field length-prefixed):

    "PQS2" | header | kem_ct | nonce | ciphertext+tag | signature

  header     plaintext JSON the cloud needs for routing only:
             {v, suite, sender, recipient, file_id, ts}
  ciphertext AES-GCM over {filename, category} + file bytes (+ optional padding),
             with the header as associated data (AAD)
  signature  sender's signature over header, kem_ct, nonce and ciphertext

Filename and category live inside the encryption: the cloud must not see them.

The recipient checks cheap, public things first and decrypts last:
  parse -> recipient ID -> sender certificate -> signature -> replay -> decrypt.
Every failure raises PackageRejected with the same message; `.reason` exists for
tests and the demo log only.
"""

import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .encoding import Reader, canonical_json, lp
from .pki import CertificateError, Identity, verify_certificate
from .suites import get_suite

MAGIC = b"PQS2"
SIGN_DOMAIN = b"pqcshare-package-v2|"
KDF_DOMAIN = b"pqcshare-file-key-v2|"
HEADER_KEYS = {"v", "suite", "sender", "recipient", "file_id", "ts"}


class PackageRejected(Exception):
    def __init__(self, reason: str):
        super().__init__("package rejected")
        self.reason = reason


@dataclass
class OpenedFile:
    sender: str
    filename: str
    category: str
    data: bytes
    file_id: str
    timestamp: int


def _derive_key(shared_secret: bytes, header_bytes: bytes, kem_ct: bytes) -> bytes:
    # Binding the header and KEM ciphertext into the key ties this key to this package only.
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=KDF_DOMAIN + lp(header_bytes) + lp(kem_ct)).derive(shared_secret)


def _to_be_signed(header_bytes: bytes, kem_ct: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return SIGN_DOMAIN + lp(header_bytes) + lp(kem_ct) + lp(nonce) + lp(ciphertext)


def padded_length(n: int, policy: int | str | None) -> int:
    """Length that n bytes are padded to under a padding policy (Act 4 size experiment).

      None     no padding
      int N    round up to a multiple of N bytes ("buckets")
      "pow2"   round up to a power of two (at most 2x the size)
      "padme"  Padmé (Nikitin et al., PoPETs 2019): keeps only the top bits of the
               length; at most about 12% overhead, while leaking far less than the exact size
    """
    if policy is None or n <= 1:
        return n
    if policy == "pow2":
        return 1 << (n - 1).bit_length()
    if policy == "padme":
        exponent = n.bit_length() - 1              # floor(log2 n)
        kept = exponent.bit_length()               # floor(log2 exponent) + 1
        mask = (1 << (exponent - kept)) - 1
        return (n + mask) & ~mask
    if isinstance(policy, int) and policy > 0:
        return n + (-n % policy)
    raise ValueError(f"unknown padding policy {policy!r}")


class _Steps:
    """Records how long each step took (µs) into `out`, when the caller asks for it."""

    def __init__(self, out: dict | None):
        self.out = out
        self.last = time.perf_counter()

    def done(self, step: str) -> None:
        if self.out is not None:
            now = time.perf_counter()
            self.out[step] = (now - self.last) * 1e6
            self.last = now


def parse_package(package: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Split a package into (header, kem_ct, nonce, ciphertext, signature). Raises ValueError."""
    r = Reader(package)
    if r.take(4) != MAGIC:
        raise ValueError("not a v2 package")
    fields = tuple(r.field() for _ in range(5))
    r.done()
    return fields


def read_header(package: bytes) -> dict:
    """What the cloud can see: the routing header, without verifying anything."""
    return json.loads(parse_package(package)[0])


def seal(data: bytes, *, sender: Identity, recipient_cert: dict, ta_pk: bytes,
         filename: str, category: str, pad_to: int | str | None = None, now: float | None = None,
         timings: dict | None = None) -> bytes:
    """Encrypt and sign `data` for the user named in `recipient_cert`.

    `pad_to` is a padding policy (see padded_length) applied before encryption.
    Pass a dict as `timings` to get each step's duration in microseconds.
    """
    steps = _Steps(timings)
    suite = get_suite(sender.suite)
    # Refuse a certificate the TA did not sign: this blocks key substitution by the cloud.
    recipient = verify_certificate(recipient_cert, ta_pk, sender.suite, now=now)
    steps.done("check recipient certificate")

    header_bytes = canonical_json({
        "v": 2,
        "suite": sender.suite,
        "sender": sender.user_id,
        "recipient": recipient["user_id"],
        "file_id": secrets.token_hex(16),
        "ts": int(time.time() if now is None else now),
    })
    kem_ct, shared_secret = suite.encaps(bytes.fromhex(recipient["kem_pk"]))
    key = _derive_key(shared_secret, header_bytes, kem_ct)
    steps.done("encapsulate + derive key")

    inner = lp(canonical_json({"filename": filename, "category": category})) + lp(data)
    inner += bytes(padded_length(len(inner), pad_to) - len(inner))
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, inner, header_bytes)
    steps.done("AES-GCM encrypt")
    signature = suite.sign(sender.sig_sk, _to_be_signed(header_bytes, kem_ct, nonce, ciphertext))
    steps.done("sign")
    return MAGIC + lp(header_bytes) + lp(kem_ct) + lp(nonce) + lp(ciphertext) + lp(signature)


def open_package(package: bytes, *, recipient: Identity, ta_pk: bytes,
                 fetch_cert: Callable[[str], dict], seen_ids: set[str],
                 now: float | None = None, timings: dict | None = None) -> OpenedFile:
    """Verify and decrypt a package addressed to `recipient`.

    `fetch_cert` looks up a sender's certificate (usually from the untrusted cloud).
    `seen_ids` holds file IDs already accepted; the new ID is added on success.
    Pass a dict as `timings` to get each completed step's duration in microseconds.
    """
    steps = _Steps(timings)
    suite = get_suite(recipient.suite)

    try:
        header_bytes, kem_ct, nonce, ciphertext, signature = parse_package(package)
        header = json.loads(header_bytes)
        if not isinstance(header, dict) or set(header) != HEADER_KEYS or canonical_json(header) != header_bytes:
            raise ValueError("bad header")
        if header["v"] != 2 or not isinstance(header["ts"], int) or len(nonce) != 12:
            raise ValueError("bad version, timestamp or nonce")
        if not all(isinstance(header[k], str) for k in ("suite", "sender", "recipient", "file_id")):
            raise ValueError("bad header field types")
    except (ValueError, TypeError) as exc:
        raise PackageRejected(f"malformed package: {exc}") from None

    if header["suite"] != recipient.suite:
        raise PackageRejected("wrong suite")
    if header["recipient"] != recipient.user_id:
        raise PackageRejected("addressed to someone else")
    steps.done("parse + check recipient")

    try:
        sender_cert = verify_certificate(fetch_cert(header["sender"]), ta_pk, recipient.suite,
                                         expected_user=header["sender"], now=now)
    except (CertificateError, KeyError, OSError, ValueError) as exc:
        raise PackageRejected(f"sender certificate invalid: {exc}") from None
    steps.done("check sender certificate")

    if not suite.verify(bytes.fromhex(sender_cert["sig_pk"]),
                        _to_be_signed(header_bytes, kem_ct, nonce, ciphertext), signature):
        raise PackageRejected("bad signature")
    steps.done("verify signature")

    if header["file_id"] in seen_ids:
        raise PackageRejected("replay: file already received")
    steps.done("replay check")

    try:
        shared_secret = suite.decaps(recipient.kem_sk, kem_ct)
        key = _derive_key(shared_secret, header_bytes, kem_ct)
        steps.done("decapsulate + derive key")
        inner = AESGCM(key).decrypt(nonce, ciphertext, header_bytes)
        steps.done("AES-GCM decrypt")
        r = Reader(inner)
        meta = json.loads(r.field())
        data = r.field()  # anything after this is padding
    except Exception:  # noqa: BLE001 - any failure here is a rejection
        raise PackageRejected("decryption failed") from None

    seen_ids.add(header["file_id"])
    return OpenedFile(header["sender"], meta["filename"], meta["category"], data,
                      header["file_id"], header["ts"])
