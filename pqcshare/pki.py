"""Identities, the Trust Authority, and certificates (the "ID cards").

The Trust Authority (TA) signs a certificate for each user that binds their user
ID to their KEM and signature public keys. Everyone pins the TA's public key, so
a certificate fetched from the untrusted cloud can be checked: the cloud cannot
forge one without the TA's private key.

Lab only: private keys are saved unencrypted as JSON. A real system would keep
them in a keychain or a hardware security module.
"""

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .encoding import canonical_json
from .suites import get_suite

CERT_DOMAIN = b"pqcshare-cert-v1|"


class CertificateError(Exception):
    pass


def _save_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2))


@dataclass
class Identity:
    """One user's key pairs: KEM keys to receive files, signature keys to send them."""

    user_id: str
    suite: str
    kem_pk: bytes
    kem_sk: bytes
    sig_pk: bytes
    sig_sk: bytes

    @classmethod
    def generate(cls, user_id: str, suite: str = "pq") -> "Identity":
        s = get_suite(suite)
        kem_pk, kem_sk = s.kem_keygen()
        sig_pk, sig_sk = s.sig_keygen()
        return cls(user_id, suite, kem_pk, kem_sk, sig_pk, sig_sk)

    def save(self, path: Path) -> None:
        _save_json(path, {k: v.hex() if isinstance(v, bytes) else v for k, v in asdict(self).items()})

    @classmethod
    def load(cls, path: Path) -> "Identity":
        d = json.loads(Path(path).read_text())
        return cls(d["user_id"], d["suite"], *(bytes.fromhex(d[k]) for k in ("kem_pk", "kem_sk", "sig_pk", "sig_sk")))


@dataclass
class TrustAuthority:
    suite: str
    sig_pk: bytes
    sig_sk: bytes

    @classmethod
    def generate(cls, suite: str = "pq") -> "TrustAuthority":
        pk, sk = get_suite(suite).sig_keygen()
        return cls(suite, pk, sk)

    def issue(self, identity: Identity, valid_days: int = 365, now: float | None = None) -> dict:
        if identity.suite != self.suite:
            raise CertificateError("identity and TA use different suites")
        now = int(time.time() if now is None else now)
        body = {
            "type": "pqcshare-cert-v1",
            "user_id": identity.user_id,
            "suite": self.suite,
            "kem_pk": identity.kem_pk.hex(),
            "sig_pk": identity.sig_pk.hex(),
            "not_before": now,
            "not_after": now + valid_days * 86400,
        }
        signature = get_suite(self.suite).sign(self.sig_sk, CERT_DOMAIN + canonical_json(body))
        return {"body": body, "ta_sig": signature.hex()}

    def save(self, path: Path) -> None:
        _save_json(path, {"suite": self.suite, "sig_pk": self.sig_pk.hex(), "sig_sk": self.sig_sk.hex()})

    @classmethod
    def load(cls, path: Path) -> "TrustAuthority":
        d = json.loads(Path(path).read_text())
        return cls(d["suite"], bytes.fromhex(d["sig_pk"]), bytes.fromhex(d["sig_sk"]))


def verify_certificate(cert: dict, ta_pk: bytes, suite: str, expected_user: str | None = None,
                       now: float | None = None) -> dict:
    """Return the certificate body if the TA signed it and it is valid now; raise otherwise."""
    try:
        body = cert["body"]
        signature = bytes.fromhex(cert["ta_sig"])
        if body["type"] != "pqcshare-cert-v1" or body["suite"] != suite:
            raise CertificateError("wrong certificate type or suite")
        if not get_suite(suite).verify(ta_pk, CERT_DOMAIN + canonical_json(body), signature):
            raise CertificateError("TA signature invalid")
        now = time.time() if now is None else now
        if not body["not_before"] <= now <= body["not_after"]:
            raise CertificateError("certificate not valid at this time")
        if expected_user is not None and body["user_id"] != expected_user:
            raise CertificateError("certificate belongs to a different user")
    except CertificateError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise CertificateError(f"malformed certificate: {exc}") from exc
    return body
