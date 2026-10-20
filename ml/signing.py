"""Sign and verify files (AI models, result reports) with ML-DSA (Act 5).

A signed manifest lists each file's name, size and SHA-256 hash, plus who signed
it and why. The signer is a normal user whose certificate the Trust Authority
issued, and verifiers accept only signers on an approved list.

    <name>.sig.json = {"manifest": {...}, "signature": "<hex>"}

verify_artifacts() returns the exact bytes it checked, so callers parse those
bytes and never re-read a file that could have changed after the check.
"""

import hashlib
import time
from pathlib import Path
from typing import Callable

from pqcshare.encoding import canonical_json
from pqcshare.pki import CertificateError, Identity, verify_certificate
from pqcshare.suites import get_suite

DOMAIN = b"pqcshare-artifacts-v1|"


class ArtifactRejected(Exception):
    def __init__(self, reason: str):
        super().__init__(f"artifact rejected: {reason}")
        self.reason = reason


def sign_artifacts(paths: list[Path], signer: Identity, purpose: str, base_dir: Path,
                   extra: dict | None = None) -> dict:
    """Return a signed manifest covering `paths` (stored relative to `base_dir`)."""
    files = []
    for path in paths:
        data = Path(path).read_bytes()
        files.append({"name": Path(path).resolve().relative_to(Path(base_dir).resolve()).as_posix(),
                      "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    manifest = {
        "type": "pqcshare-artifacts-v1",
        "purpose": purpose,
        "signer": signer.user_id,
        "suite": signer.suite,
        "created": int(time.time()),
        "files": files,
        **(extra or {}),
    }
    signature = get_suite(signer.suite).sign(signer.sig_sk, DOMAIN + canonical_json(manifest))
    return {"manifest": manifest, "signature": signature.hex()}


def verify_artifacts(signed: dict, base_dir: Path, *, ta_pk: bytes, suite: str,
                     fetch_cert: Callable[[str], dict], trusted_signers: set[str],
                     purpose: str | None = None) -> tuple[dict, dict[str, bytes]]:
    """Check signer, signature and every file hash. Returns (manifest, {name: verified bytes})."""
    try:
        manifest = signed["manifest"]
        signature = bytes.fromhex(signed["signature"])
        signer = manifest["signer"]
        if manifest["type"] != "pqcshare-artifacts-v1" or manifest["suite"] != suite:
            raise ArtifactRejected("wrong manifest type or suite")
        if not isinstance(manifest["purpose"], str) or not manifest["files"] or not all(
                isinstance(f["name"], str) and isinstance(f["bytes"], int) and isinstance(f["sha256"], str)
                for f in manifest["files"]):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise ArtifactRejected("malformed manifest") from None

    if purpose is not None and manifest["purpose"] != purpose:
        raise ArtifactRejected(f"manifest is for {manifest['purpose']!r}, not {purpose!r}")
    if signer not in trusted_signers:
        raise ArtifactRejected(f"{signer!r} is not an approved signer")
    try:
        cert = verify_certificate(fetch_cert(signer), ta_pk, suite, expected_user=signer)
    except (CertificateError, KeyError, OSError, ValueError) as exc:
        raise ArtifactRejected(f"signer certificate invalid: {exc}") from None
    if not get_suite(suite).verify(bytes.fromhex(cert["sig_pk"]), DOMAIN + canonical_json(manifest), signature):
        raise ArtifactRejected("bad signature")

    base = Path(base_dir).resolve()
    verified = {}
    for entry in manifest["files"]:
        path = (base / entry["name"]).resolve()
        if not path.is_relative_to(base):
            raise ArtifactRejected(f"{entry['name']}: path outside the signed folder")
        try:
            data = path.read_bytes()
        except OSError:
            raise ArtifactRejected(f"{entry['name']}: missing") from None
        if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ArtifactRejected(f"{entry['name']}: contents changed since signing")
        verified[entry["name"]] = data
    return manifest, verified
