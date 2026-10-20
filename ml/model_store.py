"""Save AI models safely and load them only after their signature checks out.

Models are saved with skops, not pickle: loading a pickle can run any code hidden
inside it. skops refuses object types it was not told to trust, and we trust only
the one type a random forest needs.

The loader order matters: verify signer, signature and hash first, then parse
the very bytes that were verified.
"""

import json
from pathlib import Path

import skops.io as sio

from .signing import ArtifactRejected, sign_artifacts, verify_artifacts

MODEL_PURPOSE = "approved AI model"
TRUSTED_TYPES = ["sklearn.tree._tree.Tree"]


def signature_path(model_path: Path) -> Path:
    return Path(model_path).with_suffix(".sig.json")


def save_signed_model(model, model_path: Path, signer, info: dict) -> Path:
    """Write the model and its signed manifest; return the manifest path."""
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    model_path.write_bytes(sio.dumps(model))
    signed = sign_artifacts([model_path], signer, MODEL_PURPOSE, model_path.parent,
                            extra={"model": info, "format": "skops"})
    sig_path = signature_path(model_path)
    sig_path.write_text(json.dumps(signed, indent=2))
    return sig_path


def load_verified_model(model_path: Path, *, ta_pk: bytes, suite: str, fetch_cert,
                        trusted_signers: set[str]):
    """Return (model, manifest). Raises ArtifactRejected before parsing anything unverified."""
    model_path = Path(model_path)
    try:
        signed = json.loads(signature_path(model_path).read_text())
    except (OSError, ValueError):
        raise ArtifactRejected("signature file missing or unreadable") from None
    manifest, verified = verify_artifacts(signed, model_path.parent, ta_pk=ta_pk, suite=suite,
                                          fetch_cert=fetch_cert, trusted_signers=trusted_signers,
                                          purpose=MODEL_PURPOSE)
    if [f["name"] for f in manifest["files"]] != [model_path.name]:
        raise ArtifactRejected("manifest does not cover exactly this model file")
    data = verified[model_path.name]
    if set(sio.get_untrusted_types(data=data)) - set(TRUSTED_TYPES):
        raise ArtifactRejected("model contains object types we do not trust")
    return sio.loads(data, trusted=TRUSTED_TYPES), manifest
