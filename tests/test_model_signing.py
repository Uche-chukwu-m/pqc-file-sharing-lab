import json

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from ml.model_store import load_verified_model, save_signed_model, signature_path
from ml.signing import DOMAIN, ArtifactRejected, sign_artifacts, verify_artifacts
from pqcshare.encoding import canonical_json
from pqcshare.pki import Identity, TrustAuthority
from pqcshare.suites import get_suite


@pytest.fixture(scope="module")
def pki():
    ta = TrustAuthority.generate("classical")
    users = {n: Identity.generate(n, "classical") for n in ("approver", "mallory")}
    return ta, users, {n: ta.issue(u) for n, u in users.items()}


def model(seed=1):
    X = np.arange(40, dtype=float).reshape(-1, 1)
    return RandomForestClassifier(n_estimators=5, random_state=seed).fit(X, ["a", "b"] * 20)


def load(path, pki):
    ta, _, certs = pki
    return load_verified_model(path, ta_pk=ta.sig_pk, suite="classical",
                               fetch_cert=certs.__getitem__, trusted_signers={"approver"})


def test_approved_model_loads(tmp_path, pki):
    path = tmp_path / "m.skops"
    save_signed_model(model(), path, pki[1]["approver"], {"name": "m"})
    loaded, manifest = load(path, pki)
    assert manifest["signer"] == "approver" and loaded.predict([[3.0]]).shape == (1,)


def test_changed_byte_is_refused(tmp_path, pki):
    path = tmp_path / "m.skops"
    save_signed_model(model(), path, pki[1]["approver"], {})
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(ArtifactRejected, match="changed"):
        load(path, pki)


def test_edited_manifest_is_refused(tmp_path, pki):
    path = tmp_path / "m.skops"
    save_signed_model(model(), path, pki[1]["approver"], {})
    signed = json.loads(signature_path(path).read_text())
    signed["manifest"]["model"] = {"note": "edited"}
    signature_path(path).write_text(json.dumps(signed))
    with pytest.raises(ArtifactRejected, match="bad signature"):
        load(path, pki)


def test_valid_signature_from_unapproved_user_is_refused(tmp_path, pki):
    path = tmp_path / "m.skops"
    save_signed_model(model(), path, pki[1]["mallory"], {})
    with pytest.raises(ArtifactRejected, match="not an approved signer"):
        load(path, pki)


def test_manifest_cannot_point_outside_its_folder(tmp_path, pki):
    ta, users, certs = pki
    (tmp_path / "inner").mkdir()
    (tmp_path / "secret.txt").write_text("x")
    signed = sign_artifacts([tmp_path / "secret.txt"], users["approver"], "p", tmp_path)
    signed["manifest"]["files"][0]["name"] = "../secret.txt"
    # Re-sign so only the path check can stop it.
    signed["signature"] = get_suite("classical").sign(
        users["approver"].sig_sk, DOMAIN + canonical_json(signed["manifest"])).hex()
    with pytest.raises(ArtifactRejected, match="outside"):
        verify_artifacts(signed, tmp_path / "inner", ta_pk=ta.sig_pk, suite="classical",
                         fetch_cert=certs.__getitem__, trusted_signers={"approver"})


@pytest.mark.parametrize("signed", [{}, {"manifest": {}, "signature": "zz"}, {"manifest": [], "signature": ""}])
def test_malformed_manifest_is_refused(tmp_path, pki, signed):
    ta, _, certs = pki
    with pytest.raises(ArtifactRejected, match="malformed"):
        verify_artifacts(signed, tmp_path, ta_pk=ta.sig_pk, suite="classical",
                         fetch_cert=certs.__getitem__, trusted_signers={"approver"})
