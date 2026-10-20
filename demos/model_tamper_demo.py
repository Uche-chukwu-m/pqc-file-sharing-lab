"""Act 5: only the approved AI model gets loaded.

    python -m demos.model_tamper_demo

Someone wants our leakage analysis to report "no leak", so they try to swap in a
rigged model, one trained on shuffled labels that only guesses at random. Every
attempt is refused before the model file is even parsed.
"""

import json
import random
import shutil
import tempfile
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from experiments.size_leakage import generate_dataset, package_sizes
from ml.model_store import load_verified_model, save_signed_model, signature_path
from ml.signing import ArtifactRejected
from pqcshare.pki import Identity, TrustAuthority


def run_scenarios(per_category: int = 50) -> list[dict]:
    """Run the five attempts. Each result: title, loaded (bool), detail, ms (time to verify + load)."""
    ta = TrustAuthority.generate("pq")
    approver, mallory = Identity.generate("approver"), Identity.generate("mallory")
    certs = {"approver": ta.issue(approver), "mallory": ta.issue(mallory)}

    files = generate_dataset(per_category, random.Random(1))
    X = np.log2(np.array(package_sizes(files, None), dtype=float)).reshape(-1, 1)
    y = np.array([f["category"] for f in files])
    real = RandomForestClassifier(n_estimators=50, random_state=1).fit(X, y)
    rigged = RandomForestClassifier(n_estimators=50, random_state=1).fit(X, np.random.default_rng(1).permutation(y))
    info = {"name": "size_classifier", "classes": real.classes_.tolist()}

    workdir = Path(tempfile.mkdtemp(prefix="model_demo_"))
    model_path = workdir / "size_classifier.skops"
    results = []

    def attempt(title: str) -> None:
        start = time.perf_counter()
        try:
            model, manifest = load_verified_model(model_path, ta_pk=ta.sig_pk, suite="pq",
                                                  fetch_cert=certs.__getitem__, trusted_signers={"approver"})
            guess = model.predict(np.log2([[2_600_000.0]]))[0]
            loaded, detail = True, f"signed by {manifest['signer']}; it guesses a 2.6 MB package is {guess}"
        except ArtifactRejected as exc:
            loaded, detail = False, exc.reason
        results.append({"title": title, "loaded": loaded, "detail": detail,
                        "ms": (time.perf_counter() - start) * 1000})

    try:
        save_signed_model(real, model_path, approver, info)
        attempt("1. The approved model, signed by the approver")

        original = model_path.read_bytes()
        model_path.write_bytes(original[:1000] + bytes([original[1000] ^ 1]) + original[1001:])
        attempt("2. One byte of the model file changed")

        # Swap in the rigged model and also fix up the hash in the manifest.
        save_signed_model(real, model_path, approver, info)
        signed = json.loads(signature_path(model_path).read_text())
        rigged_bytes_path = workdir / "rigged.skops"
        save_signed_model(rigged, rigged_bytes_path, mallory, info)
        shutil.copy(rigged_bytes_path, model_path)
        rigged_manifest = json.loads(signature_path(rigged_bytes_path).read_text())["manifest"]
        signed["manifest"]["files"][0].update({k: rigged_manifest["files"][0][k] for k in ("bytes", "sha256")})
        signature_path(model_path).write_text(json.dumps(signed))
        attempt("3. Rigged model swapped in, with the manifest's hash edited to match")

        # Mallory has a real certificate, so her signature is valid, but she is not an approver.
        save_signed_model(rigged, model_path, mallory, info)
        attempt("4. Rigged model properly signed by Mallory (a real user, not an approver)")

        signature_path(model_path).unlink()
        attempt("5. Signature file deleted")
    finally:
        shutil.rmtree(workdir)
    return results


def main() -> None:
    for r in run_scenarios():
        outcome = "LOADED" if r["loaded"] else "REFUSED"
        print(f"{r['title']}\n    -> {outcome}: {r['detail']}  ({r['ms']:.1f} ms)\n")


if __name__ == "__main__":
    main()
