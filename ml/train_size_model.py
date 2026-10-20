"""Train the Act 4 size classifier and save it signed by the approver (Act 5).

    python -m pqcshare.cli setup --force          # once: creates the TA and users, incl. "approver"
    python -m ml.train_size_model                 # train, save models/size_classifier.skops + .sig.json
    python -m ml.train_size_model --check         # load it the safe way and run a prediction

The model is the "no padding" attacker from experiments/size_leakage.py: it guesses a
file's category from its encrypted package size.
"""

import argparse
import hashlib
import json
import random
import sys
from pathlib import Path

import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier

from experiments.size_leakage import generate_dataset, package_sizes
from pqcshare.cloud import CloudFolder
from pqcshare.pki import Identity, TrustAuthority

from .model_store import load_verified_model, save_signed_model
from .signing import ArtifactRejected

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "size_classifier.skops"
APPROVERS = {"approver"}


def train(per_category: int, seed: int):
    files = generate_dataset(per_category, random.Random(seed))
    sizes = package_sizes(files, None)
    X = np.log2(np.array(sizes, dtype=float)).reshape(-1, 1)
    y = np.array([f["category"] for f in files])
    model = RandomForestClassifier(n_estimators=200, min_samples_leaf=3, random_state=seed).fit(X, y)
    training_data = json.dumps([[f["category"], s] for f, s in zip(files, sizes)]).encode()
    info = {
        "name": "size_classifier",
        "task": "guess file category from encrypted package size",
        "feature": "log2(package bytes)",
        "classes": model.classes_.tolist(),
        "training": {"files": len(files), "seed": seed, "padding": "none",
                     "data_sha256": hashlib.sha256(training_data).hexdigest()},
        "sklearn": sklearn.__version__,
    }
    return model, info


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--lab", default="lab")
    parser.add_argument("--signer", default="approver")
    parser.add_argument("--per-category", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--check", action="store_true", help="only verify and load the saved model")
    args = parser.parse_args()

    lab = Path(args.lab)
    try:
        ta = TrustAuthority.load(lab / "ta.json")
    except FileNotFoundError:
        sys.exit("no lab folder: run  python -m pqcshare.cli setup  first")
    cloud = CloudFolder(lab / "cloud")

    if not args.check:
        signer_file = lab / "users" / args.signer / "identity.json"
        if not signer_file.exists():
            sys.exit(f"no user {args.signer!r} in {lab}: run  python -m pqcshare.cli setup --force")
        model, info = train(args.per_category, args.seed)
        sig_path = save_signed_model(model, MODEL_PATH, Identity.load(signer_file), info)
        print(f"trained on {info['training']['files']} files; saved {MODEL_PATH.name}, signed by "
              f"{args.signer} -> {sig_path.name}")

    try:
        model, manifest = load_verified_model(MODEL_PATH, ta_pk=ta.sig_pk, suite=ta.suite,
                                              fetch_cert=cloud.get_cert, trusted_signers=APPROVERS)
    except ArtifactRejected as exc:
        sys.exit(f"REFUSED to load model: {exc.reason}")
    guesses = model.predict(np.log2([[2_600_000.0], [75_000.0]]))
    print(f"verified (signer: {manifest['signer']}) and loaded. "
          f"A 2.6 MB package looks {guesses[0]}; a 75 KB package looks {guesses[1]}.")


if __name__ == "__main__":
    main()
