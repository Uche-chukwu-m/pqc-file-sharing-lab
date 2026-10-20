"""Act 4: can the cloud guess a file's category from its encrypted package size?

    python -m experiments.size_leakage                  # 200 fictional files per category
    python -m experiments.size_leakage --per-category 500 --seed 7

1. Make a fictional dataset: file sizes drawn from DOC_TYPES below (our assumptions
   about typical sizes; state them in the paper as a limitation).
2. Seal every file with Version B v2 under each padding policy, and keep only
   what the cloud sees: the package size.
3. Attack: from package size alone, guess the category with
     - chance (25%: four equally common categories)
     - a simple rule: pick the category whose median size is closest
     - an AI model: a random forest trained on package sizes
   Accuracy comes from repeated stratified 5-fold cross-validation, so every
   score is measured on files the model never trained on.
4. Cost: how much extra storage each padding policy needs.

Outputs (results/): size_leakage_files.csv, size_leakage_summary.csv, size_leakage.md
"""

import argparse
import csv
import math
import random
import statistics
from pathlib import Path

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import RepeatedStratifiedKFold, StratifiedKFold, cross_val_predict, cross_val_score

from pqcshare.pki import Identity, TrustAuthority
from pqcshare.signed_package import seal

RESULTS = Path(__file__).resolve().parent.parent / "results"
CATEGORIES = ["medical", "legal", "personal", "financial"]

# (document type, typical size in bytes, spread). Sizes follow a log-normal
# distribution: "spread" is the standard deviation of the natural log of the size,
# so 0.5 means most files fall within roughly 0.6x to 1.6x the typical size.
DOC_TYPES = {
    "medical": [("lab report PDF", 60_000, 0.5), ("appointment note", 6_000, 0.6),
                ("prescription scan", 350_000, 0.5)],
    "legal": [("contract PDF", 250_000, 0.7), ("case note", 15_000, 0.6),
              ("evidence scan", 1_500_000, 0.6)],
    "personal": [("family message", 2_000, 0.8), ("photo", 2_500_000, 0.5),
                 ("ID scan", 500_000, 0.4)],
    "financial": [("bank statement PDF", 180_000, 0.5), ("invoice PDF", 70_000, 0.5),
                  ("transaction export CSV", 40_000, 1.0)],
}
MIN_SIZE, MAX_SIZE = 200, 8_000_000

POLICIES = [
    ("no padding", None),
    ("64 KB buckets", 64 * 1024),
    ("1 MB buckets", 1024 * 1024),
    ("power of 2", "pow2"),
    ("Padmé", "padme"),
    ("uniform (everything padded to 8 MiB)", 8 * 1024 * 1024),
]


def generate_dataset(per_category: int, rng: random.Random) -> list[dict]:
    files = []
    for category in CATEGORIES:
        for _ in range(per_category):
            doc_type, typical, spread = rng.choice(DOC_TYPES[category])
            size = int(rng.lognormvariate(math.log(typical), spread))
            files.append({"category": category, "doc_type": doc_type,
                          "file_size": min(MAX_SIZE, max(MIN_SIZE, size))})
    return files


def package_sizes(files: list[dict], policy, suite: str = "pq") -> list[int]:
    """Really seal every file and return what the cloud sees: package lengths."""
    ta = TrustAuthority.generate(suite)
    alice, bob = Identity.generate("alice", suite), Identity.generate("bob", suite)
    bob_cert = ta.issue(bob)
    content = bytes(MAX_SIZE)  # contents don't change sizes; encryption hides them anyway
    sizes = []
    for i, f in enumerate(files):
        package = seal(content[:f["file_size"]], sender=alice, recipient_cert=bob_cert, ta_pk=ta.sig_pk,
                       filename=f"file{i:05d}.bin", category=f["category"], pad_to=policy)
        sizes.append(len(package))
    return sizes


class NearestMedianRule(ClassifierMixin, BaseEstimator):
    """The simple, non-AI attacker: guess the category whose median size is closest."""

    def fit(self, X, y):
        self.classes_ = np.unique(y)
        self.medians_ = np.array([np.median(X[y == c, 0]) for c in self.classes_])
        return self

    def predict(self, X):
        return self.classes_[np.abs(X[:, :1] - self.medians_).argmin(axis=1)]


def attackers(seed: int) -> dict:
    return {
        "simple size rule": NearestMedianRule(),
        "AI (random forest)": RandomForestClassifier(n_estimators=200, min_samples_leaf=3, random_state=seed),
    }


def evaluate(sizes: list[int], labels: list[str], seed: int) -> dict:
    """Mean and standard deviation of accuracy over repeated stratified 5-fold CV."""
    X = np.log2(np.array(sizes, dtype=float)).reshape(-1, 1)
    y = np.array(labels)
    cv = RepeatedStratifiedKFold(n_splits=5, n_repeats=3, random_state=seed)
    out = {}
    for name, model in attackers(seed).items():
        scores = cross_val_score(model, X, y, cv=cv)
        out[name] = (scores.mean(), scores.std())
    return out


def ai_confusion(sizes: list[int], labels: list[str], seed: int) -> np.ndarray:
    X = np.log2(np.array(sizes, dtype=float)).reshape(-1, 1)
    predicted = cross_val_predict(attackers(seed)["AI (random forest)"], X, np.array(labels),
                                  cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=seed))
    return confusion_matrix(labels, predicted, labels=CATEGORIES)


def run_experiment(per_category: int = 200, seed: int = 1, policies=POLICIES, progress=None):
    """Returns (files with package sizes per policy, summary rows, AI confusion matrices).

    `progress(fraction, policy_name)` is called before each policy, for progress bars.
    """
    files = generate_dataset(per_category, random.Random(seed))
    labels = [f["category"] for f in files]
    total_file_bytes = sum(f["file_size"] for f in files)
    rows, confusions = [], {}
    for i, (name, policy) in enumerate(policies):
        if progress:
            progress(i / len(policies), name)
        sizes = package_sizes(files, policy)
        for f, s in zip(files, sizes):
            f[name] = s
        scores = evaluate(sizes, labels, seed)
        rows.append({
            "policy": name,
            "distinct_sizes": len(set(sizes)),
            "storage_overhead": sum(sizes) / total_file_bytes - 1,
            "median_overhead": statistics.median(s / f["file_size"] - 1 for f, s in zip(files, sizes)),
            **{f"{k} acc": v[0] for k, v in scores.items()},
            **{f"{k} sd": v[1] for k, v in scores.items()},
        })
        if name in ("no padding", "Padmé"):
            confusions[name] = ai_confusion(sizes, labels, seed)
    if progress:
        progress(1.0, "done")
    return files, rows, confusions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--per-category", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    files, rows, confusions = run_experiment(
        args.per_category, args.seed, progress=lambda f, name: print(f"  sealing and attacking: {name}"))
    total_file_bytes = sum(f["file_size"] for f in files)

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "size_leakage_files.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(files[0]))
        w.writeheader()
        w.writerows(files)
    with open(RESULTS / "size_leakage_summary.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    md = report(rows, confusions, args, len(files), total_file_bytes)
    (RESULTS / "size_leakage.md").write_text(md)
    print("\n" + md)
    print("Saved results/size_leakage_files.csv, results/size_leakage_summary.csv, results/size_leakage.md")


def report(rows, confusions, args, n_files, total_bytes) -> str:
    out = ["# Size leakage (Act 4)", "",
           f"{n_files} fictional files ({args.per_category} per category, {total_bytes / 1e6:.0f} MB), seed {args.seed}. "
           "Each file was sealed with Version B v2 (ML-KEM-768 + ML-DSA-65); the attackers see only package sizes.",
           "Accuracy = mean ± standard deviation over 5-fold cross-validation repeated 3 times. Chance = 25%.", "",
           "| Padding policy | Simple size rule | AI (random forest) | Distinct sizes seen | Extra storage (total) "
           "| Extra storage (median file) |",
           "|---|---|---|---|---|---|"]
    for r in rows:
        out.append(f"| {r['policy']} | {r['simple size rule acc']:.1%} ± {r['simple size rule sd']:.1%} "
                   f"| {r['AI (random forest) acc']:.1%} ± {r['AI (random forest) sd']:.1%} "
                   f"| {r['distinct_sizes']} | {r['storage_overhead']:+.1%} | {r['median_overhead']:+.1%} |")
    for name, cm in confusions.items():
        out += ["", f"## AI confusion matrix: {name}", "", "Rows = true category, columns = AI's guess.", "",
                "| | " + " | ".join(CATEGORIES) + " |", "|---|" + "---|" * len(CATEGORIES)]
        for category, row in zip(CATEGORIES, cm):
            out.append(f"| **{category}** | " + " | ".join(str(v) for v in row) + " |")
    out += ["", "## Assumed file types and typical sizes", "", "| Category | Document type | Typical size | Spread |",
            "|---|---|---|---|"]
    for category, types in DOC_TYPES.items():
        for doc_type, typical, spread in types:
            out.append(f"| {category} | {doc_type} | {typical / 1000:,.0f} KB | {spread} |")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    main()
