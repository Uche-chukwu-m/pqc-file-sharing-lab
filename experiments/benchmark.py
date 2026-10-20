"""Week 4: time and size cost of each setup (the story's epilogue).

    python -m experiments.benchmark                  # 200 timed runs per measurement
    python -m experiments.benchmark --runs 1000      # for the final paper

Setups compared:
  A             Version A: AES-CBC with a fixed key (no key exchange; reference only)
  B v1 (pq)     ML-KEM-768 + AES-256-GCM, unsigned (rough draft design)
  v2 classical  X25519 + Ed25519 + AES-256-GCM, signed (today's common choice)
  v2 pq         ML-KEM-768 + ML-DSA-65 + AES-256-GCM, signed (our design)

The fair comparison is v2 classical vs v2 pq: the code is identical except the
key exchange and signature algorithms.

Method: everything runs in memory (no file I/O); each measurement gets warm-up
runs; measurements are interleaved in a shuffled order each round so slow drift
(heat, background apps) spreads evenly; garbage collection is paused while
timing. Results: medians and interquartile ranges (IQR) in microseconds.

Outputs (results/):
  benchmark_raw.csv      every single timing
  benchmark_summary.csv  median, IQR and package sizes per measurement
  benchmark.md           tables for the paper + machine details
"""

import argparse
import csv
import gc
import platform
import random
import statistics
import subprocess
import sys
import time
from datetime import datetime
from importlib.metadata import version
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqcshare import version_a, version_b
from pqcshare._oqs import oqs
from pqcshare.pki import Identity, TrustAuthority
from pqcshare.signed_package import open_package, seal
from pqcshare.suites import get_suite

RESULTS = Path(__file__).resolve().parent.parent / "results"
SIZES = {"1 KB": 1024, "100 KB": 100 * 1024, "1 MB": 1024 * 1024}
SETUPS = ["A", "B v1 (pq)", "v2 classical", "v2 pq"]


def build_tasks(rng: random.Random) -> tuple[list[tuple], dict]:
    """Return timed tasks as (group, setup, size, operation, fn) and package sizes per (setup, size)."""
    tasks, sizes = [], {}

    labs = {}
    for suite in ("classical", "pq"):
        ta = TrustAuthority.generate(suite)
        alice, bob = Identity.generate("alice", suite), Identity.generate("bob", suite)
        labs[suite] = (ta, alice, bob, {"alice": ta.issue(alice), "bob": ta.issue(bob)})

    for size_name, n in SIZES.items():
        data = rng.randbytes(n)

        stored = version_a.encrypt(data)
        sizes[("A", size_name)] = (n, len(stored))
        tasks.append(("end-to-end", "A", size_name, "encrypt", lambda d=data: version_a.encrypt(d)))
        tasks.append(("end-to-end", "A", size_name, "decrypt", lambda c=stored: version_a.decrypt(c)))

        _, _, bob, _ = labs["pq"]
        package = version_b.encrypt(data, bob.kem_pk)
        sizes[("B v1 (pq)", size_name)] = (n, len(package))
        tasks.append(("end-to-end", "B v1 (pq)", size_name, "encrypt",
                      lambda d=data, pk=bob.kem_pk: version_b.encrypt(d, pk)))
        tasks.append(("end-to-end", "B v1 (pq)", size_name, "decrypt",
                      lambda p=package, sk=bob.kem_sk: version_b.decrypt(p, sk)))

        for suite in ("classical", "pq"):
            ta, alice, bob, certs = labs[suite]
            setup = f"v2 {suite}"

            def do_seal(d=data, a=alice, c=certs, t=ta):
                return seal(d, sender=a, recipient_cert=c["bob"], ta_pk=t.sig_pk,
                            filename="file.bin", category="medical")

            package = do_seal()
            sizes[(setup, size_name)] = (n, len(package))
            tasks.append(("end-to-end", setup, size_name, "encrypt", do_seal))
            # A fresh "seen" set each time, so the replay check never rejects the benchmark.
            tasks.append(("end-to-end", setup, size_name, "decrypt",
                          lambda p=package, b=bob, c=certs, t=ta: open_package(
                              p, recipient=b, ta_pk=t.sig_pk, fetch_cert=c.__getitem__, seen_ids=set())))

        key, nonce = AESGCM.generate_key(256), b"\x00" * 12  # fixed nonce is fine: timing only
        ct = AESGCM(key).encrypt(nonce, data, None)
        tasks.append(("building block", "AES-256-GCM", size_name, "encrypt",
                      lambda k=key, d=data: AESGCM(k).encrypt(nonce, d, None)))
        tasks.append(("building block", "AES-256-GCM", size_name, "decrypt",
                      lambda k=key, c=ct: AESGCM(k).decrypt(nonce, c, None)))

    for suite in ("classical", "pq"):
        s = get_suite(suite)
        _, _, bob, _ = labs[suite]
        kem_ct, _ = s.encaps(bob.kem_pk)
        message = b"m" * 200  # about the size of what the package signature covers, minus the file
        sig = s.sign(bob.sig_sk, message)
        for op, fn in [
            ("KEM keygen", s.kem_keygen),
            ("encapsulate", lambda s=s, pk=bob.kem_pk: s.encaps(pk)),
            ("decapsulate", lambda s=s, sk=bob.kem_sk, c=kem_ct: s.decaps(sk, c)),
            ("signature keygen", s.sig_keygen),
            ("sign", lambda s=s, sk=bob.sig_sk: s.sign(sk, message)),
            ("verify", lambda s=s, pk=bob.sig_pk, g=sig: s.verify(pk, message, g)),
        ]:
            tasks.append(("building block", f"{s.kem_alg} / {s.sig_alg}", "—", op, fn))
    return tasks, sizes


def time_once(fn) -> int:
    gc.disable()
    try:
        start = time.perf_counter_ns()
        fn()
        return time.perf_counter_ns() - start
    finally:
        gc.enable()


def environment() -> dict:
    def run(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    cpu = run(["sysctl", "-n", "machdep.cpu.brand_string"]) or platform.processor() or "unknown"
    power = run(["pmset", "-g", "batt"]).split("\n")[0].replace("Now drawing from ", "").strip("'") or "unknown"
    return {
        "date": datetime.now().isoformat(timespec="seconds"),
        "cpu": cpu,
        "os": platform.platform(),
        "python": sys.version.split()[0],
        "liboqs": oqs.oqs_version(),
        "liboqs-python": version("liboqs-python"),
        "cryptography": version("cryptography"),
        "power source": power,
    }


def iqr(values) -> float:
    q = statistics.quantiles(values, n=4)
    return q[2] - q[0]


def measure(runs: int = 200, warmup: int = 20, seed: int = 1, progress=None) -> tuple[dict, dict, dict]:
    """Run the benchmark. Returns (samples in ns per measurement, package sizes, machine details).

    `progress(fraction)` is called after each round, for progress bars.
    """
    rng = random.Random(seed)
    tasks, sizes = build_tasks(rng)
    for task in tasks:
        for _ in range(warmup):
            task[4]()

    samples = {task[:4]: [] for task in tasks}
    order = list(tasks)
    for i in range(runs):
        rng.shuffle(order)
        for task in order:
            samples[task[:4]].append(time_once(task[4]))
        if progress:
            progress((i + 1) / runs)
    return samples, sizes, environment()


def summarize(samples: dict) -> dict:
    """(median µs, IQR µs) per measurement."""
    return {key: (statistics.median(v) / 1000, iqr(v) / 1000) for key, v in samples.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--runs", type=int, default=200, help="timed runs per measurement")
    parser.add_argument("--warmup", type=int, default=20, help="untimed runs per measurement first")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    print(f"{args.runs} runs per measurement...")
    samples, sizes, env = measure(args.runs, args.warmup, args.seed,
                                  progress=lambda f: print(f"  {f:.0%}") if round(f * 10) == f * 10 else None)
    summary = summarize(samples)

    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "benchmark_raw.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group", "setup", "file_size", "operation", "run", "ns"])
        for key, values in samples.items():
            for run, ns in enumerate(values):
                w.writerow([*key, run, ns])

    with open(RESULTS / "benchmark_summary.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["group", "setup", "file_size", "operation", "runs", "median_us", "iqr_us",
                    "file_bytes", "package_bytes", "overhead_bytes"])
        for key, (med, spread) in summary.items():
            n, pkg = sizes.get((key[1], key[2]), ("", ""))
            w.writerow([*key, len(samples[key]), f"{med:.1f}", f"{spread:.1f}", n, pkg,
                        pkg - n if pkg != "" else ""])

    md = report(summary, sizes, env, args)
    (RESULTS / "benchmark.md").write_text(md)
    print("\n" + md)
    print("Saved results/benchmark_raw.csv, results/benchmark_summary.csv, results/benchmark.md")


def report(summary: dict, sizes: dict, env: dict, args) -> str:
    def cell(key):
        med, spread = summary[key]
        return f"{med:,.1f} (IQR {spread:,.1f})"

    out = ["# Benchmark results", "",
           f"{args.runs} timed runs per measurement after {args.warmup} warm-up runs; seed {args.seed}.",
           "Times are medians in microseconds (µs), with the interquartile range. No file I/O.", "",
           "## Machine", ""]
    out += [f"- **{k}:** {v}" for k, v in env.items()]

    for op, title in (("encrypt", "Sender: encrypt (and sign)"), ("decrypt", "Recipient: verify and decrypt")):
        out += ["", f"## {title}, µs", "", "| Setup | " + " | ".join(SIZES) + " |",
                "|---|" + "---|" * len(SIZES)]
        for setup in SETUPS:
            out.append(f"| {setup} | " + " | ".join(cell(("end-to-end", setup, s, op)) for s in SIZES) + " |")

    out += ["", "## Package size", "", "| Setup | " + " | ".join(SIZES) + " | Fixed overhead |",
            "|---|" + "---|" * (len(SIZES) + 1)]
    for setup in SETUPS:
        cells = []
        for s in SIZES:
            n, pkg = sizes[(setup, s)]
            cells.append(f"{pkg:,} B (+{(pkg - n) / n:.2%})")
        n, pkg = sizes[(setup, "1 KB")]
        out.append(f"| {setup} | " + " | ".join(cells) + f" | {pkg - n:,} B |")
    out += ["", "Version A's overhead is only padding. Its packages are small because it has no key exchange and no "
            "integrity check, not because it is efficient."]

    out += ["", "## Building blocks, µs", "", "| Algorithms | Operation | Median (IQR) |", "|---|---|---|"]
    for key in summary:
        if key[0] == "building block" and key[2] == "—":
            out.append(f"| {key[1]} | {key[3]} | {cell(key)} |")
    out += ["", "| AES-256-GCM | " + " | ".join(SIZES) + " |", "|---|" + "---|" * len(SIZES)]
    for op in ("encrypt", "decrypt"):
        out.append(f"| {op} | " + " | ".join(cell(("building block", "AES-256-GCM", s, op)) for s in SIZES) + " |")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    main()
