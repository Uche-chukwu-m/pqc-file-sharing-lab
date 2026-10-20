"""Week 3: the attack table. Plays the untrusted cloud (and Mallory) against all three versions.

    python -m attacks.attack_table            # 200 trials per random attack
    python -m attacks.attack_table --trials 1000 --seed 7

Writes results/attack_table.csv (one row per version x attack) and
results/attack_table.md (the table for the paper).

Each trial ends as BLOCKED (with where it was stopped) or SUCCEEDED (the attacker
got what they wanted: a changed/forged file accepted, or a file read by the
wrong person). Version A sometimes "blocks" a random edit only because the
padding happens to come out invalid; that is luck, not an integrity check, and
the table labels it so.
"""

import argparse
import csv
import json
import random
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag

from demos.make_samples import INVOICE
from pqcshare import version_a, version_b
from pqcshare.encoding import canonical_json, lp
from pqcshare.pki import CertificateError, Identity, TrustAuthority
from pqcshare.signed_package import MAGIC, PackageRejected, _to_be_signed, open_package, parse_package, seal
from pqcshare.suites import get_suite

RESULTS = Path(__file__).resolve().parent.parent / "results"
DATA = INVOICE.encode()
SUCCEEDED = "succeeded"
NOT_APPLICABLE = "n/a"


@dataclass
class Row:
    version: str
    attack: str
    outcomes: Counter = field(default_factory=Counter)

    def record(self, outcome: str) -> None:
        self.outcomes[outcome] += 1

    @property
    def trials(self) -> int:
        return sum(self.outcomes.values())

    @property
    def blocked(self) -> int:
        return self.trials - self.outcomes[SUCCEEDED] - self.outcomes[NOT_APPLICABLE]

    def cell(self) -> str:
        if self.outcomes[NOT_APPLICABLE]:
            return "n/a"
        if self.blocked == self.trials:
            where = ", ".join(sorted(self.outcomes))
            return f"✅ blocked {self.blocked}/{self.trials} ({where})"
        if self.blocked == 0:
            return f"❌ succeeded {self.trials}/{self.trials}"
        lucky = ", ".join(k for k in sorted(self.outcomes) if k != SUCCEEDED)
        return f"❌ succeeded {self.outcomes[SUCCEEDED]}/{self.trials} (rest: {lucky})"


class Lab:
    """A Trust Authority, alice, bob and mallory, with certificates the cloud stores."""

    def __init__(self, suite: str = "pq"):
        self.ta = TrustAuthority.generate(suite)
        self.users = {n: Identity.generate(n, suite) for n in ("alice", "bob", "mallory")}
        self.certs = {n: self.ta.issue(u) for n, u in self.users.items()}

    def seal(self, data: bytes = DATA, sender: str = "alice", to: str = "bob", identity=None) -> bytes:
        return seal(data, sender=identity or self.users[sender], recipient_cert=self.certs[to],
                    ta_pk=self.ta.sig_pk, filename="financial_invoice.txt", category="financial")

    def open(self, package: bytes, as_user: str = "bob", seen=None):
        return open_package(package, recipient=self.users[as_user], ta_pk=self.ta.sig_pk,
                            fetch_cert=self.certs.__getitem__, seen_ids=set() if seen is None else seen)


def flip_random_bit(data: bytes, start: int, end: int, rng: random.Random) -> bytes:
    out = bytearray(data)
    out[rng.randrange(start, end)] ^= 1 << rng.randrange(8)
    return bytes(out)


def edit_amount(data: bytes, at: int) -> bytes:
    """XOR "$100" into "$900" at byte offset `at` of a ciphertext."""
    out = bytearray(data)
    for i, (a, b) in enumerate(zip(b"$100", b"$900")):
        out[at + i] ^= a ^ b
    return bytes(out)


def rebuild(fields) -> bytes:
    return MAGIC + b"".join(lp(f) for f in fields)


def v2_regions(package: bytes) -> dict[str, tuple[int, int]]:
    """Byte ranges of each part of a v2 package, for targeted bit flips."""
    names = ["header", "KEM ciphertext", "nonce", "AES ciphertext + tag", "signature"]
    regions, pos = {}, 4
    for name, f in zip(names, parse_package(package)):
        regions[name] = (pos + 4, pos + 4 + len(f))
        pos += 4 + len(f)
    return regions


# ---------------------------------------------------------------- Version A

def attack_version_a(trials: int, rng: random.Random) -> list[Row]:
    rows = []
    stored = version_a.encrypt(DATA)

    def outcome(tampered: bytes) -> str:
        try:
            restored = version_a.decrypt(tampered)
        except ValueError:
            return "padding error (luck)"
        return SUCCEEDED if restored != DATA else "unchanged"

    row = Row("A", "Edit invoice $100 → $900")
    row.record(outcome(edit_amount(stored, DATA.index(b"$100") - 16)))
    rows.append(row)

    row = Row("A", "Random bit flip (anywhere)")
    for _ in range(trials):
        row.record(outcome(flip_random_bit(stored, 0, len(stored), rng)))
    rows.append(row)

    row = Row("A", "Truncate last block")
    row.record(outcome(stored[:-16]))
    rows.append(row)

    # The key is in the source code, so anyone can make a "valid" file.
    row = Row("A", "Cloud forges a new file")
    row.record(outcome(version_a.encrypt(b"FAKE INVOICE: pay $9,000 to Mallory")))
    rows.append(row)

    row = Row("A", "Replay an old file")
    row.record(SUCCEEDED)  # nothing identifies a file, so a copy is indistinguishable
    rows.append(row)

    row = Row("A", "Mallory pretends to be Alice")
    row.record(SUCCEEDED)  # there is no sender identity at all
    rows.append(row)

    row = Row("A", "Wrong person opens the file")
    row.record(SUCCEEDED if version_a.decrypt(stored) == DATA else "blocked")
    rows.append(row)

    rows.append(Row("A", "Cloud swaps recipient's key", Counter({NOT_APPLICABLE: 1})))
    rows.append(Row("A", "Signature swap", Counter({NOT_APPLICABLE: 1})))
    rows.append(Row("A", "Redirect package to Mallory", Counter({NOT_APPLICABLE: 1})))
    return rows


# ---------------------------------------------------------------- Version B v1

def attack_version_b(lab: Lab, trials: int, rng: random.Random) -> list[Row]:
    rows = []
    bob, mallory = lab.users["bob"], lab.users["mallory"]
    package = version_b.encrypt(DATA, bob.kem_pk)
    aes_start = 4 + 1088 + 12

    def outcome(tampered: bytes, sk: bytes = bob.kem_sk) -> str:
        try:
            restored = version_b.decrypt(tampered, sk)
        except InvalidTag:
            return "GCM tag"
        except ValueError:
            return "length check"
        return SUCCEEDED if restored != DATA else "unchanged"

    row = Row("B v1", "Edit invoice $100 → $900")
    row.record(outcome(edit_amount(package, aes_start + DATA.index(b"$100"))))
    rows.append(row)

    row = Row("B v1", "Random bit flip (anywhere)")
    for _ in range(trials):
        row.record(outcome(flip_random_bit(package, 0, len(package), rng)))
    rows.append(row)

    row = Row("B v1", "Truncate last block")
    row.record(outcome(package[:-16]))
    rows.append(row)

    # Bob's public key is public, so the cloud can build a perfectly valid package.
    row = Row("B v1", "Cloud forges a new file")
    row.record(SUCCEEDED if version_b.decrypt(version_b.encrypt(b"FAKE INVOICE", bob.kem_pk),
                                              bob.kem_sk) == b"FAKE INVOICE" else "blocked")
    rows.append(row)

    row = Row("B v1", "Replay an old file")
    row.record(SUCCEEDED if version_b.decrypt(package, bob.kem_sk) == DATA else "blocked")
    rows.append(row)

    row = Row("B v1", "Mallory pretends to be Alice")
    row.record(SUCCEEDED)  # packages carry no sender identity
    rows.append(row)

    row = Row("B v1", "Wrong person opens the file")
    result = outcome(package, mallory.kem_sk)
    row.record(SUCCEEDED if result == "unchanged" else result)  # "unchanged" = Mallory read it
    rows.append(row)

    # Nothing authenticates Bob's key: the cloud hands Alice Mallory's key instead.
    row = Row("B v1", "Cloud swaps recipient's key")
    swapped = version_b.encrypt(DATA, mallory.kem_pk)
    row.record(SUCCEEDED if version_b.decrypt(swapped, mallory.kem_sk) == DATA else "blocked")
    rows.append(row)

    rows.append(Row("B v1", "Signature swap", Counter({NOT_APPLICABLE: 1})))
    rows.append(Row("B v1", "Redirect package to Mallory", Counter({NOT_APPLICABLE: 1})))
    return rows


# ---------------------------------------------------------------- Version B v2

def attack_version_b2(lab: Lab, trials: int, rng: random.Random) -> list[Row]:
    rows = []
    suite_sign = get_suite(lab.ta.suite).sign

    def outcome(tampered: bytes, as_user: str = "bob", seen=None) -> str:
        # Every package here is tampered, forged, replayed or misdirected: accepting it is a failure.
        try:
            lab.open(tampered, as_user=as_user, seen=seen)
        except PackageRejected as exc:
            return exc.reason.split(":")[0]
        return SUCCEEDED

    row = Row("B v2", "Edit invoice $100 → $900")
    fields = list(parse_package(lab.seal()))
    meta = canonical_json({"category": "financial", "filename": "financial_invoice.txt"})
    fields[3] = edit_amount(fields[3], 4 + len(meta) + 4 + DATA.index(b"$100"))
    row.record(outcome(rebuild(fields)))
    rows.append(row)

    row = Row("B v2", "Random bit flip (anywhere)")
    for _ in range(trials):
        package = lab.seal()
        row.record(outcome(flip_random_bit(package, 0, len(package), rng)))
    rows.append(row)

    for region in ("header", "KEM ciphertext", "nonce", "AES ciphertext + tag", "signature"):
        row = Row("B v2", f"Random bit flip in {region}")
        for _ in range(max(1, trials // 5)):
            package = lab.seal()
            row.record(outcome(flip_random_bit(package, *v2_regions(package)[region], rng)))
        rows.append(row)

    row = Row("B v2", "Truncate last block")
    row.record(outcome(lab.seal()[:-16]))
    rows.append(row)

    # The cloud makes its own key pair, calls itself "alice", and signs a fake file.
    row = Row("B v2", "Cloud forges a new file")
    fake_alice = Identity.generate("alice", lab.ta.suite)
    row.record(outcome(lab.seal(b"FAKE INVOICE", identity=fake_alice)))
    rows.append(row)

    row = Row("B v2", "Replay an old file")
    seen, package = set(), lab.seal()
    lab.open(package, seen=seen)
    row.record(outcome(package, seen=seen))
    rows.append(row)

    # Mallory is a real user with a real certificate, but writes "alice" as the sender.
    row = Row("B v2", "Mallory pretends to be Alice")
    h, k, n, c, _ = parse_package(lab.seal(sender="mallory"))
    header = json.loads(h)
    header["sender"] = "alice"
    h = canonical_json(header)
    row.record(outcome(rebuild([h, k, n, c, suite_sign(lab.users["mallory"].sig_sk, _to_be_signed(h, k, n, c))])))
    rows.append(row)

    row = Row("B v2", "Wrong person opens the file")
    row.record(outcome(lab.seal(), as_user="mallory"))
    rows.append(row)

    # The cloud puts Mallory's KEM key into Bob's certificate; it cannot re-sign it.
    row = Row("B v2", "Cloud swaps recipient's key")
    forged_cert = {"body": dict(lab.certs["bob"]["body"]), "ta_sig": lab.certs["bob"]["ta_sig"]}
    forged_cert["body"]["kem_pk"] = lab.certs["mallory"]["body"]["kem_pk"]
    try:
        seal(DATA, sender=lab.users["alice"], recipient_cert=forged_cert, ta_pk=lab.ta.sig_pk,
             filename="x.txt", category="financial")
        row.record(SUCCEEDED)
    except CertificateError:
        row.record("sender refused certificate")
    rows.append(row)

    # Mallory takes Alice's package, claims it as her own and re-signs it.
    row = Row("B v2", "Signature swap")
    h, k, n, c, _ = parse_package(lab.seal())
    header = json.loads(h)
    header["sender"] = "mallory"
    h = canonical_json(header)
    row.record(outcome(rebuild([h, k, n, c, suite_sign(lab.users["mallory"].sig_sk, _to_be_signed(h, k, n, c))])))
    rows.append(row)

    # The cloud rewrites the routing header so Bob's file lands in Mallory's inbox.
    row = Row("B v2", "Redirect package to Mallory")
    h, k, n, c, s = parse_package(lab.seal())
    header = json.loads(h)
    header["recipient"] = "mallory"
    row.record(outcome(rebuild([canonical_json(header), k, n, c, s]), as_user="mallory"))
    rows.append(row)
    return rows


# ---------------------------------------------------------------- report

def build_table(rows: list[Row]) -> str:
    versions = ["A", "B v1", "B v2"]
    # v2 runs every attack, so its order (region rows under "anywhere") sets the table order.
    attacks = list(dict.fromkeys([r.attack for r in rows if r.version == "B v2"] + [r.attack for r in rows]))
    cells = {(r.version, r.attack): r.cell() for r in rows}
    lines = ["| Attack | Version A | Version B v1 | Version B v2 |", "|---|---|---|---|"]
    for attack in attacks:
        lines.append(f"| {attack} | " + " | ".join(cells.get((v, attack), "—") for v in versions) + " |")
    return "\n".join(lines)


def run(trials: int = 200, seed: int = 1, suite: str = "pq") -> list[Row]:
    rng = random.Random(seed)
    lab = Lab(suite)
    return attack_version_a(trials, rng) + attack_version_b(lab, trials, rng) + attack_version_b2(lab, trials, rng)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--trials", type=int, default=200, help="trials per random attack")
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()

    rows = run(args.trials, args.seed)
    RESULTS.mkdir(exist_ok=True)
    with open(RESULTS / "attack_table.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["version", "attack", "trials", "blocked", "succeeded", "outcomes"])
        for r in rows:
            writer.writerow([r.version, r.attack, r.trials, r.blocked, r.outcomes[SUCCEEDED],
                             json.dumps(dict(r.outcomes))])
    table = build_table(rows)
    (RESULTS / "attack_table.md").write_text(
        f"# Attack table\n\nTrials per random attack: {args.trials}, seed {args.seed}.\n\n{table}\n")
    print(table)
    print(f"\nSaved {RESULTS / 'attack_table.csv'} and {RESULTS / 'attack_table.md'}")


if __name__ == "__main__":
    main()
