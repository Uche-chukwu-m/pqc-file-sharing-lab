import random

import pytest

from experiments.size_leakage import evaluate, generate_dataset, package_sizes
from pqcshare.encoding import canonical_json
from pqcshare.signed_package import padded_length, parse_package
from tests.test_signed_package import World


@pytest.mark.parametrize("n", [2, 3, 100, 1000, 4097, 65_537, 1_000_000, 7_999_999])
def test_policies_never_shrink_and_respect_their_bounds(n):
    assert padded_length(n, None) == n
    assert padded_length(n, 4096) % 4096 == 0 and 0 <= padded_length(n, 4096) - n < 4096
    p2 = padded_length(n, "pow2")
    assert p2 >= n and p2 & (p2 - 1) == 0 and p2 < 2 * n
    assert n <= padded_length(n, "padme") <= n * 1.12 + 1


def test_padme_collapses_many_sizes_into_few():
    sizes = {padded_length(n, "padme") for n in range(100_000, 200_000)}
    assert len(sizes) < 300


def test_unknown_policy_is_an_error():
    with pytest.raises(ValueError):
        padded_length(10, "zip")


@pytest.mark.parametrize("policy", ["pow2", "padme", 1024])
def test_padded_packages_still_round_trip(policy):
    world = World("classical")
    data = b"x" * 1500
    package = world.seal(data, pad_to=policy)
    meta = canonical_json({"category": "medical", "filename": "lab_report.txt"})
    inner = 4 + len(meta) + 4 + len(data)        # lp(meta) + lp(data), before padding
    assert len(parse_package(package)[3]) - 16 == padded_length(inner, policy)
    assert world.open(package).data == data


def test_size_experiment_runs_end_to_end():
    files = generate_dataset(10, random.Random(1))
    labels = [f["category"] for f in files]
    for policy in (None, 8 * 1024 * 1024):
        scores = evaluate(package_sizes(files, policy, suite="classical"), labels, seed=1)
        assert set(scores) == {"simple size rule", "AI (random forest)"}
    # One identical size for everything: no attacker can beat chance.
    assert scores["AI (random forest)"][0] == pytest.approx(0.25)
