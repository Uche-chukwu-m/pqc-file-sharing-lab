from attacks.attack_table import SUCCEEDED, run


def test_signed_version_blocks_every_attack():
    rows = run(trials=20, seed=3)
    v2 = [r for r in rows if r.version == "B v2"]
    assert v2 and all(r.outcomes[SUCCEEDED] == 0 and r.blocked == r.trials for r in v2)


def test_unsigned_version_falls_to_forgery_replay_and_key_swap():
    rows = {r.attack: r for r in run(trials=5, seed=3) if r.version == "B v1"}
    for attack in ("Cloud forges a new file", "Replay an old file", "Cloud swaps recipient's key"):
        assert rows[attack].outcomes[SUCCEEDED] == 1
