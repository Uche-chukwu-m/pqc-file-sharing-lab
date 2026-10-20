import random

from experiments.benchmark import SETUPS, SIZES, build_tasks


def test_every_benchmark_task_runs_once():
    tasks, sizes = build_tasks(random.Random(1))
    for *_, fn in tasks:
        fn()
    assert set(sizes) == {(setup, size) for setup in SETUPS for size in SIZES}


def test_unsigned_pq_overhead_matches_the_rough_draft():
    _, sizes = build_tasks(random.Random(1))
    n, package = sizes[("B v1 (pq)", "1 KB")]
    assert package - n == 4 + 1088 + 12 + 16
