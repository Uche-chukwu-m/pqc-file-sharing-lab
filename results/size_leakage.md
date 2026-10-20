# Size leakage (Act 4)

800 fictional files (200 per category, 459 MB), seed 1. Each file was sealed with Version B v2 (ML-KEM-768 + ML-DSA-65); the attackers see only package sizes.
Accuracy = mean ± standard deviation over 5-fold cross-validation repeated 3 times. Chance = 25%.

| Padding policy | Simple size rule | AI (random forest) | Distinct sizes seen | Extra storage (total) | Extra storage (median file) |
|---|---|---|---|---|---|
| no padding | 39.6% ± 2.7% | 46.6% ± 3.2% | 797 | +0.8% | +3.5% |
| 64 KB buckets | 39.9% ± 2.4% | 42.5% ± 3.3% | 67 | +7.6% | +23.1% |
| 1 MB buckets | 25.0% ± 0.0% | 32.8% ± 1.6% | 6 | +142.1% | +699.6% |
| power of 2 | 37.0% ± 2.0% | 50.2% ± 3.9% | 15 | +47.5% | +60.7% |
| Padmé | 39.5% ± 2.8% | 48.1% ± 2.9% | 272 | +2.0% | +4.6% |
| uniform (everything padded to 8 MiB) | 25.0% ± 0.0% | 25.0% ± 0.0% | 1 | +1363.0% | +6272.6% |

## AI confusion matrix: no padding

Rows = true category, columns = AI's guess.

| | medical | legal | personal | financial |
|---|---|---|---|---|
| **medical** | 78 | 30 | 32 | 60 |
| **legal** | 32 | 63 | 54 | 51 |
| **personal** | 32 | 47 | 118 | 3 |
| **financial** | 46 | 38 | 4 | 112 |

## AI confusion matrix: Padmé

Rows = true category, columns = AI's guess.

| | medical | legal | personal | financial |
|---|---|---|---|---|
| **medical** | 71 | 33 | 34 | 62 |
| **legal** | 26 | 66 | 55 | 53 |
| **personal** | 32 | 51 | 115 | 2 |
| **financial** | 38 | 37 | 3 | 122 |

## Assumed file types and typical sizes

| Category | Document type | Typical size | Spread |
|---|---|---|---|
| medical | lab report PDF | 60 KB | 0.5 |
| medical | appointment note | 6 KB | 0.6 |
| medical | prescription scan | 350 KB | 0.5 |
| legal | contract PDF | 250 KB | 0.7 |
| legal | case note | 15 KB | 0.6 |
| legal | evidence scan | 1,500 KB | 0.6 |
| personal | family message | 2 KB | 0.8 |
| personal | photo | 2,500 KB | 0.5 |
| personal | ID scan | 500 KB | 0.4 |
| financial | bank statement PDF | 180 KB | 0.5 |
| financial | invoice PDF | 70 KB | 0.5 |
| financial | transaction export CSV | 40 KB | 1.0 |
