# Benchmark results

200 timed runs per measurement after 20 warm-up runs; seed 1.
Times are medians in microseconds (µs), with the interquartile range. No file I/O.

## Machine

- **date:** 2026-10-15T19:16:03
- **cpu:** Apple M4
- **os:** macOS-27.0.1-arm64-arm-64bit-Mach-O
- **python:** 3.14.3
- **liboqs:** 0.16.0
- **liboqs-python:** 0.16.0.1
- **cryptography:** 50.0.2
- **power source:** Battery Power

## Sender: encrypt (and sign), µs

| Setup | 1 KB | 100 KB | 1 MB |
|---|---|---|---|
| A | 4.6 (IQR 0.7) | 54.5 (IQR 5.1) | 504.7 (IQR 15.9) |
| B v1 (pq) | 20.7 (IQR 2.0) | 32.9 (IQR 2.9) | 139.0 (IQR 9.1) |
| v2 classical | 108.5 (IQR 8.4) | 237.6 (IQR 16.8) | 1,407.9 (IQR 24.6) |
| v2 pq | 175.0 (IQR 51.0) | 354.3 (IQR 56.4) | 1,945.5 (IQR 76.1) |

## Recipient: verify and decrypt, µs

| Setup | 1 KB | 100 KB | 1 MB |
|---|---|---|---|
| A | 4.2 (IQR 0.9) | 20.5 (IQR 2.6) | 143.6 (IQR 13.0) |
| B v1 (pq) | 22.1 (IQR 2.0) | 33.7 (IQR 3.1) | 139.0 (IQR 11.7) |
| v2 classical | 115.9 (IQR 9.8) | 185.8 (IQR 12.4) | 824.5 (IQR 22.5) |
| v2 pq | 138.7 (IQR 11.8) | 304.5 (IQR 20.4) | 1,872.2 (IQR 55.4) |

## Package size

| Setup | 1 KB | 100 KB | 1 MB | Fixed overhead |
|---|---|---|---|---|
| A | 1,040 B (+1.56%) | 102,416 B (+0.02%) | 1,048,592 B (+0.00%) | 16 B |
| B v1 (pq) | 2,144 B (+109.38%) | 103,520 B (+1.09%) | 1,049,696 B (+0.11%) | 1,120 B |
| v2 classical | 1,347 B (+31.54%) | 102,723 B (+0.32%) | 1,048,899 B (+0.03%) | 323 B |
| v2 pq | 5,641 B (+450.88%) | 107,017 B (+4.51%) | 1,053,193 B (+0.44%) | 4,617 B |

Version A's overhead is only padding. Its packages are small because it has no key exchange and no integrity check, not because it is efficient.

## Building blocks, µs

| Algorithms | Operation | Median (IQR) |
|---|---|---|
| X25519 / Ed25519 | KEM keygen | 15.7 (IQR 1.5) |
| X25519 / Ed25519 | encapsulate | 30.8 (IQR 2.6) |
| X25519 / Ed25519 | decapsulate | 29.2 (IQR 3.0) |
| X25519 / Ed25519 | signature keygen | 15.9 (IQR 1.4) |
| X25519 / Ed25519 | sign | 27.0 (IQR 2.9) |
| X25519 / Ed25519 | verify | 35.1 (IQR 3.4) |
| ML-KEM-768 / ML-DSA-65 | KEM keygen | 15.1 (IQR 1.3) |
| ML-KEM-768 / ML-DSA-65 | encapsulate | 15.7 (IQR 1.3) |
| ML-KEM-768 / ML-DSA-65 | decapsulate | 17.7 (IQR 1.7) |
| ML-KEM-768 / ML-DSA-65 | signature keygen | 43.9 (IQR 3.8) |
| ML-KEM-768 / ML-DSA-65 | sign | 71.4 (IQR 45.3) |
| ML-KEM-768 / ML-DSA-65 | verify | 40.6 (IQR 3.7) |

| AES-256-GCM | 1 KB | 100 KB | 1 MB |
|---|---|---|---|
| encrypt | 1.4 (IQR 0.2) | 11.9 (IQR 1.2) | 107.5 (IQR 10.2) |
| decrypt | 1.5 (IQR 0.2) | 11.7 (IQR 1.1) | 105.3 (IQR 10.0) |
