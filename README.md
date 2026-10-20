# PQC File Sharing Lab

A mock cloud file-sharing app (inspired by how iMessage and WhatsApp handle
attachments) that we build, attack, and measure. Fictional data only.

| Story act | What it shows | Code |
|---|---|---|
| 1. The old system | Hard-coded key, fixed IV, no integrity check | `pqcshare/version_a.py` |
| 2. Quantum-safe lock | ML-KEM-768 + HKDF + AES-256-GCM (rough draft design) | `pqcshare/version_b.py` |
| 3. Who sent it? | Trust Authority certificates + ML-DSA-65 signed packages | `pqcshare/pki.py`, `pqcshare/signed_package.py` |
| 4. What still leaks? | File size → category (AI attacker), padding fix | `experiments/size_leakage.py` |
| 5. Trust the AI | Signed AI model and result reports | `ml/`, `demos/model_tamper_demo.py` |
| Epilogue | Time and size cost vs. X25519 + Ed25519 | `experiments/benchmark.py` |

## Setup

macOS (Homebrew):

```sh
brew install liboqs
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q          # 74 tests should pass
```

`pqcshare/_oqs.py` points liboqs-python at Homebrew's liboqs automatically. On
Windows or Linux, install liboqs 0.16 and set `OQS_INSTALL_PATH` to its install
prefix. Otherwise liboqs-python tries to build liboqs itself, which needs cmake.

## Live demo app

```sh
.venv/bin/streamlit run app/demo_app.py      # opens http://localhost:8501
```

One page per act, plus **Run everything** (about 15 s). Every button runs the real
code and shows timings. Act 4 and the Epilogue can run live (small settings) or
show the saved full-size results from `results/`. It runs entirely on the laptop;
nothing is sent anywhere.

### Deploying (Streamlit Community Cloud)

1. At https://share.streamlit.io choose **Create app**, pick this repository, branch
   `main`, main file `app/demo_app.py`.
2. Under **Advanced settings**, choose Python **3.12**.
3. `packages.txt` installs the build tools liboqs needs on Linux. On first start,
   liboqs-python downloads and compiles liboqs (1–2 minutes), so the first page load is slow.

## Command-line demos

```sh
P=.venv/bin/python
$P -m demos.make_samples                 # fictional files in data/samples/
$P -m demos.bitflip_demo                 # $100 -> $900: A accepts, B v1 and v2 reject

$P -m pqcshare.cli setup                 # TA + alice, bob, mallory, approver (--suite classical for baseline)
$P -m pqcshare.cli send --from alice --to bob --file data/samples/medical_lab_report.txt --category medical
$P -m pqcshare.cli receive --as bob      # verifies, decrypts to lab/users/bob/received/

$P -m attacks.attack_table              # Week 3 attack table -> results/attack_table.{csv,md}
$P -m experiments.benchmark             # Week 4 time + size -> results/benchmark*.{csv,md}
$P -m experiments.size_leakage          # Act 4 AI size attack -> results/size_leakage*.{csv,md} (~30 s)
$P -m demos.model_tamper_demo           # Act 5: approved model loads, 4 tampering attempts refused
$P -m ml.train_size_model               # train + sign models/size_classifier.skops (needs setup)
$P -m ml.sign_results sign              # approver signs results/; "verify" checks them

# Replay: the cloud re-delivers an old package
cp lab/users/bob/downloaded/*.pkg lab/cloud/inbox/bob/ && $P -m pqcshare.cli receive --as bob
```

`lab/` holds private keys in plain JSON (lab only) and is git-ignored.

## Version B v2 design (Act 3)

**Package:** `"PQS2" | header | kem_ct | nonce | ciphertext+tag | signature`, every field length-prefixed.

- **Header** (visible to the cloud, routing only): `v, suite, sender, recipient, file_id, ts`.
- **Encrypted inside:** filename, category, file bytes, and optional padding.
- **AES key** = HKDF(shared secret, info = header + kem_ct), so each key belongs to one package.
- **AES-GCM AAD** = header, so the routing fields cannot be changed.
- **Signature** (sender's ML-DSA) covers header, kem_ct, nonce and ciphertext.

**Sender** checks the recipient's certificate against the pinned TA key before
encrypting. That blocks key substitution.

**Recipient order:** parse → addressed to me? → sender certificate valid? →
signature valid? → seen this file_id? → decapsulate and decrypt. Every failure
gives the same `package rejected` message; `.reason` is for tests and demo logs.

Measured package overhead with the pq suite: about 4.6 KB per file (1088 B KEM
ciphertext + 3309 B ML-DSA signature + nonce, tag and header).

## Next steps

- **Week 3, Partner B:** done. `attacks/attack_table.py` runs 10 attacks (plus bit flips
  per package region) against A, B v1 and B v2. Re-run with more trials for the
  paper, e.g. `--trials 1000`.
- **Week 4:** benchmarks done (`experiments/benchmark.py`). For the paper: plug the
  laptop in, close other apps, run `--runs 1000`. The power source is recorded in
  `results/benchmark.md`.
- **Weeks 4–5:** size leakage done (`experiments/size_leakage.py`). The assumed file
  sizes are in `DOC_TYPES` at the top. Results depend on them, so say so in the paper.
  Padding policies: `seal(..., pad_to=N | "pow2" | "padme")`, or `--pad` in the CLI.
- **Week 5:** model and report signing done (`ml/`). Models are saved with skops, never
  pickle. The loader checks signer → signature → hash, then parses only the
  verified bytes. Only users in `APPROVERS` may sign.
- **Demo app:** `app/demo_app.py` (Streamlit) shows every act live, with charts.
- **Next:** Week 6 buffer and code freeze; Week 7 figures and writing.

## Limitations (keep in the paper)

- Private keys unencrypted on disk; no key rotation or revocation.
- No forward secrecy: if Bob's KEM key leaks, past packages can be decrypted.
- Python timing is noisy; no side-channel resistance is claimed.
- The cloud still sees sender, recipient, time and package size.
