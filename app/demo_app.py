"""Harbor Point demo: the whole project, running live.

    .venv/bin/streamlit run app/demo_app.py

Every button runs the real project code (pqcshare, attacks, experiments, ml) on
this laptop and shows what happened and how long it took.
"""

import json
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402
from cryptography.exceptions import InvalidTag  # noqa: E402

import charts  # noqa: E402
from attacks import attack_table  # noqa: E402
from demos.make_samples import INVOICE, SAMPLES  # noqa: E402
from demos.model_tamper_demo import run_scenarios  # noqa: E402
from experiments import benchmark, size_leakage  # noqa: E402
from pqcshare import version_a, version_b  # noqa: E402
from pqcshare.encoding import canonical_json, lp  # noqa: E402
from pqcshare.pki import CertificateError, Identity, TrustAuthority  # noqa: E402
from pqcshare.signed_package import (MAGIC, PackageRejected, _to_be_signed, open_package,  # noqa: E402
                                     parse_package, read_header, seal)
from pqcshare.suites import get_suite  # noqa: E402

RESULTS = ROOT / "results"
RECEIVE_STEPS = ["parse + check recipient", "check sender certificate", "verify signature", "replay check",
                 "decapsulate + derive key", "AES-GCM decrypt"]
PADDING = {"none": None, "Padmé": "padme", "64 KB buckets": 64 * 1024, "power of 2": "pow2"}

st.set_page_config(page_title="Harbor Point PQC demo", page_icon="🔐", layout="wide")


# ---------------------------------------------------------------- shared state

def fmt_us(us: float) -> str:
    if us < 1000:
        return f"{us:,.0f} µs"
    return f"{us / 1000:,.2f} ms" if us < 1e6 else f"{us / 1e6:,.1f} s"


def timed(fn, *args, **kwargs):
    start = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, (time.perf_counter() - start) * 1e6


def new_world() -> dict:
    """A Trust Authority, alice, bob and mallory, and an in-memory cloud."""
    ta = TrustAuthority.generate("pq")
    users = {n: Identity.generate(n) for n in ("alice", "bob", "mallory")}
    world = {"ta": ta, "users": users, "certs": {n: ta.issue(u) for n, u in users.items()},
             "inbox": [], "delivered": [], "seen": set()}
    # Warm-up: the first call to each primitive is slow; keep that out of the demo timings.
    for _ in range(3):
        p = seal(b"warm-up", sender=users["alice"], recipient_cert=world["certs"]["bob"], ta_pk=ta.sig_pk,
                 filename="w", category="medical")
        open_package(p, recipient=users["bob"], ta_pk=ta.sig_pk, fetch_cert=world["certs"].__getitem__,
                     seen_ids=set())
    return world


def world() -> dict:
    if "world" not in st.session_state:
        with st.spinner("Creating the Trust Authority and keys for alice, bob and mallory…"):
            st.session_state.world = new_world()
    return st.session_state.world


def flip(data: bytes, position: int, delta: bytes) -> bytes:
    out = bytearray(data)
    for i, d in enumerate(delta):
        out[position + i] ^= d
    return bytes(out)


AMOUNT_DELTA = bytes(a ^ b for a, b in zip(b"$100", b"$900"))


# ---------------------------------------------------------------- pages

def page_overview():
    st.title("🔐 Harbor Point: post-quantum file sharing")
    st.markdown(
        "A mock cloud file-sharing app, inspired by how iMessage and WhatsApp handle attachments, that we "
        "**built, attacked, measured, and defended**. All data is fictional.")
    st.markdown("""
| | Act | What you'll see |
|---|---|---|
| 1 | **The old system** | AES-CBC with a hard-coded key: the cloud changes an invoice from \\$100 to \\$900 and nobody notices |
| 2 | **Quantum-safe lock** | ML-KEM-768 + AES-256-GCM rejects the edit, but can't tell *who* sent a file |
| 3 | **Who sent it?** | ML-DSA certificates and signatures: send files live, attack them, run the full attack table |
| 4 | **What still leaks?** | An AI model guesses a file's category from its encrypted size; padding vs storage cost |
| 5 | **Trust the AI** | Only the signed, approved AI model loads; four tampering attempts refused |
| — | **The price tag** | Live benchmarks: time and size cost of post-quantum vs classical crypto |
""")
    st.subheader("The cast")
    st.markdown("""
- **Alice**: caseworker, sends files · **Bob**: manager, receives files
- **The Cloud**: stores everything, *not trusted*: it may snoop, edit, replay or forge
- **Mallory**: a real staff member who tries to impersonate Alice
- **Trudy, the Trust Authority**: signs everyone's certificate (ID card)
- **Eve from the future**: records traffic today, hoping a quantum computer decrypts it later
""")
    ta = world()["ta"]
    st.caption(f"Keys for this session were generated when the page opened (suite: {ta.suite}: "
               f"{get_suite(ta.suite).kem_alg} + {get_suite(ta.suite).sig_alg}). "
               "Use **Run everything** in the sidebar for the full demo in one go.")


def page_act1():
    st.title("Act 1: The old system (Version A)")
    st.markdown("AES-CBC with the **key and IV hard-coded in the source** and **no integrity check**.")
    st.code(INVOICE, language="text")

    c1, c2 = st.columns(2)
    with c1:
        if st.button("Encrypt the invoice twice with Version A", type="primary"):
            (ct1, us1), (ct2, _) = timed(version_a.encrypt, INVOICE.encode()), timed(version_a.encrypt, INVOICE.encode())
            st.session_state.a_ct = ct1
            st.write(f"Encrypted in **{fmt_us(us1)}**. First 32 bytes of each ciphertext:")
            st.code(f"run 1: {ct1[:32].hex()}\nrun 2: {ct2[:32].hex()}", language="text")
            st.warning("Identical. The same file always encrypts to the same bytes, so the cloud can tell "
                       "when two files are equal without decrypting anything.")
    with c2:
        if st.button("☁️ Cloud edits the amount: \\$100 → \\$900", disabled="a_ct" not in st.session_state):
            ct = st.session_state.a_ct
            target = INVOICE.encode().index(b"$100")
            restored, us = timed(version_a.decrypt, flip(ct, target - 16, AMOUNT_DELTA))
            st.write(f"The cloud XORs a few bytes in the **previous** block; Bob decrypts in {fmt_us(us)}:")
            st.code(restored[:48].decode("latin-1"), language="text")
            st.error("❌ ACCEPTED. The invoice now says **\\$900**. Only the first block is garbled, and "
                     "Version A never checks.")


def page_act2():
    st.title("Act 2: Quantum-safe lock (Version B v1)")
    st.markdown("**ML-KEM-768** agrees on a fresh key for every file; **AES-256-GCM** encrypts it and adds a seal (tag).")
    w = world()
    bob = w["users"]["bob"]
    data = INVOICE.encode()

    if st.button("Encrypt the invoice for Bob with Version B v1", type="primary"):
        package, us = timed(version_b.encrypt, data, bob.kem_pk)
        st.session_state.b_pkg = package
        st.write(f"Encrypted in **{fmt_us(us)}**: {len(data)} B file → {len(package):,} B package.")
        st.dataframe(pd.DataFrame([
            ("length field", 4), ("ML-KEM ciphertext", 1088), ("nonce", 12),
            ("encrypted invoice", len(data)), ("GCM tag (seal)", 16)], columns=["part", "bytes"]),
            hide_index=True, width=360)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("☁️ Cloud edits the amount: \\$100 → \\$900", disabled="b_pkg" not in st.session_state):
            tampered = flip(st.session_state.b_pkg, 4 + 1088 + 12 + data.index(b"$100"), AMOUNT_DELTA)
            try:
                version_b.decrypt(tampered, bob.kem_sk)
                st.error("Accepted (unexpected)")
            except InvalidTag:
                st.success("✅ REJECTED: the GCM seal is broken.")
    with c2:
        if st.button("☁️ Cloud forges a brand-new file for Bob"):
            fake = b"FAKE INVOICE: pay $9,000 to Mallory"
            opened = version_b.decrypt(version_b.encrypt(fake, bob.kem_pk), bob.kem_sk)
            st.error(f"❌ ACCEPTED: Bob reads “{opened.decode()}”. His public key is public, so anyone can "
                     "lock a box for him. Version B can't tell **who** sent a file. That's Act 3.")


def _seal_into_inbox(sender: str, filename: str, data: bytes, category: str, pad, label: str):
    w = world()
    timings = {}
    package = seal(data, sender=w["users"][sender], recipient_cert=w["certs"]["bob"], ta_pk=w["ta"].sig_pk,
                   filename=filename, category=category, pad_to=pad, timings=timings)
    w["inbox"].append({"package": package, "label": label})
    return package, timings


def _rebuild(fields) -> bytes:
    return MAGIC + b"".join(lp(f) for f in fields)


def page_act3():
    st.title("Act 3: Who sent it? (Version B v2)")
    st.markdown("Every user has a **certificate** signed by the Trust Authority, and every package is "
                "**signed with ML-DSA-65**. Bob checks cheap public things first and decrypts last.")
    w = world()

    st.subheader("1 · Alice sends a file")
    c1, c2, c3 = st.columns(3)
    filename = c1.selectbox("File (fictional)", list(SAMPLES))
    category = c2.selectbox("Category", ["medical", "legal", "personal", "financial"],
                            index=["medical", "legal", "personal", "financial"].index(filename.split("_")[0]))
    pad_name = c3.selectbox("Padding (Act 4)", list(PADDING))
    if st.button("Send from Alice to Bob", type="primary"):
        data = SAMPLES[filename].encode()
        package, timings = _seal_into_inbox("alice", filename, data, category, PADDING[pad_name],
                                            f"{filename} from alice")
        st.session_state.last_send = (filename, len(data), package, timings)
    if "last_send" in st.session_state:
        filename_sent, n, package, timings = st.session_state.last_send
        left, right = st.columns([1, 1])
        with left:
            st.metric("Total time to encrypt and sign", fmt_us(sum(timings.values())))
            st.write(f"{n} B file → **{len(package):,} B** package. What the cloud can read:")
            st.json(read_header(package))
            st.caption("Filename and category are inside the encryption; the cloud can't see them.")
        with right:
            st.altair_chart(charts.step_times(timings, "Sender steps"), theme=None)

    st.subheader("2 · The cloud attacks")
    st.caption("Each button puts a malicious package into Bob's inbox (except the key swap, which targets Alice).")
    b1, b2, b3, b4, b5 = st.columns(5)
    suite = get_suite(w["ta"].suite)
    if b1.button("Flip one bit", disabled=not w["inbox"]):
        newest = w["inbox"][-1]["package"]
        w["inbox"].append({"package": flip(newest, random.randrange(len(newest)), b"\x01"),
                           "label": "⚠️ bit flipped by the cloud"})
    if b2.button("Replay an old file", disabled=not w["delivered"]):
        w["inbox"].append({"package": w["delivered"][-1], "label": "⚠️ replay of a delivered file"})
    if b3.button("Forge as Alice"):
        fake_alice = Identity.generate("alice")
        package = seal(b"FAKE: pay Mallory $9,000", sender=fake_alice, recipient_cert=w["certs"]["bob"],
                       ta_pk=w["ta"].sig_pk, filename="invoice.txt", category="financial")
        w["inbox"].append({"package": package, "label": "⚠️ forged by the cloud with its own key"})
    if b4.button("Mallory poses as Alice"):
        h, k, n, c, _ = parse_package(seal(b"Please send me the case files", sender=w["users"]["mallory"],
                                           recipient_cert=w["certs"]["bob"], ta_pk=w["ta"].sig_pk,
                                           filename="note.txt", category="legal"))
        header = {**json.loads(h), "sender": "alice"}
        h = canonical_json(header)
        sig = suite.sign(w["users"]["mallory"].sig_sk, _to_be_signed(h, k, n, c))
        w["inbox"].append({"package": _rebuild([h, k, n, c, sig]), "label": "⚠️ Mallory's file claiming to be Alice's"})
    if b5.button("Swap Bob's key"):
        forged = {"body": dict(w["certs"]["bob"]["body"]), "ta_sig": w["certs"]["bob"]["ta_sig"]}
        forged["body"]["kem_pk"] = w["certs"]["mallory"]["body"]["kem_pk"]
        try:
            seal(b"x", sender=w["users"]["alice"], recipient_cert=forged, ta_pk=w["ta"].sig_pk,
                 filename="x", category="medical")
            st.error("Alice encrypted to the swapped key (unexpected)")
        except CertificateError as exc:
            st.success(f"✅ Alice REFUSES to send: Bob's certificate fails the check ({exc}). "
                       "The cloud can't forge the Trust Authority's signature.")

    st.subheader("3 · Bob opens his inbox")
    if w["inbox"]:
        st.dataframe(pd.DataFrame([{"package": i["label"], "size": f"{len(i['package']):,} B"} for i in w["inbox"]]),
                     hide_index=True)
    else:
        st.caption("Inbox is empty. Send a file first.")
    if st.button("Bob verifies and opens everything", type="primary", disabled=not w["inbox"]):
        rows, accepted_steps = [], None
        for item in w["inbox"]:
            timings = {}
            try:
                opened = open_package(item["package"], recipient=w["users"]["bob"], ta_pk=w["ta"].sig_pk,
                                      fetch_cert=w["certs"].__getitem__, seen_ids=w["seen"], timings=timings)
                w["delivered"].append(item["package"])
                result, reason, stopped = "✅ accepted", f"from {opened.sender}: {opened.filename}", "—"
                accepted_steps = timings
            except PackageRejected as exc:
                stopped = RECEIVE_STEPS[len(timings)] if len(timings) < len(RECEIVE_STEPS) else "—"
                result, reason = "❌ rejected", exc.reason
            rows.append({"package": item["label"], "result": result, "detail": reason,
                         "stopped at": stopped, "time": fmt_us(sum(timings.values()))})
        w["inbox"].clear()
        st.session_state.last_receive = (rows, accepted_steps)
    if "last_receive" in st.session_state:
        rows, accepted_steps = st.session_state.last_receive
        st.dataframe(pd.DataFrame(rows), hide_index=True)
        st.caption("Rejections stop early, at the first failed check. Nothing unverified is ever decrypted.")
        if accepted_steps:
            st.altair_chart(charts.step_times(accepted_steps, "Recipient steps (last accepted file)"), theme=None)

    st.subheader("4 · The full attack table")
    trials = st.slider("Random trials per attack", 20, 1000, 200, step=20)
    if st.button("Run all attacks against Versions A, B v1 and B v2", type="primary"):
        with st.spinner("Attacking…"):
            rows, us = timed(attack_table.run, trials, 1)
        st.session_state.attack_rows = (rows, us, trials)
    if "attack_rows" in st.session_state:
        rows, us, trials = st.session_state.attack_rows
        _show_attack_table(rows, us, trials)


def _show_attack_table(rows, us, trials):
    v2 = [r for r in rows if r.version == "B v2"]
    blocked = sum(r.blocked for r in v2)
    total = sum(r.trials for r in v2)
    m1, m2, m3 = st.columns(3)
    m1.metric("Attack attempts on v2 blocked", f"{blocked:,} / {total:,}")
    m2.metric("Trials per random attack", trials)
    m3.metric("Time for the whole table", fmt_us(us))
    cells = {(r.version, r.attack): r.cell() for r in rows}
    attacks = list(dict.fromkeys([r.attack for r in v2] + [r.attack for r in rows]))
    st.dataframe(pd.DataFrame([{"attack": a, **{v: cells.get((v, a), "—") for v in ("A", "B v1", "B v2")}}
                               for a in attacks]), hide_index=True)


def _load_saved_leakage():
    summary, files = RESULTS / "size_leakage_summary.csv", RESULTS / "size_leakage_files.csv"
    if not summary.exists():
        return None
    rows = pd.read_csv(summary).to_dict("records")
    df_files = pd.read_csv(files)[["category", "doc_type", "file_size"]] if files.exists() else None
    return rows, df_files, None


def page_act4():
    st.title("Act 4: What still leaks?")
    st.markdown("Encryption hides **what's in** a file, not **how big** it is. Can an AI model guess the "
                "category (medical, legal, personal, financial) from the encrypted package size alone? "
                "And how much does padding cost to stop it?")
    c1, c2 = st.columns([2, 1])
    per_cat = c1.slider("Fictional files per category (live run)", 25, 200, 50, step=25,
                        help="Every file is really sealed with Version B v2 under six padding policies.")
    c2.write("")
    run = c2.button("Run live", type="primary")
    saved = c2.button("Show saved results (800 files)")
    if run:
        bar = st.progress(0.0, text="Starting…")
        result, us = timed(size_leakage.run_experiment, per_cat, 1,
                           progress=lambda f, name: bar.progress(f, text=f"Sealing and attacking: {name}"))
        files, rows, confusions = result
        bar.empty()
        st.session_state.leak = (rows, pd.DataFrame(files)[["category", "doc_type", "file_size"]], confusions,
                                 f"live: {len(files)} files in {fmt_us(us)}")
    if saved:
        loaded = _load_saved_leakage()
        if loaded is None:
            st.warning("No saved results yet: run `python -m experiments.size_leakage` first.")
        else:
            st.session_state.leak = (*loaded, "saved results from results/size_leakage_summary.csv")
    if "leak" not in st.session_state:
        return
    rows, df_files, confusions, source = st.session_state.leak
    st.caption(source)
    no_pad = next(r for r in rows if r["policy"] == "no padding")
    uniform = next(r for r in rows if r["policy"].startswith("uniform"))
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Chance", "25%")
    m2.metric("AI, no padding", f"{no_pad['AI (random forest) acc']:.1%}")
    m3.metric("Simple size rule, no padding", f"{no_pad['simple size rule acc']:.1%}")
    m4.metric("AI, everything padded equal", f"{uniform['AI (random forest) acc']:.1%}",
              delta=f"{uniform['storage_overhead']:+.0%} storage", delta_color="inverse")
    if df_files is not None:
        st.altair_chart(charts.size_strip(df_files), theme=None)
    st.altair_chart(charts.leakage_tradeoff(pd.DataFrame(
        [{"policy": r["policy"].split(" (")[0], "storage_overhead": r["storage_overhead"],
          "ai_acc": r["AI (random forest) acc"]} for r in rows])), theme=None)
    st.dataframe(pd.DataFrame([{
        "padding policy": r["policy"],
        "simple rule": f"{r['simple size rule acc']:.1%} ± {r['simple size rule sd']:.1%}",
        "AI (random forest)": f"{r['AI (random forest) acc']:.1%} ± {r['AI (random forest) sd']:.1%}",
        "distinct sizes seen": r["distinct_sizes"],
        "extra storage": f"{r['storage_overhead']:+.1%}"} for r in rows]), hide_index=True)
    if confusions:
        st.markdown("**AI confusion matrix, no padding** (rows = true category, columns = AI's guess)")
        st.dataframe(pd.DataFrame(confusions["no padding"], index=size_leakage.CATEGORIES,
                                  columns=size_leakage.CATEGORIES))
    st.caption("File sizes are our assumptions (DOC_TYPES in experiments/size_leakage.py). "
               "Accuracy: 5-fold cross-validation repeated 3 times, always on files the model didn't train on.")


def page_act5():
    st.title("Act 5: Trust the AI")
    st.markdown("Someone wants the leakage analysis to say *no leak*, so they try to swap in a **rigged model** "
                "(trained on shuffled labels). The loader checks **approved signer → certificate → ML-DSA "
                "signature → SHA-256 hash**, and only then parses the exact bytes it checked. "
                "Models are saved with skops, never pickle.")
    if st.button("Run the five attempts", type="primary"):
        with st.spinner("Training a small model, signing it, and tampering with it…"):
            st.session_state.models = run_scenarios()
    for r in st.session_state.get("models", []):
        box = st.success if r["loaded"] else st.error
        icon = "✅ LOADED" if r["loaded"] else "🚫 REFUSED"
        box(f"**{r['title']}**  \n{icon}: {r['detail']}  ·  {r['ms']:.1f} ms")
    if st.session_state.get("models"):
        st.caption("Refusals are fast because nothing gets parsed; only the approved model reaches the parser.")


def _benchmark_frames(summary: dict, sizes: dict):
    e2e = pd.DataFrame([{"setup": k[1], "file_size": k[2], "operation": k[3], "median_us": v[0], "iqr_us": v[1]}
                        for k, v in summary.items() if k[0] == "end-to-end"])
    blocks = pd.DataFrame([{"suite": k[1], "operation": k[3], "median_us": v[0]}
                           for k, v in summary.items() if k[0] == "building block" and k[2] == "—"])
    overhead = pd.DataFrame([{"setup": s, "overhead_bytes": pkg - n}
                             for (s, size), (n, pkg) in sizes.items() if size == "1 KB"])
    return e2e, blocks, overhead


def _load_saved_benchmark():
    path = RESULTS / "benchmark_summary.csv"
    if not path.exists():
        return None
    df = pd.read_csv(path)
    summary = {(r.group, r.setup, r.file_size, r.operation): (r.median_us, r.iqr_us) for r in df.itertuples()}
    sizes = {(r.setup, r.file_size): (int(r.file_bytes), int(r.package_bytes))
             for r in df.itertuples() if r.group == "end-to-end" and pd.notna(r.package_bytes)}
    env = {}
    md = RESULTS / "benchmark.md"
    if md.exists():
        for line in md.read_text().splitlines():
            if line.startswith("- **") and ":**" in line:
                k, v = line[4:].split(":**", 1)
                env[k] = v.strip()
    return summary, sizes, env


def page_epilogue():
    st.title("Epilogue: The price tag")
    st.markdown("Time and size for all four setups. The fair comparison is **v2 pq vs v2 classical**: "
                "identical code, only the key exchange and signature algorithms differ.")
    c1, c2 = st.columns([2, 1])
    runs = c1.slider("Timed runs per measurement (live run)", 20, 1000, 100, step=20)
    c2.write("")
    run = c2.button("Run live", type="primary")
    saved = c2.button("Show saved results")
    if run:
        bar = st.progress(0.0, text="Warming up…")
        (samples, sizes, env), us = timed(benchmark.measure, runs, 20, 1,
                                         progress=lambda f: bar.progress(f, text=f"Measuring… {f:.0%}"))
        bar.empty()
        st.session_state.bench = (benchmark.summarize(samples), sizes, env, f"live: {runs} runs, {fmt_us(us)}")
    if saved:
        loaded = _load_saved_benchmark()
        if loaded is None:
            st.warning("No saved results yet: run `python -m experiments.benchmark` first.")
        else:
            st.session_state.bench = (*loaded, "saved results from results/benchmark_summary.csv")
    if "bench" not in st.session_state:
        return
    summary, sizes, env, source = st.session_state.bench
    st.caption(source)
    e2e, blocks, overhead = _benchmark_frames(summary, sizes)
    pq_enc = blocks.query("suite == 'ML-KEM-768 / ML-DSA-65' and operation == 'encapsulate'")["median_us"].iloc[0]
    cl_enc = blocks.query("suite == 'X25519 / Ed25519' and operation == 'encapsulate'")["median_us"].iloc[0]
    pq_over = overhead.query("setup == 'v2 pq'")["overhead_bytes"].iloc[0]
    cl_over = overhead.query("setup == 'v2 classical'")["overhead_bytes"].iloc[0]
    m1, m2, m3 = st.columns(3)
    m1.metric("ML-KEM encapsulate vs X25519", fmt_us(pq_enc), delta=f"{pq_enc / cl_enc:.2f}× X25519's time",
              delta_color="off")
    m2.metric("Extra bytes per file, v2 pq", f"{pq_over:,}", delta=f"vs {cl_over:,} classical", delta_color="off")
    m3.metric("Machine", env.get("cpu", "?"), delta=env.get("power source", ""), delta_color="off")
    for op, title in (("encrypt", "Sender: encrypt (and sign)"), ("decrypt", "Recipient: verify and decrypt")):
        st.altair_chart(charts.setup_times(e2e[e2e["operation"] == op], title), theme=None)
    left, right = st.columns(2)
    left.altair_chart(charts.overhead_bars(overhead), theme=None)
    right.altair_chart(charts.building_blocks(blocks), theme=None)
    with st.expander("Data tables and machine details"):
        table = e2e.pivot_table(index=["operation", "setup"], columns="file_size", values="median_us")
        st.dataframe(table[[s for s in charts.SIZES if s in table.columns]].round(1))
        st.dataframe(blocks.round(1), hide_index=True)
        st.json(env)
    if "Battery" in env.get("power source", ""):
        st.warning("Measured on battery. For the paper, plug in and use 1000 runs.")


def page_run_all():
    st.title("Run everything")
    st.markdown("Runs every act in order with demo-sized settings and reports how long each took.")
    if not st.button("▶ Run the whole project", type="primary"):
        return
    w = world()
    total_start = time.perf_counter()
    summary = {}

    with st.status("Act 1 · Version A accepts the \\$900 invoice", expanded=False) as s:
        ct = version_a.encrypt(INVOICE.encode())
        restored, us = timed(version_a.decrypt, flip(ct, INVOICE.encode().index(b"$100") - 16, AMOUNT_DELTA))
        ok = b"$900" in restored
        s.update(label=f"Act 1 · Version A {'accepted' if ok else 'rejected'} the \\$900 edit ({fmt_us(us)})",
                 state="complete")
    with st.status("Act 2 · Version B rejects it", expanded=False) as s:
        data = INVOICE.encode()
        pkg = version_b.encrypt(data, w["users"]["bob"].kem_pk)
        try:
            version_b.decrypt(flip(pkg, 4 + 1088 + 12 + data.index(b"$100"), AMOUNT_DELTA), w["users"]["bob"].kem_sk)
            label = "Act 2 · Version B accepted the edit (unexpected)"
        except InvalidTag:
            label = "Act 2 · Version B rejected the edit (GCM tag)"
        s.update(label=label, state="complete")
    with st.status("Act 3 · Signed send + full attack table", expanded=False) as s:
        t_send, t_open = {}, {}
        package = seal(SAMPLES["medical_lab_report.txt"].encode(), sender=w["users"]["alice"],
                       recipient_cert=w["certs"]["bob"], ta_pk=w["ta"].sig_pk, filename="medical_lab_report.txt",
                       category="medical", timings=t_send)
        open_package(package, recipient=w["users"]["bob"], ta_pk=w["ta"].sig_pk,
                     fetch_cert=w["certs"].__getitem__, seen_ids=set(), timings=t_open)
        rows, us = timed(attack_table.run, 200, 1)
        st.session_state.attack_rows = (rows, us, 200)
        v2 = [r for r in rows if r.version == "B v2"]
        summary["attacks"] = (sum(r.blocked for r in v2), sum(r.trials for r in v2))
        s.update(label=f"Act 3 · Send {fmt_us(sum(t_send.values()))}, receive {fmt_us(sum(t_open.values()))}; "
                       f"v2 blocked {summary['attacks'][0]:,}/{summary['attacks'][1]:,} attacks ({fmt_us(us)})",
                 state="complete")
    with st.status("Act 4 · AI size-leakage experiment (50 files per category)", expanded=False) as s:
        (files, rows, confusions), us = timed(size_leakage.run_experiment, 50, 1)
        st.session_state.leak = (rows, pd.DataFrame(files)[["category", "doc_type", "file_size"]], confusions,
                                 f"live: {len(files)} files in {fmt_us(us)}")
        no_pad = next(r for r in rows if r["policy"] == "no padding")["AI (random forest) acc"]
        uniform = next(r for r in rows if r["policy"].startswith("uniform"))["AI (random forest) acc"]
        summary["ai"] = (no_pad, uniform)
        s.update(label=f"Act 4 · AI accuracy {no_pad:.0%} without padding, {uniform:.0%} fully padded ({fmt_us(us)})",
                 state="complete")
    with st.status("Act 5 · Signed model vs tampering", expanded=False) as s:
        results, us = timed(run_scenarios)
        st.session_state.models = results
        refused = sum(not r["loaded"] for r in results[1:])
        summary["models"] = (results[0]["loaded"], refused, len(results) - 1)
        s.update(label=f"Act 5 · Approved model {'loaded' if results[0]['loaded'] else 'NOT loaded'}; "
                       f"{refused}/{len(results) - 1} tampering attempts refused ({fmt_us(us)})", state="complete")
    with st.status("Epilogue · Benchmarks (50 runs)", expanded=False) as s:
        (samples, sizes, env), us = timed(benchmark.measure, 50, 10, 1)
        bsum = benchmark.summarize(samples)
        st.session_state.bench = (bsum, sizes, env, f"live: 50 runs, {fmt_us(us)}")
        n, pkg = sizes[("v2 pq", "1 KB")]
        summary["overhead"] = pkg - n
        s.update(label=f"Epilogue · v2 pq adds {pkg - n:,} B per file; measured in {fmt_us(us)}", state="complete")

    total = (time.perf_counter() - total_start)
    st.subheader(f"Done in {total:.1f} s")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Attacks on v2 blocked", f"{summary['attacks'][0]:,}/{summary['attacks'][1]:,}")
    m2.metric("AI size attack: no padding → full padding", f"{summary['ai'][0]:.0%} → {summary['ai'][1]:.0%}")
    m3.metric("Tampered models refused", f"{summary['models'][1]}/{summary['models'][2]}")
    m4.metric("PQC size cost per file", f"{summary['overhead']:,} B")
    st.caption("Open each act in the sidebar to see the detailed charts from this run.")


pages = [
    st.Page(page_overview, title="Overview", icon="🏠", default=True),
    st.Page(page_act1, title="Act 1 · The old system", icon="🔓", url_path="act1"),
    st.Page(page_act2, title="Act 2 · Quantum-safe lock", icon="🔒", url_path="act2"),
    st.Page(page_act3, title="Act 3 · Who sent it?", icon="🪪", url_path="act3"),
    st.Page(page_act4, title="Act 4 · What still leaks?", icon="📏", url_path="act4"),
    st.Page(page_act5, title="Act 5 · Trust the AI", icon="🤖", url_path="act5"),
    st.Page(page_epilogue, title="Epilogue · The price tag", icon="⏱️", url_path="epilogue"),
    st.Page(page_run_all, title="Run everything", icon="▶️", url_path="run-all"),
]
if __name__ == "__main__":  # streamlit run; tests import the page functions instead
    st.navigation(pages).run()
