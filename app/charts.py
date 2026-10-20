"""Altair charts for the demo app.

Colors come from a validated colorblind-safe categorical palette, assigned to
entities in a fixed order so the same thing is always the same color:
our design (v2 pq) is always blue, the classical baseline always orange.
"""

import altair as alt
import pandas as pd

FONT = "system-ui, -apple-system, Segoe UI, sans-serif"
INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS = "#e1e0d9", "#c3c2b7"
SLOTS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100"]  # blue, orange, aqua, yellow

SETUPS = ["v2 pq", "v2 classical", "B v1 (pq)", "A"]
SETUP_LABELS = {
    "v2 pq": "v2 pq (ML-KEM + ML-DSA)",
    "v2 classical": "v2 classical (X25519 + Ed25519)",
    "B v1 (pq)": "B v1 (ML-KEM, unsigned)",
    "A": "A (weak CBC)",
}
SUITES = ["ML-KEM-768 / ML-DSA-65", "X25519 / Ed25519"]
SIZES = ["1 KB", "100 KB", "1 MB"]


def _style(chart):
    return (chart.configure(font=FONT)
            .configure_view(stroke=None)
            .configure_axis(gridColor=GRID, domainColor=AXIS, tickColor=AXIS, labelColor=INK_2,
                            titleColor=INK_2, titleFontWeight="normal", labelFontSize=12, titleFontSize=12)
            .configure_legend(orient="top", title=None, labelColor=INK_2, labelFontSize=12, symbolType="square",
                              labelLimit=320)
            .configure_header(labelColor=INK, labelFontSize=13, titleColor=INK_2)
            .configure_title(color=INK, fontSize=14, anchor="start", fontWeight="normal"))


def _setup_scale():
    return alt.Scale(domain=[SETUP_LABELS[s] for s in SETUPS], range=SLOTS)


def setup_times(df: pd.DataFrame, title: str):
    """df columns: setup, file_size, median_us, iqr_us. One panel per file size, own y scale."""
    df = df.assign(label=df["setup"].map(SETUP_LABELS))
    base = alt.Chart(df).encode(
        x=alt.X("label:N", sort=[SETUP_LABELS[s] for s in SETUPS], axis=None),
        y=alt.Y("median_us:Q", title="median time (µs)"),
        tooltip=[alt.Tooltip("label:N", title="setup"), alt.Tooltip("file_size:N", title="file"),
                 alt.Tooltip("median_us:Q", title="median µs", format=",.1f"),
                 alt.Tooltip("iqr_us:Q", title="IQR µs", format=",.1f")],
    )
    bars = base.mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, width={"band": 0.7}).encode(
        color=alt.Color("label:N", scale=_setup_scale(), legend=alt.Legend(columns=2)))
    text = base.mark_text(dy=-6, color=INK_2, fontSize=11).encode(text=alt.Text("median_us:Q", format=",.0f"))
    chart = (bars + text).properties(width=190, height=220).facet(
        column=alt.Column("file_size:N", sort=SIZES, title=None)).resolve_scale(y="independent")
    return _style(chart.properties(title=title))


def overhead_bars(df: pd.DataFrame):
    """df columns: setup, overhead_bytes."""
    df = df.assign(label=df["setup"].map(SETUP_LABELS))
    base = alt.Chart(df).encode(
        y=alt.Y("label:N", sort=[SETUP_LABELS[s] for s in SETUPS], title=None),
        x=alt.X("overhead_bytes:Q", title="bytes added to every file"),
        tooltip=[alt.Tooltip("label:N", title="setup"), alt.Tooltip("overhead_bytes:Q", title="bytes", format=",")],
    )
    bars = base.mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, height={"band": 0.6}).encode(
        color=alt.Color("label:N", scale=_setup_scale(), legend=None))
    text = base.mark_text(align="left", dx=6, color=INK_2, fontSize=12).encode(
        text=alt.Text("overhead_bytes:Q", format=",.0f"))
    return _style((bars + text).properties(height=180, title="Fixed size overhead per file"))


def building_blocks(df: pd.DataFrame):
    """df columns: suite, operation, median_us."""
    order = ["KEM keygen", "encapsulate", "decapsulate", "signature keygen", "sign", "verify"]
    base = alt.Chart(df).encode(
        y=alt.Y("operation:N", sort=order, title=None),
        yOffset=alt.YOffset("suite:N", sort=SUITES, scale=alt.Scale(paddingInner=0.12)),
        x=alt.X("median_us:Q", title="median time (µs)"),
        tooltip=[alt.Tooltip("suite:N"), alt.Tooltip("operation:N"),
                 alt.Tooltip("median_us:Q", title="median µs", format=",.1f")],
    )
    bars = base.mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
        color=alt.Color("suite:N", scale=alt.Scale(domain=SUITES, range=SLOTS[:2])))
    text = base.mark_text(align="left", dx=4, color=INK_2, fontSize=11).encode(
        text=alt.Text("median_us:Q", format=",.0f"))
    return _style((bars + text).properties(height=320, title="Building blocks: post-quantum vs classical"))


def step_times(steps: dict, title: str):
    """Horizontal bars, one per step, in the order the steps ran."""
    df = pd.DataFrame({"step": list(steps), "us": list(steps.values())})
    base = alt.Chart(df).encode(
        y=alt.Y("step:N", sort=list(steps), title=None),
        x=alt.X("us:Q", title="µs"),
        tooltip=[alt.Tooltip("step:N"), alt.Tooltip("us:Q", title="µs", format=",.1f")],
    )
    bars = base.mark_bar(color=SLOTS[0], cornerRadiusTopRight=4, cornerRadiusBottomRight=4, height={"band": 0.6})
    text = base.mark_text(align="left", dx=4, color=INK_2, fontSize=11).encode(text=alt.Text("us:Q", format=",.0f"))
    return _style((bars + text).properties(height=34 * len(steps) + 20, title=title))


def leakage_tradeoff(df: pd.DataFrame):
    """df columns: policy, storage_overhead (fraction), ai_acc (fraction). Chance line at 25%."""
    df = df.assign(overhead_pct=(df["storage_overhead"] * 100).clip(lower=0.1), acc_pct=df["ai_acc"] * 100)
    base = alt.Chart(df).encode(
        x=alt.X("overhead_pct:Q", scale=alt.Scale(type="log"), title="extra storage (log scale)",
                axis=alt.Axis(values=[0.1, 1, 10, 100, 1000, 10000],
                              labelExpr="format(datum.value, ',~f') + '%'")),
        y=alt.Y("acc_pct:Q", scale=alt.Scale(domain=[0, max(60, df["acc_pct"].max() + 5)]),
                title="AI attacker accuracy (%)"),
        tooltip=[alt.Tooltip("policy:N"), alt.Tooltip("acc_pct:Q", title="AI accuracy %", format=".1f"),
                 alt.Tooltip("overhead_pct:Q", title="extra storage %", format=",.1f")],
    )
    points = base.mark_circle(size=110, color=SLOTS[0], opacity=1, stroke="#fcfcfb", strokeWidth=2)
    # Labels sit above each point; the lowest-overhead point's label goes below so close points don't collide.
    lowest = df["overhead_pct"].idxmin()
    labels = (base.transform_filter(alt.datum.policy != df.loc[lowest, "policy"])
              .mark_text(align="left", dx=9, dy=-8, color=INK_2, fontSize=11).encode(text="policy:N")
              + base.transform_filter(alt.datum.policy == df.loc[lowest, "policy"])
              .mark_text(align="left", dx=6, dy=14, color=INK_2, fontSize=11).encode(text="policy:N"))
    chance = alt.Chart(pd.DataFrame({"y": [25]})).mark_rule(color=MUTED, strokeDash=[4, 4]).encode(y="y:Q")
    chance_label = alt.Chart(pd.DataFrame({"y": [25], "t": ["chance (25%)"]})).mark_text(
        align="left", x=4, dy=-7, color=MUTED, fontSize=11).encode(y="y:Q", text="t:N")
    return _style((chance + chance_label + points + labels).properties(
        height=340, title="Hiding file size: privacy vs storage cost"))


def size_strip(df: pd.DataFrame):
    """df columns: category, file_size. One row per category; position carries identity."""
    return _style(alt.Chart(df).mark_tick(color=SLOTS[0], opacity=0.45, thickness=1.5, size=22).encode(
        x=alt.X("file_size:Q", scale=alt.Scale(type="log"), title="file size (bytes, log scale)",
                axis=alt.Axis(values=[100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000], format="~s")),
        y=alt.Y("category:N", title=None, sort=["medical", "legal", "personal", "financial"]),
        tooltip=[alt.Tooltip("category:N"), alt.Tooltip("doc_type:N", title="type"),
                 alt.Tooltip("file_size:Q", title="bytes", format=",")],
    ).properties(height=200, title="Fictional dataset: file sizes by category (each tick is one file)"))
