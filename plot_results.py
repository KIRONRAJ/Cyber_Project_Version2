"""
plot_results_final.py  (v2)
===========================
Generates the upgraded result figures from the v2 simulation CSVs.

Input : results_upgraded_grid.csv, results_nonce_sweep.csv  (from main_final.py)
Output: five PNGs ->
    fig1_asr_all_v2.png        ASR across all 7 attack scenarios (incl. rollback)
    fig2_frr_vs_nonce.png      FRR vs nonce field length  (the new "money" figure)
    fig3_frr_by_method.png     FRR on clean traffic, with 95% CI (false positives)
    fig4_latency_v2.png        Mean validation latency + 95% CI + overhead
    fig5_capability_v2.png     Attack scenarios neutralised (ASR <= 1%)

Requirements: matplotlib, numpy
"""

import csv
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COLOURS = {
    "No Validation": "#9aa0a6",
    "Nonce-Only":    "#e8a33d",
    "Counter-Only":  "#4c8fbf",
    "Hybrid":        "#2e9e5b",
}
ORDER = ["No Validation", "Nonce-Only", "Counter-Only", "Hybrid"]
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11})


def f(x):
    return None if x in ("", None) else float(x)


def load(name):
    with open(name) as fh:
        return list(csv.DictReader(fh))


grid = load("results_upgraded_grid.csv")
sweep = load("results_nonce_sweep.csv")

asr = {(r["method"], r["scenario"]): f(r["asr_mean"]) for r in grid}
asr_ci = {(r["method"], r["scenario"]): f(r["asr_ci"]) for r in grid}
frr = {(r["method"], r["scenario"]): f(r["frr_mean"]) for r in grid}
frr_ci = {(r["method"], r["scenario"]): f(r["frr_ci"]) for r in grid}
lat = {(r["method"], r["scenario"]): f(r["lat_mean"]) for r in grid}
lat_ci = {(r["method"], r["scenario"]): f(r["lat_ci"]) for r in grid}


# =====================================================================
# FIGURE 1 : ASR across all 7 attack scenarios
# =====================================================================
scen = ["delayed_replay", "multiple_replay", "out_of_order", "counter_skip",
        "reset_attack", "desync_attack", "counter_rollback"]
labels = ["Delayed", "Multiple", "Out-of-\norder", "Counter-\nskip",
          "Reset", "Desync", "Rollback"]

fig, ax = plt.subplots(figsize=(12, 5.4))
x = np.arange(len(scen))
bw = 0.2
for i, m in enumerate(ORDER):
    vals = [asr[(m, s)] for s in scen]
    bars = ax.bar(x + (i - 1.5) * bw, vals, bw, label=m, color=COLOURS[m],
                  edgecolor="black", linewidth=0.4)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v + 1.5, f"{v:.0f}",
                ha="center", va="bottom", fontsize=7)
ax.axvspan(3.5, 6.5, color="#fff4e6", alpha=0.6, zorder=0)
ax.text(5.0, 109, "Robustness scenarios", ha="center", fontsize=9,
        style="italic", color="#a8631b")
ax.set_xticks(x); ax.set_xticklabels(labels)
ax.set_ylabel("Attack Success Rate (%)"); ax.set_ylim(0, 118)
ax.set_title("Attack Success Rate across All Attack Scenarios (lower is better)\n"
             "Nonce-Only fails Reset & Desync; Counter-Only fails Rollback; "
             "Hybrid blocks all")
ax.legend(ncol=4, loc="upper center", frameon=False, bbox_to_anchor=(0.5, -0.13))
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)
fig.tight_layout(); fig.savefig("fig1_asr_all_v2.png", dpi=200, bbox_inches="tight")
plt.close(fig)


# =====================================================================
# FIGURE 2 : FRR vs nonce field length  (money figure)
# =====================================================================
bits = [int(r["nonce_bits"]) for r in sweep]
n_frr = [float(r["nonce_only_frr"]) for r in sweep]
c_frr = [float(r["counter_only_frr"]) for r in sweep]

fig, ax = plt.subplots(figsize=(9, 5.2))
ax.plot(bits, n_frr, "-o", color=COLOURS["Nonce-Only"], linewidth=2,
        markersize=7, label="Nonce-Only  =  Hybrid")
ax.plot(bits, c_frr, "-s", color=COLOURS["Counter-Only"], linewidth=2,
        markersize=7, label="Counter-Only")
for bx, by in zip(bits, n_frr):
    ax.text(bx, by + 0.18, f"{by:.2f}%", ha="center", fontsize=8,
            color="#8a5a10")
# highlight the headline 8-bit operating point
ax.axvline(8, color="#bbb", linestyle="--", linewidth=1)
ax.text(8.15, 6.2, "headline\noperating point\n(8-bit nonce)", fontsize=8,
        color="#666", va="top")
ax.set_xlabel("Nonce field length (bits)")
ax.set_ylabel("False Rejection Rate on legitimate traffic (%)")
ax.set_title("False Rejection Rate vs Nonce Field Length\n"
             "Short nonce fields collide (birthday bound); Counter-Only is immune")
ax.set_xticks(bits); ax.set_ylim(-0.4, 7.6)
ax.legend(frameon=False, loc="upper right")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)
fig.tight_layout(); fig.savefig("fig2_frr_vs_nonce.png", dpi=200, bbox_inches="tight")
plt.close(fig)


# =====================================================================
# FIGURE 3 : FRR by method on clean traffic (with 95% CI)
# =====================================================================
fig, ax = plt.subplots(figsize=(8, 4.8))
vals = [frr[(m, "no_attack")] for m in ORDER]
errs = [frr_ci[(m, "no_attack")] for m in ORDER]
bars = ax.bar(ORDER, vals, color=[COLOURS[m] for m in ORDER],
              edgecolor="black", linewidth=0.5, width=0.6,
              yerr=errs, capsize=5, error_kw={"elinewidth": 1.1})
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.12, f"{v:.2f}%",
            ha="center", va="bottom", fontsize=10, fontweight="bold")
ax.set_ylabel("False Rejection Rate (%)  +/- 95% CI")
ax.set_ylim(0, 2.8)
ax.set_title("False Rejection Rate on Clean Traffic (8-bit nonce, 1000 trials)\n"
             "Nonce-based methods pay a false-positive cost; Counter-Only does not")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)
fig.tight_layout(); fig.savefig("fig3_frr_by_method.png", dpi=200, bbox_inches="tight")
plt.close(fig)


# =====================================================================
# FIGURE 4 : mean validation latency + 95% CI + overhead
# =====================================================================
# average each method's latency across all scenarios
lat_mean = {m: np.mean([lat[(m, s)] for s in
                        [r["scenario"] for r in grid if r["method"] == m]])
            for m in ORDER}
lat_err = {m: np.mean([lat_ci[(m, s)] for s in
                      [r["scenario"] for r in grid if r["method"] == m]])
           for m in ORDER}
baseline = lat_mean["No Validation"]

fig, ax = plt.subplots(figsize=(8.5, 5))
vals = [lat_mean[m] for m in ORDER]
errs = [lat_err[m] for m in ORDER]
bars = ax.bar(ORDER, vals, color=[COLOURS[m] for m in ORDER],
              edgecolor="black", linewidth=0.5, width=0.6,
              yerr=errs, capsize=5, error_kw={"elinewidth": 1.1})
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.02, f"{v:.3f}",
            ha="center", va="bottom", fontsize=10, fontweight="bold")
ax.axhline(baseline, color="#9aa0a6", linestyle="--", linewidth=1.1)
ax.text(3.45, baseline + 0.01, f"baseline ({baseline:.3f})", ha="right",
        fontsize=8, color="#666")
for i, m in enumerate(["Nonce-Only", "Counter-Only", "Hybrid"], start=1):
    ov = lat_mean[m] - baseline
    ax.annotate(f"+{ov:.3f}", xy=(i, lat_mean[m]),
                xytext=(i, lat_mean[m] + 0.07), ha="center", fontsize=8,
                color="#444", arrowprops=dict(arrowstyle="-", color="#bbb", lw=0.8))
ax.set_ylabel("Average validation latency (microseconds) +/- 95% CI")
ax.set_ylim(0, max(vals) + 0.18)
ax.set_title("Mean Per-Message Validation Latency by Method\n"
             "All sub-microsecond; ordering among protected methods is within noise")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)
fig.tight_layout(); fig.savefig("fig4_latency_v2.png", dpi=200, bbox_inches="tight")
plt.close(fig)


# =====================================================================
# FIGURE 5 : capability -- scenarios neutralised (ASR <= 1%)
# =====================================================================
neutralised = {m: sum(1 for s in scen if (asr[(m, s)] or 0) <= 1.0) for m in ORDER}
fig, ax = plt.subplots(figsize=(8, 4.8))
vals = [neutralised[m] for m in ORDER]
bars = ax.bar(ORDER, vals, color=[COLOURS[m] for m in ORDER],
              edgecolor="black", linewidth=0.5)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.08, f"{v} / 7",
            ha="center", va="bottom", fontweight="bold")
ax.set_ylabel("Attack scenarios neutralised\n(ASR <= 1%)")
ax.set_ylim(0, 7.8)
ax.set_title("Security Capability by Attack Coverage\n"
             "(number of the 7 attack scenarios where ASR <= 1%)")
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)
fig.tight_layout(); fig.savefig("fig5_capability_v2.png", dpi=200, bbox_inches="tight")
plt.close(fig)

print("Generated 5 figures.")