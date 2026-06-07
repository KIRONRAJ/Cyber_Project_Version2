"""
Plot_graph.py
Generates result graphs from the simulation CSV output files.

Usage:
    1. Run main_final.py first to generate the CSV files.
    2. Run this script in the same folder as the CSVs:
       python Plot_graph.py

Output:
    Four PNG files are saved in the current directory:
      - fig1_asr_all.png          (ASR across all 6 attack scenarios)
      - fig2_asr_robustness.png   (ASR under reset and desync only)
      - fig3_capability_DR.png    (Detection Rate capability summary)
      - fig4_latency.png          (mean validation latency per method)

Requirements:
    pip install matplotlib numpy
"""

import csv
import numpy as np
import matplotlib
matplotlib.use("Agg")  # non-interactive backend (works on servers)
import matplotlib.pyplot as plt

# ---- Consistent colours across all charts ----
COLOURS = {
    "No Validation": "#9aa0a6",   # grey
    "Nonce-Only":    "#e8a33d",   # amber
    "Counter-Only":  "#4c8fbf",   # blue
    "Hybrid":        "#2e9e5b",   # green
}
METHOD_ORDER = ["No Validation", "Nonce-Only", "Counter-Only", "Hybrid"]

# ---- CSV file names (produced by main_final.py) ----
GRID_FILE    = "results_full_grid.csv"
RESET_FILE   = "results_reset_scenario.csv"
DESYNC_FILE  = "results_desync_scenario.csv"

# Single-method files (produced by menu option [4] for each method)
SINGLE_FILES = {
    "No Validation": "results_no_validation.csv",
    "Nonce-Only":    "results_nonce_only.csv",
    "Counter-Only":  "results_counter_only.csv",
    "Hybrid":        "results_hybrid.csv",
}


# =====================================================================
#  Helper functions
# =====================================================================

def load_csv(filename):
    """Load a CSV file and return a list of row dictionaries."""
    with open(filename) as f:
        return list(csv.DictReader(f))


def to_float(value):
    """Convert a CSV cell to float, returning None for empty values."""
    if value in ("", None):
        return None
    return float(value)


# =====================================================================
#  Load all data
# =====================================================================

print("Loading CSV files...")
grid_rows   = load_csv(GRID_FILE)
reset_rows  = load_csv(RESET_FILE)
desync_rows = load_csv(DESYNC_FILE)

# Build a lookup: (method_name, scenario) -> ASR value
asr_lookup = {}
for row in grid_rows + reset_rows + desync_rows:
    asr_lookup[(row["method_name"], row["scenario"])] = to_float(row["asr"])

# Build a lookup: (method_name, scenario) -> Detection Rate value
dr_lookup = {}
for row in grid_rows + reset_rows + desync_rows:
    dr_lookup[(row["method_name"], row["scenario"])] = to_float(row["detection_rate"])

print("Data loaded.\n")

# ---- Shared plot settings ----
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 11})


# =====================================================================
#  FIGURE 1: ASR across all 6 attack scenarios (combined chart)
# =====================================================================

print("Generating Figure 1: ASR across all scenarios...")

scenarios = [
    "delayed_replay", "multiple_replay", "out_of_order",
    "counter_skip", "reset_attack", "desync_attack",
]
scenario_labels = [
    "Delayed", "Multiple", "Out-of-\norder",
    "Counter-\nskip", "Reset", "Desync",
]

fig, ax = plt.subplots(figsize=(11, 5.2))
x = np.arange(len(scenarios))
bar_width = 0.2

for i, method in enumerate(METHOD_ORDER):
    values = [asr_lookup[(method, s)] for s in scenarios]
    bars = ax.bar(
        x + (i - 1.5) * bar_width, values, bar_width,
        label=method, color=COLOURS[method],
        edgecolor="black", linewidth=0.4,
    )
    # Add value labels on each bar
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2, val + 1.5,
            f"{val:.0f}", ha="center", va="bottom", fontsize=7.5,
        )

# Shade the robustness region
ax.axvspan(3.5, 5.5, color="#fff4e6", alpha=0.6, zorder=0)
ax.text(4.5, 108, "Robustness scenarios", ha="center",
        fontsize=9, style="italic", color="#a8631b")

ax.set_xticks(x)
ax.set_xticklabels(scenario_labels)
ax.set_ylabel("Attack Success Rate (%)")
ax.set_ylim(0, 118)
ax.set_title("Attack Success Rate across All Attack Scenarios (lower is better)")
ax.legend(ncol=4, loc="upper center", frameon=False,
          bbox_to_anchor=(0.5, -0.13))
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)

fig.tight_layout()
fig.savefig("fig1_asr_all.png", dpi=200, bbox_inches="tight")
plt.close(fig)
print("  -> fig1_asr_all.png saved")


# =====================================================================
#  FIGURE 2: ASR for robustness scenarios only (reset + desync)
# =====================================================================

print("Generating Figure 2: ASR robustness scenarios...")

asr_reset  = {r["method_name"]: to_float(r["asr"]) for r in reset_rows}
asr_desync = {r["method_name"]: to_float(r["asr"]) for r in desync_rows}

fig, ax = plt.subplots(figsize=(8.5, 5))
scenario_names = ["Reset\n(power loss)", "Desync\n(jamming)"]
x = np.arange(2)
bar_width = 0.2

for i, method in enumerate(METHOD_ORDER):
    values = [asr_reset[method], asr_desync[method]]
    bars = ax.bar(
        x + (i - 1.5) * bar_width, values, bar_width,
        label=method, color=COLOURS[method],
        edgecolor="black", linewidth=0.4,
    )
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2, val + 1.5,
            f"{val:.0f}", ha="center", va="bottom", fontsize=9,
            fontweight="bold" if val >= 100 else "normal",
        )

# Annotate Nonce-Only failures
ax.annotate("FAILS", xy=(-0.5 * bar_width, 100),
            xytext=(-0.5 * bar_width, 55),
            ha="center", color="#b3261e", fontweight="bold", fontsize=9)
ax.annotate("FAILS", xy=(1 - 0.5 * bar_width, 100),
            xytext=(1 - 0.5 * bar_width, 55),
            ha="center", color="#b3261e", fontweight="bold", fontsize=9)

ax.set_xticks(x)
ax.set_xticklabels(scenario_names)
ax.set_ylabel("Attack Success Rate (%)")
ax.set_ylim(0, 115)
ax.set_title(
    "Attack Success Rate under Robustness Scenarios\n"
    "(Nonce-Only fails both; Counter-Only and Hybrid block all)"
)
ax.legend(ncol=4, loc="upper center", frameon=False,
          bbox_to_anchor=(0.5, -0.12))
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)

fig.tight_layout()
fig.savefig("fig2_asr_robustness.png", dpi=200, bbox_inches="tight")
plt.close(fig)
print("  -> fig2_asr_robustness.png saved")


# =====================================================================
#  FIGURE 3: Security capability by Detection Rate
# =====================================================================

print("Generating Figure 3: Security capability (Detection Rate)...")

# Count how many of the 6 attack scenarios each method fully defends
defended = {}
for method in METHOD_ORDER:
    count = sum(
        1 for s in scenarios
        if (dr_lookup.get((method, s)) or 0) >= 100
    )
    defended[method] = count

fig, ax = plt.subplots(figsize=(8, 4.8))
values = [defended[m] for m in METHOD_ORDER]
bars = ax.bar(
    METHOD_ORDER, values,
    color=[COLOURS[m] for m in METHOD_ORDER],
    edgecolor="black", linewidth=0.4,
)
for bar, val in zip(bars, values):
    ax.text(
        bar.get_x() + bar.get_width() / 2, val + 0.08,
        f"{val} / 6", ha="center", va="bottom", fontweight="bold",
    )

ax.set_ylabel("Scenarios fully defended\n(100% Detection Rate)")
ax.set_ylim(0, 6.9)
ax.set_title(
    "Security Capability by Detection Rate\n"
    "(number of attack scenarios where Detection Rate = 100%)"
)
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)

fig.tight_layout()
fig.savefig("fig3_capability_DR.png", dpi=200, bbox_inches="tight")
plt.close(fig)
print("  -> fig3_capability_DR.png saved")


# =====================================================================
#  FIGURE 4: Mean validation latency (no error bars, with overhead)
# =====================================================================

print("Generating Figure 4: Validation latency...")

# Compute mean latency per method from single-method CSVs
mean_latency = {}
for method, filename in SINGLE_FILES.items():
    rows = load_csv(filename)
    latencies = [to_float(r["avg_latency_us"]) for r in rows]
    mean_latency[method] = sum(latencies) / len(latencies)

baseline = mean_latency["No Validation"]

fig, ax = plt.subplots(figsize=(8.5, 5))
values = [mean_latency[m] for m in METHOD_ORDER]
bars = ax.bar(
    METHOD_ORDER, values,
    color=[COLOURS[m] for m in METHOD_ORDER],
    edgecolor="black", linewidth=0.5, width=0.6,
)

# Bold value labels on each bar
for bar, val in zip(bars, values):
    ax.text(
        bar.get_x() + bar.get_width() / 2, val + 0.006,
        f"{val:.3f}", ha="center", va="bottom",
        fontsize=10, fontweight="bold",
    )

# Dashed baseline line
ax.axhline(baseline, color="#9aa0a6", linestyle="--", linewidth=1.2)
ax.text(3.45, baseline + 0.004, f"baseline ({baseline:.3f})",
        ha="right", va="bottom", fontsize=8, color="#666")

# Overhead annotations for protected methods
for i, method in enumerate(["Nonce-Only", "Counter-Only", "Hybrid"], start=1):
    overhead = mean_latency[method] - baseline
    ax.annotate(
        f"+{overhead:.3f}", xy=(i, mean_latency[method]),
        xytext=(i, mean_latency[method] + 0.035),
        ha="center", fontsize=8, color="#444",
        arrowprops=dict(arrowstyle="-", color="#bbb", lw=0.8),
    )

ax.set_ylabel("Average validation latency (microseconds)")
ax.set_ylim(0, 0.46)
ax.set_title(
    "Mean Per-Message Validation Latency by Method\n"
    "(dashed line = no-protection baseline; +value = overhead added)"
)
for spine in ("top", "right"):
    ax.spines[spine].set_visible(False)
ax.grid(axis="y", linestyle=":", alpha=0.5)

fig.tight_layout()
fig.savefig("fig4_latency.png", dpi=200, bbox_inches="tight")
plt.close(fig)
print("  -> fig4_latency.png saved")


# =====================================================================
#  Done
# =====================================================================
print("\nAll four figures generated successfully.")
print("Copy them to your LaTeX images/ folder for the report.")