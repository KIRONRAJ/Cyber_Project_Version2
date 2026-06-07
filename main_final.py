"""
main_final.py  (v2)
===================
Experiment controller for the upgraded replay-attack simulation.

WHAT CHANGED IN v2 (vs v1)
--------------------------
1. NEW METRIC: False Rejection Rate (FRR) -- the share of LEGITIMATE messages
   wrongly rejected. Emerges from nonce collisions when the field is short.
2. NEW SCENARIO: counter_rollback (RollBack attack).
3. TRIALS raised to 1000, each with its OWN seed, so every metric is a
   DISTRIBUTION reported as mean +/- 95% confidence interval.
4. PAIRED design: one message stream per trial is fed to all four methods.
5. STATISTICS: paired t-test where valid, structural notes where not.
6. NONCE-SPACE SWEEP: FRR as a function of nonce field length.

WHAT WAS RESTORED IN THIS REVISION
----------------------------------
The interactive MENU from v1 is back (and extended for the v2 scenarios). You
can run one experiment at a time, or option [8] to run everything.

NO THIRD-PARTY PACKAGES NEEDED. This file uses only the Python standard library
(statistics, math) -- no numpy, no scipy -- so it runs without `pip install`.
(Plotting in plot_results_final.py still needs matplotlib.)

Run:
    python main_final.py            # interactive menu
    python main_final.py --all      # run everything, no menu (writes both CSVs)

Output CSVs: results_upgraded_grid.csv, results_nonce_sweep.csv
"""

import csv
import sys
import math
import time
import random
import statistics

from sender_final import KeyFob
from receiver_final import CarECU
from attacker_final import Attacker

# ---------------- configuration ----------------
NUM_LEGIT = 10                 # legitimate messages per trial
MULTIPLE_REPLAY_COUNT = 5
NUM_TRIALS = 1000
BASE_SEED = 42
HEADLINE_NONCE_BITS = 8        # short, constrained-device nonce field
COUNTER_WINDOW = 256           # forward acceptance window W
SWEEP_BITS = [6, 8, 10, 12, 14, 16]
Z95 = 1.96                     # 95% CI multiplier (large-sample normal approx.)

METHODS = [
    (CarECU.METHOD_NO_VALIDATION, "No Validation"),
    (CarECU.METHOD_NONCE_ONLY, "Nonce-Only"),
    (CarECU.METHOD_COUNTER_ONLY, "Counter-Only"),
    (CarECU.METHOD_HYBRID, "Hybrid"),
]
METHOD_NAME = {mid: name for mid, name in METHODS}

SCENARIOS = [
    "no_attack", "delayed_replay", "multiple_replay", "out_of_order",
    "counter_skip", "reset_attack", "desync_attack", "counter_rollback",
]


# =====================================================================
#  CORE SIMULATION (numerically identical to the auto-run version)
# =====================================================================

def run_trial(method_id, scenario, stream, counter_window):
    """Run one (method, scenario) trial on a pre-built message stream."""
    car = CarECU(method=method_id, counter_window=counter_window)
    attacker = Attacker()
    legit_sent = legit_accepted = 0
    attacks_total = attacks_accepted = 0
    latencies = []

    def deliver(msg):
        nonlocal legit_sent, legit_accepted
        attacker.intercept(msg)                 # adversary records on the wire
        t0 = time.perf_counter()
        ok = car.receive(msg)
        latencies.append((time.perf_counter() - t0) * 1_000_000)
        legit_sent += 1
        legit_accepted += int(ok)

    # --- legitimate phase + build attack set ---
    if scenario in ("no_attack", "delayed_replay", "multiple_replay",
                    "out_of_order", "counter_skip"):
        for m in stream:
            deliver(m)
        if scenario == "no_attack":
            attack_msgs = []
        elif scenario == "delayed_replay":
            attack_msgs = attacker.delayed_replay(0)
        elif scenario == "multiple_replay":
            attack_msgs = attacker.multiple_replay(0, MULTIPLE_REPLAY_COUNT)
        elif scenario == "out_of_order":
            attack_msgs = attacker.out_of_order_replay()
        else:  # counter_skip
            attack_msgs = attacker.counter_skip_replay()

    elif scenario == "reset_attack":
        for m in stream:
            deliver(m)
        car.volatile_reset()                    # wipe nonce RAM, keep counter
        attack_msgs = attacker.replay_all()

    elif scenario == "counter_rollback":
        for m in stream:
            deliver(m)
        car.rollback()                          # force counter back, keep nonces
        attack_msgs = attacker.replay_all()

    elif scenario == "desync_attack":
        half = len(stream) // 2
        for m in stream[:half]:
            deliver(m)
        jammed = stream[half]
        attacker.silent_capture(jammed)         # captured, never delivered
        for m in stream[half + 1:]:
            deliver(m)
        attack_msgs = [jammed]
    else:
        raise ValueError(scenario)

    # --- attack phase ---
    for m in attack_msgs:
        t0 = time.perf_counter()
        ok = car.receive(m)
        latencies.append((time.perf_counter() - t0) * 1_000_000)
        attacks_total += 1
        attacks_accepted += int(ok)

    return {
        "legit_sent": legit_sent,
        "legit_accepted": legit_accepted,
        "attacks_total": attacks_total,
        "attacks_accepted": attacks_accepted,
        "mean_latency": statistics.mean(latencies) if latencies else 0.0,
    }


def ci95(values):
    """95% confidence-interval half-width for the mean.

    Uses the large-sample normal approximation (z = 1.96). For n = 1000 this is
    identical to the t-value to two decimal places, and needs no scipy.
    """
    n = len(values)
    if n < 2:
        return 0.0
    sd = statistics.stdev(values)               # sample SD (ddof = 1)
    return Z95 * sd / math.sqrt(n)


def _mean(xs):
    return statistics.mean(xs) if xs else None


def run_cell(method_id, scenario, nonce_bits, counter_window, num_trials):
    """Run num_trials paired trials and aggregate metrics with CIs."""
    frr, dr, asr, lat = [], [], [], []
    for t in range(num_trials):
        rng = random.Random(BASE_SEED + t)                 # paired across methods
        kf = KeyFob(nonce_bits=nonce_bits, rng=rng)
        stream = [kf.unlock() for _ in range(NUM_LEGIT)]
        r = run_trial(method_id, scenario, stream, counter_window)
        if r["legit_sent"]:
            frr.append((1 - r["legit_accepted"] / r["legit_sent"]) * 100)
        if r["attacks_total"]:
            d = (1 - r["attacks_accepted"] / r["attacks_total"]) * 100
            dr.append(d)
            asr.append(100 - d)
        lat.append(r["mean_latency"])
    return {
        "frr_mean": _mean(frr), "frr_ci": ci95(frr) if frr else None, "frr_list": frr,
        "dr_mean": _mean(dr),
        "asr_mean": _mean(asr), "asr_ci": ci95(asr) if asr else None,
        "lat_mean": _mean(lat), "lat_ci": ci95(lat), "lat_list": lat,
    }


def paired_t(a, b):
    """Manual paired t-statistic (no scipy). Returns (t, df, mean_diff)."""
    diffs = [x - y for x, y in zip(a, b)]
    n = len(diffs)
    md = statistics.mean(diffs)
    sd = statistics.stdev(diffs) if n > 1 else 0.0
    se = sd / math.sqrt(n) if sd else 0.0
    t = md / se if se else float("inf")
    return t, n - 1, md


# =====================================================================
#  FORMATTING HELPERS
# =====================================================================

def f(v, nd=2):
    """Format a number to nd decimals, or 'N/A' if None."""
    return f"{v:.{nd}f}" if v is not None else "N/A"


def hr(char="-", width=78):
    print(char * width)


# =====================================================================
#  EXPERIMENT [1]: FULL GRID  (4 methods x 8 scenarios)
# =====================================================================

def compute_full_grid():
    grid = {}
    for mid, mname in METHODS:
        for sc in SCENARIOS:
            grid[(mname, sc)] = run_cell(mid, sc, HEADLINE_NONCE_BITS,
                                         COUNTER_WINDOW, NUM_TRIALS)
    return grid


def print_full_grid(grid):
    hr("=")
    print(f" FULL GRID  --  nonce={HEADLINE_NONCE_BITS} bits, window={COUNTER_WINDOW}, "
          f"{NUM_TRIALS} trials/cell")
    hr("=")
    print(f" {'Method':<15}{'Scenario':<18}{'DR%':>7}{'ASR%':>8}{'FRR%':>8}{'Lat(us)':>10}")
    hr()
    for mid, mname in METHODS:
        for sc in SCENARIOS:
            c = grid[(mname, sc)]
            print(f" {mname:<15}{sc:<18}{f(c['dr_mean']):>7}{f(c['asr_mean']):>8}"
                  f"{f(c['frr_mean']):>8}{f(c['lat_mean'], 3):>10}")
        hr()


def write_grid_csv(grid, path="results_upgraded_grid.csv"):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["method", "scenario", "dr_mean", "asr_mean", "asr_ci",
                    "frr_mean", "frr_ci", "lat_mean", "lat_ci", "trials"])
        for (mname, sc), c in grid.items():
            w.writerow([mname, sc, c["dr_mean"], c["asr_mean"], c["asr_ci"],
                        c["frr_mean"], c["frr_ci"], c["lat_mean"], c["lat_ci"],
                        NUM_TRIALS])
    print(f" -> wrote {path}")


def experiment_full_grid():
    print("\nRunning full grid (32 cells x 1000 trials)... please wait a few seconds.")
    grid = compute_full_grid()
    print_full_grid(grid)
    write_grid_csv(grid)


# =====================================================================
#  EXPERIMENT [2/3/4]: SINGLE SCENARIO, ALL 4 METHODS
# =====================================================================

def experiment_single_scenario(scenario, pretty):
    print(f"\nRunning '{scenario}' against all 4 methods (1000 trials each)...")
    hr("=")
    print(f" SCENARIO: {pretty}  ({scenario})")
    hr("=")
    print(f" {'Method':<15}{'DR%':>7}{'ASR% (95% CI)':>20}{'FRR% (95% CI)':>20}{'Lat(us)':>9}")
    hr()
    for mid, mname in METHODS:
        c = run_cell(mid, scenario, HEADLINE_NONCE_BITS, COUNTER_WINDOW, NUM_TRIALS)
        asr_s = f"{f(c['asr_mean'])} (+/-{f(c['asr_ci'])})" if c['asr_mean'] is not None else "N/A"
        frr_s = f"{f(c['frr_mean'])} (+/-{f(c['frr_ci'])})" if c['frr_mean'] is not None else "N/A"
        print(f" {mname:<15}{f(c['dr_mean']):>7}{asr_s:>20}{frr_s:>20}{f(c['lat_mean'], 3):>9}")
    hr()


# =====================================================================
#  EXPERIMENT [5]: SINGLE METHOD, ALL 8 SCENARIOS
# =====================================================================

def choose_method():
    print("\n Pick a method:")
    for i, (mid, mname) in enumerate(METHODS, start=1):
        print(f"   [{i}] {mname}")
    while True:
        choice = input(" Enter method [1-4]: ").strip()
        if choice in ("1", "2", "3", "4"):
            return METHODS[int(choice) - 1]
        print(" Invalid choice. Please enter 1-4.")


def experiment_single_method(method_id, mname):
    print(f"\nRunning '{mname}' against all 8 scenarios (1000 trials each)...")
    hr("=")
    print(f" METHOD: {mname}")
    hr("=")
    print(f" {'Scenario':<18}{'DR%':>7}{'ASR%':>8}{'FRR%':>8}{'Lat(us)':>10}")
    hr()
    for sc in SCENARIOS:
        c = run_cell(method_id, sc, HEADLINE_NONCE_BITS, COUNTER_WINDOW, NUM_TRIALS)
        print(f" {sc:<18}{f(c['dr_mean']):>7}{f(c['asr_mean']):>8}"
              f"{f(c['frr_mean']):>8}{f(c['lat_mean'], 3):>10}")
    hr()


# =====================================================================
#  EXPERIMENT [6]: NONCE-SPACE SWEEP  (FRR vs nonce field length)
# =====================================================================

def compute_sweep():
    rows = []
    for bits in SWEEP_BITS:
        n = run_cell(CarECU.METHOD_NONCE_ONLY, "no_attack", bits,
                     COUNTER_WINDOW, NUM_TRIALS)["frr_mean"]
        c = run_cell(CarECU.METHOD_COUNTER_ONLY, "no_attack", bits,
                     COUNTER_WINDOW, NUM_TRIALS)["frr_mean"]
        h = run_cell(CarECU.METHOD_HYBRID, "no_attack", bits,
                     COUNTER_WINDOW, NUM_TRIALS)["frr_mean"]
        rows.append((bits, 1 << bits, n, c, h))
    return rows


def experiment_sweep():
    print("\nRunning nonce-space sweep (FRR on clean traffic)...")
    rows = compute_sweep()
    hr("=")
    print(" NONCE-SPACE SWEEP  --  False Rejection Rate vs nonce field length")
    hr("=")
    print(f" {'bits':>5}{'space':>9}{'Nonce-FRR%':>13}{'Counter-FRR%':>14}{'Hybrid-FRR%':>13}")
    hr()
    for bits, space, n, c, h in rows:
        print(f" {bits:>5}{space:>9}{f(n):>13}{f(c):>14}{f(h):>13}")
    hr()
    with open("results_nonce_sweep.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["nonce_bits", "nonce_space", "nonce_only_frr",
                    "counter_only_frr", "hybrid_frr"])
        for row in rows:
            w.writerow(row)
    print(" -> wrote results_nonce_sweep.csv")


# =====================================================================
#  EXPERIMENT [7]: STATISTICS
# =====================================================================

def experiment_statistics():
    print("\nComputing statistics on clean traffic (1000 paired trials)...")
    cells = {m: run_cell(mid, "no_attack", HEADLINE_NONCE_BITS,
                         COUNTER_WINDOW, NUM_TRIALS) for mid, m in METHODS}
    n_frr = cells["Nonce-Only"]["frr_list"]
    h_frr = cells["Hybrid"]["frr_list"]
    c_lat = cells["Counter-Only"]["lat_list"]
    h_lat = cells["Hybrid"]["lat_list"]

    hr("=")
    print(" STATISTICAL ANALYSIS")
    hr("=")
    print(f" Nonce-Only FRR = {statistics.mean(n_frr):.3f}% (+/-{ci95(n_frr):.3f})")
    print(f" Hybrid     FRR = {statistics.mean(h_frr):.3f}% (+/-{ci95(h_frr):.3f})")

    identical = all(abs(a - b) < 1e-12 for a, b in zip(n_frr, h_frr))
    print()
    print(" [1] FRR, Nonce-Only vs Hybrid:")
    if identical:
        print("     per-trial difference is exactly 0 in every trial.")
        print("     -> IDENTICAL BY CONSTRUCTION (a t-test is undefined here).")
    else:
        t, df, md = paired_t(n_frr, h_frr)
        print(f"     paired t = {t:.3f}, df = {df}, mean diff = {md:.4f}")

    t, df, md = paired_t(h_lat, c_lat)
    sig = "p < 0.001 (highly significant)" if abs(t) > 3.30 else "not significant at 0.001"
    print()
    print(" [2] Latency, Counter-Only vs Hybrid:")
    print(f"     paired t = {t:.3f}, df = {df}, mean diff = {md:.4f} us")
    print(f"     -> {sig}, BUT effect size ~{abs(md):.3f} us is practically negligible")
    print("        (vs ~100 ms physical actuation). Significant != meaningful.")

    print()
    print(" [3] FRR, Counter-Only vs Hybrid:")
    print(f"     Counter-Only FRR = {f(cells['Counter-Only']['frr_mean'], 3)}% with zero variance.")
    print("     -> STRUCTURAL difference (Counter-Only uses no nonce, so it")
    print("        cannot false-reject). Reported as structural, not statistical.")
    hr()


# =====================================================================
#  EXPERIMENT [8]: RUN EVERYTHING
# =====================================================================

def experiment_everything():
    experiment_full_grid()
    experiment_sweep()
    experiment_statistics()
    print("\nAll experiments complete. Both CSVs written.")
    print("Next: run  python plot_results_final.py  to generate the 5 figures.")


# =====================================================================
#  MENU
# =====================================================================

def show_menu():
    print()
    hr("=")
    print(" REPLAY ATTACK PREVENTION SIMULATION  (v2)")
    print(" Hybrid Nonce-Counter Framework for Smart Car IoT")
    hr("=")
    print()
    print(f" Configuration: {NUM_TRIALS} trials/cell, {NUM_LEGIT} legit messages/trial,")
    print(f"                {HEADLINE_NONCE_BITS}-bit nonce, counter window W={COUNTER_WINDOW}")
    print()
    print(" Choose an experiment:")
    print()
    print("   [1] Full Grid            4 methods x 8 scenarios (writes grid CSV)")
    print("   [2] Reset Scenario       all 4 methods vs ECU power loss")
    print("   [3] Desync Scenario      all 4 methods vs message jamming")
    print("   [4] Rollback Scenario    all 4 methods vs RollBack attack   (new in v2)")
    print("   [5] Single Method        pick one method vs all 8 scenarios")
    print("   [6] Nonce-Space Sweep    FRR vs nonce field length (writes sweep CSV)")
    print("   [7] Statistics           paired t-tests + structural notes")
    print("   [8] Run Everything       grid + sweep + stats, write both CSVs")
    print("   [9] Exit")
    print()
    while True:
        choice = input(" Enter choice [1-9]: ").strip()
        if choice in ("1", "2", "3", "4", "5", "6", "7", "8", "9"):
            return choice
        print(" Invalid choice. Please enter 1-9.")


def main():
    # Non-interactive shortcut for the "run then plot" workflow.
    if "--all" in sys.argv:
        experiment_everything()
        return

    while True:
        choice = show_menu()
        if choice == "1":
            experiment_full_grid()
        elif choice == "2":
            experiment_single_scenario("reset_attack", "Reset (power loss)")
        elif choice == "3":
            experiment_single_scenario("desync_attack", "Desync (jamming)")
        elif choice == "4":
            experiment_single_scenario("counter_rollback", "Rollback (RollBack attack)")
        elif choice == "5":
            mid, mname = choose_method()
            experiment_single_method(mid, mname)
        elif choice == "6":
            experiment_sweep()
        elif choice == "7":
            experiment_statistics()
        elif choice == "8":
            experiment_everything()
        elif choice == "9":
            print("\nExiting. Goodbye.")
            break


if __name__ == "__main__":
    main()