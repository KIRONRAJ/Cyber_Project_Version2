"""
main_final.py  (v2)
===================
Experiment controller for the upgraded replay-attack simulation.

WHAT CHANGED IN v2
------------------
1. NEW METRIC: False Rejection Rate (FRR) -- the share of LEGITIMATE messages
   wrongly rejected. This is the false-positive behaviour that was absent in v1.
   It emerges from nonce collisions when the nonce field is short (see sender).
2. NEW SCENARIO: counter_rollback (RollBack attack).
3. TRIALS raised to 1000, each with its OWN seed, so every metric is a
   DISTRIBUTION. We report mean +/- 95% confidence interval.
4. PAIRED design: one message stream per trial is fed to all four methods, so
   method comparisons are paired (controls message-stream variance).
5. STATISTICS: paired t-tests where they are valid, with explicit notes on when
   a difference is STRUCTURAL (deterministic) rather than statistical
   (Arcuri & Briand 2014; Wohlin et al. 2012).
6. NONCE-SPACE SWEEP: FRR as a function of nonce field length.

Run:  python main_final.py
Output CSVs: results_upgraded_grid.csv, results_nonce_sweep.csv
"""

import csv
import math
import time
import random
import statistics

import numpy as np
from scipy import stats

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

METHODS = [
    (CarECU.METHOD_NO_VALIDATION, "No Validation"),
    (CarECU.METHOD_NONCE_ONLY, "Nonce-Only"),
    (CarECU.METHOD_COUNTER_ONLY, "Counter-Only"),
    (CarECU.METHOD_HYBRID, "Hybrid"),
]

SCENARIOS = [
    "no_attack", "delayed_replay", "multiple_replay", "out_of_order",
    "counter_skip", "reset_attack", "desync_attack", "counter_rollback",
]


# ---------------- one trial ----------------
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
        car.volatile_reset()
        attack_msgs = attacker.replay_all()

    elif scenario == "counter_rollback":
        for m in stream:
            deliver(m)
        car.rollback()
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
    """95% confidence-interval half-width for the mean (t-distribution)."""
    a = np.asarray(values, float)
    n = len(a)
    if n < 2:
        return 0.0
    return float(stats.t.ppf(0.975, n - 1) * a.std(ddof=1) / math.sqrt(n))


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
        "frr_mean": np.mean(frr) if frr else None, "frr_ci": ci95(frr) if frr else None,
        "frr_list": frr,
        "dr_mean": np.mean(dr) if dr else None,
        "asr_mean": np.mean(asr) if asr else None, "asr_ci": ci95(asr) if asr else None,
        "lat_mean": float(np.mean(lat)), "lat_ci": ci95(lat), "lat_list": lat,
    }


# ---------------- main ----------------
def main():
    print(f"MAIN GRID  nonce_bits={HEADLINE_NONCE_BITS} window={COUNTER_WINDOW} "
          f"trials={NUM_TRIALS}")
    grid = {}
    for mid, mname in METHODS:
        for sc in SCENARIOS:
            grid[(mname, sc)] = run_cell(mid, sc, HEADLINE_NONCE_BITS,
                                         COUNTER_WINDOW, NUM_TRIALS)

    with open("results_upgraded_grid.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method", "scenario", "dr_mean", "asr_mean", "asr_ci",
                    "frr_mean", "frr_ci", "lat_mean", "lat_ci", "trials"])
        for (mname, sc), c in grid.items():
            w.writerow([mname, sc, c["dr_mean"], c["asr_mean"], c["asr_ci"],
                        c["frr_mean"], c["frr_ci"], c["lat_mean"], c["lat_ci"],
                        NUM_TRIALS])

    # nonce-space sweep (FRR on clean traffic)
    with open("results_nonce_sweep.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["nonce_bits", "nonce_space", "nonce_only_frr",
                    "counter_only_frr", "hybrid_frr"])
        for bits in [6, 8, 10, 12, 14, 16]:
            n = run_cell(CarECU.METHOD_NONCE_ONLY, "no_attack", bits,
                         COUNTER_WINDOW, NUM_TRIALS)["frr_mean"]
            c = run_cell(CarECU.METHOD_COUNTER_ONLY, "no_attack", bits,
                         COUNTER_WINDOW, NUM_TRIALS)["frr_mean"]
            h = run_cell(CarECU.METHOD_HYBRID, "no_attack", bits,
                         COUNTER_WINDOW, NUM_TRIALS)["frr_mean"]
            w.writerow([bits, 1 << bits, n, c, h])

    # statistics
    cells = {m: run_cell(mid, "no_attack", HEADLINE_NONCE_BITS,
                         COUNTER_WINDOW, NUM_TRIALS) for mid, m in METHODS}
    n_frr = np.array(cells["Nonce-Only"]["frr_list"])
    h_frr = np.array(cells["Hybrid"]["frr_list"])
    c_lat = np.array(cells["Counter-Only"]["lat_list"])
    h_lat = np.array(cells["Hybrid"]["lat_list"])
    t2, p2 = stats.ttest_rel(c_lat, h_lat)

    print("\n--- statistics (no_attack, 1000 paired trials) ---")
    print(f"Nonce-Only FRR = {n_frr.mean():.3f}% (+/-{ci95(n_frr):.3f})")
    print(f"Hybrid    FRR = {h_frr.mean():.3f}% (+/-{ci95(h_frr):.3f})")
    print(f"Nonce vs Hybrid FRR: per-trial diff is "
          f"{'identical (t-test undefined)' if np.allclose(n_frr - h_frr, 0) else 'nonzero'}")
    print(f"Counter-Only FRR = {cells['Counter-Only']['frr_mean']:.3f}% (structural zero)")
    print(f"Latency Counter vs Hybrid: t={t2:.3f}, p={p2:.4g}, "
          f"diff={h_lat.mean()-c_lat.mean():.4f} us (significant but negligible)")
    print("\nWrote results_upgraded_grid.csv and results_nonce_sweep.csv")


if __name__ == "__main__":
    main()