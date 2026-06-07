"""
main_final.py
Entry point for the replay attack prevention simulation.

Provides an interactive menu to run experiments comparing four validation
methods (No Validation, Nonce-Only, Counter-Only, Hybrid) against five
standard attack scenarios and two robustness scenarios (reset, desync).

Each experiment is run with isolated objects (fresh KeyFob, CarECU, Attacker)
and averaged over NUM_TRIALS repetitions. Results are saved to CSV.
"""

import time
import csv
import sys
import io
import contextlib
import random
import statistics
from typing import Dict, List

from sender_final import KeyFob
from receiver_final import CarECU
from attacker_final import Attacker


# =============================================================================
# Configuration
# =============================================================================

NUM_NORMAL_MESSAGES = 10
NUM_TRIALS = 30
MULTIPLE_REPLAY_COUNT = 5
RANDOM_SEED = 42

METHODS = [
    (1, "No Validation"),
    (2, "Nonce-Only"),
    (3, "Counter-Only"),
    (4, "Hybrid"),
]

STANDARD_SCENARIOS = [
    "no_attack",
    "delayed_replay",
    "multiple_replay",
    "out_of_order",
    "counter_skip",
]


# =============================================================================
# Single experiment
# =============================================================================

def run_experiment(method_id: int, scenario: str) -> Dict:
    """
    Run one experiment for a given (method, scenario) combination.

    Each call creates fresh KeyFob, CarECU, and Attacker instances so that
    no state carries over from previous runs.
    """
    keyfob = KeyFob()
    car = CarECU(method=method_id)
    attacker = Attacker()

    legitimate_accepted = 0
    legitimate_rejected = 0
    legitimate_latencies: List[float] = []

    attacks_accepted = 0
    attacks_rejected = 0
    attack_latencies: List[float] = []

    # ---- Standard scenarios ----
    if scenario in STANDARD_SCENARIOS:
        commands = ["UNLOCK", "LOCK", "START"]
        for i in range(NUM_NORMAL_MESSAGES):
            cmd = commands[i % 3]
            if cmd == "UNLOCK":
                msg = keyfob.unlock()
            elif cmd == "LOCK":
                msg = keyfob.lock()
            else:
                msg = keyfob.start()

            captured = attacker.intercept(msg)

            start = time.perf_counter()
            accepted = car.receive(captured)
            end = time.perf_counter()

            legitimate_latencies.append((end - start) * 1_000_000)
            if accepted:
                legitimate_accepted += 1
            else:
                legitimate_rejected += 1

        if scenario == "no_attack":
            attack_messages: List = []
        elif scenario == "delayed_replay":
            attack_messages = attacker.delayed_replay(index=0)
        elif scenario == "multiple_replay":
            attack_messages = attacker.multiple_replay(
                index=0, count=MULTIPLE_REPLAY_COUNT
            )
        elif scenario == "out_of_order":
            attack_messages = attacker.out_of_order_replay()
        else:  # counter_skip
            attack_messages = attacker.counter_skip_replay()

        for msg in attack_messages:
            start = time.perf_counter()
            accepted = car.receive(msg)
            end = time.perf_counter()

            attack_latencies.append((end - start) * 1_000_000)
            if accepted:
                attacks_accepted += 1
            else:
                attacks_rejected += 1

    # ---- Reset scenario ----
    elif scenario == "reset_attack":
        for _ in range(NUM_NORMAL_MESSAGES):
            msg = keyfob.unlock()
            captured = attacker.intercept(msg)

            start = time.perf_counter()
            accepted = car.receive(captured)
            end = time.perf_counter()

            legitimate_latencies.append((end - start) * 1_000_000)
            if accepted:
                legitimate_accepted += 1
            else:
                legitimate_rejected += 1

        car.volatile_reset()

        attack_messages = list(attacker.captured_messages)
        for msg in attack_messages:
            start = time.perf_counter()
            accepted = car.receive(msg)
            end = time.perf_counter()

            attack_latencies.append((end - start) * 1_000_000)
            if accepted:
                attacks_accepted += 1
            else:
                attacks_rejected += 1

    # ---- Desync scenario ----
    elif scenario == "desync_attack":
        first_batch = NUM_NORMAL_MESSAGES // 2

        for _ in range(first_batch):
            msg = keyfob.unlock()
            captured = attacker.intercept(msg)

            start = time.perf_counter()
            accepted = car.receive(captured)
            end = time.perf_counter()

            legitimate_latencies.append((end - start) * 1_000_000)
            if accepted:
                legitimate_accepted += 1
            else:
                legitimate_rejected += 1

        jammed_msg = keyfob.unlock()
        attacker.silent_capture(jammed_msg)

        for _ in range(NUM_NORMAL_MESSAGES - first_batch - 1):
            msg = keyfob.unlock()
            captured = attacker.intercept(msg)

            start = time.perf_counter()
            accepted = car.receive(captured)
            end = time.perf_counter()

            legitimate_latencies.append((end - start) * 1_000_000)
            if accepted:
                legitimate_accepted += 1
            else:
                legitimate_rejected += 1

        attack_messages = [jammed_msg]
        for msg in attack_messages:
            start = time.perf_counter()
            accepted = car.receive(msg)
            end = time.perf_counter()

            attack_latencies.append((end - start) * 1_000_000)
            if accepted:
                attacks_accepted += 1
            else:
                attacks_rejected += 1

    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    # ---- Metrics ----
    total_attacks = len(attack_latencies)
    if total_attacks > 0:
        detection_rate = (attacks_rejected / total_attacks) * 100
        asr = (attacks_accepted / total_attacks) * 100
    else:
        detection_rate = None
        asr = None

    all_latencies = legitimate_latencies + attack_latencies
    avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else 0.0

    return {
        "method_id": method_id,
        "scenario": scenario,
        "legitimate_total": len(legitimate_latencies),
        "legitimate_accepted": legitimate_accepted,
        "legitimate_rejected": legitimate_rejected,
        "attacks_total": total_attacks,
        "attacks_accepted": attacks_accepted,
        "attacks_rejected": attacks_rejected,
        "detection_rate": detection_rate,
        "asr": asr,
        "avg_latency_us": avg_latency,
    }


# =============================================================================
# Multi-trial averaging
# =============================================================================

def run_trials(method_id: int, scenario: str, num_trials: int) -> Dict:
    """Run a single experiment cell multiple times and average the results."""
    trials = [run_experiment(method_id, scenario) for _ in range(num_trials)]

    numeric_fields = [
        "legitimate_accepted",
        "legitimate_rejected",
        "attacks_accepted",
        "attacks_rejected",
        "avg_latency_us",
    ]

    avg = {
        "method_id": method_id,
        "scenario": scenario,
        "num_trials": num_trials,
        "legitimate_total": trials[0]["legitimate_total"],
        "attacks_total": trials[0]["attacks_total"],
    }

    for field in numeric_fields:
        avg[field] = sum(t[field] for t in trials) / num_trials

    latencies = [t["avg_latency_us"] for t in trials]
    avg["std_latency_us"] = statistics.stdev(latencies) if len(latencies) > 1 else 0.0

    det_rates = [t["detection_rate"] for t in trials if t["detection_rate"] is not None]
    asrs = [t["asr"] for t in trials if t["asr"] is not None]
    avg["detection_rate"] = sum(det_rates) / len(det_rates) if det_rates else None
    avg["asr"] = sum(asrs) / len(asrs) if asrs else None

    return avg


# =============================================================================
# Output formatting
# =============================================================================

def print_metric_table(grid: Dict, scenarios: List[str], metric: str, title: str) -> None:
    """Print a single metric as a table with methods as rows and scenarios as columns."""
    print()
    print("=" * 95)
    print(f"  {title}")
    print("=" * 95)

    header = f"  {'Method':<18}"
    for scenario in scenarios:
        header += f" {scenario:>15}"
    print(header)
    print("  " + "-" * 93)

    for method_id, method_name in METHODS:
        row = f"  {method_name:<18}"
        for scenario in scenarios:
            cell = grid[(method_id, scenario)]
            if metric == "detection_rate":
                value = cell["detection_rate"]
            elif metric == "asr":
                value = cell["asr"]
            elif metric == "latency":
                value = cell["avg_latency_us"]
            else:
                value = None

            if value is None:
                row += f" {'N/A':>15}"
            elif metric == "latency":
                row += f" {value:>12.2f} us"
            else:
                row += f" {value:>13.1f}%"
        print(row)
    print()


def save_to_csv(grid: Dict, scenarios: List[str], filename: str) -> None:
    """Save grid results to a CSV file (one row per method-scenario pair)."""
    fields = [
        "method_id", "method_name", "scenario",
        "legitimate_total", "legitimate_accepted", "legitimate_rejected",
        "attacks_total", "attacks_accepted", "attacks_rejected",
        "detection_rate", "asr", "avg_latency_us", "std_latency_us",
        "num_trials",
    ]
    method_names = {mid: name for mid, name in METHODS}

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for method_id, _ in METHODS:
            for scenario in scenarios:
                if (method_id, scenario) not in grid:
                    continue
                row = dict(grid[(method_id, scenario)])
                row["method_name"] = method_names[method_id]
                for k, v in row.items():
                    if v is None:
                        row[k] = ""
                writer.writerow(row)

    print(f"  Results saved to: {filename}")


# =============================================================================
# Experiment modes
# =============================================================================

def run_full_grid() -> None:
    """Run all 4 methods against all 5 standard scenarios (20 cells)."""
    print()
    print("=" * 75)
    print(f"  FULL GRID EXPERIMENT")
    print(f"  {len(METHODS)} methods x {len(STANDARD_SCENARIOS)} scenarios "
          f"x {NUM_TRIALS} trials per cell")
    print("=" * 75)
    print()

    grid: Dict = {}
    total = len(METHODS) * len(STANDARD_SCENARIOS)
    count = 0

    for method_id, method_name in METHODS:
        for scenario in STANDARD_SCENARIOS:
            count += 1
            print(f"  [{count:2d}/{total}] {method_name:<18} + {scenario:<16} ... ",
                  end="", flush=True)
            grid[(method_id, scenario)] = run_trials(method_id, scenario, NUM_TRIALS)
            print("done")

    print_metric_table(grid, STANDARD_SCENARIOS, "detection_rate",
                       "DETECTION RATE (%)  -  Higher is better")
    print_metric_table(grid, STANDARD_SCENARIOS, "asr",
                       "ATTACK SUCCESS RATE (%)  -  Lower is better")
    print_metric_table(grid, STANDARD_SCENARIOS, "latency",
                       "AVERAGE LATENCY (us)  -  Lower is better")

    print("=" * 75)
    save_to_csv(grid, STANDARD_SCENARIOS, "results_full_grid.csv")
    print()


def run_reset_experiment() -> None:
    """Run reset scenario for all 4 methods."""
    print()
    print("=" * 75)
    print(f"  RESET SCENARIO  -  {NUM_TRIALS} trials per method")
    print("=" * 75)
    print()
    print("  Simulates ECU power loss after legitimate traffic:")
    print("    1. Send legitimate messages (attacker captures all of them)")
    print("    2. ECU suffers power loss")
    print("       - nonce_list (RAM) is cleared")
    print("       - last_counter (EEPROM) is preserved")
    print("    3. Attacker replays all captured messages")
    print()

    grid: Dict = {}
    for method_id, method_name in METHODS:
        print(f"  Running {method_name:<18} ... ", end="", flush=True)
        grid[(method_id, "reset_attack")] = run_trials(method_id, "reset_attack", NUM_TRIALS)
        print("done")

    print_metric_table(grid, ["reset_attack"], "detection_rate",
                       "DETECTION RATE (%)  -  Higher is better")
    print_metric_table(grid, ["reset_attack"], "asr",
                       "ATTACK SUCCESS RATE (%)  -  Lower is better")
    print_metric_table(grid, ["reset_attack"], "latency",
                       "AVERAGE LATENCY (us)  -  Lower is better")

    print("=" * 75)
    save_to_csv(grid, ["reset_attack"], "results_reset_scenario.csv")
    print()


def run_desync_experiment() -> None:
    """Run desync scenario for all 4 methods."""
    print()
    print("=" * 75)
    print(f"  DESYNC SCENARIO  -  {NUM_TRIALS} trials per method")
    print("=" * 75)
    print()
    print("  Simulates a jamming attack that creates a state gap:")
    print("    1. Send half the legitimate messages (received normally)")
    print("    2. Attacker jams one message in transit")
    print("       - Attacker captures it, ECU never sees it")
    print("    3. Send remaining messages")
    print("       - ECU counter advances past the jammed message")
    print("    4. Attacker replays the jammed message")
    print()

    grid: Dict = {}
    for method_id, method_name in METHODS:
        print(f"  Running {method_name:<18} ... ", end="", flush=True)
        grid[(method_id, "desync_attack")] = run_trials(method_id, "desync_attack", NUM_TRIALS)
        print("done")

    print_metric_table(grid, ["desync_attack"], "detection_rate",
                       "DETECTION RATE (%)  -  Higher is better")
    print_metric_table(grid, ["desync_attack"], "asr",
                       "ATTACK SUCCESS RATE (%)  -  Lower is better")
    print_metric_table(grid, ["desync_attack"], "latency",
                       "AVERAGE LATENCY (us)  -  Lower is better")

    print("=" * 75)
    save_to_csv(grid, ["desync_attack"], "results_desync_scenario.csv")
    print()


def run_single_method() -> None:
    """Run all scenarios for one chosen method."""
    print()
    print("=" * 75)
    print("  SINGLE METHOD MODE")
    print("=" * 75)
    print()
    print("  Choose a validation method:")
    print("    [1] No Validation")
    print("    [2] Nonce-Only")
    print("    [3] Counter-Only")
    print("    [4] Hybrid")
    print()

    while True:
        choice = input("  Enter choice [1-4]: ").strip()
        if choice in ("1", "2", "3", "4"):
            method_id = int(choice)
            break
        print("  Invalid choice. Please enter 1, 2, 3, or 4.")

    method_name = dict(METHODS)[method_id]
    all_scenarios = STANDARD_SCENARIOS + ["reset_attack", "desync_attack"]

    print()
    print(f"  Running {method_name} against all {len(all_scenarios)} scenarios")
    print(f"  ({NUM_TRIALS} trials per scenario)")
    print()

    grid: Dict = {}
    for scenario in all_scenarios:
        print(f"  Running {scenario:<20} ... ", end="", flush=True)
        grid[(method_id, scenario)] = run_trials(method_id, scenario, NUM_TRIALS)
        print("done")

    print()
    print("=" * 75)
    print(f"  RESULTS FOR {method_name.upper()}")
    print("=" * 75)
    print()
    print(f"  {'Scenario':<20} {'Det.Rate':>10} {'ASR':>10} {'Latency (us)':>15}")
    print("  " + "-" * 67)
    for scenario in all_scenarios:
        cell = grid[(method_id, scenario)]
        det = "N/A" if cell["detection_rate"] is None else f"{cell['detection_rate']:.1f}%"
        asr = "N/A" if cell["asr"] is None else f"{cell['asr']:.1f}%"
        lat = f"{cell['avg_latency_us']:.2f}"
        print(f"  {scenario:<20} {det:>10} {asr:>10} {lat:>15}")
    print()

    safe_name = method_name.lower().replace(" ", "_").replace("-", "_")
    filename = f"results_{safe_name}.csv"
    save_to_csv(grid, all_scenarios, filename)
    print()


# =============================================================================
# Menu
# =============================================================================

def show_menu() -> str:
    """Display the main menu and return the user's selection."""
    print()
    print("=" * 75)
    print("  REPLAY ATTACK PREVENTION SIMULATION")
    print("  Hybrid Nonce-Counter Framework for Smart Car IoT")
    print("=" * 75)
    print()
    print(f"  Configuration: {NUM_TRIALS} trials per experiment, "
          f"{NUM_NORMAL_MESSAGES} normal messages per trial")
    print()
    print("  Choose an experiment:")
    print()
    print("    [1] Full Grid Experiment")
    print("        4 methods x 5 standard scenarios = 20 experiments")
    print()
    print("    [2] Reset Scenario")
    print("        All 4 methods tested against ECU power loss")
    print()
    print("    [3] Desync Scenario")
    print("        All 4 methods tested against message jamming")
    print()
    print("    [4] Single Method")
    print("        Pick one method, run it against all 7 scenarios")
    print()
    print("    [5] Exit")
    print()

    while True:
        choice = input("  Enter choice [1-5]: ").strip()
        if choice in ("1", "2", "3", "4", "5"):
            return choice
        print("  Invalid choice. Please enter 1-5.")


def main() -> None:
    if RANDOM_SEED is not None:
        random.seed(RANDOM_SEED)

    while True:
        choice = show_menu()

        if choice == "1":
            run_full_grid()
        elif choice == "2":
            run_reset_experiment()
        elif choice == "3":
            run_desync_experiment()
        elif choice == "4":
            run_single_method()
        elif choice == "5":
            print()
            print("  Exiting.")
            print()
            break

        print()
        again = input("  Run another experiment? [y/N]: ").strip().lower()
        if again != "y":
            print()
            print("  Done. CSV files have been saved to the current directory.")
            print()
            break


if __name__ == "__main__":
    main()
