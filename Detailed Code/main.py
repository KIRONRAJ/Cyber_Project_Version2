"""
MAIN.PY
=======
Main experiment runner for the Replay Attack Prevention simulation.

EXPERIMENTAL DESIGN (per supervisor meeting 16-05):
====================================================
The user is presented with a menu to choose what to run:

  [1] Full Grid          - 4 methods × 5 standard scenarios = 20 experiments
                           (no_attack, delayed, multiple, out_of_order, counter_skip)
  
  [2] Reset Scenario     - Tests how each method handles ECU power loss
                           (volatile state lost, persistent state preserved)
  
  [3] Desync Scenario    - Tests how each method handles message jamming
                           (attacker drops one msg, then replays it later)
  
  [4] Single Method      - Pick ONE method, run all scenarios with verbose output
                           (good for detailed inspection of a specific method)

Each experiment is COMPLETELY ISOLATED — fresh KeyFob, CarECU, Attacker.


DEFAULT TRIAL COUNT:
====================
NUM_TRIALS = 30 (standard statistical minimum — change at top of file).
"""

import time
import csv
import sys
import io
import contextlib
import random
import statistics
from typing import Dict, Optional
from sender import KeyFob
from receiver import CarECU
from attacker import Attacker


# =========================================================================
# CONFIGURATION
# =========================================================================

NUM_NORMAL_MESSAGES = 10       # Legitimate messages sent before any attack
NUM_TRIALS = 30                # How many times to repeat each cell (for averaging)
MULTIPLE_REPLAY_COUNT = 5      # In "multiple replay" attack: replay msg N times
RANDOM_SEED = 42               # Makes random nonces reproducible (None = random)

# The 4 validation methods we're comparing
METHODS = [
    (1, "No Validation"),
    (2, "Nonce-Only"),
    (3, "Counter-Only"),
    (4, "Hybrid"),
]

# Standard scenarios (for the full grid)
STANDARD_SCENARIOS = [
    "no_attack",
    "delayed_replay",
    "multiple_replay",
    "out_of_order",
    "counter_skip",
]


# =========================================================================
# HELPER: SUPPRESS PRINT OUTPUT
# =========================================================================
# Our sender/receiver/attacker have many print statements (for learning).
# When running 600+ experiments (20 cells × 30 trials), the output would
# be overwhelming. This silences them temporarily.

@contextlib.contextmanager
def suppress_print():
    """
    Temporarily redirect stdout to a discard buffer.
    
    Usage:
        with suppress_print():
            run_experiment(...)   # all the prints inside are silenced
    """
    old_stdout = sys.stdout
    sys.stdout = io.StringIO()
    try:
        yield
    finally:
        sys.stdout = old_stdout


# =========================================================================
# CORE: SINGLE EXPERIMENT RUNNER
# =========================================================================

def run_experiment(method_id: int, scenario: str) -> Dict:
    """
    Run ONE experiment cell.
    
    Steps:
    1. Create FRESH KeyFob, CarECU, Attacker (no state from previous run)
    2. Send NUM_NORMAL_MESSAGES legitimate messages (attacker captures them)
    3. Execute the scenario-specific attack
    4. Measure: detection rate, attack success rate, average latency
    
    Returns:
        Dict with all metrics for this single experiment.
    """
    # Fresh, isolated instances
    keyfob = KeyFob()
    car = CarECU(method=method_id)
    attacker = Attacker()
    
    legitimate_accepted = 0
    legitimate_rejected = 0
    legitimate_latencies = []
    
    attacks_accepted = 0
    attacks_rejected = 0
    attack_latencies = []
    
    # ---- STANDARD SCENARIOS PATH ----
    if scenario in STANDARD_SCENARIOS:
        # Normal phase: send legitimate messages, attacker captures
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
            if accepted: legitimate_accepted += 1
            else: legitimate_rejected += 1
        
        # Attack phase
        attack_messages = []
        if scenario == "no_attack":
            attack_messages = []
        elif scenario == "delayed_replay":
            attack_messages = attacker.delayed_replay(delay_index=0)
        elif scenario == "multiple_replay":
            attack_messages = attacker.multiple_replay(msg_index=0, count=MULTIPLE_REPLAY_COUNT)
        elif scenario == "out_of_order":
            attack_messages = attacker.out_of_order_replay()
        elif scenario == "counter_skip":
            attack_messages = attacker.counter_skip_replay()
        
        # Process attack messages
        for msg in attack_messages:
            start = time.perf_counter()
            accepted = car.receive(msg)
            end = time.perf_counter()
            
            attack_latencies.append((end - start) * 1_000_000)
            if accepted: attacks_accepted += 1
            else: attacks_rejected += 1
    
    # ---- RESET SCENARIO PATH ----
    elif scenario == "reset_attack":
        # Phase 1: Normal traffic (attacker captures)
        for i in range(NUM_NORMAL_MESSAGES):
            msg = keyfob.unlock()
            captured = attacker.intercept(msg)
            
            start = time.perf_counter()
            accepted = car.receive(captured)
            end = time.perf_counter()
            
            legitimate_latencies.append((end - start) * 1_000_000)
            if accepted: legitimate_accepted += 1
            else: legitimate_rejected += 1
        
        # Phase 2: VOLATILE RESET (simulates power loss)
        # nonce_list is cleared (was in RAM)
        # last_counter is PRESERVED (was in EEPROM)
        car.volatile_reset()
        
        # Phase 3: Attacker replays captured messages
        # The goal: see if the car still rejects them after losing nonce memory
        attack_messages = list(attacker.captured_messages)  # replay all captured
        
        for msg in attack_messages:
            start = time.perf_counter()
            accepted = car.receive(msg)
            end = time.perf_counter()
            
            attack_latencies.append((end - start) * 1_000_000)
            if accepted: attacks_accepted += 1
            else: attacks_rejected += 1
    
    # ---- DESYNC SCENARIO PATH ----
    elif scenario == "desync_attack":
        # Phase 1: Send some normal messages (deliver to car)
        first_batch = NUM_NORMAL_MESSAGES // 2  # half the messages
        for i in range(first_batch):
            msg = keyfob.unlock()
            captured = attacker.intercept(msg)
            
            start = time.perf_counter()
            accepted = car.receive(captured)
            end = time.perf_counter()
            
            legitimate_latencies.append((end - start) * 1_000_000)
            if accepted: legitimate_accepted += 1
            else: legitimate_rejected += 1
        
        # Phase 2: Attacker JAMS the next message
        # Sender sends it, attacker captures it, but it NEVER reaches the car
        jammed_msg = keyfob.unlock()
        attacker.silent_capture(jammed_msg)
        # Note: this message is in attacker.captured_messages but NOT in car
        
        # Phase 3: Send the rest of the normal messages
        # The car's counter "skips over" the jammed message
        for i in range(NUM_NORMAL_MESSAGES - first_batch - 1):
            msg = keyfob.unlock()
            captured = attacker.intercept(msg)
            
            start = time.perf_counter()
            accepted = car.receive(captured)
            end = time.perf_counter()
            
            legitimate_latencies.append((end - start) * 1_000_000)
            if accepted: legitimate_accepted += 1
            else: legitimate_rejected += 1
        
        # Phase 4: Attacker replays the JAMMED message
        # This is the critical test:
        # - The car has NEVER seen this nonce → Nonce-Only check passes → ACCEPTS (FAILURE!)
        # - The counter is LOWER than the car's current state → Counter-Only catches it
        # - Hybrid catches via counter check
        attack_messages = [jammed_msg]
        
        for msg in attack_messages:
            start = time.perf_counter()
            accepted = car.receive(msg)
            end = time.perf_counter()
            
            attack_latencies.append((end - start) * 1_000_000)
            if accepted: attacks_accepted += 1
            else: attacks_rejected += 1
    
    else:
        raise ValueError(f"Unknown scenario: {scenario}")
    
    # ---- METRICS ----
    total_attacks = len(attack_latencies)
    
    if total_attacks > 0:
        detection_rate = (attacks_rejected / total_attacks) * 100
        asr = (attacks_accepted / total_attacks) * 100
    else:
        detection_rate = None
        asr = None
    
    all_latencies = legitimate_latencies + attack_latencies
    avg_latency = sum(all_latencies) / len(all_latencies) if all_latencies else 0
    
    return {
        'method_id': method_id,
        'scenario': scenario,
        'legitimate_total': len(legitimate_latencies),
        'legitimate_accepted': legitimate_accepted,
        'legitimate_rejected': legitimate_rejected,
        'attacks_total': total_attacks,
        'attacks_accepted': attacks_accepted,
        'attacks_rejected': attacks_rejected,
        'detection_rate': detection_rate,
        'asr': asr,
        'avg_latency_us': avg_latency,
    }


# =========================================================================
# MULTI-TRIAL RUNNER
# =========================================================================

def run_trials(method_id: int, scenario: str, num_trials: int, verbose: bool = False) -> Dict:
    """
    Run the same experiment multiple times and average results.
    Also computes standard deviation for latency.
    
    Parameters:
        method_id (int):  validation method
        scenario (str):   scenario to run
        num_trials (int): how many repetitions
        verbose (bool):   if True, don't suppress print output (for single-method mode)
    """
    trials = []
    for _ in range(num_trials):
        if verbose:
            result = run_experiment(method_id, scenario)
        else:
            with suppress_print():
                result = run_experiment(method_id, scenario)
        trials.append(result)
    
    # Average numeric fields
    numeric_fields = [
        'legitimate_accepted', 'legitimate_rejected',
        'attacks_accepted', 'attacks_rejected',
        'avg_latency_us',
    ]
    
    avg = {
        'method_id': method_id,
        'scenario': scenario,
        'num_trials': num_trials,
        'legitimate_total': trials[0]['legitimate_total'],
        'attacks_total': trials[0]['attacks_total'],
    }
    
    for field in numeric_fields:
        avg[field] = sum(t[field] for t in trials) / num_trials
    
    # Latency std dev (only meaningful with multiple trials)
    latencies = [t['avg_latency_us'] for t in trials]
    avg['std_latency_us'] = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
    
    # detection_rate and asr can be None (for no_attack)
    det_rates = [t['detection_rate'] for t in trials if t['detection_rate'] is not None]
    asrs = [t['asr'] for t in trials if t['asr'] is not None]
    
    avg['detection_rate'] = sum(det_rates) / len(det_rates) if det_rates else None
    avg['asr'] = sum(asrs) / len(asrs) if asrs else None
    
    return avg


# =========================================================================
# OUTPUT: FORMATTED TABLES
# =========================================================================

def print_metric_table(grid: Dict, scenarios: list, metric: str, title: str):
    """Print one table for one metric across the methods × scenarios grid."""
    print()
    print("=" * 95)
    print(f"  {title}")
    print("=" * 95)
    
    # Header row
    header = f"  {'Method':<18}"
    for scenario in scenarios:
        header += f" {scenario:>15}"
    print(header)
    print("  " + "─" * 93)
    
    # Data rows
    for method_id, method_name in METHODS:
        row = f"  {method_name:<18}"
        for scenario in scenarios:
            cell = grid[(method_id, scenario)]
            
            if metric == "detection_rate":
                value = cell['detection_rate']
            elif metric == "asr":
                value = cell['asr']
            elif metric == "latency":
                value = cell['avg_latency_us']
            else:
                value = None
            
            if value is None:
                row += f" {'N/A':>15}"
            elif metric == "latency":
                row += f" {value:>12.2f} µs"
            else:
                row += f" {value:>13.1f}%"
        print(row)
    print()


# =========================================================================
# OUTPUT: CSV EXPORT
# =========================================================================

def save_to_csv(grid: Dict, scenarios: list, filename: str):
    """Save grid to CSV — one row per (method, scenario)."""
    fields = [
        'method_id', 'method_name', 'scenario',
        'legitimate_total', 'legitimate_accepted', 'legitimate_rejected',
        'attacks_total', 'attacks_accepted', 'attacks_rejected',
        'detection_rate', 'asr', 'avg_latency_us', 'std_latency_us',
        'num_trials',
    ]
    
    method_names = {mid: name for mid, name in METHODS}
    
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        
        for method_id, _ in METHODS:
            for scenario in scenarios:
                if (method_id, scenario) not in grid:
                    continue
                row = dict(grid[(method_id, scenario)])
                row['method_name'] = method_names[method_id]
                for k, v in row.items():
                    if v is None:
                        row[k] = ""
                writer.writerow(row)
    
    print(f"  ✓ Results saved to: {filename}")


# =========================================================================
# OPTION 1: FULL GRID
# =========================================================================

def run_full_grid():
    """Run all 4×5 = 20 experiments (standard scenarios)."""
    print()
    print("=" * 75)
    print(f"  FULL GRID EXPERIMENT ({NUM_TRIALS} trials per cell, "
          f"{len(METHODS) * len(STANDARD_SCENARIOS)} cells)")
    print("=" * 75)
    print()
    
    grid = {}
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
                       "DETECTION RATE (%) — Higher is better")
    print_metric_table(grid, STANDARD_SCENARIOS, "asr",
                       "ATTACK SUCCESS RATE (%) — Lower is better")
    print_metric_table(grid, STANDARD_SCENARIOS, "latency",
                       "AVERAGE LATENCY (µs) — Lower is better")
    
    print("=" * 75)
    save_to_csv(grid, STANDARD_SCENARIOS, "results_full_grid.csv")
    print()


# =========================================================================
# OPTION 2: RESET SCENARIO
# =========================================================================

def run_reset_experiment():
    """Run reset scenario for all 4 methods."""
    print()
    print("=" * 75)
    print(f"  RESET SCENARIO ({NUM_TRIALS} trials per method)")
    print("=" * 75)
    print()
    print("  What this tests:")
    print("    1. Send legitimate messages (attacker captures)")
    print("    2. Car suffers a power loss → volatile state lost")
    print("       (nonce_list cleared, last_counter preserved in EEPROM)")
    print("    3. Attacker replays all captured messages")
    print()
    print("  Expected pattern:")
    print("    No Validation:  100% ASR (accepts everything anyway)")
    print("    Nonce-Only:     HIGH ASR  ← fails because nonce_list was wiped")
    print("    Counter-Only:   0% ASR    ← counter persisted, replays caught")
    print("    Hybrid:         0% ASR    ← counter check catches replays")
    print()
    
    grid = {}
    for method_id, method_name in METHODS:
        print(f"  Running {method_name:<18} ... ", end="", flush=True)
        grid[(method_id, "reset_attack")] = run_trials(method_id, "reset_attack", NUM_TRIALS)
        print("done")
    
    print_metric_table(grid, ["reset_attack"], "detection_rate",
                       "DETECTION RATE (%) — Higher is better")
    print_metric_table(grid, ["reset_attack"], "asr",
                       "ATTACK SUCCESS RATE (%) — Lower is better")
    print_metric_table(grid, ["reset_attack"], "latency",
                       "AVERAGE LATENCY (µs) — Lower is better")
    
    print("=" * 75)
    save_to_csv(grid, ["reset_attack"], "results_reset_scenario.csv")
    print()


# =========================================================================
# OPTION 3: DESYNC SCENARIO
# =========================================================================

def run_desync_experiment():
    """Run desync scenario for all 4 methods."""
    print()
    print("=" * 75)
    print(f"  DESYNC SCENARIO ({NUM_TRIALS} trials per method)")
    print("=" * 75)
    print()
    print("  What this tests:")
    print("    1. Send some normal messages (delivered to car)")
    print("    2. Sender sends a message — but attacker JAMS it")
    print("       (Captured by attacker, never reaches car)")
    print("    3. Sender continues — car keeps receiving")
    print("       (Car's counter advances past the jammed message)")
    print("    4. Attacker replays the JAMMED message")
    print()
    print("  Why this is interesting:")
    print("    The car's nonce_list NEVER recorded the jammed nonce.")
    print("    So Nonce-Only sees a 'fresh' nonce and ACCEPTS the replay.")
    print("    But Counter-Only sees the counter is lower than current state.")
    print()
    print("  Expected pattern:")
    print("    No Validation:  100% ASR (no defence)")
    print("    Nonce-Only:     100% ASR ← FAILS: nonce was never seen by car")
    print("    Counter-Only:   0% ASR   ← catches it: counter too low")
    print("    Hybrid:         0% ASR   ← catches via counter check")
    print()
    
    grid = {}
    for method_id, method_name in METHODS:
        print(f"  Running {method_name:<18} ... ", end="", flush=True)
        grid[(method_id, "desync_attack")] = run_trials(method_id, "desync_attack", NUM_TRIALS)
        print("done")
    
    print_metric_table(grid, ["desync_attack"], "detection_rate",
                       "DETECTION RATE (%) — Higher is better")
    print_metric_table(grid, ["desync_attack"], "asr",
                       "ATTACK SUCCESS RATE (%) — Lower is better")
    print_metric_table(grid, ["desync_attack"], "latency",
                       "AVERAGE LATENCY (µs) — Lower is better")
    
    print("=" * 75)
    save_to_csv(grid, ["desync_attack"], "results_desync_scenario.csv")
    print()


# =========================================================================
# OPTION 4: SINGLE METHOD (VERBOSE)
# =========================================================================

def run_single_method():
    """Run all scenarios for ONE chosen method, with verbose output."""
    print()
    print("=" * 75)
    print("  SINGLE METHOD MODE")
    print("=" * 75)
    print()
    print("  Choose which method to test:")
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
        print("  Invalid choice. Try again.")
    
    method_name = dict(METHODS)[method_id]
    
    print()
    print(f"  Running {method_name} against all scenarios...")
    print(f"  Trials per scenario: {NUM_TRIALS}")
    print(f"  (verbose mode — you'll see each step)")
    print()
    
    # For verbose mode, run just ONE trial visibly so the user can see what's happening,
    # then NUM_TRIALS-1 more silently for averaging.
    all_scenarios = STANDARD_SCENARIOS + ["reset_attack", "desync_attack"]
    
    grid = {}
    for scenario in all_scenarios:
        print()
        print("─" * 75)
        print(f"  SCENARIO: {scenario}")
        print("─" * 75)
        
        # Show ONE verbose trial so user understands what happens
        if NUM_TRIALS > 1:
            print(f"  (Showing one verbose trial, then averaging across {NUM_TRIALS} silent trials)")
            print()
            run_experiment(method_id, scenario)
            print()
        
        # Run the full set of trials (silently) for averaging
        grid[(method_id, scenario)] = run_trials(method_id, scenario, NUM_TRIALS)
    
    # Custom display for single method (transposed: scenarios as rows)
    print()
    print("=" * 75)
    print(f"  RESULTS FOR {method_name.upper()}")
    print("=" * 75)
    print()
    print(f"  {'Scenario':<20} {'Det.Rate':>10} {'ASR':>10} {'Latency (µs)':>15}")
    print("  " + "─" * 67)
    for scenario in all_scenarios:
        cell = grid[(method_id, scenario)]
        det = "N/A" if cell['detection_rate'] is None else f"{cell['detection_rate']:.1f}%"
        asr = "N/A" if cell['asr'] is None else f"{cell['asr']:.1f}%"
        lat = f"{cell['avg_latency_us']:.2f}"
        print(f"  {scenario:<20} {det:>10} {asr:>10} {lat:>15}")
    print()
    
    filename = f"results_{method_name.lower().replace(' ', '_').replace('-', '_')}.csv"
    save_to_csv(grid, all_scenarios, filename)
    print()


# =========================================================================
# INTERACTIVE MENU
# =========================================================================

def show_menu():
    """Display the main menu and get user choice."""
    print()
    print("=" * 75)
    print("  REPLAY ATTACK PREVENTION SIMULATION")
    print("  Hybrid Nonce-Counter Framework for Smart Car IoT")
    print("=" * 75)
    print()
    print(f"  Configuration: {NUM_TRIALS} trials per experiment, "
          f"{NUM_NORMAL_MESSAGES} normal messages per trial")
    print()
    print("  What would you like to run?")
    print()
    print("    [1] Full Grid Experiment")
    print("        Runs all 4 methods × 5 standard scenarios = 20 experiments.")
    print("        Best for: complete research data, generating tables/graphs.")
    print()
    print("    [2] Reset Scenario")
    print("        Tests all 4 methods against ECU power loss (volatile reset).")
    print("        Reveals: Nonce-Only's weakness vs Counter-Only/Hybrid's resilience.")
    print()
    print("    [3] Desync Scenario")
    print("        Tests all 4 methods against jammed/dropped messages.")
    print("        Reveals: Nonce-Only's blind spot vs Counter-Only/Hybrid's defence.")
    print()
    print("    [4] Single Method (Verbose)")
    print("        Pick ONE method, run it against all scenarios with detailed output.")
    print("        Best for: understanding HOW a method behaves, not just metrics.")
    print()
    print("    [5] Exit")
    print()
    
    while True:
        choice = input("  Enter choice [1-5]: ").strip()
        if choice in ("1", "2", "3", "4", "5"):
            return choice
        print("  Invalid choice. Please enter 1-5.")


def main():
    """Top-level orchestrator."""
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
            print("  Goodbye!")
            print()
            break
        
        # After running, ask if they want to do something else
        print()
        again = input("  Run another experiment? [y/N]: ").strip().lower()
        if again != "y":
            print()
            print("  Done. Check the generated CSV files for your results.")
            print()
            break


if __name__ == "__main__":
    main()