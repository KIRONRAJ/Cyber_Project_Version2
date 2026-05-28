# Replay Attack Prevention Simulation

A Python-based simulation comparing four validation methods for replay attack
prevention in smart car IoT systems. Implements and evaluates a hybrid
nonce-counter framework against nonce-only, counter-only, and no-validation
baselines under multiple attack scenarios.

## Project Context

This codebase supports the Master's research project on replay attack prevention
in smart car IoT systems. The simulation models communication between a key fob
(sender) and a vehicle ECU (receiver), with an attacker positioned to intercept
and replay messages.

## Files

| File | Description |
|------|-------------|
| `message_final.py` | Message dataclass (command, nonce, counter, timestamp) |
| `sender_final.py` | Key fob simulation that generates authenticated messages |
| `receiver_final.py` | Car ECU implementing four validation methods |
| `attacker_final.py` | Adversary that captures and replays messages |
| `main_final.py` | Experiment runner with interactive menu |
| `README.md` | This file |

## Requirements

- Python 3.8 or higher
- No external dependencies (uses only the standard library)

## How to Run

```
python3 main_final.py
```

This launches an interactive menu with four experiment options:

1. **Full Grid Experiment** — Runs all 4 methods against all 5 standard
   scenarios (20 experiments total).
2. **Reset Scenario** — Tests all 4 methods against ECU power loss.
3. **Desync Scenario** — Tests all 4 methods against message jamming.
4. **Single Method** — Tests one chosen method against all 7 scenarios.

Each option saves results to a CSV file in the current directory.

## How the 5 Files Connect

```
┌────────────────────────────────────────────────────────────────────┐
│                              main.py                               │
│                       (Interactive menu)                           │
│                                                                    │
│  [1] Full Grid   [2] Reset   [3] Desync   [4] Single Method        │
│                                                                    │
│  For each chosen experiment:                                       │
│    - Create fresh objects                                          │
│    - Run normal traffic                                            │
│    - Run scenario-specific events                                  │
│    - Measure metrics                                               │
│  Then: print tables + export CSV                                   │
└─────────────────────────┬──────────────────────────────────────────┘
                          │ creates instances of:
        ┌─────────────────┼──────────────────┐
        ▼                 ▼                  ▼
   ┌─────────┐       ┌──────────┐       ┌──────────┐
   │ KeyFob  │       │  CarECU  │       │ Attacker │
   │ (sender)│       │(receiver)│       │          │
   └─────────┘       └──────────┘       └──────────┘
        │                  ▲                  │
        │ produces         │ validates        │ intercepts
        └────────► passes ─┴── through ◄──────┘
                      ┌─────────┐
                      │ Message │  (data being passed)
                      └─────────┘
```

---

## Configuration

                    The four decision flows

   No Validation       Nonce-Only         Counter-Only         Hybrid
   ─────────────       ──────────         ────────────         ──────

   Message in          Message in         Message in           Message in
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
    ACCEPT          Nonce seen?         Counter > last?     Nonce seen?
                    /        \           /         \         /         \
                  Yes        No        No         Yes      Yes          No
                   │          │         │           │       │            │
                   ▼          ▼         ▼           ▼       ▼            ▼
                REJECT     ACCEPT   REJECT      ACCEPT  REJECT     Counter > last?
                                                                    /         \
                                                                   No         Yes
                                                                   │           │
                                                                   ▼           ▼
                                                                REJECT      ACCEPT
```

---

## The Four Validation Methods

| ID | Method | Behaviour |
|----|--------|-----------|
| 1 | No Validation | Accepts every message. Baseline control case. |
| 2 | Nonce-Only | Rejects if the nonce has been seen before. |
| 3 | Counter-Only | Rejects if the counter is not greater than the last accepted. |
| 4 | Hybrid | Requires both nonce uniqueness AND counter increment. |

## The Scenarios

### Standard Scenarios

| Scenario | Description |
|----------|-------------|
| `no_attack` | Legitimate traffic only. Baseline for latency measurement. |
| `delayed_replay` | Attacker replays one captured message after the original was processed. |
| `multiple_replay` | Attacker replays the same captured message multiple times. |
| `out_of_order` | Attacker replays all captured messages in reverse order. |
| `counter_skip` | Attacker replays the oldest captured message (lowest counter). |

### Robustness Scenarios

| Scenario | Description |
|----------|-------------|
| `reset_attack` | Simulates ECU power loss. The nonce list (RAM) is cleared; the last counter (EEPROM) is preserved. Attacker then replays all captured messages. |
| `desync_attack` | Attacker jams one message in transit. The ECU never sees that nonce or counter value. Attacker later replays the jammed message. |

## Experimental Design

- Each experiment cell is **isolated**: fresh KeyFob, CarECU, and Attacker for every run.
- Each cell is repeated `NUM_TRIALS` times (default 30) and averaged.


## Metrics

Three metrics are computed per experiment cell:

| Metric | Definition | Direction |
|--------|------------|-----------|
| Detection Rate | Percentage of attack messages rejected | Higher is better |
| Attack Success Rate (ASR) | Percentage of attack messages accepted | Lower is better |
| Average Latency | Mean processing time per message (microseconds) | Lower is better |

For scenarios with no attack messages (`no_attack`), detection rate and ASR
are reported as N/A; only latency is meaningful.

## Output Files

Each experiment mode produces a CSV file with one row per (method, scenario)
combination:

- `results_full_grid.csv` — Full grid experiment
- `results_reset_scenario.csv` — Reset scenario
- `results_desync_scenario.csv` — Desync scenario
- `results_<method_name>.csv` — Single method mode

CSV columns include all metrics plus raw counts (legitimate messages accepted
or rejected, attack messages accepted or rejected, standard deviation of
latency across trials, and the number of trials).

## Expected Results

### Standard Scenarios

All three protected methods (Nonce-Only, Counter-Only, Hybrid) detect
all replays of previously-captured messages, achieving 100% detection rate.

| Method | Standard Scenarios |
|--------|-------------------|
| No Validation | 100% Attack Success Rate |
| Nonce-Only | 0% ASR |
| Counter-Only | 0% ASR |
| Hybrid | 0% ASR |

### Robustness Scenarios

The two robustness scenarios reveal differences between the methods:

| Method | Reset Scenario | Desync Scenario |
|--------|---------------|-----------------|
| No Validation | 100% ASR | 100% ASR |
| Nonce-Only | 100% ASR (fails) | 100% ASR (fails) |
| Counter-Only | 0% ASR | 0% ASR |
| Hybrid | 0% ASR | 0% ASR |

**Reset scenario:** Nonce-Only fails because the nonce list is cleared on
power loss, allowing all captured messages to be replayed successfully.
Counter-Only and Hybrid survive because the persistent counter still
rejects messages with stale counter values.

**Desync scenario:** Nonce-Only fails because the jammed nonce was never
recorded in the ECU's nonce list. To Nonce-Only, the replayed message
appears fresh. Counter-Only and Hybrid catch it because the counter value
is lower than the ECU's current state.

### Latency

Validation overhead is small in all methods. Hybrid is the slowest because
it performs two checks instead of one, but the difference is below one
microsecond on typical hardware.



## Limitations

- This is a software-level simulation. Physical-layer effects (RF signal
  strength, jamming bandwidth, propagation delay) are not modelled.
- The attacker is assumed to capture messages perfectly. Real-world capture
  rates are lower.
- No cryptographic operations are simulated. Replay attacks do not require
  breaking encryption, but real systems combine replay protection with
  authenticated encryption.
- Latency measurements reflect Python interpreter overhead, not deployment
  on constrained hardware. Relative comparisons between methods remain
  meaningful, but absolute values are not representative of microcontroller
  performance.

## File Structure

```
.
├── README.md
├── message_final.py
├── sender_final.py
├── receiver_final.py
├── attacker_final.py
└── main_final.py
```
