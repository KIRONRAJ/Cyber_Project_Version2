# Replay Attack Prevention in Smart Car IoT — Hybrid Nonce-Counter Framework

A Python simulation that tests how well different lightweight security methods stop **replay attacks** on a car's wireless key fob system. It compares four validation methods against seven attack scenarios and measures which one offers the best security with the least performance cost.

**Project — IT9115, Whitecliffe NZ**

---

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

This launches an interactive menu. The main options are:

1. **Full Grid Experiment** — Runs all 4 methods against every scenario.
2. **Reset Scenario** — Tests all 4 methods against ECU power loss.
3. **Desync Scenario** — Tests all 4 methods against message jamming.
4. **Rollback Scenario** — Tests all 4 methods against a counter-rollback attack.
5. **Single Method** — Tests one chosen method against all scenarios.
6. **Nonce-Field Sweep** — Measures the False Rejection Rate as the nonce length increases from 6 to 16 bits.
7. **Statistics** — Runs the paired statistical comparisons between methods.
8. **Run Everything** — Runs all of the above and exports every CSV.

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

---

```
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
| 3 | Counter-Only | Accepts only if the counter is within a forward window above the last accepted (rejects stale or far-ahead counters). |
| 4 | Hybrid | Requires both nonce uniqueness AND counter increment. |

## The Scenarios


## How the simulation is built

The code models three "characters" talking over a wireless channel:

```
   KEY FOB  ──sends message──►  ATTACKER  ──forwards──►  CAR ECU
  (sender)                    (captures &              (receiver,
                               replays)                 validates)
```

- **Key Fob** generates messages (UNLOCK / LOCK / START), each carrying a command, a random nonce, and a counter.
- **Attacker** sits on the channel. It copies every message, lets it through, and later replays the copies to try to fool the car.
- **Car ECU** receives messages and decides ACCEPT or REJECT using whichever security method is being tested.

Everything runs as plain Python objects in one program, so we get exact control over message order, attack timing, and precise timing measurements.

---

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
| `counter_rollback` | Simulates a rollback attack (such as RollBack from the literature). The counter is forced backwards while the nonce list is preserved. Attacker then replays all captured messages. |

## Experimental Design

- Each experiment cell is **isolated**: fresh KeyFob, CarECU, and Attacker for every run.
- Each cell is repeated `NUM_TRIALS` times (default **1000**) and averaged.
- Trials are **paired**: in each trial the same seeded message stream is given to all four methods, so any difference comes from the method and not from luck.
- Results are reported as averages with **95% confidence intervals**.


---

## How performance is measured

Four metrics:

- **Detection Rate (DR)** = % of attacks caught. *Higher is better.*
  `DR = (attacks rejected / total attacks) × 100`
- **Attack Success Rate (ASR)** = % of attacks that got through. *Lower is better.*
  `ASR = 100 − DR`
- **False Rejection Rate (FRR)** = % of *genuine* messages wrongly rejected. *Lower is better.* This happens when two genuine messages pick the same short nonce by chance.
  `FRR = (genuine messages rejected / total genuine messages) × 100`
- **Latency** = time to validate one message, in microseconds (millionths of a second). *Lower is better.* Measured with Python's high-resolution `time.perf_counter()`.

---


### Standard Scenarios

All three protected methods (Nonce-Only, Counter-Only, Hybrid) detect
all replays of previously-captured messages, achieving 100% detection rate.

| Method | Standard Scenarios |
|--------|-------------------|
| No Validation | 100% Attack Success Rate |
| Nonce-Only | 0% ASR |
| Counter-Only | 0% ASR |
| Hybrid | 0% ASR |

With the realistic short nonce, Nonce-Only and Hybrid also wrongly reject about
1.96% of genuine messages (their False Rejection Rate) at an 8-bit nonce, while
Counter-Only and No Validation have 0% FRR.

### Robustness Scenarios

The two robustness scenarios reveal differences between the methods:

| Method | Reset | Desync | Rollback |
|--------|-------|--------|----------|
| No Validation | 100% ASR | 100% ASR | 100% ASR |
| Nonce-Only | 98% ASR (fails) | 97% ASR (fails) | 0% ASR |
| Counter-Only | 0% ASR | 0% ASR | 100% ASR (fails) |
| Hybrid | 0% ASR | 0% ASR | 0% ASR |

**Reset scenario:** Nonce-Only fails because the nonce list is cleared on
power loss, allowing all captured messages to be replayed successfully.
Counter-Only and Hybrid survive because the persistent counter still
rejects messages with stale counter values.

**Desync scenario:** Nonce-Only fails because the jammed nonce was never
recorded in the ECU's nonce list. To Nonce-Only, the replayed message
appears fresh. Counter-Only and Hybrid catch it because the counter value
is lower than the ECU's current state.

**Rollback scenario:** Counter-Only fails because the counter is forced
backwards, so old captured messages look fresh again and are accepted.
Nonce-Only and Hybrid survive because the nonce list still recognises the
replayed messages.

### Latency

Validation overhead is small in all methods. Hybrid is the slowest because
it performs two checks instead of one, but the difference is below one
microsecond on typical hardware.

## Results — and the verdict

Below is real output from running the simulation (4 methods × 7 attack scenarios, 1000 trials each, seed 42). Latency is in microseconds (µs); exact values depend on the machine, but the **pattern** is what matters.

### Attack Success Rate — the key table (lower = better; 0% means every attack was stopped)

| Method | delayed | multiple | out_of_order | counter_skip | **reset** | **desync** | **rollback** |
|--------|:-------:|:--------:|:------------:|:------------:|:---------:|:----------:|:------------:|
| No Validation | 100% | 100% | 100% | 100% | 100% | 100% | 100% |
| **Nonce-Only** | 0% | 0% | 0% | 0% | **98% ❌** | **97% ❌** | 0% ✅ |
| **Counter-Only** | 0% | 0% | 0% | 0% | 0% ✅ | 0% ✅ | **100% ❌** |
| **Hybrid** | 0% | 0% | 0% | 0% | **0% ✅** | **0% ✅** | **0% ✅** |

### What this shows

On the **four standard attacks**, all three protected methods score a perfect 0% ASR — they look identical. The story only appears in the **last three columns**:

- **Nonce-Only FAILS** the reset and desync scenarios. After a power loss its memory is wiped, and a jammed message was never recorded — so in both cases old messages look new and get accepted.
- **Counter-Only FAILS** the rollback scenario. When the counter is forced backwards, old captured messages look fresh again and are accepted.
- **Only the Hybrid HOLDS everywhere.** A reset or desync is caught by the surviving counter, and a rollback is caught by the surviving nonce memory — the two checks cover each other's blind spots.

### Latency cost (average µs per message; lower = better)

| Method | Typical latency | Overhead vs baseline |
|--------|:---------------:|:--------------------:|
| No Validation | ~0.20 µs | — (baseline) |
| Nonce-Only | ~0.31 µs | ~0.11 µs |
| Counter-Only | ~0.33 µs | ~0.13 µs |
| Hybrid | ~0.44 µs | ~0.24 µs |

The Hybrid is the slowest, but the difference is about **0.24 millionths of a second** per message. For comparison, a car door physically unlocking takes about 100 milliseconds — roughly **two hundred thousand times slower**. The security cost is invisible in practice.

### The verdict

**The Hybrid method is the recommended choice.**

1. **It is strictly the strongest.** It is the only method that stops every attack scenario tested.
2. **It survives the realistic failure modes that defeat the single methods** — a reset or desync (which defeat Nonce-Only) and a rollback (which defeats Counter-Only).
3. **It is defence-in-depth.** An attacker has to beat *two* independent checks: attacks that target the counter (such as rollback) are still caught by the nonce, and attacks that target the nonce memory are still caught by the counter.
4. **The extra cost is small and measurable** — a false-rejection rate of about 1.96% at an 8-bit nonce (which shrinks to near zero with a longer nonce), plus the highest latency of the methods, still well under a microsecond.

Unlike the earlier version of this project, Counter-Only no longer ties with the Hybrid: the rollback scenario defeats it. This makes the case for the Hybrid clearer — it is the only single design with no fatal scenario, and it pays only a small, tunable cost for that robustness.

---

## Generating the result graphs

After running the experiments and producing the CSV files, generate the five report figures:

```bash
pip install matplotlib numpy    # one-time setup
python Plot_graph.py
```

This reads the CSV files in the current directory and outputs:

| Output file | What it shows |
|-------------|---------------|
| `fig1_asr_all_v2.png` | Attack Success Rate across all seven attack scenarios |
| `fig2_frr_vs_nonce.png` | False Rejection Rate as the nonce field length increases |
| `fig3_frr_by_method.png` | False Rejection Rate by method (Counter-Only is structurally zero) |
| `fig4_latency_v2.png` | Mean validation latency per method |
| `fig5_capability_v2.png` | Security capability (attack scenarios neutralised out of seven) |


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
- The methods stop replays of *previously seen* messages, but not the
  **RollJam** attack, where an attacker jams and stores a genuine message and
  replays it later. That replayed message is genuinely fresh (new nonce,
  forward counter), so it defeats all four methods including the Hybrid.
  Defeating RollJam needs a two-way challenge-response exchange, which is
  identified as future work.

## Project structure

```
.
├── message_final.py      # Message structure
├── sender_final.py       # Key fob (sender)
├── receiver_final.py     # Car ECU (receiver) + 4 validation methods
├── attacker_final.py     # Attacker + replay strategies
├── main_final.py         # Experiment runner + menu + CSV export
├── Plot_graph.py         # Graph generator (reads CSVs, writes PNGs)
└── README.md             # This file
```

---
