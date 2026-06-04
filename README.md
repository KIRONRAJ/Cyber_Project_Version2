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
| 3 | Counter-Only | Rejects if the counter is not greater than the last accepted. |
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

## Experimental Design

- Each experiment cell is **isolated**: fresh KeyFob, CarECU, and Attacker for every run.
- Each cell is repeated `NUM_TRIALS` times (default 30) and averaged.


---

## How performance is measured

Three metrics:

- **Detection Rate (DR)** = % of attacks caught. *Higher is better.*
  `DR = (attacks rejected / total attacks) × 100`
- **Attack Success Rate (ASR)** = % of attacks that got through. *Lower is better.*
  `ASR = 100 − DR`
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

## Results — and the verdict

Below is real output from running the simulation (4 methods × 7 scenarios, 30 trials each, seed 42). Latency is in microseconds (µs); exact values depend on the machine, but the **pattern** is what matters.

### Attack Success Rate — the key table (lower = better; 0% means every attack was stopped)

| Method | delayed | multiple | out_of_order | counter_skip | **reset** | **desync** |
|--------|:-------:|:--------:|:------------:|:------------:|:---------:|:----------:|
| No Validation | 100% | 100% | 100% | 100% | 100% | 100% |
| **Nonce-Only** | 0% | 0% | 0% | 0% | **100% ❌** | **100% ❌** |
| Counter-Only | 0% | 0% | 0% | 0% | 0% ✅ | 0% ✅ |
| **Hybrid** | 0% | 0% | 0% | 0% | **0% ✅** | **0% ✅** |

### What this shows

On the **five standard attacks**, all three protected methods score a perfect 0% ASR — they look identical. The story only appears in the **last two columns**:

- **Nonce-Only FAILS** both the reset and desync scenarios. After a power loss its memory is wiped, and a jammed message was never recorded — so in both cases old messages look new and get accepted. **100% of those attacks succeed.**
- **Counter-Only and Hybrid HOLD.** The counter survives power loss (it lives in EEPROM) and always moves forward, so replayed old messages are rejected every time.

### Latency cost (average µs per message; lower = better)

| Method | Typical latency | Overhead vs baseline |
|--------|:---------------:|:--------------------:|
| No Validation | ~0.19 µs | — (baseline) |
| Counter-Only | ~0.26 µs | ~0.07 µs |
| Nonce-Only | ~0.32 µs | ~0.13 µs |
| Hybrid | ~0.37 µs | ~0.18 µs |

The Hybrid is the slowest, but the difference is about **0.18 millionths of a second** per message. For comparison, a car door physically unlocking takes about 100 milliseconds — roughly **half a million times slower**. The security cost is invisible in practice.

### The verdict

**The Hybrid method is the recommended choice.**

1. **It is never worse** than the best individual method in any scenario tested.
2. **It survives the realistic failure modes** (reset and desync) that defeat Nonce-Only.
3. **It is defence-in-depth.** An attacker has to beat *two* independent checks. Attacks that target the counter (such as rollback attacks in the literature) are still caught by the nonce check, and attacks that target the nonce memory are still caught by the counter.
4. **The extra cost is negligible** — well under a microsecond per message.

Counter-Only ties with Hybrid in these specific tests, because no tested scenario defeats the counter. But Counter-Only is one new attack (e.g. a counter-rollback exploit) or one implementation bug away from failure, whereas the Hybrid keeps a backup check at almost no cost. **For a real safety-critical system, the Hybrid's redundancy is worth its tiny overhead.**

---

## Generating the result graphs

After running the experiments and producing the CSV files, generate the four report figures:

```bash
pip install matplotlib numpy    # one-time setup
python Plot_graph.py
```

This reads the CSV files in the current directory and outputs:

| Output file | What it shows |
|-------------|---------------|
| `fig1_asr_all.png` | Attack Success Rate across all 6 scenarios (standard + robustness) |
| `fig2_asr_robustness.png` | ASR under reset and desync only (the key finding) |
| `fig3_capability_DR.png` | Security capability summary (scenarios defended at 100% Detection Rate) |
| `fig4_latency.png` | Mean validation latency per method with baseline overhead |


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
