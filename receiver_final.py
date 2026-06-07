"""
receiver_final.py  (v2)
=======================
Simulates the car ECU and its four validation methods.

WHAT CHANGED IN v2
------------------
1. COUNTER ACCEPTANCE WINDOW. v1 accepted any strictly-increasing counter
   (an infinite forward window). Real rolling-code RKE systems accept counters
   only within a finite forward window so that a few missed button presses do
   not lock the user out. The counter check is now:
       last_counter < C <= last_counter + counter_window
   This is the documented rolling-code behaviour exploited by RollJam / RollBack
   (Csikor et al. 2023; Bianchi et al. 2025).

2. rollback() METHOD. Models the RollBack attack: the counter state is forced
   backwards while the nonce memory survives. This is the mirror image of
   volatile_reset() (power loss clears the nonce RAM but preserves the counter).
   Together they let us show that EACH single method has one fatal scenario and
   only the Hybrid survives both.

The nonce false-positive behaviour (False Rejection Rate) is NOT injected here;
it emerges naturally from this unchanged nonce check when the sender uses a
short, collision-prone nonce field.
"""

from typing import Set
from message_final import Message


class CarECU:
    """Car ECU that validates incoming messages using a configurable method."""

    METHOD_NO_VALIDATION = 1
    METHOD_NONCE_ONLY = 2
    METHOD_COUNTER_ONLY = 3
    METHOD_HYBRID = 4

    def __init__(self, method: int = METHOD_NO_VALIDATION, counter_window: int = 256):
        self.method = method
        self.counter_window = counter_window      # forward window size W
        self.nonce_list: Set[int] = set()
        self.last_counter: int = 0
        self.accepted_count: int = 0
        self.rejected_count: int = 0

    # ---------------- routing ----------------
    def receive(self, msg: Message) -> bool:
        if self.method == self.METHOD_NO_VALIDATION:
            result = self._no_validation(msg)
        elif self.method == self.METHOD_NONCE_ONLY:
            result = self._nonce_only(msg)
        elif self.method == self.METHOD_COUNTER_ONLY:
            result = self._counter_only(msg)
        elif self.method == self.METHOD_HYBRID:
            result = self._hybrid(msg)
        else:
            raise ValueError(f"Unknown validation method: {self.method}")

        if result:
            self.accepted_count += 1
        else:
            self.rejected_count += 1
        return result

    # ---------------- methods ----------------
    def _no_validation(self, msg: Message) -> bool:
        """Accept everything. Baseline control case."""
        return True

    def _nonce_only(self, msg: Message) -> bool:
        """Reject if the nonce was seen before, else accept and store it."""
        if msg.nonce in self.nonce_list:
            return False
        self.nonce_list.add(msg.nonce)
        return True

    def _counter_only(self, msg: Message) -> bool:
        """Accept only if the counter is inside the forward window."""
        if self.last_counter < msg.counter <= self.last_counter + self.counter_window:
            self.last_counter = msg.counter
            return True
        return False

    def _hybrid(self, msg: Message) -> bool:
        """Two sequential checks: nonce freshness AND counter window."""
        if msg.nonce in self.nonce_list:                 # check 1
            return False
        if not (self.last_counter < msg.counter <= self.last_counter + self.counter_window):
            return False                                 # check 2
        self.nonce_list.add(msg.nonce)
        self.last_counter = msg.counter
        return True

    # ---------------- state events ----------------
    def reset(self) -> None:
        """Full reset of all state. Used between experiments for isolation."""
        self.nonce_list.clear()
        self.last_counter = 0
        self.accepted_count = 0
        self.rejected_count = 0

    def volatile_reset(self) -> None:
        """
        Realistic ECU power loss (reset scenario).
        The nonce list (volatile RAM) is cleared; the last counter
        (non-volatile EEPROM) is preserved. Defeats Nonce-Only.
        """
        self.nonce_list.clear()
        # last_counter intentionally preserved

    def rollback(self) -> None:
        """
        RollBack attack (rollback scenario).
        The counter state is forced backwards to its initial value while the
        nonce memory survives. Defeats Counter-Only; Nonce-Only and Hybrid hold
        because the replayed nonces are still on record.
        """
        self.last_counter = 0
        # nonce_list intentionally preserved