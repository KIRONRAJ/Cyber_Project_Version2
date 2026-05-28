"""
receiver_final.py
Simulates the car ECU. Implements four validation methods for incoming
messages: no protection, nonce-only, counter-only, and hybrid.
"""

from typing import Set
from message_final import Message


class CarECU:
    """Car ECU that validates incoming messages using a configurable method."""

    METHOD_NO_VALIDATION = 1
    METHOD_NONCE_ONLY = 2
    METHOD_COUNTER_ONLY = 3
    METHOD_HYBRID = 4

    def __init__(self, method: int = METHOD_NO_VALIDATION):
        self.method = method
        self.nonce_list: Set[int] = set()
        self.last_counter: int = 0
        self.accepted_count: int = 0
        self.rejected_count: int = 0

    def receive(self, msg: Message) -> bool:
        """Validate an incoming message and return True if accepted."""
        if self.method == self.METHOD_NO_VALIDATION:
            result = self._method_no_validation(msg)
        elif self.method == self.METHOD_NONCE_ONLY:
            result = self._method_nonce_only(msg)
        elif self.method == self.METHOD_COUNTER_ONLY:
            result = self._method_counter_only(msg)
        elif self.method == self.METHOD_HYBRID:
            result = self._method_hybrid(msg)
        else:
            raise ValueError(f"Unknown validation method: {self.method}")

        if result:
            self.accepted_count += 1
        else:
            self.rejected_count += 1
        return result

    # ---- Validation methods ----

    def _method_no_validation(self, msg: Message) -> bool:
        """Accept every message without checks. Baseline control case."""
        return True

    def _method_nonce_only(self, msg: Message) -> bool:
        """Reject if the nonce has been seen before, otherwise accept and store."""
        if msg.nonce in self.nonce_list:
            return False
        self.nonce_list.add(msg.nonce)
        return True

    def _method_counter_only(self, msg: Message) -> bool:
        """Accept only if the counter exceeds the last accepted counter."""
        if msg.counter <= self.last_counter:
            return False
        self.last_counter = msg.counter
        return True

    def _method_hybrid(self, msg: Message) -> bool:
        """Accept only if nonce is unseen AND counter exceeds last accepted."""
        if msg.nonce in self.nonce_list:
            return False
        if msg.counter <= self.last_counter:
            return False
        self.nonce_list.add(msg.nonce)
        self.last_counter = msg.counter
        return True

    # ---- Reset methods ----

    def reset(self) -> None:
        """Full reset of all state. Used between experiments for isolation."""
        self.nonce_list.clear()
        self.last_counter = 0
        self.accepted_count = 0
        self.rejected_count = 0

    def volatile_reset(self) -> None:
        """
        Simulate a realistic ECU power loss.

        The nonce list (assumed to live in volatile RAM) is cleared.
        The last counter (assumed to live in non-volatile EEPROM) is preserved.
        Statistics counters are also preserved so attack-phase accounting
        in the reset scenario remains correct.
        """
        self.nonce_list.clear()
        # last_counter is intentionally preserved
