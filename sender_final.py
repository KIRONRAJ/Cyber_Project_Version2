"""
sender_final.py  (v2)
=====================
Simulates the smart-car key fob.

WHAT CHANGED IN v2
------------------
The nonce field is now CONFIGURABLE (`nonce_bits`). v1 always drew a 6-digit
nonce from a space so large that two legitimate messages never collided, which
is why every result was a perfect 100% / 0%. Real lightweight RF devices use
SHORT nonce fields to save bandwidth and energy, and short fields collide
(birthday bound, see Zenner 2009; Koien 2015). A configurable field lets us
measure the False Rejection Rate as a function of nonce length.

An optional `rng` (random.Random) can be injected so that each experimental
trial uses its OWN seeded generator. This makes trials reproducible AND lets
the experiment controller feed the *same* message stream to every validation
method, so method comparisons are statistically PAIRED.
"""

import random
from message_final import Message, create_message


class KeyFob:
    """Key fob that generates command messages for transmission to the ECU."""

    def __init__(self, nonce_bits: int = 24, rng: random.Random = None):
        """
        nonce_bits : width of the nonce field. nonce is drawn from [0, 2^bits - 1].
                     Small values (6-10) cause realistic birthday collisions;
                     large values (>=24) behave like the original collision-free v1.
        rng        : optional seeded random.Random for reproducible / paired trials.
                     If None, a fresh unseeded generator is used.
        """
        self.counter = 0
        self.nonce_bits = nonce_bits
        self.nonce_max = (1 << nonce_bits) - 1
        self._rng = rng if rng is not None else random.Random()

    def _generate_nonce(self) -> int:
        return self._rng.randint(0, self.nonce_max)

    def _send_command(self, command: str) -> Message:
        self.counter += 1
        return create_message(
            command=command,
            nonce=self._generate_nonce(),
            counter=self.counter,
        )

    def unlock(self) -> Message:
        return self._send_command("UNLOCK")

    def lock(self) -> Message:
        return self._send_command("LOCK")

    def start(self) -> Message:
        return self._send_command("START")

    def reset(self) -> None:
        """Reset the counter to zero (simulates key-fob battery removal)."""
        self.counter = 0