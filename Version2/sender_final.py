"""
sender_final.py
Simulates a smart car key fob. Generates authenticated command messages
containing a command, a random nonce, and an incrementing counter.
"""

import random
from message_final import Message, create_message


class KeyFob:
    """Key fob that generates command messages for transmission to the ECU."""

    NONCE_MIN = 100_000
    NONCE_MAX = 999_999

    def __init__(self):
        self.counter = 0

    def _generate_nonce(self) -> int:
        return random.randint(self.NONCE_MIN, self.NONCE_MAX)

    def _send_command(self, command: str) -> Message:
        self.counter += 1
        return create_message(
            command=command,
            nonce=self._generate_nonce(),
            counter=self.counter
        )

    def unlock(self) -> Message:
        return self._send_command("UNLOCK")

    def lock(self) -> Message:
        return self._send_command("LOCK")

    def start(self) -> Message:
        return self._send_command("START")

    def reset(self) -> None:
        """Reset the counter to zero (simulates battery removal)."""
        self.counter = 0
