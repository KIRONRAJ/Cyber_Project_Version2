"""
message_final.py  (v2)
======================
Defines the Message structure exchanged between the key fob and the car ECU.

This module is UNCHANGED from v1 -- the message fields were already sufficient.
It is included so the v2 codebase is complete and self-contained.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Message:
    """A command message transmitted from the key fob to the car ECU."""
    command: str      # UNLOCK / LOCK / START
    nonce: int        # freshness token (random per message)
    counter: int      # monotonic sequence number
    timestamp: float  # creation time (seconds)

    def __str__(self) -> str:
        return f"[{self.command}] Counter={self.counter} Nonce={self.nonce}"


def create_message(command: str, nonce: int, counter: int) -> Message:
    """Construct a Message stamped with the current time."""
    return Message(
        command=command,
        nonce=nonce,
        counter=counter,
        timestamp=datetime.now().timestamp(),
    )