"""
message_final.py
Defines the Message structure exchanged between key fob and ECU.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Message:
    """A command message transmitted from the key fob to the car ECU."""
    command: str
    nonce: int
    counter: int
    timestamp: float

    def __str__(self) -> str:
        return f"[{self.command}] Counter={self.counter} Nonce={self.nonce}"


def create_message(command: str, nonce: int, counter: int) -> Message:
    """Construct a Message with the current timestamp."""
    return Message(
        command=command,
        nonce=nonce,
        counter=counter,
        timestamp=datetime.now().timestamp()
    )
