"""
attacker_final.py
Simulates an adversary positioned between the key fob and the ECU.
Captures messages passively and replays them under various strategies.
"""

from typing import List
from message_final import Message


class Attacker:
    """Adversary that captures and replays messages between key fob and ECU."""

    def __init__(self):
        self.captured_messages: List[Message] = []

    # ---- Capture ----

    def intercept(self, msg: Message) -> Message:
        """Capture a message in transit and forward it unchanged to the ECU."""
        self.captured_messages.append(msg)
        return msg

    def silent_capture(self, msg: Message) -> None:
        """
        Capture a message without forwarding it to the ECU.
        Simulates a jamming attack: the message is intercepted in transit
        and never reaches the receiver.
        """
        self.captured_messages.append(msg)

    # ---- Replay strategies ----

    def delayed_replay(self, index: int = 0) -> List[Message]:
        """Replay a single previously captured message at the given index."""
        if index >= len(self.captured_messages):
            return []
        return [self.captured_messages[index]]

    def multiple_replay(self, index: int = 0, count: int = 3) -> List[Message]:
        """Replay the same captured message multiple times in succession."""
        if index >= len(self.captured_messages):
            return []
        return [self.captured_messages[index]] * count

    def out_of_order_replay(self) -> List[Message]:
        """Replay all captured messages in reverse chronological order."""
        return list(reversed(self.captured_messages))

    def counter_skip_replay(self) -> List[Message]:
        """Replay the oldest captured message (lowest counter)."""
        if not self.captured_messages:
            return []
        return [self.captured_messages[0]]

    # ---- Utility ----

    def clear_captured(self) -> None:
        self.captured_messages.clear()
