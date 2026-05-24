"""
MESSAGE STRUCTURE
=================
This file defines what a "message" looks like in our simulation.

Think of it like designing an envelope that carries information
from the key fob to the car.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Message:
    """
    A message sent from key fob to car.
    
    Contains 4 pieces of information:
    - command: what to do (UNLOCK, LOCK, START)
    - nonce: random number (makes message unique)
    - counter: sequence number (shows order)
    - timestamp: when message was created
    """
    
    command: str      # What action to perform
    nonce: int        # Random number (prevents replay attacks)
    counter: int      # Message sequence number (1, 2, 3, ...)
    timestamp: float  # When message was created (in seconds)
    
    def __str__(self):
        """
        Makes the message readable when we print it.
        Instead of: Message(command='UNLOCK', nonce=123456, ...)
        We get:     [UNLOCK] Counter=1 Nonce=123456
        """
        return f"[{self.command}] Counter={self.counter} Nonce={self.nonce}"


# HELPER FUNCTION
def create_message(command: str, nonce: int, counter: int) -> Message:
    """
    Creates a new message with a timestamp.
    
    Why a helper function?
    - The timestamp is always "now", so we don't want to type it each time
    - This makes creating messages simpler
    
    Usage:
        msg = create_message("UNLOCK", 456789, 1)
    """
    return Message(
        command=command,
        nonce=nonce,
        counter=counter,
        timestamp=datetime.now().timestamp()
    )


# TESTING CODE (only runs when you run this file directly)
if __name__ == "__main__":
    print("Testing Message Structure\n" + "="*50)
    
    # Create a test message
    test_msg = create_message(command="UNLOCK", nonce=123456, counter=1)
    
    # Print it in a readable way
    print(f"Created message: {test_msg}")
    print(f"\nFull details:")
    print(f"  Command:   {test_msg.command}")
    print(f"  Nonce:     {test_msg.nonce}")
    print(f"  Counter:   {test_msg.counter}")
    print(f"  Timestamp: {test_msg.timestamp}")
    
    # Show that each message is unique even with same command
    print("\n\nCreating 3 UNLOCK messages:")
    for i in range(1, 4):
        msg = create_message("UNLOCK", 100000 + i, i)
        print(f"  Message {i}: {msg}")