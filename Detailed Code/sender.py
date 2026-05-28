"""
SENDER (KEY FOB)
================
This file simulates a car key fob that sends commands to the car.

The key fob can send three commands:
- UNLOCK (unlock the car doors)
- LOCK (lock the car doors)
- START (start the engine)

Each time you press a button, it generates a unique message.
"""

import random
from message import Message, create_message


class KeyFob:
    """
    Simulates a car key fob.
    
    The key fob keeps track of:
    - counter: how many messages have been sent (starts at 0)
    
    Each time you press a button (unlock/lock/start), it:
    1. Increases the counter
    2. Generates a random nonce
    3. Creates and returns a message
    """
    
    def __init__(self):
        """
        Initialize a new key fob.
        
        Logic:
        - Set counter to 0 (will become 1 when first button is pressed)
        
        Why start at 0?
        - When we press the first button, we do counter += 1, so it becomes 1
        - This is cleaner than starting at 1 and incrementing after
        """
        self.counter = 0
        print("🔑 Key fob initialized (counter starts at 0)")
    
    
    def _generate_nonce(self) -> int:
        """
        Generate a random nonce (number used once).
        
        Logic:
        - Pick a random number between 100000 and 999999
        - This gives us 6-digit random numbers
        
        Why random?
        - Makes each message unique
        - Even if you press UNLOCK twice, the nonces are different
        - This helps prevent replay attacks
        
        The underscore (_) in the name means:
        - This is a "private" helper method
        - Only used inside this class, not meant to be called from outside
        """
        return random.randint(100000, 999999)
    
    
    def _send_command(self, command: str) -> Message:
        """
        Internal method that creates a message for any command.
        
        Logic:
        1. Increase counter by 1
        2. Generate a random nonce
        3. Create the message
        4. Print what we're sending (for debugging)
        5. Return the message
        
        Why have this method?
        - UNLOCK, LOCK, and START all follow the same pattern
        - Instead of repeating code 3 times, we write it once here
        - Then unlock(), lock(), start() just call this with different commands
        """
        # Step 1: Increase counter
        self.counter += 1
        
        # Step 2: Generate random nonce
        nonce = self._generate_nonce()
        
        # Step 3: Create the message
        msg = create_message(
            command=command,
            nonce=nonce,
            counter=self.counter
        )
        
        # Step 4: Show what we're sending (helpful for debugging)
        print(f"📤 Sending: {msg}")
        
        # Step 5: Return it
        return msg
    
    
    # ========== PUBLIC METHODS (The "buttons" on the key fob) ==========
    
    def unlock(self) -> Message:
        """
        Press the UNLOCK button.
        
        Returns: A message with command="UNLOCK"
        """
        return self._send_command("UNLOCK")
    
    
    def lock(self) -> Message:
        """
        Press the LOCK button.
        
        Returns: A message with command="LOCK"
        """
        return self._send_command("LOCK")
    
    
    def start(self) -> Message:
        """
        Press the START button.
        
        Returns: A message with command="START"
        """
        return self._send_command("START")
    
    
    def reset(self):
        """
        Reset the key fob (like replacing the battery).
        
        Logic:
        - Set counter back to 0
        - This simulates what happens if the key fob loses power
        
        Why do we need this?
        - For testing different scenarios
        - In real life, if a key fob battery dies, the counter resets
        - This is actually a security weakness we'll discuss later
        """
        old_counter = self.counter
        self.counter = 0
        print(f"🔄 Key fob reset (counter: {old_counter} → 0)")


# ============== TESTING CODE ==============
if __name__ == "__main__":
    print("Testing Key Fob\n" + "="*60 + "\n")
    
    # Create a new key fob
    keyfob = KeyFob()
    print()
    
    # Press different buttons and see what messages are generated
    print("Scenario 1: Normal usage")
    print("-" * 60)
    msg1 = keyfob.unlock()
    msg2 = keyfob.start()
    msg3 = keyfob.lock()
    print()
    
    # Show that counter is increasing
    print("Scenario 2: Press UNLOCK 5 times in a row")
    print("-" * 60)
    for i in range(5):
        msg = keyfob.unlock()
    print()
    
    # Show what happens after reset
    print("Scenario 3: Reset the key fob")
    print("-" * 60)
    keyfob.reset()
    msg_after_reset = keyfob.unlock()
    print()
    
    print("="*60)
    print("✅ Key fob test complete!")
    print()
    print("Key observations:")
    print("  • Counter increases with each button press")
    print("  • Nonce is random each time (even for same command)")
    print("  • After reset, counter goes back to 0")