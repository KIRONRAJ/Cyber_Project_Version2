"""
ATTACKER
========
This file simulates an attacker who tries to break into the car.

The attacker can perform 4 types of replay attacks:
  1. Delayed Replay    - capture message, replay it later
  2. Multiple Replay   - replay same message many times  
  3. Out-of-Order      - capture multiple messages, replay in wrong order
  4. Counter-Skip      - replay old message (testing counter validation)

The attacker acts as a "man-in-the-middle":
  Key Fob → [Attacker captures] → Car
           [Attacker replays] → Car
"""

from message import Message
from typing import List


class Attacker:
    """
    Simulates an attacker who intercepts and replays messages.
    
    The attacker sits between the key fob and the car.
    Every message sent passes through the attacker first.
    The attacker can:
    - Let messages pass through normally
    - Store messages for later replay
    - Replay stored messages in various ways
    """
    
    def __init__(self):
        """
        Initialize the attacker.
        
        Logic:
        - Create an empty list to store captured messages
        - Keep count of how many attacks succeeded
        """
        self.captured_messages: List[Message] = []
        self.attacks_attempted = 0
        self.attacks_succeeded = 0
        
        print("🎭 Attacker initialized (listening for messages)")
        print()
    
    
    def intercept(self, msg: Message) -> Message:
        """
        Intercept a message sent from key fob to car.
        
        This is called for EVERY message sent.
        The attacker captures it and stores it, but also lets it through.
        
        Logic:
        1. Store the message in captured_messages list
        2. Print what was captured (for visibility)
        3. Return the message (so it continues to the car)
        
        Why return the message?
        - We want normal communication to continue
        - The attacker is "listening" but not blocking
        - Later, we'll replay the captured messages
        
        Parameters:
            msg (Message): The message to intercept
            
        Returns:
            Message: The same message (passed through)
        """
        self.captured_messages.append(msg)
        print(f"🎭 Attacker captured: {msg}")
        return msg
    
    
    # ==================== ATTACK TYPE 1: DELAYED REPLAY ====================
    
    def delayed_replay(self, delay_index: int = 0) -> List[Message]:
        """
        Attack Type 1: Delayed Replay
        
        Strategy:
        - Capture a message when it's sent
        - Wait (do nothing for a while)
        - Replay the old message later
        
        Real-world example:
        - User presses UNLOCK at 9:00 AM (attacker captures)
        - User walks away
        - Attacker replays UNLOCK at 9:30 PM (when car is parked)
        
        Parameters:
            delay_index (int): Which captured message to replay (0 = first, 1 = second, etc.)
        
        Returns:
            List[Message]: List containing the replayed message
        """
        if delay_index >= len(self.captured_messages):
            print(f"❌ Attack failed: No message at index {delay_index}")
            return []
        
        replayed_msg = self.captured_messages[delay_index]
        print(f"🎭 ATTACK: Delayed Replay")
        print(f"   Strategy: Replaying message from earlier")
        print(f"   Target: {replayed_msg}")
        
        return [replayed_msg]
    
    
    # ==================== ATTACK TYPE 2: MULTIPLE REPLAY ====================
    
    def multiple_replay(self, msg_index: int = 0, count: int = 3) -> List[Message]:
        """
        Attack Type 2: Multiple Replay
        
        Strategy:
        - Capture a message
        - Replay it multiple times in quick succession
        
        Real-world example:
        - User presses UNLOCK once
        - Attacker captures it
        - Attacker sends it 10 times
        - If car doesn't check for duplicates, car unlocks 10 times
          (or executes the command 10 times)
        
        Parameters:
            msg_index (int): Which captured message to replay
            count (int): How many times to replay it
        
        Returns:
            List[Message]: List of replayed messages (same message, multiple times)
        """
        if msg_index >= len(self.captured_messages):
            print(f"❌ Attack failed: No message at index {msg_index}")
            return []
        
        replayed_msg = self.captured_messages[msg_index]
        print(f"🎭 ATTACK: Multiple Replay")
        print(f"   Strategy: Sending same message {count} times")
        print(f"   Target: {replayed_msg}")
        
        # Return the same message 'count' times
        return [replayed_msg] * count
    
    
    # ==================== ATTACK TYPE 3: OUT-OF-ORDER REPLAY ====================
    
    def out_of_order_replay(self) -> List[Message]:
        """
        Attack Type 3: Out-of-Order Replay
        
        Strategy:
        - Capture multiple messages (A, B, C)
        - Replay them in wrong order (C, A, B)
        
        Real-world example:
        - User sends: UNLOCK (counter=1), START (counter=2), LOCK (counter=3)
        - Attacker captures all three
        - Attacker replays: LOCK (counter=3), UNLOCK (counter=1), START (counter=2)
        - If car only checks nonces, this might work
        - If car checks counters, this fails (out of sequence)
        
        Returns:
            List[Message]: Captured messages in reverse order
        """
        if len(self.captured_messages) == 0:
            print(f"❌ Attack failed: No messages captured")
            return []
        
        # Reverse the order of captured messages
        reversed_msgs = list(reversed(self.captured_messages))
        
        print(f"🎭 ATTACK: Out-of-Order Replay")
        print(f"   Strategy: Replaying {len(reversed_msgs)} messages in reverse order")
        print(f"   Original order: {[msg.counter for msg in self.captured_messages]}")
        print(f"   Replay order: {[msg.counter for msg in reversed_msgs]}")
        
        return reversed_msgs
    
    
    # ==================== ATTACK TYPE 4: COUNTER-SKIP REPLAY ====================
    
    def counter_skip_replay(self) -> List[Message]:
        """
        Attack Type 4: Counter-Skip Replay
        
        Strategy:
        - Capture messages with counters 1, 2, 3, 4, 5
        - Replay message with counter=1 (skipping back)
        
        Real-world example:
        - Car has accepted messages up to counter=5
        - Attacker replays old message with counter=1
        - If car ONLY checks counter (is it > last?), this fails
        - But if car doesn't check counter OR resets, this might work
        
        This attack tests whether the counter validation is actually working.
        
        Returns:
            List[Message]: The first captured message (lowest counter)
        """
        if len(self.captured_messages) == 0:
            print(f"❌ Attack failed: No messages captured")
            return []
        
        # Replay the FIRST message (lowest counter value)
        old_msg = self.captured_messages[0]
        
        print(f"🎭 ATTACK: Counter-Skip Replay")
        print(f"   Strategy: Replaying old message (low counter)")
        print(f"   Target: {old_msg}")
        print(f"   Counter value: {old_msg.counter} (expecting higher)")
        
        return [old_msg]
    
    
    # ==================== HELPER METHODS ====================
    
    def clear_captured(self):
        """
        Clear all captured messages.
        
        Use this between experiments to start fresh.
        """
        count = len(self.captured_messages)
        self.captured_messages.clear()
        self.attacks_attempted = 0
        self.attacks_succeeded = 0
        print(f"🗑️  Attacker cleared {count} captured messages")
        print()
    
    
    def show_captured(self):
        """
        Display all captured messages.
        
        Useful for debugging and understanding what the attacker has.
        """
        print(f"🎭 Attacker has captured {len(self.captured_messages)} messages:")
        for i, msg in enumerate(self.captured_messages):
            print(f"   [{i}] {msg}")
        print()
    
    
    def get_stats(self) -> dict:
        """
        Get statistics about attacks.
        
        Returns:
            dict: Statistics with keys 'attempted', 'succeeded', 'failed'
        """
        return {
            'attempted': self.attacks_attempted,
            'succeeded': self.attacks_succeeded,
            'failed': self.attacks_attempted - self.attacks_succeeded
        }


# ==================== TESTING CODE ====================
if __name__ == "__main__":
    from sender import KeyFob
    from receiver import CarECU
    
    print("Testing Attacker with Different Attack Strategies")
    print("="*70)
    print()
    
    # Create components
    keyfob = KeyFob()
    attacker = Attacker()
    car = CarECU(method=2)  # Use Nonce-Only for testing
    
    # ========== SCENARIO 1: NORMAL COMMUNICATION ==========
    print("SCENARIO 1: Normal Communication (No Attack)")
    print("-"*70)
    
    # User sends 3 normal messages
    msg1 = keyfob.unlock()
    car.receive(attacker.intercept(msg1))  # Passes through attacker
    
    msg2 = keyfob.start()
    car.receive(attacker.intercept(msg2))
    
    msg3 = keyfob.lock()
    car.receive(attacker.intercept(msg3))
    
    print()
    attacker.show_captured()
    
    
    # ========== SCENARIO 2: DELAYED REPLAY ATTACK ==========
    print("SCENARIO 2: Delayed Replay Attack")
    print("-"*70)
    
    attack_msgs = attacker.delayed_replay(delay_index=0)
    for msg in attack_msgs:
        result = car.receive(msg)
        attacker.attacks_attempted += 1
        if result:
            attacker.attacks_succeeded += 1
    
    print()
    
    
    # ========== SCENARIO 3: MULTIPLE REPLAY ATTACK ==========
    print("SCENARIO 3: Multiple Replay Attack")
    print("-"*70)
    
    attack_msgs = attacker.multiple_replay(msg_index=1, count=3)
    for msg in attack_msgs:
        result = car.receive(msg)
        attacker.attacks_attempted += 1
        if result:
            attacker.attacks_succeeded += 1
    
    print()
    
    
    # ========== SCENARIO 4: OUT-OF-ORDER ATTACK ==========
    print("SCENARIO 4: Out-of-Order Replay Attack")
    print("-"*70)
    
    # Reset and capture new messages
    car.reset()
    keyfob.reset()
    attacker.clear_captured()
    
    # Capture 3 messages in order
    for i in range(3):
        msg = keyfob.unlock()
        car.receive(attacker.intercept(msg))
    
    print()
    
    # Now replay them out of order
    attack_msgs = attacker.out_of_order_replay()
    for msg in attack_msgs:
        result = car.receive(msg)
        attacker.attacks_attempted += 1
        if result:
            attacker.attacks_succeeded += 1
    
    print()
    
    # Show final statistics
    stats = attacker.get_stats()
    print("="*70)
    print(f"📊 Attack Statistics:")
    print(f"   Attempted: {stats['attempted']}")
    print(f"   Succeeded: {stats['succeeded']}")
    print(f"   Failed: {stats['failed']}")