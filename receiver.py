"""
RECEIVER (CAR ECU)
==================
This file simulates the car's Electronic Control Unit (ECU).
It receives messages from the key fob and decides: ACCEPT or REJECT.

The car has 4 different security methods:
  Method 1: No Protection     (accepts everything - INSECURE)
  Method 2: Nonce-Only        (rejects duplicate nonces)
  Method 3: Counter-Only      (rejects out-of-order messages)
  Method 4: Hybrid            (uses BOTH nonce AND counter)
"""

from message import Message
from typing import Set


class CarECU:
    """
    Simulates a car's Electronic Control Unit.
    
    The ECU can operate in 4 different security modes.
    Each mode has different rules for accepting/rejecting messages.
    """
    
    def __init__(self, method: int = 1):
        """
        Initialize the car ECU.
        
        Parameters:
            method (int): Which security method to use (1, 2, 3, or 4)
                1 = No Protection
                2 = Nonce-Only
                3 = Counter-Only
                4 = Hybrid (Nonce + Counter)
        
        Logic:
        - Store which method we're using
        - Initialize tracking variables for nonce and counter
        - Create counters for accepted/rejected messages (for statistics)
        """
        self.method = method
        
        # For Method 2 and 4: Store all nonces we've seen
        # Set = a collection that doesn't allow duplicates (perfect for nonces!)
        self.nonce_list: Set[int] = set()
        
        # For Method 3 and 4: Track the last accepted counter
        # Starts at 0 because first valid message should have counter=1
        self.last_counter = 0
        
        # Statistics (how many messages accepted vs rejected)
        self.accepted_count = 0
        self.rejected_count = 0
        
        # Method names for display
        method_names = {
            1: "No Protection (BASELINE)",
            2: "Nonce-Only",
            3: "Counter-Only", 
            4: "Hybrid (Nonce + Counter)"
        }
        
        print(f"🚗 Car ECU initialized")
        print(f"   Security Method: {method_names.get(method, 'Unknown')}")
        print()
    
    
    def receive(self, msg: Message) -> bool:
        """
        Receive a message and decide: ACCEPT or REJECT?
        
        This is the main function that routes to the correct validation method.
        
        Parameters:
            msg (Message): The message to validate
            
        Returns:
            bool: True if accepted, False if rejected
        """
        print(f"📥 Received: {msg}")
        
        # Route to the correct validation method
        if self.method == 1:
            result = self._method1_no_protection(msg)
        elif self.method == 2:
            result = self._method2_nonce_only(msg)
        elif self.method == 3:
            result = self._method3_counter_only(msg)
        elif self.method == 4:
            result = self._method4_hybrid(msg)
        else:
            print(f"❌ ERROR: Unknown method {self.method}")
            return False
        
        # Update statistics
        if result:
            self.accepted_count += 1
            print(f"   ✅ ACCEPTED")
        else:
            self.rejected_count += 1
            print(f"   ❌ REJECTED (replay attack detected)")
        
        print()
        return result
    
    
    # ==================== METHOD 1: NO PROTECTION ====================
    
    def _method1_no_protection(self, msg: Message) -> bool:
        """
        Method 1: No Protection (BASELINE)
        
        Logic:
        - Accept EVERY message, no questions asked
        - No validation, no checking
        - This is INSECURE but serves as our baseline for comparison
        
        Why have this?
        - Shows how bad things are without protection
        - Attack Success Rate will be 100%
        - Detection Rate will be 0%
        
        Returns:
            bool: Always True (always accepts)
        """
        # No validation performed
        # Just execute the command
        self._execute_command(msg.command)
        return True
    
    
    # ==================== METHOD 2: NONCE-ONLY ====================
    
    def _method2_nonce_only(self, msg: Message) -> bool:
        """
        Method 2: Nonce-Only Validation
        
        Logic:
        1. Check: Is this nonce in our nonce_list?
        2. If YES → REJECT (we've seen it before = replay attack!)
        3. If NO  → ACCEPT and add nonce to the list
        
        Strength:
        - Prevents delayed replay (attacker replays an old message)
        - Prevents multiple replay (attacker sends same message many times)
        
        Weakness:
        - If the car loses power, nonce_list is cleared
        - Memory grows with every message (has to store all nonces)
        - Doesn't check message ordering
        
        Returns:
            bool: True if accepted, False if rejected
        """
        # Check if nonce already exists in our list
        if msg.nonce in self.nonce_list:
            # This nonce was seen before = REPLAY ATTACK
            print(f"   🔍 Nonce {msg.nonce} already in list")
            return False
        
        # This is a fresh nonce
        # Add it to the list and accept the message
        self.nonce_list.add(msg.nonce)
        print(f"   🔍 Fresh nonce, stored for future checks")
        self._execute_command(msg.command)
        return True
    
    
    # ==================== METHOD 3: COUNTER-ONLY ====================
    
    def _method3_counter_only(self, msg: Message) -> bool:
        """
        Method 3: Counter-Only Validation
        
        Logic:
        1. Check: Is msg.counter > last_counter?
        2. If YES → ACCEPT and update last_counter
        3. If NO  → REJECT (old or out-of-order message)
        
        Strength:
        - Prevents delayed replay (old counter values rejected)
        - No memory growth (only stores one number)
        - Enforces message ordering
        
        Weakness:
        - Vulnerable to desynchronization
          (if network drops a message, valid messages get rejected)
        - If attacker resets the car, counter resets to 0
        
        Returns:
            bool: True if accepted, False if rejected
        """
        # Check if counter is strictly increasing
        if msg.counter > self.last_counter:
            # Counter is higher = this is a newer message
            print(f"   🔢 Counter OK: {msg.counter} > {self.last_counter}")
            self.last_counter = msg.counter
            self._execute_command(msg.command)
            return True
        else:
            # Counter is same or lower = replay or out-of-order
            print(f"   🔢 Counter FAIL: {msg.counter} ≤ {self.last_counter}")
            return False
    
    
    # ==================== METHOD 4: HYBRID (NONCE + COUNTER) ====================
    
    def _method4_hybrid(self, msg: Message) -> bool:
        """
        Method 4: Hybrid (Nonce + Counter)
        
        This is our PROPOSED solution that combines Methods 2 and 3.
        
        Logic:
        1. CHECK 1: Is nonce fresh? (not in nonce_list)
        2. If NO → REJECT immediately
        3. If YES → Continue to CHECK 2
        
        4. CHECK 2: Is counter > last_counter?
        5. If NO → REJECT
        6. If YES → ACCEPT, store nonce, update counter
        
        Why two checks?
        - Nonce check prevents replay of old messages (even with fresh counter)
        - Counter check prevents out-of-order delivery
        - Together they cover weaknesses of individual methods
        
        Strength:
        - Best security: blocks all replay types
        - Resilient to both desync and reset attacks
        
        Weakness:
        - Slightly higher overhead (two checks instead of one)
        - Memory usage (stores nonces)
        
        Returns:
            bool: True if accepted, False if rejected
        """
        # CHECK 1: Nonce uniqueness
        if msg.nonce in self.nonce_list:
            print(f"   🔍 FAIL: Nonce {msg.nonce} already seen")
            return False
        
        print(f"   🔍 PASS: Fresh nonce")
        
        # CHECK 2: Counter freshness
        if msg.counter <= self.last_counter:
            print(f"   🔢 FAIL: Counter {msg.counter} ≤ {self.last_counter}")
            return False
        
        print(f"   🔢 PASS: Counter {msg.counter} > {self.last_counter}")
        
        # BOTH checks passed → ACCEPT
        self.nonce_list.add(msg.nonce)
        self.last_counter = msg.counter
        self._execute_command(msg.command)
        return True
    
    
    # ==================== HELPER METHODS ====================
    
    def _execute_command(self, command: str):
        """
        Execute the command (unlock, lock, start).
        
        In a real car, this would trigger actual hardware.
        In our simulation, we just print what would happen.
        
        Parameters:
            command (str): The command to execute
        """
        actions = {
            "UNLOCK": "🔓 Doors unlocked",
            "LOCK": "🔒 Doors locked",
            "START": "🚗 Engine started"
        }
        print(f"   {actions.get(command, f'⚙️ Executed: {command}')}")
    
    
    def reset(self):
        """
        Reset the car ECU (like battery disconnect or system reboot).
        
        Logic:
        - Clear the nonce list (forget all seen nonces)
        - Reset counter to 0
        - Reset statistics
        
        Why needed?
        - Simulates power loss
        - Tests vulnerability to reset attacks
        - Allows running multiple experiments
        """
        old_nonces = len(self.nonce_list)
        old_counter = self.last_counter
        
        self.nonce_list.clear()
        self.last_counter = 0
        self.accepted_count = 0
        self.rejected_count = 0
        
        print(f"🔄 Car ECU reset:")
        print(f"   Nonces cleared: {old_nonces}")
        print(f"   Counter: {old_counter} → 0")
        print()
    
    
    def get_stats(self) -> dict:
        """
        Get statistics about how many messages were accepted/rejected.
        
        Returns:
            dict: Statistics with keys 'accepted', 'rejected', 'total'
        """
        return {
            'accepted': self.accepted_count,
            'rejected': self.rejected_count,
            'total': self.accepted_count + self.rejected_count
        }


# ==================== TESTING CODE ====================
if __name__ == "__main__":
    from sender import KeyFob
    
    print("Testing Car ECU with Different Security Methods")
    print("="*70)
    print()
    
    # Create a key fob
    keyfob = KeyFob()
    
    # ========== TEST METHOD 1: NO PROTECTION ==========
    print("TEST 1: Method 1 (No Protection)")
    print("-"*70)
    car = CarECU(method=1)
    
    # Send 3 normal messages
    msg1 = keyfob.unlock()
    car.receive(msg1)
    
    msg2 = keyfob.start()
    car.receive(msg2)
    
    # Now replay msg1 (should be accepted because no protection!)
    print("🎭 ATTACKER: Replaying the first UNLOCK message...")
    car.receive(msg1)
    
    stats = car.get_stats()
    print(f"📊 Results: {stats['accepted']} accepted, {stats['rejected']} rejected")
    print()
    
    
    # ========== TEST METHOD 2: NONCE-ONLY ==========
    print("TEST 2: Method 2 (Nonce-Only)")
    print("-"*70)
    keyfob.reset()
    car = CarECU(method=2)
    
    msg1 = keyfob.unlock()
    car.receive(msg1)
    
    msg2 = keyfob.start()
    car.receive(msg2)
    
    # Replay msg1 (should be REJECTED - nonce seen before)
    print("🎭 ATTACKER: Replaying the first UNLOCK message...")
    car.receive(msg1)
    
    stats = car.get_stats()
    print(f"📊 Results: {stats['accepted']} accepted, {stats['rejected']} rejected")
    print()
    
    
    # ========== TEST METHOD 4: HYBRID ==========
    print("TEST 3: Method 4 (Hybrid)")
    print("-"*70)
    keyfob.reset()
    car = CarECU(method=4)
    
    msg1 = keyfob.unlock()
    car.receive(msg1)
    
    msg2 = keyfob.start()
    car.receive(msg2)
    
    # Replay msg1 (should be REJECTED on both checks)
    print("🎭 ATTACKER: Replaying the first UNLOCK message...")
    car.receive(msg1)
    
    stats = car.get_stats()
    print(f"📊 Results: {stats['accepted']} accepted, {stats['rejected']} rejected")
    print()
    
    print("="*70)
    print("✅ All tests complete!")