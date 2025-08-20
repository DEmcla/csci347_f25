# Week 2 Tutorial: Hashing and Digital Signatures

**Estimated Time**: 4-5 hours  
**Prerequisites**: Week 1 completed, understanding of symmetric encryption

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. Implemented secure hashing with multiple algorithms
2. Created a secure password storage system
3. Built message authentication with HMAC
4. Generated and verified digital signatures
5. Constructed a file integrity monitoring system

---

## Part 1: Hash Functions and Data Integrity (45 minutes)

### Understanding Hash Functions

Hash functions are one-way mathematical functions that:
- Take input of any size
- Produce fixed-size output (digest/hash)
- Are deterministic (same input = same output)
- Are collision-resistant (hard to find two inputs with same output)
- Have avalanche effect (small input change = completely different output)

### Step 1: Basic Hashing Operations

Create `hashing_basics.py`:

```python
import hashlib
import os
import time
from pathlib import Path

class HashingToolkit:
    """Comprehensive hashing utilities"""
    
    @staticmethod
    def hash_string(text, algorithm='sha256'):
        """Hash a string using specified algorithm"""
        # Convert string to bytes
        data_bytes = text.encode('utf-8')
        
        # Create hash object
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data_bytes)
        
        # Return hexadecimal digest
        return hash_obj.hexdigest()
    
    @staticmethod
    def hash_file(filepath, algorithm='sha256', chunk_size=8192):
        """Hash a file efficiently using chunks"""
        hash_obj = hashlib.new(algorithm)
        
        with open(filepath, 'rb') as f:
            # Read file in chunks to handle large files
            while chunk := f.read(chunk_size):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def compare_algorithms():
        """Compare different hash algorithms"""
        test_data = "The quick brown fox jumps over the lazy dog"
        
        algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'sha3_256']
        
        print("🔍 Hash Algorithm Comparison")
        print("="*50)
        print(f"Input: '{test_data}'")
        print()
        
        for algo in algorithms:
            try:
                hash_value = HashingToolkit.hash_string(test_data, algo)
                print(f"{algo.upper():<8}: {hash_value}")
            except ValueError:
                print(f"{algo.upper():<8}: Not available")
    
    @staticmethod
    def demonstrate_properties():
        """Demonstrate key properties of hash functions"""
        print("\n🔬 Hash Function Properties")
        print("="*50)
        
        # 1. Deterministic
        text = "Hello, World!"
        hash1 = HashingToolkit.hash_string(text)
        hash2 = HashingToolkit.hash_string(text)
        print(f"1. Deterministic (same input = same output):")
        print(f"   Hash 1: {hash1}")
        print(f"   Hash 2: {hash2}")
        print(f"   Match: {hash1 == hash2}")
        
        # 2. Avalanche Effect
        print(f"\n2. Avalanche Effect (small change = big difference):")
        original = "Hello, World!"
        modified = "Hello, world!"  # Just changed 'W' to 'w'
        
        hash_orig = HashingToolkit.hash_string(original)
        hash_mod = HashingToolkit.hash_string(modified)
        
        print(f"   Original: '{original}'")
        print(f"   Hash:     {hash_orig}")
        print(f"   Modified: '{modified}'")
        print(f"   Hash:     {hash_mod}")
        
        # Count different characters
        different_chars = sum(c1 != c2 for c1, c2 in zip(hash_orig, hash_mod))
        print(f"   Different characters: {different_chars}/64")
        
        # 3. Fixed Output Size
        print(f"\n3. Fixed Output Size:")
        short_input = "A"
        long_input = "A" * 1000000  # 1 million A's
        
        short_hash = HashingToolkit.hash_string(short_input)
        long_hash = HashingToolkit.hash_string(long_input)
        
        print(f"   Short input (1 char): {len(short_hash)} chars")
        print(f"   Long input (1M chars): {len(long_hash)} chars")
        print(f"   Both produce same length: {len(short_hash) == len(long_hash)}")

# Demonstrate basic hashing
if __name__ == "__main__":
    toolkit = HashingToolkit()
    
    # Compare algorithms
    toolkit.compare_algorithms()
    
    # Show properties
    toolkit.demonstrate_properties()
```

**Run it:**
```bash
python hashing_basics.py
```

### Step 2: File Integrity Checking

Add this to demonstrate practical file integrity:

```python
def demo_file_integrity():
    """Demonstrate file integrity checking"""
    print("\n📁 File Integrity Demo")
    print("="*50)
    
    # Create a test file
    test_file = "integrity_test.txt"
    original_content = """Important Document
    
This file contains critical data that must not be modified.
- Account numbers: 12345, 67890
- Access codes: ABC123, XYZ789
- Signatures: John Doe, Jane Smith

Any unauthorized modification will be detected.
"""
    
    with open(test_file, 'w') as f:
        f.write(original_content)
    
    # Calculate original hash
    original_hash = HashingToolkit.hash_file(test_file)
    print(f"📄 Created {test_file}")
    print(f"🔒 Original hash: {original_hash}")
    
    # Verify integrity (should pass)
    current_hash = HashingToolkit.hash_file(test_file)
    if current_hash == original_hash:
        print("✅ File integrity verified - no changes detected")
    else:
        print("❌ File integrity compromised!")
    
    # Simulate tampering
    print(f"\n🔧 Simulating file tampering...")
    with open(test_file, 'a') as f:
        f.write("\n[UNAUTHORIZED ADDITION]")
    
    # Check integrity again
    tampered_hash = HashingToolkit.hash_file(test_file)
    print(f"🔒 New hash: {tampered_hash}")
    
    if tampered_hash == original_hash:
        print("❌ Tampering not detected (this shouldn't happen!)")
    else:
        print("✅ Tampering detected successfully!")
        
    # Show how small the change was vs. how different the hash is
    with open(test_file, 'r') as f:
        new_content = f.read()
    
    print(f"\n📊 Change Analysis:")
    print(f"   Original size: {len(original_content)} characters")
    print(f"   New size: {len(new_content)} characters")
    print(f"   Bytes added: {len(new_content) - len(original_content)}")
    
    # Compare hashes
    different_chars = sum(c1 != c2 for c1, c2 in zip(original_hash, tampered_hash))
    print(f"   Hash differences: {different_chars}/64 characters")
    
    # Cleanup
    os.remove(test_file)
```

---

## Part 2: Secure Password Hashing (60 minutes)

Never store passwords in plaintext! Let's build a secure password management system.

### Step 1: Password Hashing Best Practices

Create `password_security.py`:

```python
import hashlib
import secrets
import hmac
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

class SecurePasswordManager:
    """Secure password hashing and verification"""
    
    def __init__(self):
        self.min_iterations = 100000  # NIST recommendation
    
    def hash_password(self, password, salt=None, iterations=None):
        """
        Hash password with salt using PBKDF2
        
        Args:
            password (str): Plain text password
            salt (bytes): Salt (generates random if None)
            iterations (int): Number of iterations
            
        Returns:
            tuple: (salt, hashed_password, iterations)
        """
        if salt is None:
            salt = secrets.token_bytes(32)  # 256-bit salt
        
        if iterations is None:
            iterations = self.min_iterations
        
        # Use PBKDF2 with SHA-256
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # 512-bit output
            salt=salt,
            iterations=iterations,
        )
        
        password_bytes = password.encode('utf-8')
        password_hash = kdf.derive(password_bytes)
        
        return salt, password_hash, iterations
    
    def verify_password(self, password, salt, stored_hash, iterations):
        """
        Verify password against stored hash
        
        Args:
            password (str): Password to verify
            salt (bytes): Original salt
            stored_hash (bytes): Stored password hash
            iterations (int): Number of iterations used
            
        Returns:
            bool: True if password matches
        """
        # Hash the provided password with same parameters
        _, computed_hash, _ = self.hash_password(password, salt, iterations)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_hash, computed_hash)
    
    def benchmark_iterations(self, password="test_password_123", target_time_ms=500):
        """
        Benchmark to find optimal iteration count for target time
        
        Args:
            password (str): Test password
            target_time_ms (int): Target time in milliseconds
            
        Returns:
            int: Recommended iteration count
        """
        print(f"🔬 Benchmarking for target time: {target_time_ms}ms")
        
        # Start with minimum and double until we exceed target time
        iterations = 10000
        
        while True:
            start_time = time.time()
            self.hash_password(password, iterations=iterations)
            end_time = time.time()
            
            elapsed_ms = (end_time - start_time) * 1000
            
            print(f"   {iterations:6} iterations: {elapsed_ms:.1f}ms")
            
            if elapsed_ms >= target_time_ms:
                return iterations
            
            iterations *= 2
            
            # Safety limit
            if iterations > 1000000:
                break
        
        return iterations

def demo_secure_passwords():
    """Demonstrate secure password hashing"""
    print("🔐 Secure Password Hashing Demo")
    print("="*50)
    
    pm = SecurePasswordManager()
    
    # Hash a password
    password = "MySecurePassword123!"
    salt, password_hash, iterations = pm.hash_password(password)
    
    print(f"🔑 Password: {password}")
    print(f"🧂 Salt: {salt.hex()}")
    print(f"🔒 Hash: {password_hash.hex()}")
    print(f"🔄 Iterations: {iterations:,}")
    
    # Verify correct password
    if pm.verify_password(password, salt, password_hash, iterations):
        print("✅ Password verification successful")
    else:
        print("❌ Password verification failed")
    
    # Try wrong password
    wrong_password = "WrongPassword"
    if pm.verify_password(wrong_password, salt, password_hash, iterations):
        print("❌ Wrong password accepted (shouldn't happen!)")
    else:
        print("✅ Wrong password correctly rejected")
    
    # Demonstrate salt importance
    print(f"\n🧂 Salt Importance Demo")
    print("-" * 30)
    
    # Same password, different salts
    salt1, hash1, _ = pm.hash_password(password)
    salt2, hash2, _ = pm.hash_password(password)
    
    print(f"Same password, salt 1: {hash1.hex()[:32]}...")
    print(f"Same password, salt 2: {hash2.hex()[:32]}...")
    print(f"Hashes are different: {hash1 != hash2}")

def demo_password_database():
    """Simulate a user database with secure password storage"""
    print(f"\n👥 User Database Simulation")
    print("="*50)
    
    pm = SecurePasswordManager()
    
    # Simulate user registration
    users_db = {}
    
    test_users = [
        ("alice", "AliceSecurePass123!"),
        ("bob", "BobsPassword456@"),
        ("charlie", "CharlieSecret789#"),
    ]
    
    print("📝 User Registration:")
    for username, password in test_users:
        salt, password_hash, iterations = pm.hash_password(password)
        
        users_db[username] = {
            'salt': salt,
            'password_hash': password_hash,
            'iterations': iterations
        }
        
        print(f"   ✅ {username} registered")
    
    # Simulate user login attempts
    print(f"\n🔓 Login Attempts:")
    
    login_attempts = [
        ("alice", "AliceSecurePass123!"),  # Correct
        ("bob", "wrong_password"),         # Wrong password
        ("charlie", "CharlieSecret789#"),  # Correct
        ("dave", "any_password"),          # User doesn't exist
    ]
    
    for username, password in login_attempts:
        if username in users_db:
            user_data = users_db[username]
            if pm.verify_password(password, 
                                user_data['salt'], 
                                user_data['password_hash'],
                                user_data['iterations']):
                print(f"   ✅ {username}: Login successful")
            else:
                print(f"   ❌ {username}: Invalid password")
        else:
            print(f"   ❌ {username}: User not found")

if __name__ == "__main__":
    demo_secure_passwords()
    demo_password_database()
    
    # Benchmark (optional - can be slow)
    print(f"\n⚡ Performance Benchmarking")
    print("="*50)
    pm = SecurePasswordManager()
    optimal_iterations = pm.benchmark_iterations()
    print(f"💡 Recommended iterations: {optimal_iterations:,}")
```

---

## Part 3: Message Authentication Codes (45 minutes)

HMAC provides both integrity and authenticity - proving the message hasn't been tampered with AND came from someone with the shared secret key.

### Step 1: HMAC Implementation

Create `message_authentication.py`:

```python
import hmac
import hashlib
import secrets
import time
from typing import Tuple

class MessageAuthenticator:
    """HMAC-based message authentication system"""
    
    def __init__(self, key=None):
        """Initialize with key (generates random if None)"""
        self.key = key if key else secrets.token_bytes(32)  # 256-bit key
    
    def create_mac(self, message, algorithm='sha256'):
        """
        Create HMAC for a message
        
        Args:
            message (str or bytes): Message to authenticate
            algorithm (str): Hash algorithm to use
            
        Returns:
            tuple: (message, mac, algorithm)
        """
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
        
        # Create HMAC
        mac = hmac.new(
            key=self.key,
            msg=message_bytes,
            digestmod=algorithm
        ).hexdigest()
        
        return message, mac, algorithm
    
    def verify_mac(self, message, mac, algorithm='sha256'):
        """
        Verify HMAC for a message
        
        Args:
            message (str or bytes): Original message
            mac (str): MAC to verify
            algorithm (str): Hash algorithm used
            
        Returns:
            bool: True if MAC is valid
        """
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
        
        # Compute expected MAC
        expected_mac = hmac.new(
            key=self.key,
            msg=message_bytes,
            digestmod=algorithm
        ).hexdigest()
        
        # Use constant-time comparison
        return hmac.compare_digest(expected_mac, mac)
    
    def secure_messaging_demo(self):
        """Demonstrate secure messaging with HMAC"""
        print("📨 Secure Messaging Demo")
        print("="*50)
        
        # Original message
        message = "Transfer $1000 from account 12345 to account 67890"
        
        # Create authenticated message
        msg, mac, algo = self.create_mac(message)
        
        print(f"📝 Original message: {message}")
        print(f"🔐 MAC: {mac}")
        print(f"🔧 Algorithm: {algo}")
        
        # Verify legitimate message
        print(f"\n✅ Verifying legitimate message:")
        if self.verify_mac(message, mac, algo):
            print("   ✅ Message authentic and unmodified")
        else:
            print("   ❌ Message verification failed")
        
        # Try tampering with message
        print(f"\n🔧 Testing tampered message:")
        tampered_message = "Transfer $9000 from account 12345 to account 67890"
        if self.verify_mac(tampered_message, mac, algo):
            print("   ❌ Tampered message accepted (BAD!)")
        else:
            print("   ✅ Tampered message correctly rejected")
        
        # Try tampering with MAC
        print(f"\n🔧 Testing tampered MAC:")
        tampered_mac = mac[:-4] + "beef"  # Change last few characters
        if self.verify_mac(message, tampered_mac, algo):
            print("   ❌ Tampered MAC accepted (BAD!)")
        else:
            print("   ✅ Tampered MAC correctly rejected")

def demo_timing_attack_protection():
    """Demonstrate timing attack protection"""
    print(f"\n⏱️  Timing Attack Protection Demo")
    print("="*50)
    
    auth = MessageAuthenticator()
    message = "Secret message"
    _, correct_mac, _ = auth.create_mac(message)
    
    # Test with completely wrong MAC
    wrong_mac = "0" * len(correct_mac)
    
    # Test with partially correct MAC (same prefix)
    partial_mac = correct_mac[:32] + "0" * (len(correct_mac) - 32)
    
    print("🔍 Testing MAC verification timing:")
    
    # Time multiple verifications
    def time_verification(mac, label):
        times = []
        for _ in range(1000):
            start = time.perf_counter()
            auth.verify_mac(message, mac)
            end = time.perf_counter()
            times.append(end - start)
        
        avg_time = sum(times) / len(times) * 1000000  # Convert to microseconds
        print(f"   {label}: {avg_time:.2f} μs average")
        return avg_time
    
    correct_time = time_verification(correct_mac, "Correct MAC")
    wrong_time = time_verification(wrong_mac, "Completely wrong MAC")
    partial_time = time_verification(partial_mac, "Partially correct MAC")
    
    print(f"\n💡 Analysis:")
    print(f"   All timing should be similar (constant-time comparison)")
    print(f"   Time difference should be < 10% for security")

def demo_key_importance():
    """Demonstrate importance of keeping HMAC keys secret"""
    print(f"\n🔑 HMAC Key Importance Demo")
    print("="*50)
    
    message = "Top secret military operation details"
    
    # Two different authenticators with different keys
    auth1 = MessageAuthenticator()  # Random key 1
    auth2 = MessageAuthenticator()  # Random key 2
    
    # Create MAC with first key
    _, mac1, _ = auth1.create_mac(message)
    
    print(f"📝 Message: {message}")
    print(f"🔐 MAC with key 1: {mac1[:16]}...")
    
    # Try to verify with second key
    if auth2.verify_mac(message, mac1):
        print("❌ MAC verified with wrong key (shouldn't happen!)")
    else:
        print("✅ MAC correctly rejected with wrong key")
    
    # Show that same key produces same MAC
    _, mac1_again, _ = auth1.create_mac(message)
    print(f"🔐 MAC with key 1 again: {mac1_again[:16]}...")
    print(f"✅ Same key produces same MAC: {mac1 == mac1_again}")

if __name__ == "__main__":
    auth = MessageAuthenticator()
    auth.secure_messaging_demo()
    
    demo_key_importance()
    demo_timing_attack_protection()
    
    print(f"\n💡 Key Takeaways:")
    print(f"   • HMAC provides both integrity and authenticity")
    print(f"   • Requires shared secret key between sender and receiver")
    print(f"   • Constant-time comparison prevents timing attacks")
    print(f"   • Different keys produce completely different MACs")
```

---

## Part 4: Digital Signatures (90 minutes)

Digital signatures provide authentication, integrity, and non-repudiation using public-key cryptography.

### Step 1: RSA Digital Signatures

Create `digital_signatures.py`:

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
import os

class DigitalSignatureManager:
    """RSA digital signature operations"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_key_pair(self, key_size=2048):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        self.public_key = self.private_key.public_key()
        
        print(f"🔑 Generated {key_size}-bit RSA key pair")
        return self.private_key, self.public_key
    
    def sign_message(self, message):
        """
        Sign a message with private key
        
        Args:
            message (str): Message to sign
            
        Returns:
            bytes: Digital signature
        """
        if not self.private_key:
            raise ValueError("No private key available. Generate key pair first.")
        
        message_bytes = message.encode('utf-8')
        
        signature = self.private_key.sign(
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify_signature(self, message, signature, public_key=None):
        """
        Verify signature with public key
        
        Args:
            message (str): Original message
            signature (bytes): Signature to verify
            public_key: Public key (uses self.public_key if None)
            
        Returns:
            bool: True if signature is valid
        """
        if public_key is None:
            public_key = self.public_key
        
        if not public_key:
            raise ValueError("No public key available")
        
        message_bytes = message.encode('utf-8')
        
        try:
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def save_keys(self, private_key_file="private_key.pem", public_key_file="public_key.pem", password=None):
        """Save keys to PEM files"""
        if not self.private_key:
            raise ValueError("No keys to save")
        
        # Save private key
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())
        else:
            encryption = serialization.NoEncryption()
        
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
        
        with open(private_key_file, 'wb') as f:
            f.write(private_pem)
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        with open(public_key_file, 'wb') as f:
            f.write(public_pem)
        
        print(f"💾 Keys saved to {private_key_file} and {public_key_file}")
    
    def load_keys(self, private_key_file="private_key.pem", public_key_file="public_key.pem", password=None):
        """Load keys from PEM files"""
        # Load private key
        with open(private_key_file, 'rb') as f:
            self.private_key = load_pem_private_key(
                f.read(),
                password=password.encode() if password else None
            )
        
        # Load public key
        with open(public_key_file, 'rb') as f:
            self.public_key = load_pem_public_key(f.read())
        
        print(f"📖 Keys loaded from {private_key_file} and {public_key_file}")

def demo_digital_signatures():
    """Comprehensive digital signature demonstration"""
    print("✍️  Digital Signatures Demo")
    print("="*50)
    
    # Create signature manager
    alice = DigitalSignatureManager()
    alice.generate_key_pair()
    
    # Alice signs a contract
    contract = """
EMPLOYMENT CONTRACT

This contract between Alice Johnson (Employee) and TechCorp Inc. (Employer) 
states the following terms:

1. Position: Senior Software Engineer
2. Salary: $120,000 per year
3. Start Date: January 1, 2024
4. Benefits: Health insurance, 401k matching

By signing this document, both parties agree to the terms stated above.

Signed: Alice Johnson
Date: December 15, 2023
    """.strip()
    
    print("📄 Alice signs contract:")
    print(f"   Contract preview: {contract[:100]}...")
    
    # Alice signs the contract
    alice_signature = alice.sign_message(contract)
    print(f"✍️  Alice's signature: {alice_signature.hex()[:32]}... ({len(alice_signature)} bytes)")
    
    # Verify signature with Alice's public key
    print(f"\n🔍 Verifying signature:")
    if alice.verify_signature(contract, alice_signature):
        print("   ✅ Signature valid - Alice definitely signed this contract")
    else:
        print("   ❌ Signature invalid")
    
    # Try to forge signature (Bob signs pretending to be Alice)
    print(f"\n🕵️  Attempting signature forgery:")
    bob = DigitalSignatureManager()
    bob.generate_key_pair()
    
    # Bob tries to forge Alice's signature
    forged_signature = bob.sign_message(contract)
    
    # Verify forged signature against Alice's public key
    if alice.verify_signature(contract, forged_signature, alice.public_key):
        print("   ❌ Forged signature accepted (this shouldn't happen!)")
    else:
        print("   ✅ Forged signature correctly rejected")
    
    # Show contract tampering detection
    print(f"\n📝 Testing contract tampering:")
    tampered_contract = contract.replace("$120,000", "$220,000")
    
    if alice.verify_signature(tampered_contract, alice_signature):
        print("   ❌ Tampered contract accepted (shouldn't happen!)")
    else:
        print("   ✅ Contract tampering detected")
    
    # Demonstrate non-repudiation
    print(f"\n🚫 Non-repudiation demonstration:")
    print("   Alice cannot deny signing the contract because:")
    print("   • Only Alice has the private key")
    print("   • The signature was created with Alice's private key")
    print("   • Anyone can verify with Alice's public key")
    print("   • The signature is mathematically linked to both Alice and the contract")

def demo_multi_party_signatures():
    """Demonstrate multi-party signature scenario"""
    print(f"\n👥 Multi-Party Signature Demo")
    print("="*50)
    
    # Create three parties
    alice = DigitalSignatureManager()
    alice.generate_key_pair()
    
    bob = DigitalSignatureManager()
    bob.generate_key_pair()
    
    charlie = DigitalSignatureManager()
    charlie.generate_key_pair()
    
    # Document that needs multiple signatures
    document = "Partnership Agreement: Alice, Bob, and Charlie agree to form TechStartup LLC with equal 33.33% ownership."
    
    print(f"📄 Document: {document}")
    
    # Each party signs the document
    alice_sig = alice.sign_message(document)
    bob_sig = bob.sign_message(document)
    charlie_sig = charlie.sign_message(document)
    
    print(f"\n✍️  Collecting signatures:")
    print(f"   Alice signed: ✅")
    print(f"   Bob signed: ✅") 
    print(f"   Charlie signed: ✅")
    
    # Verify all signatures
    print(f"\n🔍 Verifying all signatures:")
    
    signatures = [
        ("Alice", alice_sig, alice.public_key),
        ("Bob", bob_sig, bob.public_key),
        ("Charlie", charlie_sig, charlie.public_key)
    ]
    
    all_valid = True
    for name, sig, pub_key in signatures:
        # Use a temporary verifier
        verifier = DigitalSignatureManager()
        is_valid = verifier.verify_signature(document, sig, pub_key)
        
        print(f"   {name}'s signature: {'✅ Valid' if is_valid else '❌ Invalid'}")
        all_valid = all_valid and is_valid
    
    if all_valid:
        print("🎉 All signatures valid - partnership agreement is binding!")
    else:
        print("⚠️  Some signatures invalid - agreement not binding")

if __name__ == "__main__":
    demo_digital_signatures()
    demo_multi_party_signatures()
    
    print(f"\n💡 Digital Signature Benefits:")
    print(f"   • Authentication: Proves who signed")
    print(f"   • Integrity: Detects tampering")
    print(f"   • Non-repudiation: Signer can't deny signing")
    print(f"   • Public verification: Anyone can verify with public key")
```

---

## Part 5: File Integrity Monitoring System (60 minutes)

Now let's combine everything we've learned to build a practical file integrity monitoring system.

### Step 1: Complete File Integrity Monitor

Create `file_integrity_monitor.py`:

```python
import hashlib
import json
import os
import time
from pathlib import Path
from datetime import datetime
import hmac

class FileIntegrityMonitor:
    """Monitor files for unauthorized changes"""
    
    def __init__(self, database_file="file_integrity.db"):
        self.database_file = database_file
        self.database = {}
        self.secret_key = None
        self.load_database()
    
    def set_secret_key(self, key):
        """Set secret key for HMAC protection"""
        self.secret_key = key
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        sha256_hash = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def calculate_file_hmac(self, filepath):
        """Calculate HMAC of file using secret key"""
        if not self.secret_key:
            raise ValueError("Secret key not set")
        
        hmac_obj = hmac.new(self.secret_key, digestmod=hashlib.sha256)
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hmac_obj.update(chunk)
        
        return hmac_obj.hexdigest()
    
    def add_file(self, filepath):
        """Add file to integrity monitoring"""
        filepath = Path(filepath).resolve()
        
        if not filepath.exists():
            raise FileNotFoundError(f"{filepath} not found")
        
        # Get file metadata
        stat = filepath.stat()
        
        # Calculate hashes
        file_hash = self.calculate_file_hash(filepath)
        file_hmac = self.calculate_file_hmac(filepath) if self.secret_key else None
        
        # Store in database
        self.database[str(filepath)] = {
            'hash': file_hash,
            'hmac': file_hmac,
            'size': stat.st_size,
            'modified': stat.st_mtime,
            'added': datetime.now().isoformat(),
            'last_checked': datetime.now().isoformat()
        }
        
        self.save_database()
        return file_hash
    
    def check_file(self, filepath):
        """Check file integrity"""
        filepath = Path(filepath).resolve()
        filepath_str = str(filepath)
        
        if filepath_str not in self.database:
            return {
                'status': 'unknown',
                'message': 'File not in database'
            }
        
        if not filepath.exists():
            return {
                'status': 'missing',
                'message': 'File has been deleted'
            }
        
        # Get current file info
        stat = filepath.stat()
        current_hash = self.calculate_file_hash(filepath)
        current_hmac = self.calculate_file_hmac(filepath) if self.secret_key else None
        
        stored_info = self.database[filepath_str]
        
        # Check for modifications
        changes = []
        
        if current_hash != stored_info['hash']:
            changes.append('content_modified')
        
        if self.secret_key and current_hmac != stored_info['hmac']:
            changes.append('hmac_mismatch')
        
        if stat.st_size != stored_info['size']:
            changes.append(f"size_changed: {stored_info['size']} -> {stat.st_size}")
        
        if stat.st_mtime != stored_info['modified']:
            changes.append('timestamp_changed')
        
        # Update last checked time
        self.database[filepath_str]['last_checked'] = datetime.now().isoformat()
        self.save_database()
        
        if changes:
            return {
                'status': 'modified',
                'changes': changes,
                'original_hash': stored_info['hash'],
                'current_hash': current_hash
            }
        else:
            return {
                'status': 'unchanged',
                'message': 'File integrity verified'
            }
    
    def scan_directory(self, directory, pattern="*"):
        """Scan directory and add all matching files"""
        directory = Path(directory)
        added_files = []
        
        for filepath in directory.glob(pattern):
            if filepath.is_file():
                try:
                    hash_value = self.add_file(filepath)
                    added_files.append({
                        'path': str(filepath),
                        'hash': hash_value
                    })
                    print(f"✅ Added: {filepath.name}")
                except Exception as e:
                    print(f"❌ Error adding {filepath}: {e}")
        
        return added_files
    
    def check_all(self):
        """Check integrity of all monitored files"""
        results = {
            'unchanged': [],
            'modified': [],
            'missing': [],
            'unknown': []
        }
        
        for filepath in list(self.database.keys()):
            result = self.check_file(filepath)
            status = result['status']
            
            if status in results:
                results[status].append({
                    'file': filepath,
                    'result': result
                })
        
        return results
    
    def save_database(self):
        """Save database to file with integrity protection"""
        # Calculate database checksum
        db_json = json.dumps(self.database, sort_keys=True)
        
        if self.secret_key:
            checksum = hmac.new(
                self.secret_key,
                db_json.encode(),
                hashlib.sha256
            ).hexdigest()
        else:
            checksum = hashlib.sha256(db_json.encode()).hexdigest()
        
        # Save with checksum
        save_data = {
            'database': self.database,
            'checksum': checksum,
            'version': '1.0'
        }
        
        with open(self.database_file, 'w') as f:
            json.dump(save_data, f, indent=2)
    
    def load_database(self):
        """Load database from file with integrity check"""
        if not os.path.exists(self.database_file):
            self.database = {}
            return
        
        try:
            with open(self.database_file, 'r') as f:
                save_data = json.load(f)
            
            # Verify checksum if we have a key
            if self.secret_key and 'checksum' in save_data:
                db_json = json.dumps(save_data['database'], sort_keys=True)
                expected_checksum = hmac.new(
                    self.secret_key,
                    db_json.encode(),
                    hashlib.sha256
                ).hexdigest()
                
                if expected_checksum != save_data['checksum']:
                    raise ValueError("Database integrity check failed!")
            
            self.database = save_data.get('database', {})
            
        except Exception as e:
            print(f"⚠️  Error loading database: {e}")
            self.database = {}
    
    def generate_report(self):
        """Generate integrity report"""
        results = self.check_all()
        
        report = []
        report.append("=" * 60)
        report.append("FILE INTEGRITY MONITORING REPORT")
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        
        # Summary
        report.append("\n📊 SUMMARY:")
        report.append(f"   Total files monitored: {len(self.database)}")
        report.append(f"   ✅ Unchanged: {len(results['unchanged'])}")
        report.append(f"   ⚠️  Modified: {len(results['modified'])}")
        report.append(f"   ❌ Missing: {len(results['missing'])}")
        
        # Details for modified files
        if results['modified']:
            report.append("\n⚠️  MODIFIED FILES:")
            for item in results['modified']:
                report.append(f"\n   File: {item['file']}")
                report.append(f"   Changes: {', '.join(item['result']['changes'])}")
                report.append(f"   Original hash: {item['result']['original_hash'][:16]}...")
                report.append(f"   Current hash:  {item['result']['current_hash'][:16]}...")
        
        # List missing files
        if results['missing']:
            report.append("\n❌ MISSING FILES:")
            for item in results['missing']:
                report.append(f"   {item['file']}")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)

def demo_file_integrity_monitor():
    """Demonstrate file integrity monitoring"""
    print("🔍 File Integrity Monitor Demo")
    print("="*50)
    
    # Create monitor with secret key
    fim = FileIntegrityMonitor("demo_integrity.db")
    fim.set_secret_key(b"my_secret_monitoring_key_12345")
    
    # Create test files
    test_dir = Path("test_monitor")
    test_dir.mkdir(exist_ok=True)
    
    # Create some test files
    test_files = {
        "config.ini": "[database]\nhost=localhost\nport=5432\nuser=admin",
        "script.py": "#!/usr/bin/env python\nprint('Hello, World!')",
        "data.txt": "Important data that should not be modified\nLine 2\nLine 3"
    }
    
    print("📁 Creating test files...")
    for filename, content in test_files.items():
        filepath = test_dir / filename
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"   Created: {filename}")
    
    # Add files to monitoring
    print("\n📝 Adding files to integrity monitoring...")
    for filename in test_files.keys():
        filepath = test_dir / filename
        hash_value = fim.add_file(filepath)
        print(f"   {filename}: {hash_value[:16]}...")
    
    # Initial check - should all be unchanged
    print("\n✅ Initial integrity check:")
    results = fim.check_all()
    print(f"   Unchanged: {len(results['unchanged'])}")
    print(f"   Modified: {len(results['modified'])}")
    
    # Simulate file modification
    print("\n🔧 Simulating file tampering...")
    tampered_file = test_dir / "config.ini"
    with open(tampered_file, 'a') as f:
        f.write("\npassword=hacked123")
    print(f"   Modified: config.ini")
    
    # Delete a file
    deleted_file = test_dir / "data.txt"
    os.remove(deleted_file)
    print(f"   Deleted: data.txt")
    
    # Check integrity again
    print("\n🔍 Checking integrity after changes...")
    report = fim.generate_report()
    print(report)
    
    # Cleanup
    import shutil
    shutil.rmtree(test_dir)
    os.remove("demo_integrity.db")
    
    print("\n💡 Key Features Demonstrated:")
    print("   • File hash calculation and storage")
    print("   • HMAC for authenticated integrity")
    print("   • Change detection (content, size, timestamp)")
    print("   • Missing file detection")
    print("   • Database integrity protection")
    print("   • Comprehensive reporting")

if __name__ == "__main__":
    demo_file_integrity_monitor()
```

### Step 2: Advanced Monitoring Features

Add these advanced features to your monitor:

```python
def demo_advanced_monitoring():
    """Demonstrate advanced monitoring features"""
    print("\n🚀 Advanced Monitoring Features")
    print("="*50)
    
    # Create monitor
    fim = FileIntegrityMonitor("advanced_monitor.db")
    fim.set_secret_key(os.urandom(32))
    
    # Monitor system files (example paths - adjust for your OS)
    critical_files = [
        "/etc/hosts",           # Network configuration
        "/etc/passwd",          # User accounts
        "/etc/ssh/sshd_config", # SSH configuration
    ]
    
    print("📋 Monitoring critical system files:")
    for filepath in critical_files:
        if os.path.exists(filepath):
            try:
                fim.add_file(filepath)
                print(f"   ✅ Added: {filepath}")
            except PermissionError:
                print(f"   ⚠️  Permission denied: {filepath}")
        else:
            print(f"   ❌ Not found: {filepath}")
    
    # Schedule periodic checks (conceptual - would use cron/scheduler in production)
    print("\n⏰ Scheduled integrity checks:")
    print("   In production, use cron or task scheduler:")
    print("   */15 * * * * python fim_check.py  # Every 15 minutes")
    print("   0 2 * * * python fim_report.py     # Daily at 2 AM")
    
    # Alerting on changes (conceptual)
    print("\n🚨 Alert Configuration:")
    print("   Email alerts on critical file changes")
    print("   Syslog integration for SIEM")
    print("   Webhook notifications to security team")
    
    # Cleanup
    if os.path.exists("advanced_monitor.db"):
        os.remove("advanced_monitor.db")
```

---

## ✅ Tutorial Completion Checklist

After completing all parts, verify your understanding:

- [ ] You can explain the difference between hashing and encryption
- [ ] You understand why salts are crucial for password storage
- [ ] You can implement HMAC for message authentication
- [ ] You know how digital signatures provide non-repudiation
- [ ] You can build a file integrity monitoring system
- [ ] You understand the security properties each primitive provides

## 🚀 Ready for the Assignment?

Great! Now you have all the tools to build your secure document signing system. The assignment will combine these concepts into a complete application.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **Cryptographic hashing** for data integrity
2. **Secure password storage** with salt and key derivation
3. **Message authentication** with HMAC
4. **Digital signatures** for authentication and non-repudiation
5. **File integrity monitoring** for security compliance
6. **Key management** best practices
7. **Timing attack prevention** techniques

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!