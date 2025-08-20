# Week 1 Tutorial: Symmetric Encryption with Python

**Estimated Time**: 2.5-3 hours (broken into 4 modules)  
**Prerequisites**: Completed required readings, Python environment set up

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Module 1** (30 min): Implemented basic string encryption/decryption
2. **Module 2** (45 min): Built a secure file encryption utility
3. **Module 3** (30 min): Understood encryption modes and their dangers
4. **Module 4** (45 min): Created a password-based key derivation system

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Module 1: Basic Encryption ✅ Checkpoint 1
- [ ] Module 2: File Encryption ✅ Checkpoint 2  
- [ ] Module 3: Encryption Modes ✅ Checkpoint 3
- [ ] Module 4: Key Derivation ✅ Checkpoint 4

## 🧠 Prerequisites Quick Review

**New to Python?** Complete this 5-minute refresher before starting:

### Essential Python Review
```python
# Variables and data types (we'll use these)
message = "Hello World"     # String (text)
key_size = 256             # Integer (number)
is_encrypted = True        # Boolean (True/False)

# Functions - reusable code blocks
def show_message(text):
    print(f"Message: {text}")

show_message("This is a function call!")

# Lists - storing multiple items
passwords = ["password1", "password2", "password3"]
print(passwords[0])  # Get first item: "password1"

# Try/except - handling errors gracefully
try:
    risky_code()
except Exception as error:
    print(f"Error occurred: {error}")
```

### Command Line Essentials
```bash
# Basic navigation
cd week1-crypto            # Go to folder
pwd                        # Show where you are
ls                         # List files (Mac/Linux)  
dir                        # List files (Windows)

# Running Python
python script.py           # Run your script
python -c "print('test')"  # Quick Python command
```

**💡 Need more help?** 
- Watch: [Python in 5 minutes](https://www.python.org/about/gettingstarted/) 
- Read: [Command line basics](../resources/command-line-help.md)
- **Don't spend more than 10 minutes** - ask for help in discussions!

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Check cryptography library
python -c "from cryptography.fernet import Fernet; print('✅ Cryptography ready')"

# Create working directory
mkdir week1-work
cd week1-work
```

**⚠️ Problems with setup?** 
- Check [troubleshooting guide](../resources/troubleshooting.md)
- Post in Canvas discussions with your error message
- **Don't spend more than 15 minutes stuck** - get help!

---

## 📘 Module 1: Basic String Encryption (30 minutes)

**Learning Objective**: Understand the encrypt-decrypt cycle with symmetric keys

**What you'll build**: Simple text encryption program

Let's start with the simplest case: encrypting and decrypting text messages.

### Step 1: Your First Encryption

Create a new file `crypto_basics.py`:

```python
# Import the encryption tools we need
from cryptography.fernet import Fernet

# Step 1: Generate a key
# Think of this like creating a password that only you know
key = Fernet.generate_key()
print(f"🔑 Generated key: {key.decode()}")
# ^ This prints your key so you can see it

# Step 2: Create a cipher suite  
# This is like getting ready to use your lock and key
cipher_suite = Fernet(key)

# Step 3: Encrypt a message
message = "This is my secret message that nobody should see!"

# Convert text to bytes (computers need this format)
message_bytes = message.encode('utf-8')
# ^ Don't worry about 'utf-8' - it's just the standard text format

# Now encrypt it! (Lock it up)
encrypted_message = cipher_suite.encrypt(message_bytes)
print(f"🔒 Encrypted: {encrypted_message}")
# ^ This will look like gibberish - that's good!

# Step 4: Decrypt the message (Unlock it)
decrypted_bytes = cipher_suite.decrypt(encrypted_message)

# Convert bytes back to readable text
decrypted_message = decrypted_bytes.decode('utf-8')
print(f"🔓 Decrypted: {decrypted_message}")

# Check that we got back exactly what we started with
print(f"✅ Messages match: {message == decrypted_message}")
```

**🤔 What if you're confused?**
- Each line has a comment explaining what it does
- The `print()` statements let you see what's happening
- Don't worry about understanding every detail - focus on the big picture

**Run it:**
```bash
python crypto_basics.py
```

**Expected output:**
```
🔑 Generated key: [random base64 string like gAAAAABh...]
🔒 Encrypted: gAAAAABh...[long encrypted string]...
🔓 Decrypted: This is my secret message that nobody should see!
✅ Messages match: True
```

### 💡 Key Concepts Learned

**Before moving to Module 2, make sure you understand:**

1. **Key Generation**: Fernet uses AES-128 with a random key
2. **Encryption**: Your plaintext becomes unreadable ciphertext  
3. **Authentication**: Fernet includes integrity checking (HMAC)
4. **Decryption**: Only possible with the correct key

### 🛤️ Choose Your Learning Path

**Struggling with the code above?** Try the **Guided Path**:

#### Guided Path: Build It Step by Step
Instead of the full code, let's build it one piece at a time:

```python
# Let's start super simple - just import and generate a key
from cryptography.fernet import Fernet
key = Fernet.generate_key()
print("I generated a key!")
print(key)
```
Run this first. See the key? Good!

```python
# Now let's add encryption of a simple message
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)

# Encrypt just one word first
simple_message = "hello"
encrypted = cipher.encrypt(simple_message.encode())
print("Encrypted:", encrypted)
```
Run this. See the gibberish? That's encryption working!

```python
# Finally, let's decrypt it back
from cryptography.fernet import Fernet
key = Fernet.generate_key()
cipher = Fernet(key)

message = "hello"
encrypted = cipher.encrypt(message.encode())
decrypted = cipher.decrypt(encrypted).decode()

print("Original:", message)
print("Encrypted:", encrypted)
print("Decrypted:", decrypted)
print("Same?", message == decrypted)
```

**🎯 Once this works, try the full example again!**

#### Advanced Path: Professional Development Extensions
Optional learning opportunities for interested students:

**Security Engineering Challenges:**
- **Implement key rotation** - How would you safely change encryption keys?
- **Add key derivation functions** - Use PBKDF2 instead of random keys
- **Performance benchmarking** - Compare AES-128 vs AES-256 performance
- **Memory security** - Implement secure key wiping after use

**Industry Scenario Extensions:**
```python
# Challenge: Implement enterprise key management
class EnterpriseKeyManager:
    def __init__(self):
        self.master_keys = {}
        self.key_versions = {}
    
    def rotate_key(self, service_id):
        # TODO: Implement safe key rotation
        # Requirements:
        # - Keep old key for decrypting existing data
        # - Use new key for new encryptions
        # - Provide migration path
        pass
```

**Research Integration:**
- **Post-quantum cryptography** - Investigate NIST's lattice-based algorithms
- **Hardware security modules** - Research HSM integration for key storage
- **Zero-knowledge proofs** - How could ZKP enhance password verification?

**Professional Portfolio:**
- Create a **technical blog post** explaining your implementation choices
- **Contribute to open source** - Submit improvements to cryptography libraries
- **Industry benchmarking** - Compare your implementation to commercial tools

### ✅ Checkpoint 1 Complete!

**Before continuing, you should be able to:**
- ✅ Generate an encryption key
- ✅ Encrypt a message (even if you don't understand every detail)
- ✅ Decrypt it back to the original
- ✅ Verify they match

**Still stuck?** 
- Post your error message in Canvas discussions
- Schedule office hours 
- **Don't spend more than 45 minutes on Module 1**
You can now encrypt and decrypt text messages. Ready for Module 2?

---

## 📘 Module 2: File Encryption (45 minutes)

**Learning Objective**: Encrypt and decrypt files while preserving data integrity

**What you'll build**: Command-line file encryption utility

### ✅ Checkpoint 1: Verify Basic Encryption Works

Before proceeding, ensure your code works correctly:

```bash
# Run your script
python crypto_basics.py

# Expected: Messages match: True
# If False or error, review your code before continuing
```

**Quick Check**: Can you explain why the key is different each time you run the program?

---

### Step 2: Demonstrate Key Importance

Add this to your file to see what happens with wrong keys:

```python
print("\n" + "="*50)
print("DEMONSTRATING KEY IMPORTANCE")
print("="*50)

# Generate a different key
wrong_key = Fernet.generate_key()
wrong_cipher = Fernet(wrong_key)

try:
    # Try to decrypt with wrong key
    wrong_cipher.decrypt(encrypted_message)
    print("❌ This shouldn't work!")
except Exception as e:
    print(f"✅ Correct behavior - wrong key rejected: {type(e).__name__}")

# Show that same plaintext encrypts differently each time
print("\n🔄 Same message, different encryptions:")
for i in range(3):
    encrypted = cipher_suite.encrypt(message_bytes)
    print(f"   Attempt {i+1}: {encrypted[:50]}...")
```

**Key Insight**: Even the same message encrypts to different ciphertext each time. This prevents patterns and replay attacks.

---

## Part 2: File Encryption (90 minutes)

Now let's build something practical: a file encryption tool.

### Step 1: Basic File Operations

Create `file_encryptor.py`:

```python
from cryptography.fernet import Fernet
import os
import sys
from pathlib import Path

class FileEncryptor:
    """A simple file encryption utility"""
    
    def __init__(self, key_file="secret.key"):
        self.key_file = key_file
        self.key = None
        
    def generate_key(self):
        """Generate a new encryption key"""
        self.key = Fernet.generate_key()
        
        # Save key to file
        with open(self.key_file, 'wb') as f:
            f.write(self.key)
        
        print(f"🔑 New key generated and saved to {self.key_file}")
        print(f"⚠️  Keep this file safe! You can't decrypt without it.")
        return self.key
    
    def load_key(self):
        """Load encryption key from file"""
        if not os.path.exists(self.key_file):
            raise FileNotFoundError(f"Key file {self.key_file} not found. Generate a key first.")
        
        with open(self.key_file, 'rb') as f:
            self.key = f.read()
        
        print(f"🔑 Key loaded from {self.key_file}")
        return self.key
    
    def encrypt_file(self, filepath):
        """Encrypt a file"""
        if not self.key:
            self.load_key()
        
        # Read the file
        file_path = Path(filepath)
        if not file_path.exists():
            raise FileNotFoundError(f"File {filepath} not found")
        
        print(f"📁 Reading {filepath}...")
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Encrypt the data
        cipher_suite = Fernet(self.key)
        encrypted_data = cipher_suite.encrypt(file_data)
        
        # Write encrypted file
        encrypted_path = file_path.with_suffix(file_path.suffix + '.encrypted')
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)
        
        print(f"🔒 File encrypted: {encrypted_path}")
        print(f"📊 Original size: {len(file_data)} bytes")
        print(f"📊 Encrypted size: {len(encrypted_data)} bytes")
        
        return encrypted_path
    
    def decrypt_file(self, filepath):
        """Decrypt a file"""
        if not self.key:
            self.load_key()
        
        # Read encrypted file
        encrypted_path = Path(filepath)
        if not encrypted_path.exists():
            raise FileNotFoundError(f"Encrypted file {filepath} not found")
        
        print(f"📁 Reading {filepath}...")
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Decrypt the data
        cipher_suite = Fernet(self.key)
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
        except Exception as e:
            raise Exception(f"Decryption failed. Wrong key or corrupted file: {e}")
        
        # Write decrypted file
        if filepath.endswith('.encrypted'):
            decrypted_path = Path(filepath[:-10])  # Remove .encrypted
        else:
            decrypted_path = Path(filepath).with_suffix('.decrypted')
        
        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)
        
        print(f"🔓 File decrypted: {decrypted_path}")
        print(f"📊 Decrypted size: {len(decrypted_data)} bytes")
        
        return decrypted_path

# Demo the file encryptor
if __name__ == "__main__":
    # Create a test file
    test_content = """This is a secret document!
    
It contains sensitive information that should be protected.
Here's some data that we want to keep confidential:
- Social Security Number: 123-45-6789
- Credit Card: 4532-1234-5678-9012
- Password: SuperSecretPassword123!

This file should be encrypted before storage or transmission.
"""
    
    with open("sensitive_document.txt", "w") as f:
        f.write(test_content)
    
    print("🏗️  DEMO: File Encryption System")
    print("="*40)
    
    # Initialize encryptor
    encryptor = FileEncryptor()
    
    # Generate a new key
    encryptor.generate_key()
    
    # Encrypt the file
    encrypted_file = encryptor.encrypt_file("sensitive_document.txt")
    
    # Show that encrypted file is unreadable
    print(f"\n👀 Let's peek at the encrypted file:")
    with open(encrypted_file, 'rb') as f:
        encrypted_peek = f.read(100)  # First 100 bytes
    print(f"🔒 Encrypted data preview: {encrypted_peek}")
    
    # Decrypt the file
    decrypted_file = encryptor.decrypt_file(encrypted_file)
    
    # Verify decryption worked
    with open(decrypted_file, 'r') as f:
        decrypted_content = f.read()
    
    print(f"\n✅ Decryption successful: {test_content == decrypted_content}")
```

**Run it:**
```bash
python file_encryptor.py
```

### Step 2: Command-Line Interface

Let's make our tool more user-friendly. Add this to the end of `file_encryptor.py`:

```python
def main():
    """Command-line interface"""
    if len(sys.argv) < 2:
        print("📋 File Encryption Tool")
        print("Usage:")
        print("  python file_encryptor.py generate          - Generate new key")
        print("  python file_encryptor.py encrypt <file>    - Encrypt file")
        print("  python file_encryptor.py decrypt <file>    - Decrypt file")
        return
    
    command = sys.argv[1].lower()
    encryptor = FileEncryptor()
    
    try:
        if command == "generate":
            encryptor.generate_key()
            
        elif command == "encrypt":
            if len(sys.argv) != 3:
                print("❌ Error: Please specify a file to encrypt")
                return
            filename = sys.argv[2]
            encryptor.encrypt_file(filename)
            
        elif command == "decrypt":
            if len(sys.argv) != 3:
                print("❌ Error: Please specify a file to decrypt")
                return
            filename = sys.argv[2]
            encryptor.decrypt_file(filename)
            
        else:
            print(f"❌ Unknown command: {command}")
            
    except Exception as e:
        print(f"❌ Error: {e}")

# Replace the demo section with:
if __name__ == "__main__":
    main()
```

**Test the CLI:**
```bash
# Generate a key
python file_encryptor.py generate

# Create a test file
echo "This is secret data!" > test.txt

# Encrypt it
python file_encryptor.py encrypt test.txt

# Try to read the encrypted file (should be gibberish)
cat test.txt.encrypted

# Decrypt it
python file_encryptor.py decrypt test.txt.encrypted

# Verify the decrypted content
cat test.txt
```

---

## Part 3: Understanding Encryption Modes (45 minutes)

Fernet uses secure modes internally, but let's see why mode selection matters.

### Step 1: The Dangers of ECB Mode

Create `encryption_modes.py`:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def pad_data(data):
    """Pad data to 16-byte blocks (AES block size)"""
    padding_length = 16 - (len(data) % 16)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad_data(padded_data):
    """Remove padding from data"""
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

class ECBDemo:
    """Demonstrate why ECB mode is insecure"""
    
    def __init__(self):
        self.key = os.urandom(32)  # 256-bit key
        
    def encrypt_ecb(self, plaintext):
        """Encrypt with ECB mode - DON'T USE IN PRODUCTION!"""
        padded_data = pad_data(plaintext)
        
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return ciphertext
    
    def encrypt_cbc(self, plaintext):
        """Encrypt with CBC mode - much better than ECB"""
        iv = os.urandom(16)  # Random initialization vector
        padded_data = pad_data(plaintext)
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext  # Prepend IV to ciphertext
    
    def demonstrate_ecb_weakness(self):
        """Show how ECB reveals patterns"""
        print("🔍 DEMONSTRATING ECB MODE WEAKNESS")
        print("="*50)
        
        # Create data with repeating patterns
        repetitive_data = b"CONFIDENTIAL_DATA! " * 10  # Same block repeated
        
        print(f"📝 Original data length: {len(repetitive_data)} bytes")
        print(f"📝 Original pattern: {repetitive_data[:40]}...")
        
        # Encrypt with ECB
        ecb_encrypted = self.encrypt_ecb(repetitive_data)
        print(f"\n🔒 ECB encrypted length: {len(ecb_encrypted)} bytes")
        
        # Encrypt with CBC  
        cbc_encrypted = self.encrypt_cbc(repetitive_data)
        print(f"🔒 CBC encrypted length: {len(cbc_encrypted)} bytes")
        
        # Analyze patterns in ECB
        print(f"\n🔍 PATTERN ANALYSIS:")
        
        # Count unique blocks in ECB ciphertext
        block_size = 16
        ecb_blocks = [ecb_encrypted[i:i+block_size] for i in range(0, len(ecb_encrypted), block_size)]
        unique_ecb_blocks = set(ecb_blocks)
        
        print(f"ECB unique blocks: {len(unique_ecb_blocks)} out of {len(ecb_blocks)} total")
        print(f"ECB pattern visibility: {'HIGH RISK' if len(unique_ecb_blocks) < len(ecb_blocks) else 'OK'}")
        
        # Count unique blocks in CBC ciphertext (skip IV)
        cbc_data = cbc_encrypted[16:]  # Skip IV
        cbc_blocks = [cbc_data[i:i+block_size] for i in range(0, len(cbc_data), block_size)]
        unique_cbc_blocks = set(cbc_blocks)
        
        print(f"CBC unique blocks: {len(unique_cbc_blocks)} out of {len(cbc_blocks)} total")
        print(f"CBC pattern visibility: {'LOW RISK' if len(unique_cbc_blocks) == len(cbc_blocks) else 'MEDIUM'}")
        
        return ecb_encrypted, cbc_encrypted

# Demo the modes
if __name__ == "__main__":
    demo = ECBDemo()
    demo.demonstrate_ecb_weakness()
    
    print(f"\n💡 KEY TAKEAWAYS:")
    print(f"   • ECB mode reveals patterns in data")
    print(f"   • CBC mode hides patterns with random IV") 
    print(f"   • Fernet uses authenticated encryption (even better)")
    print(f"   • Never use ECB for anything important!")
```

**Run it:**
```bash
python encryption_modes.py
```

### Step 2: Visualizing the Problem

Add this function to see the pattern more clearly:

```python
def visualize_patterns(self, data, title):
    """Simple visualization of data patterns"""
    print(f"\n📊 {title}:")
    
    # Show first few blocks as hex
    block_size = 16
    blocks = [data[i:i+block_size] for i in range(0, min(len(data), 64), block_size)]
    
    for i, block in enumerate(blocks):
        hex_representation = block.hex()
        print(f"   Block {i}: {hex_representation[:32]}...")
        
        # Check if this block appears elsewhere
        block_count = data.count(block)
        if block_count > 1:
            print(f"            ⚠️  This block appears {block_count} times!")

# Add this to the ECBDemo class and call it in demonstrate_ecb_weakness()
```

---

## Part 4: Password-Based Key Derivation (60 minutes)

Real applications need to derive keys from user passwords securely.

### Step 1: Secure Key Derivation

Create `password_crypto.py`:

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64
import getpass

class PasswordBasedEncryption:
    """Encryption system based on user passwords"""
    
    def derive_key_from_password(self, password, salt=None):
        """
        Derive a Fernet key from a password using PBKDF2
        
        Args:
            password (str): User password
            salt (bytes): Salt for key derivation (generates random if None)
            
        Returns:
            tuple: (derived_key, salt)
        """
        if salt is None:
            salt = os.urandom(16)  # 128-bit salt
        
        # Configure PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for Fernet
            salt=salt,
            iterations=100000,  # 100,000 iterations (adjust for security vs speed)
        )
        
        # Derive key
        password_bytes = password.encode('utf-8')
        derived_key = kdf.derive(password_bytes)
        
        # Encode for Fernet (requires base64)
        fernet_key = base64.urlsafe_b64encode(derived_key)
        
        return fernet_key, salt
    
    def encrypt_with_password(self, data, password):
        """
        Encrypt data with a password
        
        Returns:
            bytes: salt + encrypted_data
        """
        # Derive key from password
        key, salt = self.derive_key_from_password(password)
        
        # Encrypt data
        cipher_suite = Fernet(key)
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted_data = cipher_suite.encrypt(data)
        
        # Prepend salt to encrypted data
        return salt + encrypted_data
    
    def decrypt_with_password(self, encrypted_package, password):
        """
        Decrypt data with a password
        
        Args:
            encrypted_package (bytes): salt + encrypted_data
            password (str): User password
            
        Returns:
            bytes: Decrypted data
        """
        # Extract salt and encrypted data
        salt = encrypted_package[:16]
        encrypted_data = encrypted_package[16:]
        
        # Derive key from password and salt
        key, _ = self.derive_key_from_password(password, salt)
        
        # Decrypt data
        cipher_suite = Fernet(key)
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return decrypted_data
        except Exception:
            raise ValueError("Incorrect password or corrupted data")

def demo_password_encryption():
    """Demonstrate password-based encryption"""
    print("🔐 PASSWORD-BASED ENCRYPTION DEMO")
    print("="*50)
    
    pbe = PasswordBasedEncryption()
    
    # Get password from user (hidden input)
    password = getpass.getpass("Enter encryption password: ")
    
    # Secret message to encrypt
    secret_message = """
    This is a highly confidential document!
    
    Contains:
    - API keys: sk-abc123def456
    - Database password: mysqlpassword123
    - Personal information: SSN 123-45-6789
    
    This should only be readable with the correct password.
    """
    
    print(f"\n📝 Original message ({len(secret_message)} characters)")
    
    # Encrypt with password
    print("🔒 Encrypting with your password...")
    encrypted_package = pbe.encrypt_with_password(secret_message, password)
    print(f"✅ Encryption complete ({len(encrypted_package)} bytes)")
    
    # Show encrypted data is unreadable
    print(f"\n👀 Encrypted data preview: {encrypted_package[:50]}...")
    
    # Test correct password
    print(f"\n🔓 Testing decryption with correct password...")
    try:
        decrypted_data = pbe.decrypt_with_password(encrypted_package, password)
        decrypted_message = decrypted_data.decode('utf-8')
        
        print("✅ Decryption successful!")
        print(f"📄 Message matches: {secret_message.strip() == decrypted_message.strip()}")
        
    except ValueError as e:
        print(f"❌ Decryption failed: {e}")
    
    # Test wrong password
    print(f"\n🔓 Testing decryption with wrong password...")
    try:
        wrong_password = password + "wrong"
        pbe.decrypt_with_password(encrypted_package, wrong_password)
        print("❌ This shouldn't succeed!")
    except ValueError:
        print("✅ Correctly rejected wrong password")

def demo_key_derivation():
    """Show how key derivation works"""
    print("\n🔑 KEY DERIVATION DEMONSTRATION")
    print("="*50)
    
    pbe = PasswordBasedEncryption()
    password = "MySecurePassword123!"
    
    print(f"Password: {password}")
    
    # Show that same password + salt = same key
    key1, salt = pbe.derive_key_from_password(password)
    key2, _ = pbe.derive_key_from_password(password, salt)
    
    print(f"✅ Same password + salt = same key: {key1 == key2}")
    
    # Show that different salts = different keys
    key3, salt2 = pbe.derive_key_from_password(password)
    
    print(f"✅ Same password + different salt = different key: {key1 != key3}")
    print(f"   Key 1: {key1.decode()[:20]}...")
    print(f"   Key 3: {key3.decode()[:20]}...")
    
    # Show iteration effect on performance
    import time
    
    iterations_test = [1000, 10000, 100000]
    print(f"\n⏱️  ITERATION PERFORMANCE TEST:")
    
    for iterations in iterations_test:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        
        start_time = time.time()
        kdf.derive(password.encode())
        end_time = time.time()
        
        print(f"   {iterations:6} iterations: {(end_time - start_time)*1000:.1f} ms")

if __name__ == "__main__":
    demo_key_derivation()
    print()
    demo_password_encryption()
    
    print(f"\n💡 SECURITY INSIGHTS:")
    print(f"   • Salt prevents rainbow table attacks")
    print(f"   • High iteration count slows brute force")
    print(f"   • Same password produces different keys with different salts")
    print(f"   • Balance security vs performance for iterations")
```

**Run it:**
```bash
python password_crypto.py
```

### Step 2: Build a Simple Password Manager

Now let's combine everything into a basic password manager:

```python
class SimplePasswordManager:
    """A basic password manager using our encryption"""
    
    def __init__(self, vault_file="passwords.vault"):
        self.vault_file = vault_file
        self.pbe = PasswordBasedEncryption()
        self.passwords = {}
        self.master_password = None
    
    def create_vault(self, master_password):
        """Create a new password vault"""
        self.master_password = master_password
        self.passwords = {}
        self._save_vault()
        print(f"✅ New vault created: {self.vault_file}")
    
    def load_vault(self, master_password):
        """Load an existing vault"""
        if not os.path.exists(self.vault_file):
            raise FileNotFoundError(f"Vault {self.vault_file} not found")
        
        with open(self.vault_file, 'rb') as f:
            encrypted_data = f.read()
        
        try:
            decrypted_data = self.pbe.decrypt_with_password(encrypted_data, master_password)
            vault_content = decrypted_data.decode('utf-8')
            
            # Simple format: "website:username:password\n"
            self.passwords = {}
            for line in vault_content.strip().split('\n'):
                if line:
                    parts = line.split(':', 2)
                    if len(parts) == 3:
                        website, username, password = parts
                        self.passwords[website] = {'username': username, 'password': password}
            
            self.master_password = master_password
            print(f"✅ Vault loaded: {len(self.passwords)} entries")
            
        except ValueError:
            raise ValueError("Invalid master password")
    
    def add_password(self, website, username, password):
        """Add a password to the vault"""
        if not self.master_password:
            raise RuntimeError("Vault not loaded")
        
        self.passwords[website] = {'username': username, 'password': password}
        self._save_vault()
        print(f"✅ Password added for {website}")
    
    def get_password(self, website):
        """Get a password from the vault"""
        if website not in self.passwords:
            raise KeyError(f"No password found for {website}")
        
        return self.passwords[website]
    
    def list_websites(self):
        """List all websites in the vault"""
        return list(self.passwords.keys())
    
    def _save_vault(self):
        """Save the vault to disk"""
        # Convert passwords dict to simple format
        vault_content = ""
        for website, creds in self.passwords.items():
            vault_content += f"{website}:{creds['username']}:{creds['password']}\n"
        
        # Encrypt and save
        encrypted_data = self.pbe.encrypt_with_password(vault_content, self.master_password)
        
        with open(self.vault_file, 'wb') as f:
            f.write(encrypted_data)

# Add this demo to the main section
def demo_password_manager():
    """Demo the password manager"""
    print("\n🔐 PASSWORD MANAGER DEMO")
    print("="*50)
    
    pm = SimplePasswordManager("demo.vault")
    master_password = "MyMasterPassword123!"
    
    # Create vault
    pm.create_vault(master_password)
    
    # Add some passwords
    pm.add_password("github.com", "myusername", "github_password_123")
    pm.add_password("gmail.com", "user@email.com", "email_password_456")
    pm.add_password("banking.com", "account123", "very_secure_bank_pass")
    
    # List websites
    print(f"📋 Websites: {pm.list_websites()}")
    
    # Retrieve a password
    github_creds = pm.get_password("github.com")
    print(f"🔑 GitHub credentials: {github_creds}")
    
    # Test loading vault
    pm2 = SimplePasswordManager("demo.vault")
    pm2.load_vault(master_password)
    print(f"📋 Loaded vault has {len(pm2.passwords)} entries")
    
    # Clean up
    os.remove("demo.vault")
```

---

## ✅ Tutorial Completion Checklist

After completing all parts, verify your understanding:

- [ ] You can explain why the same plaintext encrypts differently each time
- [ ] You understand the importance of key management
- [ ] You can explain why ECB mode is dangerous
- [ ] You know how salt protects against rainbow table attacks
- [ ] You can build a secure file encryption tool
- [ ] You can implement password-based encryption

## 🚀 Ready for the Assignment?

Great! Now you have all the tools to build your password vault. The assignment will combine all these concepts into a complete, secure password management system.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **Symmetric encryption** with AES-128 via Fernet
2. **Key generation** and secure storage
3. **File encryption/decryption** with proper error handling
4. **Encryption modes** and why ECB is dangerous
5. **Password-based key derivation** with PBKDF2
6. **Salt usage** to prevent rainbow table attacks
7. **Iteration counts** for slowing brute force attacks

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!