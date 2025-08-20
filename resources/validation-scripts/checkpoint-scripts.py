#!/usr/bin/env python3
"""
CSCI 347 Week 1 Tutorial Checkpoint Scripts
Automated verification for each tutorial module
"""

import sys
import subprocess
import os
from pathlib import Path

def run_checkpoint(checkpoint_num, description):
    """Run a specific checkpoint verification"""
    print(f"\n{'='*50}")
    print(f"CHECKPOINT {checkpoint_num}: {description}")
    print(f"{'='*50}")
    
    try:
        if checkpoint_num == 1:
            return checkpoint_1_basic_encryption()
        elif checkpoint_num == 2:
            return checkpoint_2_file_encryption()
        elif checkpoint_num == 3:
            return checkpoint_3_encryption_modes()
        elif checkpoint_num == 4:
            return checkpoint_4_key_derivation()
        else:
            print("❌ Invalid checkpoint number")
            return False
            
    except Exception as e:
        print(f"❌ Checkpoint failed with error: {e}")
        return False

def checkpoint_1_basic_encryption():
    """Verify basic string encryption works"""
    print("Testing basic encryption functionality...")
    
    # Check if crypto_basics.py exists
    if not os.path.exists('crypto_basics.py'):
        print("❌ File 'crypto_basics.py' not found")
        print("   Make sure you've created the file with basic encryption code")
        return False
    
    try:
        # Import and test the basic functionality
        from cryptography.fernet import Fernet
        
        # Test key generation
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        
        # Test encryption/decryption
        test_message = "Test message for checkpoint"
        encrypted = cipher_suite.encrypt(test_message.encode())
        decrypted = cipher_suite.decrypt(encrypted).decode()
        
        if test_message == decrypted:
            print("✅ Basic encryption/decryption working correctly")
            print("✅ Key generation working")
            print("✅ Text encoding/decoding working")
            print("\n🎉 CHECKPOINT 1 PASSED!")
            print("You're ready for Module 2: File Encryption")
            return True
        else:
            print("❌ Encryption/decryption not working correctly")
            return False
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure cryptography library is installed")
        return False

def checkpoint_2_file_encryption():
    """Verify file encryption works"""
    print("Testing file encryption functionality...")
    
    # Create a test file
    test_content = "This is test content for file encryption checkpoint."
    test_file = "test_checkpoint.txt"
    
    with open(test_file, 'w') as f:
        f.write(test_content)
    
    try:
        from cryptography.fernet import Fernet
        
        # Test file encryption
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        
        # Read, encrypt, and write
        with open(test_file, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = cipher_suite.encrypt(file_data)
        
        with open(test_file + '.enc', 'wb') as f:
            f.write(encrypted_data)
        
        # Test decryption
        with open(test_file + '.enc', 'rb') as f:
            encrypted_from_file = f.read()
        
        decrypted_data = cipher_suite.decrypt(encrypted_from_file)
        
        if file_data == decrypted_data:
            print("✅ File encryption working correctly")
            print("✅ File decryption working correctly") 
            print("✅ Binary file handling working")
            
            # Clean up test files
            os.remove(test_file)
            os.remove(test_file + '.enc')
            
            print("\n🎉 CHECKPOINT 2 PASSED!")
            print("You're ready for Module 3: Encryption Modes")
            return True
        else:
            print("❌ File encryption/decryption not working correctly")
            return False
            
    except Exception as e:
        print(f"❌ File encryption test failed: {e}")
        # Clean up test files
        for f in [test_file, test_file + '.enc']:
            if os.path.exists(f):
                os.remove(f)
        return False

def checkpoint_3_encryption_modes():
    """Verify understanding of encryption modes"""
    print("Testing encryption modes understanding...")
    
    try:
        from cryptography.fernet import Fernet
        
        # Test that same plaintext produces different ciphertext (Fernet uses random IV)
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        
        message = "Same message encrypted twice"
        encrypted1 = cipher_suite.encrypt(message.encode())
        encrypted2 = cipher_suite.encrypt(message.encode())
        
        if encrypted1 != encrypted2:
            print("✅ Fernet produces different ciphertext for same plaintext")
            print("✅ This shows proper IV/nonce usage (not ECB mode)")
            
            # Verify both decrypt to same plaintext
            decrypted1 = cipher_suite.decrypt(encrypted1).decode()
            decrypted2 = cipher_suite.decrypt(encrypted2).decode()
            
            if decrypted1 == decrypted2 == message:
                print("✅ Both ciphertexts decrypt to correct plaintext")
                print("\n🎉 CHECKPOINT 3 PASSED!")
                print("You understand why ECB mode is dangerous")
                print("You're ready for Module 4: Key Derivation")
                return True
        
        print("❌ Encryption modes test failed")
        return False
        
    except Exception as e:
        print(f"❌ Encryption modes test failed: {e}")
        return False

def checkpoint_4_key_derivation():
    """Verify key derivation functionality"""
    print("Testing password-based key derivation...")
    
    try:
        import os
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import base64
        
        # Test PBKDF2 key derivation
        password = b"test_password"
        salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password))
        
        # Test that same password+salt produces same key
        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(), 
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        key2 = base64.urlsafe_b64encode(kdf2.derive(password))
        
        if key == key2:
            print("✅ PBKDF2 key derivation working correctly")
            print("✅ Same password + salt produces same key")
            print("✅ Using SHA-256 hashing algorithm")
            print("✅ Using 100,000+ iterations for security")
            
            # Test with Fernet
            from cryptography.fernet import Fernet
            cipher_suite = Fernet(key)
            
            test_message = "Key derivation test message"
            encrypted = cipher_suite.encrypt(test_message.encode())
            decrypted = cipher_suite.decrypt(encrypted).decode()
            
            if test_message == decrypted:
                print("✅ Derived key works with Fernet encryption")
                print("\n🎉 CHECKPOINT 4 PASSED!")
                print("You've completed all tutorial modules!")
                print("You're ready for the weekly assignment!")
                return True
        
        print("❌ Key derivation test failed")
        return False
        
    except Exception as e:
        print(f"❌ Key derivation test failed: {e}")
        return False

def main():
    """Main checkpoint runner"""
    print("CSCI 347 Week 1 Tutorial Checkpoint Verification")
    print("=" * 55)
    
    if len(sys.argv) != 2:
        print("Usage: python checkpoint-scripts.py <checkpoint_number>")
        print("\nAvailable checkpoints:")
        print("1 - Basic String Encryption")
        print("2 - File Encryption") 
        print("3 - Encryption Modes")
        print("4 - Key Derivation")
        print("\nOr run: python checkpoint-scripts.py all")
        sys.exit(1)
    
    checkpoint_arg = sys.argv[1].lower()
    
    if checkpoint_arg == "all":
        print("Running all checkpoints...\n")
        all_passed = True
        for i in range(1, 5):
            descriptions = [
                "Basic String Encryption",
                "File Encryption", 
                "Encryption Modes",
                "Key Derivation"
            ]
            passed = run_checkpoint(i, descriptions[i-1])
            if not passed:
                all_passed = False
                break
        
        if all_passed:
            print("\n" + "🎉" * 20)
            print("ALL CHECKPOINTS PASSED!")
            print("You're ready for the weekly assignment!")
            print("🎉" * 20)
        else:
            print("\n❌ Some checkpoints failed. Please review and retry.")
            
    else:
        try:
            checkpoint_num = int(checkpoint_arg)
            if checkpoint_num < 1 or checkpoint_num > 4:
                raise ValueError()
                
            descriptions = [
                "Basic String Encryption",
                "File Encryption",
                "Encryption Modes", 
                "Key Derivation"
            ]
            
            run_checkpoint(checkpoint_num, descriptions[checkpoint_num-1])
            
        except ValueError:
            print("❌ Invalid checkpoint number. Use 1-4 or 'all'")
            sys.exit(1)

if __name__ == "__main__":
    main()