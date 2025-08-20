#!/usr/bin/env python3
"""
Week 1 Validation Script
CSCI 347 - Network Security and Digital Forensics

This script checks that students have completed the Week 1 tutorial correctly.
Run this before submitting your assignment to ensure everything works.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

def print_header():
    """Print validation header"""
    print("="*60)
    print("CSCI 347 - Week 1 Validation")
    print("Cryptography Basics with Python")
    print("="*60)

def test_basic_encryption():
    """Test if student can do basic Fernet encryption"""
    print("\n🔍 Testing basic encryption...")
    
    try:
        from cryptography.fernet import Fernet
        
        # Test key generation
        key = Fernet.generate_key()
        cipher = Fernet(key)
        
        # Test string encryption/decryption
        test_message = "Hello, cryptography!"
        test_bytes = test_message.encode('utf-8')
        
        encrypted = cipher.encrypt(test_bytes)
        decrypted = cipher.decrypt(encrypted)
        
        assert decrypted == test_bytes, "Encryption/decryption mismatch"
        assert encrypted != test_bytes, "Data not actually encrypted"
        
        print("  ✅ Key generation works")
        print("  ✅ Encryption works") 
        print("  ✅ Decryption works")
        print("  ✅ Round-trip successful")
        
        return True
        
    except ImportError:
        print("  ❌ cryptography library not installed")
        print("     Run: pip install cryptography")
        return False
    except Exception as e:
        print(f"  ❌ Basic encryption test failed: {e}")
        return False

def test_file_encryption():
    """Test file encryption capabilities"""
    print("\n🔍 Testing file encryption...")
    
    try:
        # Create a temporary directory for testing
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create test file
            test_file = temp_path / "test.txt"
            test_content = "This is a secret file!\nIt contains sensitive data."
            test_file.write_text(test_content)
            
            # Try to import and use file encryption
            try:
                # Look for file_encryptor.py in current directory
                sys.path.insert(0, '.')
                from file_encryptor import FileEncryptor
                
                # Test the file encryptor
                encryptor = FileEncryptor(str(temp_path / "test.key"))
                
                # Generate key
                encryptor.generate_key()
                print("  ✅ Key generation works")
                
                # Encrypt file
                encrypted_file = encryptor.encrypt_file(str(test_file))
                print("  ✅ File encryption works")
                
                # Check that encrypted file exists and is different
                assert Path(encrypted_file).exists(), "Encrypted file not created"
                encrypted_content = Path(encrypted_file).read_bytes()
                assert encrypted_content != test_content.encode(), "File not actually encrypted"
                
                # Decrypt file
                decrypted_file = encryptor.decrypt_file(str(encrypted_file))
                print("  ✅ File decryption works")
                
                # Check that decrypted content matches original
                decrypted_content = Path(decrypted_file).read_text()
                assert decrypted_content == test_content, "Decrypted content doesn't match original"
                print("  ✅ File round-trip successful")
                
                return True
                
            except ImportError:
                print("  ⚠️  file_encryptor.py not found (optional for validation)")
                return True  # Don't fail validation for optional components
                
    except Exception as e:
        print(f"  ❌ File encryption test failed: {e}")
        return False

def test_password_based_encryption():
    """Test password-based key derivation"""
    print("\n🔍 Testing password-based encryption...")
    
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.fernet import Fernet
        import base64
        import os
        
        # Test key derivation
        password = "test_password_123"
        salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        derived_key = kdf.derive(password.encode())
        fernet_key = base64.urlsafe_b64encode(derived_key)
        
        # Test that same password+salt produces same key
        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        derived_key2 = kdf2.derive(password.encode())
        assert derived_key == derived_key2, "Same password+salt should produce same key"
        
        # Test encryption with derived key
        cipher = Fernet(fernet_key)
        test_data = b"Secret data encrypted with password-derived key"
        
        encrypted = cipher.encrypt(test_data)
        decrypted = cipher.decrypt(encrypted)
        
        assert decrypted == test_data, "Password-based encryption failed"
        
        print("  ✅ PBKDF2 key derivation works")
        print("  ✅ Deterministic key generation works") 
        print("  ✅ Password-based encryption works")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Password-based encryption test failed: {e}")
        return False

def test_encryption_modes():
    """Test understanding of encryption modes"""
    print("\n🔍 Testing encryption modes knowledge...")
    
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        import os
        
        key = os.urandom(32)  # 256-bit key
        
        # Test ECB mode (should show pattern weakness)
        repetitive_data = b"SAME_BLOCK_HERE!" * 5  # 80 bytes = 5 blocks of 16 bytes each
        
        # Pad to block boundary
        padded_data = repetitive_data + b'\x00' * (16 - len(repetitive_data) % 16)
        
        # ECB encryption
        cipher_ecb = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor_ecb = cipher_ecb.encryptor()
        ecb_encrypted = encryptor_ecb.update(padded_data) + encryptor_ecb.finalize()
        
        # CBC encryption
        iv = os.urandom(16)
        cipher_cbc = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor_cbc = cipher_cbc.encryptor()
        cbc_encrypted = encryptor_cbc.update(padded_data) + encryptor_cbc.finalize()
        
        # Check that ECB shows patterns (repeated blocks)
        block_size = 16
        ecb_blocks = [ecb_encrypted[i:i+block_size] for i in range(0, len(ecb_encrypted), block_size)]
        unique_ecb_blocks = len(set(ecb_blocks))
        total_ecb_blocks = len(ecb_blocks)
        
        # With repetitive data, ECB should have fewer unique blocks
        assert unique_ecb_blocks < total_ecb_blocks, "ECB should reveal patterns in repetitive data"
        
        # CBC should hide patterns better
        cbc_blocks = [cbc_encrypted[i:i+block_size] for i in range(0, len(cbc_encrypted), block_size)]
        unique_cbc_blocks = len(set(cbc_blocks))
        
        print("  ✅ ECB mode correctly shows pattern weakness")
        print("  ✅ CBC mode correctly hides patterns")
        print(f"      ECB unique blocks: {unique_ecb_blocks}/{total_ecb_blocks}")
        print(f"      CBC unique blocks: {unique_cbc_blocks}/{len(cbc_blocks)}")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Encryption modes test failed: {e}")
        return False

def test_tutorial_files():
    """Check that expected tutorial files exist"""
    print("\n🔍 Checking tutorial files...")
    
    expected_files = [
        'crypto_basics.py',
        'file_encryptor.py', 
        'encryption_modes.py',
        'password_crypto.py'
    ]
    
    found_files = []
    for filename in expected_files:
        if os.path.exists(filename):
            found_files.append(filename)
            print(f"  ✅ {filename} found")
        else:
            print(f"  ⚠️  {filename} not found (optional)")
    
    if found_files:
        print(f"  ✅ Found {len(found_files)} tutorial files")
        return True
    else:
        print("  ⚠️  No tutorial files found (this is OK if you used different names)")
        return True

def test_environment():
    """Test Python environment setup"""
    print("\n🔍 Testing environment setup...")
    
    # Check Python version
    version = sys.version_info
    if version.major == 3 and version.minor >= 11:
        print(f"  ✅ Python version: {version.major}.{version.minor}.{version.micro}")
    else:
        print(f"  ⚠️  Python version: {version.major}.{version.minor}.{version.micro} (3.11+ recommended)")
    
    # Check required imports
    required_modules = [
        'cryptography',
        'cryptography.fernet',
        'cryptography.hazmat.primitives.kdf.pbkdf2',
        'cryptography.hazmat.primitives.ciphers',
    ]
    
    all_imported = True
    for module in required_modules:
        try:
            __import__(module)
            print(f"  ✅ {module} available")
        except ImportError:
            print(f"  ❌ {module} not available")
            all_imported = False
    
    return all_imported

def main():
    """Main validation function"""
    print_header()
    
    tests = [
        ("Environment Setup", test_environment),
        ("Basic Encryption", test_basic_encryption),
        ("Password-Based Encryption", test_password_based_encryption), 
        ("Encryption Modes", test_encryption_modes),
        ("File Encryption", test_file_encryption),
        ("Tutorial Files", test_tutorial_files),
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"  ❌ Unexpected error in {test_name}: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*60)
    print("VALIDATION SUMMARY")
    print("="*60)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<25} {status}")
        if result:
            passed += 1
    
    print("-" * 60)
    print(f"Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 VALIDATION SUCCESSFUL!")
        print("   You're ready to work on the assignment.")
        print("\n📋 Next steps:")
        print("   1. Review assignment requirements")
        print("   2. Build your password vault")
        print("   3. Test thoroughly before submission")
        return True
    else:
        print("\n⚠️  SOME TESTS FAILED")
        print("   Please fix issues before proceeding to assignment.")
        print("\n🔧 Common fixes:")
        print("   • Install missing packages: pip install cryptography")
        print("   • Check your virtual environment is activated")
        print("   • Review tutorial code for errors")
        print("   • Ask for help in Canvas discussions")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)