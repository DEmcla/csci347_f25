# Week 1 Assignment: Secure Password Vault

**Due**: End of Week 1 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Build a command-line password manager that securely stores website credentials using the cryptographic techniques learned this week. Your implementation should demonstrate proper use of symmetric encryption, password-based key derivation, and secure file handling.

## 📋 Requirements

### Core Functionality (70 points)

Your password vault must implement these features:

#### 1. Master Password Protection (20 points)
- **Secure key derivation** using PBKDF2 with SHA-256
- **Minimum 100,000 iterations** for brute-force protection
- **Random salt generation** (16 bytes minimum)
- **Proper error handling** for incorrect passwords

#### 2. Password Storage Operations (30 points)
- **Add new passwords**: `add_password(website, username, password)`
- **Retrieve passwords**: `get_password(website)`
- **List all websites**: `list_websites()`
- **Update existing passwords**: `update_password(website, new_password)`

#### 3. Secure File Storage (20 points)
- **Encrypted vault file** using Fernet or equivalent
- **Atomic file operations** (write to temp file, then rename)
- **Data integrity verification** on load
- **Graceful handling** of corrupted or missing vault files

### Command-Line Interface (20 points)

Implement a user-friendly CLI with these commands:

```bash
# Create new vault
python password_vault.py init

# Add a password
python password_vault.py add <website> <username> <password>

# Get a password
python password_vault.py get <website>

# List all websites
python password_vault.py list

# Update a password
python password_vault.py update <website> <new_password>
```

### Security Features (10 points)

- **Input validation** to prevent injection attacks
- **Memory cleanup** of sensitive data when possible
- **Secure password generation** option (bonus)
- **Proper error messages** without revealing sensitive information

## 🔧 Technical Specifications

### Required Libraries
```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import sys
import json  # or other serialization method
import getpass
import base64
```

### File Structure
```
password_vault.py          # Main implementation
README.txt                 # Usage instructions and design notes
requirements.txt           # Dependencies (if any additional packages)
```

### Data Format
Design your own secure format for storing encrypted password data. Consider:
- How to store multiple passwords in one encrypted file
- How to handle metadata (website names, usernames)
- How to ensure data integrity

## 📝 Detailed Requirements

### 1. Vault Initialization
```python
def init_vault(master_password):
    """
    Create a new password vault
    
    Args:
        master_password (str): User's master password
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Generate salt
    # Derive key from master password
    # Create empty vault structure
    # Save encrypted vault to file
```

### 2. Password Management
```python
def add_password(website, username, password):
    """
    Add a new password entry
    
    Args:
        website (str): Website/service name
        username (str): Username/email
        password (str): Password to store
        
    Returns:
        bool: Success status
    """
    # Load and decrypt vault
    # Add new entry
    # Save encrypted vault
```

### 3. Error Handling
Your program must handle:
- **Incorrect master password**: Clear error message, no stack trace
- **Missing vault file**: Offer to create new vault
- **Corrupted vault file**: Detect and report corruption
- **Duplicate websites**: Either update or error (your choice)
- **Network/disk errors**: Graceful failure messages

### 4. Security Considerations
- **Never store master password**: Only derive keys as needed
- **Clear sensitive variables**: Use `del` or overwrite when possible  
- **Validate input**: Prevent empty passwords, excessively long inputs
- **Use secure temporary files**: For atomic operations

## 💻 Example Usage

```bash
$ python password_vault.py init
Enter master password: [hidden input]
Confirm master password: [hidden input]
✅ Vault created successfully!

$ python password_vault.py add github.com myusername MySecurePass123!
Enter master password: [hidden input]
✅ Password added for github.com

$ python password_vault.py list
Enter master password: [hidden input]
📋 Stored passwords:
   • github.com (myusername)
   • gmail.com (user@email.com)
   • banking.com (account123)

$ python password_vault.py get github.com
Enter master password: [hidden input]
🔑 github.com credentials:
   Username: myusername
   Password: MySecurePass123!

$ python password_vault.py update github.com NewEvenBetterPass456!
Enter master password: [hidden input]
✅ Password updated for github.com
```

## 📊 Grading Rubric (100 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|---------|
| **Key Derivation** | 20% | 20 points |
| **Encryption/Decryption** | 20% | 20 points |
| **File Operations** | 20% | 20 points |
| **CLI Interface** | 20% | 20 points |
| **Security Practices** | 10% | 10 points |
| **Code Quality** | 10% | 10 points |

### 5-Point Scale Criteria

**Key Derivation (20 points)**
- **Excellent (5)**: Perfect PBKDF2 implementation, proper salt handling, secure parameters
- **Proficient (4)**: Good PBKDF2 usage, minor parameter issues
- **Developing (3)**: Basic key derivation, some security concerns
- **Needs Improvement (2)**: Weak key derivation, significant issues
- **Inadequate (1)**: No proper key derivation or major security flaws
- **No Submission (0)**: Missing or no attempt

**Encryption/Decryption (20 points)**
- **Excellent (5)**: Perfect Fernet usage, comprehensive error handling
- **Proficient (4)**: Good encryption implementation, adequate error handling
- **Developing (3)**: Basic encryption works, limited error handling
- **Needs Improvement (2)**: Encryption issues, poor error handling
- **Inadequate (1)**: Major encryption problems or doesn't work
- **No Submission (0)**: Missing or no attempt

**File Operations (20 points)**
- **Excellent (5)**: Atomic writes, corruption handling, perfect file management
- **Proficient (4)**: Good file operations, minor issues
- **Developing (3)**: Basic file handling, some edge cases missed
- **Needs Improvement (2)**: File operations work but with significant issues
- **Inadequate (1)**: Poor file handling, data loss potential
- **No Submission (0)**: Missing or no attempt

**CLI Interface (20 points)**
- **Excellent (5)**: All commands work perfectly, excellent user experience
- **Proficient (4)**: Most commands work well, good usability
- **Developing (3)**: Basic commands work, adequate interface
- **Needs Improvement (2)**: Some commands work, poor usability
- **Inadequate (1)**: Major interface problems, commands don't work
- **No Submission (0)**: Missing or no attempt

**Security Practices (10 points)**
- **Excellent (5)**: Comprehensive input validation, memory cleanup, secure practices
- **Proficient (4)**: Good security practices, minor issues
- **Developing (3)**: Basic security considerations
- **Needs Improvement (2)**: Limited security practices
- **Inadequate (1)**: Poor or no security considerations
- **No Submission (0)**: Missing or no attempt

**Code Quality (10 points)**
- **Excellent (5)**: Clean structure, comprehensive comments, best practices
- **Proficient (4)**: Good structure, adequate documentation
- **Developing (3)**: Basic organization, minimal comments
- **Needs Improvement (2)**: Poor structure, limited documentation
- **Inadequate (1)**: Very poor code quality, no documentation
- **No Submission (0)**: Missing or no attempt

### Grade Scale
- **90-100 points (A)**: Exceptional work, professional quality
- **80-89 points (B)**: Good work, minor issues
- **70-79 points (C)**: Satisfactory, meets basic requirements
- **60-69 points (D)**: Below expectations, significant issues
- **Below 60 points (F)**: Unsatisfactory, major problems

## 🚀 Optional Professional Extensions

*All extensions are optional and for learning enrichment - no bonus points awarded to maintain equal grading.*

### **Professional Development Opportunities**

#### 1. Password Generator
Enhance your vault with secure password generation:
```python
def generate_password(length=16, include_symbols=True):
    """Generate a cryptographically secure password"""
    # Use os.urandom() or secrets module
    # Include uppercase, lowercase, digits, symbols
    # Return strong password
```

#### 2. Backup and Export
Add enterprise-level backup functionality:
```python
def export_vault(export_format='json'):
    """Export vault to encrypted backup file"""
    # Create timestamped backup
    # Encrypt with same or different key
    # Store in secure format
```

#### 3. Multiple Vault Support
Professional vault management:
```python
def switch_vault(vault_name):
    """Switch between different vault files"""
    # Support work.vault, personal.vault, etc.
    # Each with its own master password
```

### **Industry-Standard Features**

#### 4. Enterprise Key Management
Learn real-world key handling practices:
```python
class EnterpriseKeyManager:
    def key_rotation(self, old_key, new_key):
        """Safely rotate encryption keys without data loss"""
        # Requirements: decrypt with old, re-encrypt with new
        # Maintain key version history
        # Support gradual migration
        pass
    
    def hsm_integration(self):
        """Hardware Security Module integration"""
        # Simulate HSM key storage and retrieval
        # Implement key attestation
        pass
```

#### 5. Security Audit & Compliance  
Professional security analysis:
```python
def security_audit(self):
    """Generate security audit report"""
    # Check password strength across all entries
    # Identify reused passwords
    # Compliance checks (NIST 800-63B)
    # Generate risk assessment report
    pass

def gdpr_compliance(self):
    """GDPR/privacy compliance features"""
    # Data export (right to portability)
    # Secure deletion (right to erasure)
    # Consent tracking for data processing
    pass
```

#### 6. Threat Modeling Integration
Complete STRIDE analysis with countermeasures:
- **Spoofing**: Multi-factor authentication implementation
- **Tampering**: Digital signatures for vault integrity
- **Repudiation**: Cryptographic audit logs  
- **Information Disclosure**: Memory protection and secure deletion
- **Denial of Service**: Rate limiting and backup systems
- **Elevation of Privilege**: Principle of least privilege enforcement

### **Professional Growth & Networking**

#### 7. Industry Contributions & Recognition
Build your professional portfolio:
- **Technical blog post** (1000+ words) published on Medium/dev.to about your implementation choices
- **Open source contribution** to cryptography libraries with accepted PR
- **Conference presentation** proposal for student cybersecurity research conferences
- **Comparative analysis** paper benchmarking 5+ commercial password managers

### **Why Pursue These Extensions?**
- **Portfolio building**: Demonstrate advanced skills to future employers
- **Industry connections**: Network with security professionals through contributions
- **Certification preparation**: Many concepts align with CompTIA Security+, CISSP
- **Real-world experience**: Learn the same tools and techniques used in enterprise environments
- **Personal growth**: Deepen your understanding of cryptographic implementations

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **All required features implemented and tested**
- [ ] **Code runs without errors on fresh environment**
- [ ] **README.txt explains usage and design decisions**
- [ ] **Master password protection works correctly**
- [ ] **File encryption/decryption functions properly**
- [ ] **Error handling covers edge cases**
- [ ] **Code is well-commented and organized**
- [ ] **No hardcoded passwords or keys in source**

### Testing Your Submission
```bash
# Test basic workflow
python password_vault.py init
python password_vault.py add test.com user pass123
python password_vault.py list
python password_vault.py get test.com

# Test error cases
python password_vault.py get nonexistent.com
# (try wrong master password)
# (delete vault file and try to access)
```

## 📚 Resources and References

### Documentation
- **Cryptography library**: https://cryptography.io/en/latest/
- **PBKDF2 specification**: https://tools.ietf.org/html/rfc2898
- **Python argparse**: https://docs.python.org/3/library/argparse.html

### Security Guidelines
- **OWASP Password Storage**: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- **NIST Digital Identity Guidelines**: https://pages.nist.gov/800-63-3/sp800-63b.html

### Example Code Structure
```python
import argparse
import getpass
import sys
from pathlib import Path

class PasswordVault:
    def __init__(self, vault_file="passwords.vault"):
        self.vault_file = vault_file
        # Initialize other attributes
    
    def _derive_key(self, master_password, salt):
        """Private method for key derivation"""
        pass
    
    def _load_vault(self, master_password):
        """Private method to load and decrypt vault"""
        pass
    
    def _save_vault(self, master_password, data):
        """Private method to encrypt and save vault"""
        pass
    
    # Public methods for CLI commands
    def init_vault(self, master_password):
        pass
    
    def add_password(self, website, username, password, master_password):
        pass
    
    # ... other methods

def main():
    parser = argparse.ArgumentParser(description="Secure Password Vault")
    # Set up command-line arguments
    # Handle different commands
    pass

if __name__ == "__main__":
    main()
```

## ❓ Frequently Asked Questions

**Q: Can I use additional Python packages?**  
A: Stick to the cryptography library and Python standard library. If you need additional packages, list them in requirements.txt and justify their use in README.txt.

**Q: How should I handle the master password input?**  
A: Use `getpass.getpass()` for hidden password input. Never store the master password in memory longer than necessary.

**Q: What if the vault file gets corrupted?**  
A: Detect corruption (failed decryption, malformed data) and provide a clear error message. Consider implementing a backup/recovery feature for bonus points.

**Q: Should passwords be visible when retrieved?**  
A: Yes, the purpose is to retrieve passwords for use. However, consider security implications and maybe offer a "copy to clipboard" option.

**Q: How complex should the CLI be?**  
A: Focus on functionality over fancy features. A simple, reliable interface is better than a complex, buggy one.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Would I trust this program with my real passwords?**
2. **Does it handle all error cases gracefully?**
3. **Is the code clear and well-organized?**
4. **Have I tested it thoroughly on different scenarios?**
5. **Does it follow security best practices learned in the tutorial?**

---

**Need Help?**
- Review the tutorial materials
- Check Canvas discussions for common issues
- Attend office hours for debugging help
- Use the validation script to check your work

**Good luck!** This assignment will give you hands-on experience with real-world cryptographic applications.