# Week 2 Assignment: Secure Document Signing System

**Due**: End of Week 2 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Build a command-line document signing and verification system that uses digital signatures to ensure document authenticity and integrity. Your implementation should demonstrate proper use of hashing, digital signatures, and file integrity monitoring techniques learned this week.

## 📋 Requirements

### Core Functionality (70 points)

Your document signing system must implement these features:

#### 1. Key Management (20 points)
- **Generate RSA key pairs** (2048-bit minimum)
- **Save keys securely** to PEM files
- **Load existing keys** from files
- **Password-protect private keys** (optional encryption)

#### 2. Document Signing Operations (25 points)
- **Sign documents**: `sign_document(filepath, private_key)`
- **Verify signatures**: `verify_document(filepath, signature, public_key)`
- **Batch signing**: Sign multiple documents at once
- **Signature metadata**: Include timestamp, signer info

#### 3. Integrity Monitoring (25 points)
- **Hash verification** before and after signing
- **Tamper detection** for signed documents
- **Signature database** tracking all signed documents
- **Change detection** reporting modifications

### Command-Line Interface (20 points)

Implement a user-friendly CLI with these commands:

```bash
# Generate new key pair
python doc_signer.py generate-keys --name "John Doe"

# Sign a document
python doc_signer.py sign <document> --key private.pem

# Verify a signature
python doc_signer.py verify <document> <signature> --key public.pem

# Check document integrity
python doc_signer.py check <document>

# List all signed documents
python doc_signer.py list-signed
```

### Security Features (10 points)

- **Secure key storage** with proper permissions
- **Timestamp inclusion** to prevent replay attacks
- **Certificate chain support** (bonus)
- **Audit logging** of all operations

## 🔧 Technical Specifications

### Required Libraries
```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from pathlib import Path
```

### File Structure
```
doc_signer.py              # Main implementation
signature_db.json          # Database of signed documents
keys/                      # Directory for key storage
  ├── private_key.pem
  └── public_key.pem
signatures/                # Directory for signature files
  └── document.sig
README.txt                 # Usage instructions and design notes
requirements.txt           # Dependencies
```

### Data Format

Design your signature format to include:
- Document hash (SHA-256)
- Digital signature
- Timestamp
- Signer identity
- Algorithm used

## 📝 Detailed Requirements

### 1. Key Generation and Management
```python
class KeyManager:
    def generate_key_pair(self, key_size=2048):
        """
        Generate RSA key pair
        
        Args:
            key_size (int): Key size in bits
            
        Returns:
            tuple: (private_key, public_key)
        """
        # Generate RSA key pair
        # Return both keys
    
    def save_keys(self, private_key, public_key, password=None):
        """
        Save keys to PEM files
        
        Args:
            private_key: RSA private key object
            public_key: RSA public key object
            password (str): Optional password for private key
        """
        # Save with appropriate encryption
        # Set secure file permissions
    
    def load_private_key(self, filepath, password=None):
        """Load private key from PEM file"""
        # Load and decrypt if necessary
        # Handle errors gracefully
```

### 2. Document Signing
```python
class DocumentSigner:
    def sign_document(self, document_path, private_key):
        """
        Sign a document with private key
        
        Args:
            document_path (str): Path to document
            private_key: RSA private key
            
        Returns:
            dict: Signature package with metadata
        """
        # Calculate document hash
        # Create signature
        # Add metadata (timestamp, etc.)
        # Save to signature file
    
    def verify_signature(self, document_path, signature_path, public_key):
        """
        Verify document signature
        
        Args:
            document_path (str): Path to document
            signature_path (str): Path to signature file
            public_key: RSA public key
            
        Returns:
            dict: Verification result with details
        """
        # Load signature package
        # Verify document hash matches
        # Verify signature with public key
        # Check timestamp validity
```

### 3. Integrity Monitoring
```python
class IntegrityMonitor:
    def __init__(self, database_file="signature_db.json"):
        self.database_file = database_file
        self.database = self.load_database()
    
    def add_signed_document(self, document_path, signature_info):
        """Track signed document in database"""
        # Store document hash
        # Store signature metadata
        # Record signing time
    
    def check_document_integrity(self, document_path):
        """Check if document has been modified since signing"""
        # Calculate current hash
        # Compare with stored hash
        # Report any changes
    
    def generate_audit_report(self):
        """Generate report of all signed documents"""
        # List all signed documents
        # Show verification status
        # Highlight any issues
```

### 4. Complete Implementation Example

```python
import argparse
from pathlib import Path
import json

class SecureDocumentSigner:
    def __init__(self):
        self.key_manager = KeyManager()
        self.signer = DocumentSigner()
        self.monitor = IntegrityMonitor()
    
    def run_cli(self):
        parser = argparse.ArgumentParser(description="Secure Document Signing System")
        subparsers = parser.add_subparsers(dest='command', help='Commands')
        
        # Generate keys command
        gen_parser = subparsers.add_parser('generate-keys', help='Generate new key pair')
        gen_parser.add_argument('--name', required=True, help='Signer name')
        gen_parser.add_argument('--password', help='Password for private key')
        
        # Sign command
        sign_parser = subparsers.add_parser('sign', help='Sign a document')
        sign_parser.add_argument('document', help='Document to sign')
        sign_parser.add_argument('--key', required=True, help='Private key file')
        
        # Verify command
        verify_parser = subparsers.add_parser('verify', help='Verify signature')
        verify_parser.add_argument('document', help='Document to verify')
        verify_parser.add_argument('signature', help='Signature file')
        verify_parser.add_argument('--key', required=True, help='Public key file')
        
        # Parse and execute
        args = parser.parse_args()
        
        if args.command == 'generate-keys':
            self.generate_keys(args.name, args.password)
        elif args.command == 'sign':
            self.sign_document(args.document, args.key)
        elif args.command == 'verify':
            self.verify_document(args.document, args.signature, args.key)
        else:
            parser.print_help()
    
    def generate_keys(self, name, password=None):
        """Generate and save key pair"""
        print(f"🔑 Generating keys for {name}...")
        # Implementation here
    
    def sign_document(self, document_path, key_path):
        """Sign a document"""
        print(f"✍️ Signing {document_path}...")
        # Implementation here
    
    def verify_document(self, document_path, signature_path, key_path):
        """Verify document signature"""
        print(f"🔍 Verifying {document_path}...")
        # Implementation here

if __name__ == "__main__":
    signer = SecureDocumentSigner()
    signer.run_cli()
```

## 💻 Example Usage

```bash
$ python doc_signer.py generate-keys --name "Alice Johnson"
🔑 Generating keys for Alice Johnson...
✅ Keys generated and saved to keys/
   Private key: keys/private_key.pem
   Public key: keys/public_key.pem

$ python doc_signer.py sign contract.pdf --key keys/private_key.pem
✍️ Signing contract.pdf...
📄 Document hash: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c
✅ Document signed successfully
   Signature saved to: signatures/contract.pdf.sig

$ python doc_signer.py verify contract.pdf signatures/contract.pdf.sig --key keys/public_key.pem
🔍 Verifying contract.pdf...
✅ Signature valid!
   Signer: Alice Johnson
   Signed at: 2024-01-15 14:30:22
   Document integrity: Intact

$ python doc_signer.py check contract.pdf
📊 Integrity Check for contract.pdf
   Status: ✅ Unmodified since signing
   Original hash: 3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c
   Current hash:  3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c
   Last verified: 2024-01-15 14:35:00
```

## 📊 Grading Rubric (100 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|---------|
| **Key Management** | 20% | 20 points |
| **Document Signing** | 25% | 25 points |
| **Signature Verification** | 25% | 25 points |
| **Integrity Monitoring** | 10% | 10 points |
| **CLI Interface** | 10% | 10 points |
| **Code Quality** | 10% | 10 points |

### Detailed Rubric

**Key Management (20 points)**
- Excellent (18-20): Secure key generation, proper storage, password protection
- Good (14-17): Working key management, minor security issues
- Satisfactory (10-13): Basic key operations work
- Needs Improvement (0-9): Major issues with key handling

**Document Signing (25 points)**
- Excellent (23-25): Perfect signing, metadata included, batch support
- Good (18-22): Good signing functionality, most features work
- Satisfactory (13-17): Basic signing works
- Needs Improvement (0-12): Signing has significant issues

**Signature Verification (25 points)**
- Excellent (23-25): Comprehensive verification, tamper detection, clear reporting
- Good (18-22): Good verification, handles most cases
- Satisfactory (13-17): Basic verification works
- Needs Improvement (0-12): Verification problems

**Integrity Monitoring (10 points)**
- Excellent (9-10): Complete tracking, change detection, audit reports
- Good (7-8): Good monitoring, minor features missing
- Satisfactory (5-6): Basic monitoring works
- Needs Improvement (0-4): Limited or broken monitoring

**CLI Interface (10 points)**
- Excellent (9-10): All commands work, excellent UX, helpful output
- Good (7-8): Most commands work, good usability
- Satisfactory (5-6): Basic commands functional
- Needs Improvement (0-4): Poor interface, commands don't work

**Code Quality (10 points)**
- Excellent (9-10): Clean, well-documented, follows best practices
- Good (7-8): Good structure, adequate documentation
- Satisfactory (5-6): Acceptable code quality
- Needs Improvement (0-4): Poor code quality, no documentation

## 🚀 Bonus Opportunities (+10 points each)

### 1. Multi-Signature Support
Allow documents to require multiple signatures:
```python
def add_signature(self, document, signature, signer_name):
    """Add additional signature to document"""
    # Support documents with multiple signers
    # Track all signatures
    # Verify threshold signatures
```

### 2. Certificate Chain Validation
Implement basic PKI features:
```python
def validate_certificate_chain(self, certificate):
    """Validate certificate against trusted roots"""
    # Check certificate validity
    # Verify chain of trust
    # Handle revocation (basic)
```

### 3. Blockchain-Style Audit Log
Create tamper-evident audit log:
```python
def create_audit_chain(self):
    """Create blockchain-style audit log"""
    # Chain audit entries with hashes
    # Detect any tampering in log
    # Provide cryptographic proof of order
```

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **Key generation works correctly**
- [ ] **Documents can be signed and verified**
- [ ] **Tampered documents are detected**
- [ ] **Integrity monitoring tracks all operations**
- [ ] **CLI provides all required commands**
- [ ] **Error handling covers edge cases**
- [ ] **Code is well-commented and organized**
- [ ] **README.txt explains usage and design**

### Testing Your Submission
```bash
# Test key generation
python doc_signer.py generate-keys --name "Test User"

# Test signing
echo "Test document content" > test.txt
python doc_signer.py sign test.txt --key keys/private_key.pem

# Test verification
python doc_signer.py verify test.txt signatures/test.txt.sig --key keys/public_key.pem

# Test tampering detection
echo "Modified content" > test.txt
python doc_signer.py verify test.txt signatures/test.txt.sig --key keys/public_key.pem
# Should report verification failure

# Test integrity monitoring
python doc_signer.py check test.txt
python doc_signer.py list-signed
```

## 📚 Resources and References

### Documentation
- **Cryptography library**: https://cryptography.io/en/latest/
- **Digital signatures**: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
- **Python argparse**: https://docs.python.org/3/library/argparse.html

### Security Guidelines
- **NIST Digital Signature Standard**: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf
- **PKI Best Practices**: https://www.keyfactor.com/resources/pki-best-practices/

## ❓ Frequently Asked Questions

**Q: Should I use RSA or ECDSA for signatures?**  
A: Use RSA for this assignment (it's in the tutorial), but ECDSA is also acceptable if you prefer.

**Q: How should I format the signature file?**  
A: Use JSON to store the signature, hash, timestamp, and metadata. This makes it easy to parse and verify.

**Q: Do I need to implement certificate validation?**  
A: No, that's a bonus feature. Focus on basic signature creation and verification first.

**Q: Should signatures be attached to documents or separate?**  
A: Keep them separate for this assignment. Real systems might embed them (like PDF signatures).

**Q: How do I handle large files efficiently?**  
A: Read and hash files in chunks (see tutorial example) rather than loading entire file into memory.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Can my system detect if someone modifies a signed document?**
2. **Are private keys properly protected?**
3. **Does verification clearly report success or failure?**
4. **Is my audit log tamper-evident?**
5. **Would this system work for real document signing needs?**

---

**Need Help?**
- Review the tutorial materials
- Check Canvas discussions for common issues
- Attend office hours for debugging help

**Good luck!** This assignment will give you practical experience with digital signatures and document integrity.