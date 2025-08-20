# Week 3 Assignment: Enterprise Certificate Authority System

**Due**: End of Week 3 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Build a complete Certificate Authority (CA) system that can issue, validate, and revoke digital certificates. Your implementation should demonstrate mastery of PKI concepts, X.509 certificate handling, and certificate lifecycle management learned this week.

## 📋 Requirements

### Core Functionality (70 points)

Your CA system must implement these features:

#### 1. Root Certificate Authority Setup (20 points)
- **Self-signed root CA certificate** generation
- **RSA key pair generation** (minimum 2048 bits)
- **Proper certificate fields** (subject, issuer, validity period, extensions)
- **Certificate storage** in PEM format

#### 2. Certificate Signing Request (CSR) Processing (25 points)
- **CSR generation** for client certificates
- **CSR validation** and parsing
- **Certificate issuance** signed by root CA
- **Serial number tracking** to prevent duplicates

#### 3. Certificate Validation System (25 points)
- **Certificate chain verification** up to root CA
- **Expiration date checking**
- **Digital signature validation**
- **Certificate revocation list (CRL)** support

### Command-Line Interface (20 points)

Implement a user-friendly CLI with these commands:

```bash
# Initialize CA (create root certificate)
python ca_system.py init --ca-name "MyCompany CA"

# Generate CSR for client
python ca_system.py create-csr --name "client.example.com" --email "admin@example.com"

# Sign CSR and issue certificate
python ca_system.py sign-csr --csr-file client.csr --days 365

# Validate certificate
python ca_system.py validate --cert-file client.crt

# Revoke certificate
python ca_system.py revoke --cert-file client.crt --reason "keyCompromise"

# List all issued certificates
python ca_system.py list-certs
```

### Security Features (10 points)

- **Private key protection** with strong file permissions
- **Certificate serial number randomization**
- **Proper certificate extensions** (Key Usage, Extended Key Usage)
- **Secure revocation tracking**

## 🔧 Technical Specifications

### Required Libraries
```python
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import datetime
import os
import sys
import argparse
import json
```

### File Structure
```
ca_system.py              # Main implementation
ca_database.json          # Certificate tracking database
ca_private_key.pem        # CA private key (secure permissions)
ca_certificate.pem        # CA public certificate
crl.pem                   # Certificate Revocation List
README.txt                # Usage instructions and design notes
```

### Certificate Database Format
Design a JSON-based database to track issued certificates:
```json
{
  "serial_numbers": ["1234567890", "1234567891"],
  "issued_certificates": [
    {
      "serial_number": "1234567890",
      "subject": "CN=client.example.com,O=Example Corp",
      "issued_date": "2024-01-15T10:30:00",
      "expiry_date": "2025-01-15T10:30:00",
      "status": "active",
      "revocation_date": null,
      "revocation_reason": null
    }
  ]
}
```

## 📝 Detailed Requirements

### 1. CA Initialization
```python
def init_ca(ca_name, key_size=2048, validity_years=10):
    """
    Initialize Certificate Authority
    
    Args:
        ca_name (str): Name for the CA certificate
        key_size (int): RSA key size (default 2048)
        validity_years (int): CA certificate validity period
        
    Returns:
        bool: True if successful, False otherwise
    """
    # Generate RSA private key
    # Create self-signed root certificate
    # Set proper certificate extensions
    # Save private key and certificate securely
```

### 2. CSR Generation and Processing
```python
def create_csr(common_name, organization, email, key_size=2048):
    """
    Generate Certificate Signing Request
    
    Args:
        common_name (str): Subject common name
        organization (str): Organization name
        email (str): Contact email
        key_size (int): RSA key size
        
    Returns:
        tuple: (private_key, csr) objects
    """
    # Generate private key for client
    # Create CSR with proper subject information
    # Add relevant extensions
    # Return both private key and CSR

def sign_csr(csr_file, ca_cert, ca_private_key, validity_days=365):
    """
    Sign CSR and issue certificate
    
    Args:
        csr_file (str): Path to CSR file
        ca_cert: CA certificate object
        ca_private_key: CA private key object
        validity_days (int): Certificate validity period
        
    Returns:
        x509.Certificate: Issued certificate
    """
    # Load and validate CSR
    # Generate unique serial number
    # Create certificate with proper extensions
    # Sign with CA private key
    # Update certificate database
```

### 3. Certificate Validation
```python
def validate_certificate(cert_file, ca_cert):
    """
    Validate certificate against CA
    
    Args:
        cert_file (str): Path to certificate file
        ca_cert: CA certificate object
        
    Returns:
        dict: Validation results with details
    """
    # Load certificate from file
    # Verify signature against CA
    # Check expiration dates
    # Verify certificate chain
    # Check revocation status
    # Return comprehensive validation report
```

## 💻 Example Usage

```bash
$ python ca_system.py init --ca-name "CSCI347 Training CA"
🔐 Generating CA private key (2048 bits)...
📜 Creating root certificate...
✅ Certificate Authority initialized successfully!
   CA Certificate: ca_certificate.pem
   Private Key: ca_private_key.pem (keep secure!)

$ python ca_system.py create-csr --name "student.lab.local" --email "student@university.edu"
🔑 Generating client private key...
📝 Creating certificate signing request...
✅ CSR created successfully!
   Private Key: student.lab.local_private.pem
   CSR File: student.lab.local.csr

$ python ca_system.py sign-csr --csr-file student.lab.local.csr --days 180
📋 Processing certificate signing request...
🔍 Validating CSR contents...
🏷️  Assigning serial number: 1847293856
✅ Certificate issued successfully!
   Certificate: student.lab.local.crt
   Valid until: 2024-07-13 15:42:33

$ python ca_system.py validate --cert-file student.lab.local.crt
🔍 Validating certificate...
✅ Certificate Validation Results:
   Serial Number: 1847293856
   Subject: CN=student.lab.local,O=University Lab,emailAddress=student@university.edu
   Issuer: CN=CSCI347 Training CA
   Valid From: 2024-01-15 15:42:33
   Valid Until: 2024-07-13 15:42:33
   Status: VALID ✅
   Signature: VERIFIED ✅
   Chain: TRUSTED ✅
   Revocation: NOT REVOKED ✅

$ python ca_system.py list-certs
📋 Issued Certificates:
┌─────────────┬──────────────────────┬─────────────┬─────────────────────┬──────────┐
│ Serial      │ Subject              │ Status      │ Expiry Date         │ Days Left│
├─────────────┼──────────────────────┼─────────────┼─────────────────────┼──────────┤
│ 1847293856  │ student.lab.local    │ Active      │ 2024-07-13 15:42:33 │ 179      │
│ 1847293857  │ server.lab.local     │ Active      │ 2024-12-31 09:15:22 │ 351      │
│ 1847293858  │ client.example.com   │ Revoked     │ 2025-01-15 10:30:00 │ -        │
└─────────────┴──────────────────────┴─────────────┴─────────────────────┴──────────┘

$ python ca_system.py revoke --cert-file client.example.com.crt --reason "keyCompromise"
⚠️  Revoking certificate...
🔍 Certificate Serial: 1847293858
📅 Revocation Date: 2024-01-16 14:25:10
🚨 Reason: Key Compromise
✅ Certificate revoked successfully!
   Updated CRL: crl.pem
```

## 📊 Grading Rubric (100 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|---------|
| **CA Initialization** | 20% | 20 points |
| **CSR Processing** | 25% | 25 points |
| **Certificate Validation** | 25% | 25 points |
| **CLI Interface** | 20% | 20 points |
| **Security Practices** | 10% | 10 points |

### 5-Point Scale Criteria

**CA Initialization (20 points)**
- **Excellent (20)**: Perfect root CA creation, proper key generation, secure storage
- **Proficient (16)**: Good CA setup, minor configuration issues
- **Developing (12)**: Basic CA functionality, some security concerns
- **Needs Improvement (8)**: CA works but significant security issues
- **Inadequate (4)**: Major CA problems or doesn't work properly
- **No Submission (0)**: Missing or no attempt

**CSR Processing (25 points)**
- **Excellent (25)**: Perfect CSR generation/signing, proper extensions, serial tracking
- **Proficient (20)**: Good CSR handling, minor issues with extensions
- **Developing (15)**: Basic CSR processing, limited extension support
- **Needs Improvement (10)**: CSR processing works but with significant issues
- **Inadequate (5)**: Poor CSR handling, major functionality problems
- **No Submission (0)**: Missing or no attempt

**Certificate Validation (25 points)**
- **Excellent (25)**: Comprehensive validation, chain verification, revocation checking
- **Proficient (20)**: Good validation logic, most security checks implemented
- **Developing (15)**: Basic validation, some security checks missing
- **Needs Improvement (10)**: Limited validation, security gaps
- **Inadequate (5)**: Poor validation, major security vulnerabilities
- **No Submission (0)**: Missing or no attempt

**CLI Interface (20 points)**
- **Excellent (20)**: All commands work perfectly, excellent user experience
- **Proficient (16)**: Most commands work well, good usability
- **Developing (12)**: Basic commands functional, adequate interface
- **Needs Improvement (8)**: Some commands work, poor usability
- **Inadequate (4)**: Major interface problems, commands fail
- **No Submission (0)**: Missing or no attempt

**Security Practices (10 points)**
- **Excellent (10)**: Comprehensive security implementation, proper key protection
- **Proficient (8)**: Good security practices, minor vulnerabilities
- **Developing (6)**: Basic security considerations
- **Needs Improvement (4)**: Limited security practices
- **Inadequate (2)**: Poor or no security considerations
- **No Submission (0)**: Missing or no attempt

### Grade Scale
- **90-100 points (A)**: Professional-quality CA system
- **80-89 points (B)**: Good implementation, minor issues
- **70-79 points (C)**: Satisfactory, meets basic requirements
- **60-69 points (D)**: Below expectations, significant issues
- **Below 60 points (F)**: Unsatisfactory, major problems

## 🚀 Bonus Opportunities (+5 points each)

### 1. OCSP Responder
Implement Online Certificate Status Protocol:
```python
def create_ocsp_response(cert_serial, ca_cert, ca_private_key):
    """Create OCSP response for certificate status"""
    # Generate OCSP response
    # Include certificate status and signature
```

### 2. Certificate Transparency Log
Add basic CT log functionality:
```python
def add_to_ct_log(certificate):
    """Add certificate to transparency log"""
    # Create log entry with timestamp
    # Generate Merkle tree proof
```

### 3. Hardware Security Module Simulation
Simulate HSM for private key operations:
```python
class HSMSimulator:
    """Simulate hardware-based key operations"""
    def sign_certificate(self, cert_data):
        # Simulate hardware signing process
        # Add additional security validations
```

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **CA initialization creates proper root certificate**
- [ ] **CSR generation and signing workflow functions correctly**
- [ ] **Certificate validation performs all security checks**
- [ ] **All CLI commands work without errors**
- [ ] **Private keys are properly protected (file permissions)**
- [ ] **Certificate database tracks all issued certificates**
- [ ] **Revocation functionality updates CRL properly**
- [ ] **Code handles error conditions gracefully**
- [ ] **README.txt explains usage and security considerations**

### Testing Your CA System
```bash
# Complete workflow test
python ca_system.py init --ca-name "Test CA"
python ca_system.py create-csr --name "test.example.com" --email "test@example.com"
python ca_system.py sign-csr --csr-file test.example.com.csr --days 30
python ca_system.py validate --cert-file test.example.com.crt
python ca_system.py list-certs
python ca_system.py revoke --cert-file test.example.com.crt --reason "cessationOfOperation"

# Error handling tests
python ca_system.py validate --cert-file nonexistent.crt
python ca_system.py sign-csr --csr-file invalid.csr
```

## 📚 Resources and References

### Documentation
- **Cryptography library X.509**: https://cryptography.io/en/latest/x509/
- **RFC 5280 - X.509 Certificate Profile**: https://tools.ietf.org/html/rfc5280
- **RFC 3280 - Certificate Path Validation**: https://tools.ietf.org/html/rfc3280

### Security Guidelines
- **NIST SP 800-57 - Key Management**: https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final
- **CA/Browser Forum Requirements**: https://cabforum.org/baseline-requirements/

### Example Implementation Structure
```python
import argparse
import json
import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class CertificateAuthority:
    def __init__(self, ca_dir="./ca_data"):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(exist_ok=True)
        self.db_file = self.ca_dir / "ca_database.json"
        self.ca_cert_file = self.ca_dir / "ca_certificate.pem"
        self.ca_key_file = self.ca_dir / "ca_private_key.pem"
        
    def init_ca(self, ca_name, key_size=2048, validity_years=10):
        """Initialize Certificate Authority"""
        pass
    
    def load_ca_credentials(self):
        """Load CA certificate and private key"""
        pass
    
    def create_csr(self, common_name, organization, email, key_size=2048):
        """Generate Certificate Signing Request"""
        pass
    
    def sign_csr(self, csr_file, validity_days=365):
        """Sign CSR and issue certificate"""
        pass
    
    def validate_certificate(self, cert_file):
        """Validate certificate against CA"""
        pass
    
    def revoke_certificate(self, cert_file, reason):
        """Revoke certificate and update CRL"""
        pass
    
    def list_certificates(self):
        """List all issued certificates"""
        pass
    
    def _load_database(self):
        """Load certificate database"""
        pass
    
    def _save_database(self, data):
        """Save certificate database"""
        pass
    
    def _generate_serial_number(self):
        """Generate unique serial number"""
        pass

def main():
    parser = argparse.ArgumentParser(description="Certificate Authority System")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add subcommands for each CA operation
    init_parser = subparsers.add_parser('init', help='Initialize CA')
    csr_parser = subparsers.add_parser('create-csr', help='Create CSR')
    sign_parser = subparsers.add_parser('sign-csr', help='Sign CSR')
    # ... add other subparsers
    
    args = parser.parse_args()
    ca = CertificateAuthority()
    
    # Handle different commands
    if args.command == 'init':
        ca.init_ca(args.ca_name)
    # ... handle other commands

if __name__ == "__main__":
    main()
```

## ❓ Frequently Asked Questions

**Q: How should I store the CA private key securely?**  
A: Set restrictive file permissions (600) and consider the key as highly sensitive. In production, it would be stored in an HSM.

**Q: What certificate extensions should I include?**  
A: Include Key Usage, Extended Key Usage, Subject Alternative Name, and Authority Key Identifier extensions as appropriate.

**Q: How do I handle certificate serial number collisions?**  
A: Use cryptographically random serial numbers and track all issued serials in your database to prevent duplicates.

**Q: Should certificates be visible in plain text when listed?**  
A: Yes, displaying certificate details helps with administration, but be mindful of sensitive information.

**Q: How complex should the revocation system be?**  
A: Implement basic CRL generation. OCSP is bonus material due to complexity.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Would I trust this CA system in a production environment?**
2. **Does it properly validate all certificate fields and signatures?**
3. **Are private keys adequately protected?**
4. **Does the revocation system work correctly?**
5. **Have I tested all error conditions and edge cases?**

---

**Need Help?**
- Review the PKI tutorial materials
- Check Canvas discussions for common implementation issues
- Attend office hours for debugging assistance
- Use the certificate validation tools to verify your work

**Good luck!** This assignment will give you practical experience with real-world PKI systems used in enterprise security.