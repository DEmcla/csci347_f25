# Week 1 Assignment: Password Vault

**Student**: [Your Name - CSCI347_f25]  
**Assignment**: Secure Password Vault Implementation

## Usage Instructions

### Setup
```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install cryptography
```

### Running the Password Vault
```bash
# Initialize vault
python password_vault.py init

# Add a password
python password_vault.py add github.com myusername mypassword

# Retrieve a password
python password_vault.py get github.com

# List all stored services
python password_vault.py list
```

## Implementation Overview

### Key Security Features
- **Master password protection** using PBKDF2 with 100,000 iterations
- **AES encryption** via Fernet for stored passwords
- **Random salt generation** for each vault
- **Secure file handling** with atomic operations

### Design Decisions

**Key Derivation**:
- Chosen PBKDF2 with SHA-256 for industry-standard password-based key derivation
- 100,000 iterations balances security vs performance
- 16-byte random salt prevents rainbow table attacks

**Storage Format**:
- JSON format for human-readable structure
- Base64 encoding for binary data compatibility
- Salt stored with encrypted data for portability

**Error Handling**:
- Graceful handling of incorrect master passwords
- Clear error messages without revealing sensitive information
- Validation of input parameters

### Testing

Run the test suite:
```bash
python -m pytest tests/
```

### Examples

See the `examples/` directory for:
- Basic usage demonstration
- Error handling examples
- Performance benchmarks

## Challenges Encountered

[Describe any specific challenges you faced and how you solved them]

## Optional Extensions Implemented

[List any optional features you added, such as password generation, backup functionality, etc.]

---

**Submission**: This assignment is submitted via Pull Request as part of the professional development workflow.