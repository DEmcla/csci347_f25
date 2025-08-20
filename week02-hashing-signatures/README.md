# Week 2: Hashing and Digital Signatures

**Time Commitment**: 7-8 hours total  
**Prerequisites**: Week 1 completed, understanding of symmetric encryption

## 🎯 Learning Objectives

By the end of this week, you will be able to:

1. **Implement** secure hashing with SHA-256 and other algorithms
2. **Create and verify** Hash-based Message Authentication Codes (HMAC)
3. **Generate and verify** digital signatures using RSA and ECDSA
4. **Apply** proper password hashing with salt and iterations
5. **Build** a file integrity monitoring system
6. **Understand** the differences between encryption, hashing, and digital signatures

## 📚 This Week's Materials

### Required Reading (4 hours)
📖 **Complete these readings before starting the tutorial:**

1. **"Crypto 101" by Laurens Van Houtven**
   - **Link**: https://www.crypto101.io/
   - **Chapters**: 5-7 (Hash Functions, MACs, Digital Signatures)
   - **Pages**: 66-120
   - **Focus**: SHA-256, HMAC construction, RSA signatures

2. **NIST SP 800-107r1: Hash Algorithm Recommendations**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
   - **Pages**: 1-12 (Sections 1-5)
   - **Focus**: Approved hash functions, security considerations

3. **RFC 2104: HMAC Specification**
   - **Link**: https://datatracker.ietf.org/doc/html/rfc2104
   - **Focus**: HMAC construction and security properties

4. **Anderson's Security Engineering**
   - **Chapter**: 5.3 (Hash Functions and Message Authentication)
   - **Link**: https://www.cl.cam.ac.uk/~rja14/Papers/SEv3-ch5-7sep.pdf
   - **Focus**: Practical applications and attacks

### Optional Supplementary Materials (1 hour)
🎥 **For deeper understanding:**

- **Video**: "How Secure is 256 Bit Security?" - 3Blue1Brown
  - **Link**: https://www.youtube.com/watch?v=S9JGmA5_unY
  - **Length**: 20 minutes
  - **Value**: Intuitive understanding of cryptographic strength

- **Blog**: "A Few Thoughts on Cryptographic Engineering" - Matthew Green
  - **Link**: https://blog.cryptographyengineering.com/
  - **Focus**: Real-world crypto attacks and defenses

## 🔍 Conceptual Overview

### Hash Functions vs Encryption vs Digital Signatures

| Function | Purpose | Key Usage | Output |
|----------|---------|-----------|---------|
| **Hash** | Data integrity | No key | Fixed-size digest |
| **Encryption** | Confidentiality | Shared secret | Variable-size ciphertext |  
| **Digital Signature** | Authentication | Private/public key pair | Signature + original data |

### This Week's Cryptographic Primitives

1. **SHA-256**: Secure Hash Algorithm producing 256-bit digests
2. **HMAC**: Hash-based Message Authentication Code for integrity + authenticity
3. **RSA Signatures**: Public-key digital signatures for non-repudiation
4. **PBKDF2**: Password-Based Key Derivation Function for secure password storage

## 🛠️ Tutorial Overview

This week's hands-on tutorial covers:

1. **Part 1**: Basic hashing with SHA-256 (30 min)
2. **Part 2**: Secure password hashing and storage (60 min)
3. **Part 3**: Message Authentication Codes (HMAC) (45 min)
4. **Part 4**: Digital signatures with RSA (90 min)
5. **Part 5**: File integrity monitoring system (60 min)

**Tutorial Location**: [tutorial.md](tutorial.md)

## 📋 Pre-Tutorial Checklist

Before starting the tutorial, ensure you have:

- [ ] Completed all required readings
- [ ] Week 1 assignment submitted and validated
- [ ] Python environment active with required packages
- [ ] Understanding of symmetric encryption from Week 1
- [ ] **Git configured with your name and course identifier** (if not done in Week 1)

**Install additional packages**:
```bash
pip install cryptography hashlib-compat
```

**Set up Week 2 feature branch**:
```bash
# Ensure you're in your course repository and up-to-date
cd CSCI347_f25
git checkout main
git pull upstream main

# Create feature branch for Week 2 assignment  
git checkout -b week02-hashing-assignment

# Navigate to your Week 2 assignment directory
cd assignments/CSCI347_f25_Jane_Smith/week02  # Use your actual name

# Verify git configuration
git config --get user.name    # Should show "Jane Smith - CSCI347_f25"
git config --get user.email   # Should show your university email
```

**Verify your setup**:
```bash
python -c "import hashlib; print('Hash algorithms:', hashlib.algorithms_available)"
```

## 🎯 Weekly Assignment: Secure Document Signing System

**Due**: End of Week 2 (see Canvas for exact date)  
**Estimated Time**: 3-4 hours

Build a command-line document signing and verification system that:

1. **Generates RSA key pairs** for digital signatures
2. **Signs documents** with private keys
3. **Verifies signatures** using public keys
4. **Monitors document integrity** after signing
5. **Provides audit trails** for all signing operations

**Full requirements**: [assignment.md](assignment.md)

### Assignment Deliverables
- `doc_signer.py` - Main implementation
- `keys/` - Directory for key storage
- `signatures/` - Directory for signature files
- `README.txt` - Usage instructions and design decisions
- Sample signed documents and verification reports

## 📝 Weekly Quiz

**Points**: 25 points (T/F: 5pts, Multiple Choice: 10pts, Short Answer: 10pts)  
**Time Limit**: 30 minutes  
**Format**: Available in Canvas

Test your understanding of hash functions, digital signatures, HMAC, and secure password storage. Review all tutorial materials and readings before attempting.

**Quiz Topics**:
- SHA-256 and hash function properties
- HMAC construction and authentication
- Digital signatures and non-repudiation
- Password hashing with salt and PBKDF2
- File integrity monitoring concepts

**Location**: [quiz.md](quiz.md) (practice version)

## ✅ Self-Assessment

### Check Your Understanding
Answer these questions after completing the tutorial:

1. **Why can't hash functions be reversed** to find the original input?
2. **How does HMAC provide both integrity and authenticity** while hashes alone only provide integrity?
3. **What's the difference between RSA encryption and RSA signatures**?
4. **Why do we use salt when hashing passwords**?
5. **How do digital signatures provide non-repudiation**?

### Validation Script
Run the automated checker to verify your tutorial work:

```bash
python check-week2.py
```

**Expected output**: All cryptographic operations should work correctly.

## 🤝 Getting Help

### Common Issues
- **Hash collisions**: Understand theoretical vs. practical collision resistance
- **Signature verification failures**: Check key pairs match and data integrity
- **HMAC mismatches**: Ensure same key and message are used
- **Performance issues**: Large files may take time to hash

### Where to Ask Questions
1. **GitHub Issues**: Technical problems with cryptographic implementations  
2. **Canvas Discussions**: Conceptual questions about hash functions and signatures
3. **Office Hours**: Complex debugging and advanced cryptographic topics

## 📈 Learning Path

### Recommended Schedule (7-8 hours total)
```
Day 1-2: Readings + tutorial start (3-4 hours)
Day 3-4: Complete tutorial + quiz (2.5-3 hours)
Day 5-6: Document signing assignment (2-3 hours)  
Day 7: Review and submit
```

*The tutorial provides detailed implementations and explanations to reinforce the reading materials and support different learning styles.*

## 🔍 Going Deeper (Optional)

### Advanced Topics
1. **Hash-based signatures**: Merkle signatures and post-quantum security
2. **Zero-knowledge proofs**: Proving knowledge without revealing information
3. **Commitment schemes**: Using hashes for secure commitments
4. **Cryptocurrency**: How Bitcoin uses hashing and digital signatures

### Research Challenges
- **Implement a Merkle tree** for efficient batch verification
- **Create a simple blockchain** using hash chains
- **Build a timestamping service** using digital signatures
- **Analyze hash function attacks** (length extension, collision attacks)

## 🎓 Professional Context

### Industry Applications
- **Digital forensics**: File integrity and evidence authentication
- **Software distribution**: Code signing and package integrity
- **Certificate authorities**: Root certificate signing
- **Audit systems**: Tamper-evident logging

### Career Relevance
- **Digital forensics examiner**: Ensuring evidence integrity
- **Security architect**: Designing secure authentication systems
- **DevOps engineer**: Implementing secure CI/CD pipelines
- **Compliance auditor**: Verifying data integrity controls

## 📊 Key Concepts Summary

| Concept | Week 1 (Encryption) | Week 2 (Hashing/Signatures) |
|---------|-------------------|----------------------------|
| **Purpose** | Confidentiality | Integrity & Authentication |
| **Reversible** | Yes (with key) | No (one-way function) |
| **Key Type** | Symmetric | None (hash) or Asymmetric (signatures) |
| **Output Size** | Variable | Fixed |
| **Performance** | Fast | Very fast (hash), Slow (signatures) |

## 📅 Week 2 Schedule Summary

| Day | Activity | Time | Deliverable |
|-----|----------|------|-------------|
| 1-2 | Reading + Tutorial Start | 3-4 hours | Understanding + Code |
| 3-4 | Tutorial Complete + Quiz | 2.5-3 hours | Quiz Score |
| 5-6 | Document Signing Assignment | 2-3 hours | Complete Project |
| 7 | Review & Submit | 30 min | Final Submission |

## 🚀 Next Week Preview

**Week 3: PKI and Certificate Management** will cover:
- X.509 certificates and certificate authorities
- RSA and ECDSA key pair generation
- Certificate signing requests (CSRs)
- TLS/SSL handshake and certificate chains
- Building your own Certificate Authority

**Preparation**: Review public-key cryptography concepts and X.509 certificate format.

---

**Ready to start?** Complete the required readings, then proceed to [tutorial.md](tutorial.md).

**Questions?** Check the troubleshooting guide or post in Canvas discussions.