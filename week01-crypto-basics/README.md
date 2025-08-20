# Week 1: Cryptography Basics

**🎯 This Week's Goal**: Build a secure password vault using Python cryptography

**⏱️ Time Budget**: 7-8 hours | **Due**: End of Week 1

## 🚀 Start Here (5 minutes)

1. **📚 Read first** → [Crypto 101 Ch 1-2](https://www.crypto101.io/) (45 min)
2. **🛠️ Then practice** → [Tutorial](tutorial.md) (3 hours)
3. **📝 Build project** → [Assignment](assignment.md) (3 hours)
4. **✅ Test knowledge** → [Quiz](quiz.md) (30 min)

**❓ Need help?** → [Week overview](../quick-reference/week-at-a-glance.md) (1 min)

## 📚 This Week's Materials

### Required Reading (2.5 hours)
📖 **Core concepts - complete these first:**

1. **"Crypto 101" by Laurens Van Houtven** ⭐ **CORE**
   - **Link**: https://www.crypto101.io/
   - **Chapters**: 1-2 only (pages 1-30)
   - **Focus**: Basic cryptography concepts, terminology

2. **Python Cryptography Documentation** ⭐ **CORE**
   - **Link**: https://cryptography.io/en/latest/
   - **Section**: "Fernet (Symmetric Encryption)" - Quick Start only
   - **Focus**: Practical implementation basics

### Supplementary Reading (Optional - 1.5 hours)
📚 **For deeper understanding:**

3. **"Crypto 101" Extended**
   - **Chapters**: 3-4 (Stream and Block Ciphers)
   - **Pages**: 31-65
   - **When to read**: After completing tutorial

4. **NIST Key Management Guidelines**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf
   - **Pages**: 1-10 (Executive Summary only)
   - **Purpose**: Professional context

### Optional Supplementary Materials (1 hour)
🎥 **For additional understanding:**

- **Video**: "AES Explained" - Computerphile
  - **Link**: https://www.youtube.com/watch?v=O4xNJsjtN6E
  - **Length**: 13 minutes
  - **Value**: Visual explanation of AES encryption

- **Interactive**: CrypTool Online AES Demo
  - **Link**: https://www.cryptool.org/en/cto/aes
  - **Activity**: Try encrypting text with different keys

## 🛠️ Tutorial Overview

This week's hands-on tutorial covers:

1. **Part 1**: Basic string encryption/decryption (30 min)
2. **Part 2**: File encryption and key management (90 min) 
3. **Part 3**: Understanding encryption modes (45 min)
4. **Part 4**: Password-based key derivation (60 min)

**Tutorial Location**: [tutorial.md](tutorial.md)

## ⚡ Quick Setup Check

**🚨 Not set up yet?** → [Setup checklist](../quick-reference/setup-checklist.md) (15 min)

**✅ Ready to start?** Verify:
- [ ] Environment setup complete
- [ ] Git configured with CSCI347_f25 in name
- [ ] Can run: `python -c "from cryptography.fernet import Fernet; print('Ready!')"`

**Verify your setup**:
```bash
python -c "import cryptography; print('Cryptography version:', cryptography.__version__)"
```

## 🎯 Weekly Assignment: Simple File Encryptor

**Due**: End of Week 1 (see Canvas for exact date)  
**Estimated Time**: 2-3 hours (simplified)

Build a command-line file encryption tool that:

1. **Encrypts and decrypts files** using password-derived keys
2. **Uses secure key derivation** (PBKDF2) from passwords
3. **Handles basic error cases** gracefully
4. **Provides clean CLI interface** for encrypt/decrypt operations

**Full requirements**: [assignment-simplified.md](assignment-simplified.md)

*Note: This is a simplified version focusing on core concepts rather than a full password manager.*

### Assignment Deliverables & Professional Submission

**Complete your assignment** in the feature branch:
```bash
cd assignments/CSCI347_f25_Your_Name/week01

# Create your implementation
# - password_vault.py (main implementation)
# - README.md (usage instructions and design decisions)
# - tests/ directory with test files
# - examples/ directory with usage examples

# Commit your work with meaningful messages
git add password_vault.py
git commit -m "Implement password vault with Fernet encryption and PBKDF2"

git add README.md
git commit -m "Add comprehensive documentation and usage examples"

git add tests/
git commit -m "Add unit tests with edge case coverage"
```

**Submit via Pull Request** (Professional Code Review):
```bash
# Push your feature branch
git push origin week01-crypto-assignment

# Then on GitHub:
# 1. Go to YOUR fork: https://github.com/YourUsername/CSCI347_f25
# 2. Click "Compare & pull request"
# 3. Fill out PR description with:
#    - Summary of your implementation
#    - Key security decisions made  
#    - Any challenges encountered
#    - Testing approach used
# 4. Click "Create pull request"
```

**Required Files in Your PR**:
- `password_vault.py` - Your complete implementation
- `README.md` - Detailed usage instructions and design decisions  
- `tests/` - Comprehensive test suite
- `examples/` - Usage examples and sample outputs

**What Happens Next**:
1. **Instructor reviews** your code with line-by-line comments
2. **You respond** to feedback and make improvements  
3. **Iterative process** until code meets professional standards
4. **Final grade** recorded in Canvas after PR approval

## 📝 Weekly Quiz

**Points**: 25 points (T/F: 5pts, Multiple Choice: 10pts, Short Answer: 10pts)  
**Time Limit**: 30 minutes  
**Format**: Available in Canvas

Test your understanding of symmetric encryption, key management, encryption modes, and password-based cryptography. Review all tutorial materials and readings before attempting.

**Quiz Topics**:
- Fernet encryption and key management
- ECB vs CBC modes and security implications
- PBKDF2 and secure password storage
- Cryptographic best practices

**Location**: [quiz.md](quiz.md) (practice version)

## ✅ Self-Assessment

### Check Your Understanding
Answer these questions after completing the tutorial:

1. **Why is the same plaintext encrypted to different ciphertexts** each time with Fernet?
2. **What happens if you lose the encryption key** for your data?
3. **Why shouldn't you use ECB mode** for encrypting files?
4. **How does salt protect** against rainbow table attacks?

### Validation Script
Run the automated checker to verify your tutorial work:

```bash
python check-week1.py
```

**Expected output**: All tests should pass before submitting assignment.

## 🤝 Getting Help

### Common Issues
- **Import errors**: Ensure virtual environment is activated
- **Permission errors**: Don't use `sudo` with pip in virtual environments
- **Decryption failures**: Check you're using the correct key

### Where to Ask Questions
1. **GitHub Issues**: Technical problems with course materials
2. **Canvas Discussions**: Conceptual questions and peer help
3. **Office Hours**: Complex debugging and advanced topics

### Troubleshooting Resources
- [General troubleshooting guide](../resources/troubleshooting.md)
- [Week 1 specific issues](troubleshooting.md)

## 📈 Learning Path

### Recommended Schedule (7-8 hours total)

**For Well-Prepared Students:**
```
Day 1-2: Complete readings + start tutorial (3-4 hours)
Day 3-4: Finish tutorial + take quiz (2.5-3 hours)  
Day 5-6: Complete assignment (2-3 hours)
Day 7: Review and submit
```

**For Students Needing Extra Support:**
```
Day 1: Prerequisites review + setup (1-2 hours)
Day 2-3: Tutorial Module 1-2 only (3-4 hours) 
Day 4: Tutorial Module 3-4 + get help if stuck (3-4 hours)
Day 5: Start assignment with template (2-3 hours)
Day 6: Finish assignment + ask for help (2-3 hours)
Day 7: Review, test, and submit

Total: 12-15 hours (it's okay to take longer while learning)
```

**🚨 Time Management Rules:**
- **Don't spend more than 30 minutes stuck** without asking for help
- **Use office hours** - they're specifically for you
- **Focus on running code** before understanding theory
- **It's okay to submit working code** even if you don't understand every detail

*The tutorial includes comprehensive explanations and examples to support your learning whether you engage deeply with readings or use them as reference material.*

## 🔍 Going Deeper (Optional)

### **Professional Development Opportunities**
*Available to all students - no bonus points, just learning enrichment*

#### **Industry Certification Preparation**
This week's content directly maps to:
- **CompTIA Security+ CE**: Cryptography (15% of exam)
- **CISSP**: Domain 3 - Security Architecture and Engineering
- **CEH**: Module 20 - Cryptography

**Study Enhancement:**
- Practice with **CyberAces** cryptography challenges
- Complete **Cryptopals** crypto challenges (cryptopals.com)
- Take practice tests focusing on symmetric encryption

#### **Advanced Research Challenges**
1. **Post-quantum cryptography**: Implement lattice-based encryption
2. **Hardware security modules**: Research cloud HSM services (AWS KMS, Azure Key Vault)
3. **Side-channel attacks**: Analyze timing attacks on your implementation
4. **Formal verification**: Use cryptographic proofs to verify your algorithms

#### **Industry Connections**
- **Join professional organizations**: (ISC)² membership, ISACA student chapters
- **Attend virtual conferences**: RSA Conference, Black Hat, DEF CON (student rates)
- **Follow industry experts**: Dan Boneh (Stanford), Matthew Green (Johns Hopkins)
- **Contribute to open source**: Submit PRs to cryptography libraries

#### **Real-World Applications**
- **Enterprise scenarios**: How would Netflix encrypt streaming content?
- **Compliance requirements**: HIPAA encryption standards for healthcare data
- **Mobile security**: How does Signal implement end-to-end encryption?
- **Cloud security**: AWS S3 server-side encryption implementation

## 🎓 Professional Context

### Industry Applications
- **Data-at-rest encryption**: Database and file system encryption
- **Backup encryption**: Secure offsite storage
- **Application security**: Protecting sensitive user data
- **Compliance**: GDPR, HIPAA encryption requirements

### Career Relevance
- **Security Engineering**: Implementing encryption in products
- **SOC Analysis**: Understanding encrypted malware communication
- **Digital Forensics**: Dealing with encrypted evidence
- **Penetration Testing**: Bypassing weak encryption implementations

## 📅 Week 1 Schedule Summary

| Day | Activity | Time | Deliverable |
|-----|----------|------|-------------|
| 1-2 | Reading + Tutorial Start | 3-4 hours | Understanding + Code |
| 3-4 | Tutorial Completion + Quiz | 2.5-3 hours | Quiz Score |
| 5-6 | Assignment | 2-3 hours | Completed Project |
| 7 | Review & Submit | 30 min | Final Submission |

## 🚀 Next Week Preview

**Week 2: Hashing and Digital Signatures** will cover:
- SHA-256 and secure hashing functions
- Hash-based Message Authentication Codes (HMAC)
- Digital signatures with RSA and ECDSA
- Password hashing with salt and iterations
- File integrity monitoring systems

**Preparation**: Review basic number theory and modular arithmetic concepts.

---

**Ready to start?** Complete the required readings, then proceed to [tutorial.md](tutorial.md).

**Questions?** Check the troubleshooting guide or post in Canvas discussions.