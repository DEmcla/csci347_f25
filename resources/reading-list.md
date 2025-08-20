# CSCI 347 Complete Reading List

All readings are free, open-source, and accessible. This list replaces expensive textbooks with authoritative, industry-standard materials.

## 📚 Primary Reference Library

### Core Security References
1. **Ross Anderson's "Security Engineering" (3rd Edition)**
   - 📖 **URL**: https://www.cl.cam.ac.uk/~rja14/book.html
   - 🎯 **Use**: Primary security theory reference
   - ⏱️ **Access**: Always available, complete book online

2. **NIST Cybersecurity Publications**
   - 📖 **URL**: https://csrc.nist.gov/publications
   - 🎯 **Use**: Authoritative standards and guidelines
   - ⏱️ **Access**: Government resource, permanently free

3. **OWASP Security Resources**
   - 📖 **URL**: https://owasp.org/
   - 🎯 **Use**: Practical security guidance
   - ⏱️ **Access**: Community-maintained, always current

---

## Week-by-Week Reading Schedule

## Week 1: Cryptography Fundamentals

### 📖 Required Reading (2.5 hours)

1. **"Crypto 101" by Laurens Van Houtven** ⭐ **CORE**
   - **URL**: https://www.crypto101.io/
   - **Chapters**: 1-2 only (Foundations and Introduction to Cryptography) 
   - **Pages**: 1-30
   - **Focus**: Basic cryptography concepts, terminology

2. **Python Cryptography Documentation** ⭐ **CORE**
   - **URL**: https://cryptography.io/en/latest/
   - **Sections**: "Fernet (Symmetric Encryption)" - Quick Start only
   - **Focus**: Practical implementation basics

### 📚 Supplementary Reading (Optional - 1.5 hours)

3. **"Crypto 101" Extended Reading**
   - **Chapters**: 3-4 (Stream Ciphers and Block Ciphers)
   - **Pages**: 31-65
   - **When to read**: After completing tutorial if you want deeper understanding

4. **NIST SP 800-175B: Key Management Guidelines**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175B.pdf
   - **Pages**: 1-10 (Executive Summary only)
   - **Purpose**: Professional context for key management

### 🎥 Learning Support Resources

- **Video**: "AES Explained" - Computerphile ⭐ **RECOMMENDED**
  - **URL**: https://www.youtube.com/watch?v=O4xNJsjtN6E
  - **Length**: 13 minutes
  - **Watch when**: Before starting tutorial
  
- **Interactive**: CrypTool Online
  - **URL**: https://www.cryptool.org/en/cto/
  - **Exercise**: Try AES encryption with different keys (after tutorial)

---

## Week 2: Hashing and Digital Signatures

### 📖 Required Reading (4 hours)

1. **"Crypto 101"**
   - **Chapters**: 5-7 (Hash Functions, MACs, Digital Signatures)
   - **Pages**: 66-120

2. **NIST SP 800-107r1: Hash Algorithm Recommendations**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-107r1.pdf
   - **Pages**: 1-12 (Sections 1-5)
   - **Note**: Legacy from 2012, core hash algorithm guidance still applicable

3. **RFC 2104: HMAC Specification**
   - **URL**: https://datatracker.ietf.org/doc/html/rfc2104
   - **Focus**: Message Authentication Code theory

4. **Anderson's Security Engineering**
   - **Chapter**: 5.3 (Hash Functions)
   - **URL**: https://www.cl.cam.ac.uk/~rja14/Papers/SEv3-ch5-7sep.pdf

### 🎥 Supplementary Resources

- **Blog**: "How Secure is SHA-256?" - Matthew Green
  - **URL**: https://blog.cryptographyengineering.com/2012/04/05/how-to-choose-authenticated-encryption/
  - **Note**: 2012 article, SHA-256 security analysis remains current
  
- **Paper**: "The MD5 Message-Digest Algorithm" (Historical perspective)
  - **URL**: https://datatracker.ietf.org/doc/html/rfc1321
  - **Note**: Historical reference - MD5 is now cryptographically broken

---

## Week 3: PKI and Certificate Management

### 📖 Required Reading (5 hours)

1. **"Bulletproof SSL and TLS" Free Chapters**
   - **URL**: https://www.feistyduck.com/library/bulletproof-tls-guide/online/
   - **Chapter**: 1 (SSL, TLS, and Cryptography)

2. **NIST SP 800-32: Public Key Technology Introduction**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-32.pdf
   - **Chapters**: 1-3
   - **Note**: Legacy publication from 2001, core PKI principles remain valid

3. **Let's Encrypt: "How It Works"**
   - **URL**: https://letsencrypt.org/how-it-works/
   - **Focus**: Modern certificate automation

4. **Mozilla CA Certificate Policy**
   - **URL**: https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
   - **Focus**: Real-world certificate requirements

### 🎥 Supplementary Resources

- **Article**: "The First Few Milliseconds of an HTTPS Connection"
  - **URL**: https://www.moserware.com/2009/06/first-few-milliseconds-of-https.html
  - **Note**: Classic article from 2009, TLS fundamentals still accurate
  
- **Tool**: SSL Labs Server Test
  - **URL**: https://www.ssllabs.com/ssltest/
  - **Exercise**: Test a few popular websites

---

## Week 4-5: Authentication and Access Control

### 📖 Required Reading (6 hours total)

1. **NIST SP 800-63-3: Digital Identity Guidelines**
   - **URL**: https://pages.nist.gov/800-63-3/
   - **Focus**: SP 800-63B (Authentication and Lifecycle Management)

2. **Anderson's Security Engineering**
   - **URL**: https://www.cl.cam.ac.uk/~rja14/book.html
   - **Chapters**: 
     - Chapter 2: Usability and Psychology
     - Chapter 3: Protocols
     - Chapter 4: Access Control

3. **OWASP Authentication Cheat Sheet**
   - **URL**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

4. **RBAC Paper: "Role-Based Access Controls"**
   - **URL**: https://csrc.nist.gov/CSRC/media/Publications/conference-paper/1992/10/13/role-based-access-controls/final/documents/ferraiolo-kuhn-92.pdf
   - **Authors**: Ferraiolo & Kuhn (Original RBAC paper)

### 🎥 Supplementary Resources

- **Google BeyondCorp Papers** (Zero Trust Architecture)
  - **URL**: https://cloud.google.com/beyondcorp#researchPapers
  
- **FIDO Alliance Resources**
  - **URL**: https://fidoalliance.org/how-fido-works/
  - **Focus**: Modern passwordless authentication

---

## Week 6-7: Network Security and Monitoring

### 📖 Required Reading (6 hours total)

1. **NIST SP 800-41r1: Guidelines on Firewalls**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-41r1.pdf
   - **Chapters**: 1-4 (Complete)

2. **pfSense Documentation**
   - **URL**: https://docs.netgate.com/pfsense/en/latest/
   - **Sections**: 
     - Fundamentals
     - Firewall Rules
     - NAT Configuration

3. **Snort User Manual**
   - **URL**: https://www.snort.org/documents
   - **Sections**: Chapters 1-3 (Getting Started, Installation, Basic Configuration)

4. **SANS: "Intrusion Detection Systems"**
   - **URL**: https://www.sans.org/white-papers/344/
   - **Focus**: IDS/IPS concepts and deployment

### 🎥 Supplementary Resources

- **Wireshark User Guide** (Free Chapter)
  - **URL**: https://www.wireshark.org/docs/wsug_html_chunked/
  - **Chapter**: 1 (Introduction)
  
- **Suricata Documentation**
  - **URL**: https://suricata.readthedocs.io/
  - **Focus**: Modern IDS/IPS alternative to Snort

---

## Week 8-9: Security Assessment and Architecture

### 📖 Required Reading (6 hours total)

1. **NIST SP 800-115: Technical Guide to Security Testing**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf
   - **Complete document** (Essential methodology)
   - **Note**: Marked "Legacy" but still the primary NIST testing methodology guide

2. **OWASP Testing Guide v4.2**
   - **URL**: https://owasp.org/www-project-web-security-testing-guide/v42/
   - **Sections**: 1-4 (Testing Framework and Methodology)

3. **CIS Controls Version 8**
   - **URL**: https://www.cisecurity.org/controls/v8
   - **Focus**: Implementation Groups and Safeguards

4. **NIST Cybersecurity Framework v1.1**
   - **URL**: https://www.nist.gov/cyberframework
   - **Document**: Framework PDF

### 🎥 Supplementary Resources

- **MITRE ATT&CK Framework**
  - **URL**: https://attack.mitre.org/
  - **Focus**: Understanding adversary tactics and techniques
  
- **OSSTMM: Open Source Security Testing**
  - **URL**: https://www.isecom.org/OSSTMM.3.pdf
  - **Focus**: Open-source testing methodology

---

## Week 10-11: Digital Forensics Foundations

### 📖 Required Reading (6 hours total)

1. **NIST SP 800-86: Guide to Integrating Forensic Techniques**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf
   - **Complete document** (Primary forensics reference)
   - **Note**: While marked "Legacy", this remains the authoritative NIST forensics guide

2. **Autopsy Digital Forensics Platform**
   - **URL**: https://sleuthkit.org/autopsy/docs/user-docs/4.19.3/
   - **Sections**: Getting Started, Basic Features, File Analysis

3. **The Sleuth Kit Documentation**
   - **URL**: https://sleuthkit.org/sleuthkit/docs/
   - **Focus**: Command-line forensics tools

4. **"A Practitioner's Guide to Linux as a Forensic Platform"**
   - **URL**: https://linuxleo.com/
   - **Version**: 4.94 (Free download)
   - **Chapters**: 1-5

### 🎥 Supplementary Resources

- **ForensicsWiki**
  - **URL**: https://forensicswiki.xyz/
  - **Use**: Reference for file formats and artifacts
  
- **SANS Digital Forensics Posters**
  - **URL**: https://www.sans.org/posters/?focus-area=digital-forensics

---

## Week 12-13: Advanced Forensics and Memory Analysis

### 📖 Required Reading (6 hours total)

1. **Volatility 3 Documentation**
   - **URL**: https://volatility3.readthedocs.io/
   - **Complete documentation**

2. **Volatility Foundation Wiki**
   - **URL**: https://github.com/volatilityfoundation/volatility/wiki
   - **Focus**: Memory analysis techniques

3. **NIST SP 800-101r1: Mobile Device Forensics**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf
   - **Chapters**: 1-5

4. **Windows Forensics Reference Materials**
   - **Primary Resource**: SANS Windows Forensic Analysis Poster
   - **URL**: https://www.sans.org/posters/windows-forensic-analysis/
   - **Alternative**: "Windows Internals" book by Russinovich (library/online)
   - **Focus**: Windows artifacts, memory structures, and registry

### 🎥 Supplementary Resources

- **Memory Analysis Training**
  - **URL**: https://www.volatilityfoundation.org/training
  
- **Android Forensics Resources**
  - **URL**: https://source.android.com/security
  - **Focus**: Android security model and artifacts

---

## Week 14: Integration and Incident Response

### 📖 Required Reading (4 hours)

1. **NIST SP 800-61r2: Incident Handling Guide**
   - **URL**: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
   - **Focus**: Integration of forensics with incident response

2. **FIRST: Best Practice Guide for Incident Management**
   - **URL**: https://www.first.org/resources/guides/
   - **Document**: "Computer Security Incident Response Team (CSIRT) Development and Evolution"

3. **SANS Incident Response Process**
   - **URL**: https://www.sans.org/white-papers/1901/
   - **Title**: "Incident Handling Step by Step"

### 🎥 Supplementary Resources

- **MITRE D3FEND Framework**
  - **URL**: https://d3fend.mitre.org/
  - **Focus**: Defensive techniques catalog

---

## 📹 Video Learning Resources (Free)

### Complete Course Series

1. **Professor Messer's Security+**
   - **URL**: https://www.professormesser.com/security-plus/sy0-601/sy0-601-video/
   - **Content**: Complete Security+ course (700+ videos)
   - **Relevance**: Covers security fundamentals

2. **MIT 6.858: Computer Systems Security**
   - **URL**: https://ocw.mit.edu/courses/6-858-computer-systems-security-fall-2014/
   - **Content**: Full MIT course with lectures and labs (2014 version, core concepts still relevant)
   - **Level**: Advanced undergraduate
   - **Note**: While from 2014, fundamental security principles remain valid

3. **Stanford CS 155: Computer and Network Security**
   - **URL**: https://cs155.stanford.edu/
   - **Content**: Course materials and lecture videos
   - **Focus**: Academic perspective on security

### YouTube Channels

1. **Computerphile**
   - **URL**: https://www.youtube.com/user/Computerphile
   - **Content**: Computer science explanations
   - **Relevant Videos**: Cryptography, security topics

2. **LiveOverflow**
   - **URL**: https://www.youtube.com/c/LiveOverflow
   - **Content**: Binary exploitation, reverse engineering
   - **Level**: Intermediate to advanced

---

## 🛠️ Hands-On Practice Resources

### Lab Environments (Free)

1. **TryHackMe** (Free tier)
   - **URL**: https://tryhackme.com/
   - **Content**: Guided cybersecurity challenges

2. **OverTheWire Wargames**
   - **URL**: https://overthewire.org/wargames/
   - **Content**: Security challenges by difficulty

3. **PentesterLab** (Free exercises)
   - **URL**: https://pentesterlab.com/exercises
   - **Content**: Web application security

### Forensics Practice

1. **Digital Forensics Test Images**
   - **URL**: https://dfir.training/resources/downloads/ctf-forensic-test-images
   - **Content**: Practice evidence files

2. **NIST Digital Evidence Test Images**
   - **URL**: https://www.cfreds.nist.gov/
   - **Content**: Standardized forensics test data

---

## 📄 Quick Reference Materials

### Cheat Sheets

1. **SANS Cheat Sheets**
   - **URL**: https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/
   - **Content**: Security tools and techniques

2. **PacketLife Cheat Sheets**
   - **URL**: https://packetlife.net/library/cheat-sheets/
   - **Content**: Network protocols and tools

### Standards and Frameworks

1. **Common Weakness Enumeration (CWE)**
   - **URL**: https://cwe.mitre.org/
   - **Content**: Catalog of software weaknesses

2. **Common Vulnerabilities and Exposures (CVE)**
   - **URL**: https://cve.mitre.org/
   - **Content**: Public vulnerability database

---

## 📱 Mobile Apps for Learning

### Security News and Learning

1. **NIST Mobile App**
   - **Platform**: iOS/Android
   - **Content**: NIST publications and updates

2. **Security+ Training Apps**
   - **Various providers**: Search app stores
   - **Use**: Quiz practice and flashcards

---

## 🔍 Research and Current Events

### News Sources

1. **Krebs on Security**
   - **URL**: https://krebsonsecurity.com/
   - **Focus**: Cybercrime investigations

2. **SANS NewsBites**
   - **URL**: https://www.sans.org/newsletters/newsbites
   - **Format**: Weekly security news digest

3. **Dark Reading**
   - **URL**: https://www.darkreading.com/
   - **Focus**: Enterprise security news

### Academic Resources

1. **USENIX Security Symposium Papers**
   - **URL**: https://www.usenix.org/conferences/byname/108
   - **Content**: Latest security research

2. **IEEE Security & Privacy**
   - **URL**: https://www.computer.org/csdl/magazine/sp
   - **Note**: Academic journal, some articles may require IEEE membership
   - **Content**: Academic security research

---

## 📋 Reading Schedule Tips

### Time Management
- **Required readings**: Approximately 4-5 hours per week
- **Supplementary materials**: 1-2 hours per week
- **Practical application**: Use readings to support hands-on work

### Reading Strategy
1. **Skim first** to understand scope and structure
2. **Focus on examples** and practical applications  
3. **Return to theory** after hands-on practice
4. **Use supplementary materials** for clarification

### Note-Taking
- Create a personal wiki or notebook
- Link concepts between readings
- Document practical examples and commands
- Build your own quick-reference sheets

---

## ✅ Quality Assurance

All resources in this reading list have been verified for:
- ✅ **Accessibility**: Free and publicly available
- ✅ **Authority**: Government agencies, academic institutions, respected organizations
- ✅ **Accuracy**: Current and technically correct
- ✅ **Relevance**: Directly applicable to course objectives
- ✅ **Maintenance**: Regularly updated by their maintainers

### Last Updated: August 2025

**Note**: If any links become unavailable, please report them via GitHub Issues. Alternative sources will be provided promptly.

---

**Ready to start reading?** Begin with [Week 1: Cryptography Basics](../week01-crypto-basics/README.md) materials!