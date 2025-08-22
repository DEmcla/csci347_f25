# Week 3: PKI and Certificate Management

**Learning Track**: Both Standard and Accelerated  
**Time Commitment**: 8-10 hours total  
**Prerequisites**: Weeks 1-2 completed, understanding of digital signatures

## Start Here (5 minutes)

1. **Complete readings** - [Required Reading](#required-reading) 
2. **Follow tutorial** - [Tutorial](tutorial.md)
3. **Complete assignment** - [Assignment](assignment.md) 
4. **Take quiz** - [Quiz](quiz.md)

## Learning Objectives

By the end of this week, you will be able to:

1. **Generate and manage** X.509 certificates and certificate authorities
2. **Create Certificate Signing Requests** (CSRs) with proper extensions
3. **Build a certificate chain of trust** from root CA to end-entity certificates
4. **Implement TLS/SSL connections** with certificate validation
5. **Understand PKI concepts** including revocation and trust models
6. **Deploy a working Certificate Authority** for testing and development

## 📚 This Week's Materials

### Required Reading (5 hours)

1. **"Bulletproof SSL and TLS" Free Chapters**
   - **Link**: https://www.feistyduck.com/library/bulletproof-tls-guide/online/
   - **Chapter**: 1 (SSL, TLS, and Cryptography)
   - **Focus**: TLS handshake, certificate validation

2. **NIST SP 800-32: Public Key Technology Introduction**
   - **Link**: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-32.pdf
   - **Chapters**: 1-3 (PKI fundamentals)
   - **Focus**: Certificate authorities, trust models

3. **Let's Encrypt: "How It Works"**
   - **Link**: https://letsencrypt.org/how-it-works/
   - **Focus**: Automated certificate management (ACME protocol)

4. **Mozilla CA Certificate Policy**
   - **Link**: https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
   - **Focus**: Real-world certificate requirements and validation

## 🛠️ Tutorial Overview

This week's tutorial covers:

1. **Part 1**: X.509 certificate structure and generation (45 min)
2. **Part 2**: Building a Certificate Authority (60 min)
3. **Part 3**: Certificate Signing Requests and issuance (45 min)
4. **Part 4**: TLS/SSL implementation and validation (90 min)
5. **Part 5**: Certificate lifecycle management (45 min)

## 🎯 Weekly Assignment: Mini Certificate Authority

Build a complete PKI system that:
1. **Creates root and intermediate CAs** with proper certificate chains
2. **Issues server and client certificates** for testing
3. **Implements certificate revocation** checking
4. **Provides TLS server/client** demonstration
5. **Manages certificate lifecycle** including renewal

## ✅ Self-Assessment Questions

1. **What's the difference between a root CA and intermediate CA?**
2. **How does certificate chain validation work?**
3. **Why are certificate extensions important?**
4. **What happens during a TLS handshake?**
5. **How do browsers validate SSL certificates?**

---

**Tutorial Location**: [tutorial.md](tutorial.md)  
**Assignment Details**: [assignment.md](assignment.md)