# Week 3 Quiz: PKI and Certificates

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** X.509 certificates contain both a public key and a private key.  
**Answer**: ______

**2.** A Certificate Authority (CA) signs certificates using its private key.  
**Answer**: ______

**3.** Self-signed certificates provide the same level of trust as CA-signed certificates.  
**Answer**: ______

**4.** Certificate pinning helps prevent man-in-the-middle attacks.  
**Answer**: ______

**5.** Root certificates must be renewed more frequently than end-entity certificates for security.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** What information is NOT typically included in an X.509 certificate?
- A) Subject's public key
- B) Subject's private key
- C) Issuer's distinguished name
- D) Validity period

**Answer**: ______

**7.** What is the purpose of a Certificate Signing Request (CSR)?
- A) To revoke an existing certificate
- B) To request a new certificate from a CA
- C) To verify a certificate chain
- D) To encrypt data for transmission

**Answer**: ______

**8.** In a certificate chain, which certificate is self-signed?
- A) Intermediate certificate
- B) End-entity certificate
- C) Root certificate
- D) Client certificate

**Answer**: ______

**9.** What does Certificate Revocation List (CRL) contain?
- A) List of trusted certificates
- B) List of expired certificates
- C) List of revoked certificates
- D) List of pending certificates

**Answer**: ______

**10.** Which protocol is commonly used to check certificate revocation status in real-time?
- A) HTTP
- B) OCSP
- C) LDAP
- D) SMTP

**Answer**: ______

**11.** What is the primary purpose of an intermediate CA certificate?
- A) To encrypt web traffic
- B) To bridge trust between root CA and end-entity certificates
- C) To store private keys
- D) To generate random numbers

**Answer**: ______

**12.** Which field in a certificate uniquely identifies it?
- A) Common Name
- B) Serial Number
- C) Public Key
- D) Signature Algorithm

**Answer**: ______

**13.** What type of certificate would a web server typically use?
- A) Root certificate
- B) Client certificate
- C) Server certificate
- D) Code signing certificate

**Answer**: ______

**14.** What happens when a certificate expires?
- A) It is automatically renewed
- B) It becomes untrusted
- C) It is added to the CRL
- D) The private key is destroyed

**Answer**: ______

**15.** Which algorithm is commonly used for certificate signatures?
- A) AES
- B) RSA with SHA-256
- C) DES
- D) MD5

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain the difference between a self-signed certificate and a CA-signed certificate.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What is certificate chain validation and why is it important?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** Describe the purpose of certificate pinning in mobile applications.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** Why might an organization operate its own internal Certificate Authority?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** What is the difference between certificate expiration and certificate revocation?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **F** - X.509 certificates contain only the public key, never the private key
2. **T** - CAs sign certificates with their private key
3. **F** - Self-signed certificates are not trusted by default
4. **T** - Certificate pinning prevents MITM attacks
5. **F** - Root certificates typically have longer validity periods

### Part B: Multiple Choice
6. **B** - Subject's private key (never included)
7. **B** - To request a new certificate from a CA
8. **C** - Root certificate
9. **C** - List of revoked certificates
10. **B** - OCSP (Online Certificate Status Protocol)
11. **B** - To bridge trust between root CA and end-entity certificates
12. **B** - Serial Number
13. **C** - Server certificate
14. **B** - It becomes untrusted
15. **B** - RSA with SHA-256

### Part C: Short Answer (Sample Answers)
16. A self-signed certificate is signed by the same entity that owns it and requires manual trust establishment, while a CA-signed certificate is signed by a trusted Certificate Authority and is automatically trusted by systems that trust the CA.

17. Certificate chain validation verifies each certificate in the chain from the end-entity certificate up to a trusted root CA, ensuring that each certificate was properly signed by its issuer and establishing a complete chain of trust.

18. Certificate pinning associates a specific certificate or public key with a particular service, preventing man-in-the-middle attacks even if an attacker obtains a valid certificate from a trusted CA.

19. Organizations operate internal CAs to issue certificates for internal services, maintain complete control over their PKI, reduce costs, and manage certificates for devices and services not exposed to the public internet.

20. Certificate expiration occurs naturally when the validity period ends and is planned, while revocation is an active process to invalidate a certificate before expiration due to compromise, key loss, or other security concerns.

---

## Grading Rubric

| Section | Points | Scoring |
|---------|--------|---------|
| True/False | 5 | 1 point per correct answer |
| Multiple Choice | 10 | 1 point per correct answer |
| Short Answer | 10 | 2 points per answer: Full (2), Partial (1), Incorrect (0) |
| **Total** | **25** | |

### Short Answer Grading Guidelines:
- **2 points**: Complete, accurate answer demonstrating understanding
- **1 point**: Partially correct or incomplete answer
- **0 points**: Incorrect or no answer

### Grade Scale:
- A: 23-25 points (92-100%)
- B: 20-22 points (80-91%)
- C: 18-19 points (72-79%)
- D: 15-17 points (60-71%)
- F: Below 15 points (<60%)