# Week 4 Quiz: Authentication

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** Multi-factor authentication requires at least two different passwords.  
**Answer**: ______

**2.** TOTP (Time-based One-Time Password) codes remain valid indefinitely once generated.  
**Answer**: ______

**3.** Biometric authentication is considered a "something you are" factor.  
**Answer**: ______

**4.** OAuth 2.0 is primarily an authentication protocol.  
**Answer**: ______

**5.** Session tokens should be transmitted over HTTPS to prevent session hijacking.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** Which of the following is NOT one of the three main authentication factors?
- A) Something you know
- B) Something you have
- C) Something you are
- D) Something you need

**Answer**: ______

**7.** What is the typical time window for TOTP codes?
- A) 30 seconds
- B) 5 minutes
- C) 1 hour
- D) 24 hours

**Answer**: ______

**8.** Which authentication method is most vulnerable to replay attacks?
- A) TOTP
- B) Static passwords
- C) Challenge-response
- D) Biometrics with liveness detection

**Answer**: ______

**9.** What does SSO stand for in authentication contexts?
- A) Secure Socket Operation
- B) Single Sign-On
- C) System Security Officer
- D) Synchronized Security Option

**Answer**: ______

**10.** Which protocol is commonly used for centralized authentication in enterprise networks?
- A) HTTP
- B) FTP
- C) LDAP
- D) SMTP

**Answer**: ______

**11.** What is the primary security benefit of using JWT tokens?
- A) They are encrypted by default
- B) They are stateless and cryptographically signed
- C) They never expire
- D) They are smaller than cookies

**Answer**: ______

**12.** Which type of attack does account lockout help prevent?
- A) Phishing
- B) Brute force
- C) SQL injection
- D) Cross-site scripting

**Answer**: ______

**13.** What is a nonce in authentication?
- A) A type of password
- B) A value used only once to prevent replay attacks
- C) A user identifier
- D) An encryption key

**Answer**: ______

**14.** Which authentication factor would a smart card represent?
- A) Something you know
- B) Something you have
- C) Something you are
- D) Something you do

**Answer**: ______

**15.** What is the main difference between identification and authentication?
- A) They are the same thing
- B) Identification claims identity, authentication proves it
- C) Authentication comes before identification
- D) Identification requires a password

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain why SMS-based 2FA is considered less secure than app-based TOTP.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What is session fixation and how can it be prevented?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** Describe the difference between OAuth and OpenID Connect.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** Why is it important to implement rate limiting on authentication endpoints?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** What is a rainbow table and how does proper password storage prevent its use?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **F** - MFA requires different types of factors (know/have/are), not multiple passwords
2. **F** - TOTP codes expire after a short time window (typically 30 seconds)
3. **T** - Biometrics are "something you are"
4. **F** - OAuth 2.0 is an authorization protocol, not authentication
5. **T** - HTTPS prevents session token interception

### Part B: Multiple Choice
6. **D** - Something you need (not a standard factor)
7. **A** - 30 seconds
8. **B** - Static passwords
9. **B** - Single Sign-On
10. **C** - LDAP
11. **B** - They are stateless and cryptographically signed
12. **B** - Brute force
13. **B** - A value used only once to prevent replay attacks
14. **B** - Something you have
15. **B** - Identification claims identity, authentication proves it

### Part C: Short Answer (Sample Answers)
16. SMS-based 2FA is vulnerable to SIM swapping attacks and SS7 protocol vulnerabilities that allow interception, while app-based TOTP generates codes locally using a shared secret, making it immune to these network-based attacks.

17. Session fixation is an attack where an attacker sets a user's session ID to a known value before authentication. It can be prevented by regenerating session IDs after successful authentication and rejecting externally provided session identifiers.

18. OAuth 2.0 is an authorization framework that grants access to resources without sharing credentials, while OpenID Connect is an authentication layer built on top of OAuth 2.0 that provides user identity verification.

19. Rate limiting prevents brute force attacks by limiting the number of authentication attempts an attacker can make within a time period, making password guessing attacks impractical and protecting against credential stuffing.

20. A rainbow table is a precomputed table of password hashes used to reverse common passwords. Proper password storage using unique salts per password and key derivation functions like PBKDF2 makes rainbow tables useless since each password produces a unique hash.

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