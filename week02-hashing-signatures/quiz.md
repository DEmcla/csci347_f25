# Week 2 Quiz: Hashing and Digital Signatures

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** SHA-256 always produces a 256-bit output regardless of input size.  
**Answer**: ______

**2.** HMAC can be verified by anyone who knows the message, even without the secret key.  
**Answer**: ______

**3.** Digital signatures provide non-repudiation because only the holder of the private key could have created the signature.  
**Answer**: ______

**4.** MD5 is still considered secure for password hashing as long as you use salt.  
**Answer**: ______

**5.** Hash functions are designed to be one-way functions that cannot be reversed.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** What is the primary difference between a hash and an HMAC?
- A) HMAC is faster than hashing
- B) HMAC requires a secret key
- C) HMAC produces variable-length output
- D) HMAC is reversible

**Answer**: ______

**7.** Which property is NOT a requirement for cryptographic hash functions?
- A) Deterministic output
- B) Fast to compute
- C) Reversible with a key
- D) Collision resistant

**Answer**: ______

**8.** In digital signatures, which key is used to sign a document?
- A) Public key
- B) Private key
- C) Shared secret key
- D) Session key

**Answer**: ______

**9.** What does the avalanche effect mean for hash functions?
- A) Hash values decrease over time
- B) Small input changes produce drastically different outputs
- C) Multiple hashes can be chained together
- D) Hash collisions cascade through the system

**Answer**: ______

**10.** Which attack does salting passwords specifically prevent?
- A) Brute force attacks
- B) Rainbow table attacks
- C) Man-in-the-middle attacks
- D) Replay attacks

**Answer**: ______

**11.** What is the output size of SHA-256 in bytes?
- A) 16 bytes
- B) 32 bytes
- C) 64 bytes
- D) 256 bytes

**Answer**: ______

**12.** Which component provides authentication in HMAC?
- A) The hash algorithm alone
- B) The message content
- C) The shared secret key
- D) The output length

**Answer**: ______

**13.** What security property do digital signatures NOT provide?
- A) Authentication
- B) Integrity
- C) Confidentiality
- D) Non-repudiation

**Answer**: ______

**14.** Why is timing attack resistance important in HMAC verification?
- A) To make verification faster
- B) To prevent key recovery through timing analysis
- C) To synchronize with network time
- D) To ensure consistent hash output

**Answer**: ______

**15.** Which Python function should be used for secure password comparison?
- A) == operator
- B) str.compare()
- C) hmac.compare_digest()
- D) hash.equals()

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain the difference between using a hash function for file integrity versus using HMAC.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** Why can't digital signatures provide confidentiality for the signed message?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** What is a hash collision and why is collision resistance important for security?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** Describe how digital signatures provide non-repudiation.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** Why do we use key derivation functions like PBKDF2 instead of directly hashing passwords?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **T** - SHA-256 always produces 256-bit (32-byte) output
2. **F** - HMAC verification requires the secret key
3. **T** - Only the private key holder can create valid signatures
4. **F** - MD5 is cryptographically broken and should not be used
5. **T** - Hash functions are designed to be one-way

### Part B: Multiple Choice
6. **B** - HMAC requires a secret key
7. **C** - Reversible with a key (hashes are always one-way)
8. **B** - Private key is used to sign
9. **B** - Small input changes produce drastically different outputs
10. **B** - Rainbow table attacks
11. **B** - 32 bytes (256 bits ÷ 8)
12. **C** - The shared secret key
13. **C** - Confidentiality (signatures don't encrypt)
14. **B** - To prevent key recovery through timing analysis
15. **C** - hmac.compare_digest()

### Part C: Short Answer (Sample Answers)
16. A hash function alone provides integrity checking but anyone can recompute the hash after modifying the file. HMAC provides both integrity and authentication because only someone with the secret key can generate a valid HMAC.

17. Digital signatures don't encrypt the message; they only create a signature proving authenticity and integrity. The original message remains in plaintext alongside the signature.

18. A hash collision occurs when two different inputs produce the same hash output. Collision resistance is critical because collisions could allow attackers to forge documents or bypass security checks.

19. Digital signatures provide non-repudiation because only the holder of the private key could have created the signature, making it impossible to deny having signed the document (assuming proper key management).

20. PBKDF2 adds computational cost through many iterations and uses salt, making brute-force attacks much slower and preventing rainbow table attacks, while simple hashing would be too fast for attackers to compute.

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