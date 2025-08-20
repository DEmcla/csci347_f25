# Week 1 Quiz: Cryptography Basics

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** The same plaintext encrypted with Fernet will produce the same ciphertext every time.  
**Answer**: ______

**2.** AES is a symmetric encryption algorithm, meaning the same key is used for both encryption and decryption.  
**Answer**: ______

**3.** ECB (Electronic Codebook) mode is recommended for encrypting files because it's the simplest.  
**Answer**: ______

**4.** Salt in password hashing helps prevent rainbow table attacks.  
**Answer**: ______

**5.** Once data is encrypted with a Fernet key, it can be decrypted with any other Fernet key.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** What is the primary purpose of using PBKDF2 in password storage?
- A) To encrypt the password
- B) To compress the password for storage
- C) To derive a cryptographic key from a password
- D) To generate random passwords

**Answer**: ______

**7.** Which of the following best describes the "avalanche effect" in cryptography?
- A) Gradual weakening of encryption over time
- B) Small input changes cause large output changes
- C) Multiple encryptions of the same data
- D) Cascading system failures

**Answer**: ______

**8.** What is the recommended minimum number of iterations for PBKDF2 according to NIST?
- A) 1,000
- B) 10,000
- C) 100,000
- D) 1,000,000

**Answer**: ______

**9.** In CBC (Cipher Block Chaining) mode, what is an IV?
- A) Internal Validator
- B) Initialization Vector
- C) Integer Value
- D) Identity Verification

**Answer**: ______

**10.** Which Python library is commonly used for cryptographic operations in this course?
- A) pycrypto
- B) hashlib
- C) cryptography
- D) ssl

**Answer**: ______

**11.** What happens if you lose the encryption key for data encrypted with AES?
- A) You can recover it using the encrypted data
- B) You can brute force it easily
- C) The data is effectively lost
- D) You can use a master key to recover it

**Answer**: ______

**12.** What is the key size used by Fernet for AES encryption?
- A) 64 bits
- B) 128 bits
- C) 256 bits
- D) 512 bits

**Answer**: ______

**13.** Why is salt important in password hashing?
- A) It makes passwords taste better
- B) It ensures the same password produces different hashes
- C) It makes the hash function faster
- D) It compresses the password

**Answer**: ______

**14.** Which operation is NOT reversible?
- A) AES encryption with key
- B) Base64 encoding
- C) SHA-256 hashing
- D) XOR with a key

**Answer**: ______

**15.** What does Fernet provide beyond basic AES encryption?
- A) Only encryption
- B) Encryption with authentication (HMAC)
- C) Only compression
- D) Only key generation

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain why ECB mode reveals patterns in encrypted data.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What is the primary difference between encryption and hashing?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** Why do we use different salts for each password even if the passwords are identical?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** Describe one advantage of using authenticated encryption (like Fernet) over plain AES.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** What is key derivation and why is it necessary for password-based encryption?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **F** - Fernet uses random IVs, so same plaintext produces different ciphertext
2. **T** - AES is symmetric encryption
3. **F** - ECB is insecure and reveals patterns
4. **T** - Salt prevents rainbow table attacks
5. **F** - You need the exact same key to decrypt

### Part B: Multiple Choice
6. **C** - To derive a cryptographic key from a password
7. **B** - Small input changes cause large output changes
8. **C** - 100,000 iterations (NIST recommendation)
9. **B** - Initialization Vector
10. **C** - cryptography library
11. **C** - The data is effectively lost
12. **B** - 128 bits for AES
13. **B** - It ensures the same password produces different hashes
14. **C** - SHA-256 hashing is one-way
15. **B** - Encryption with authentication (HMAC)

### Part C: Short Answer (Sample Answers)
16. ECB mode encrypts each block independently with the same key, so identical plaintext blocks produce identical ciphertext blocks, revealing patterns in the data.

17. Encryption is reversible with the proper key and provides confidentiality, while hashing is a one-way function that produces a fixed-size digest and provides integrity.

18. Different salts ensure that even identical passwords produce different hashes, preventing attackers from identifying users with the same password and making rainbow table attacks infeasible.

19. Authenticated encryption like Fernet provides both confidentiality and integrity verification, detecting if the ciphertext has been tampered with or corrupted.

20. Key derivation transforms a human-memorable password into a cryptographically strong key of the correct size through functions like PBKDF2, adding computational cost to slow brute-force attacks.

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