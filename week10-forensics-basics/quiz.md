# Week 10 Quiz: Digital Forensics Fundamentals

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** Chain of custody documentation is only required for criminal cases, not civil investigations.  
**Answer**: ______

**2.** Creating a bit-by-bit copy of a hard drive preserves more evidence than a logical copy.  
**Answer**: ______

**3.** Digital evidence can be modified during the analysis process as long as it's documented.  
**Answer**: ______

**4.** File carving can recover deleted files even when the file system metadata is damaged.  
**Answer**: ______

**5.** Volatile memory (RAM) contains no useful information for digital forensics investigations.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** What is the primary purpose of creating forensic images of digital evidence?
- A) To save storage space
- B) To preserve original evidence while allowing analysis
- C) To compress the data for easier transport
- D) To remove unnecessary files

**Answer**: ______

**7.** Which hashing algorithm is most commonly used to verify forensic image integrity?
- A) MD5
- B) SHA-1
- C) SHA-256
- D) CRC32

**Answer**: ______

**8.** In the order of volatility, which should be collected first?
- A) Hard disk drives
- B) Network connections
- C) System memory (RAM)
- D) Log files

**Answer**: ______

**9.** What does "write blocking" prevent during forensic acquisition?
- A) Reading data from the evidence device
- B) Writing data to the evidence device
- C) Copying data between devices
- D) Analyzing the evidence

**Answer**: ______

**10.** Which file system is most commonly found on Windows systems?
- A) ext4
- B) HFS+
- C) NTFS
- D) FAT32

**Answer**: ______

**11.** What information can be found in file system metadata?
- A) File creation time
- B) File modification time
- C) File access permissions
- D) All of the above

**Answer**: ______

**12.** Which tool is commonly used for disk imaging in digital forensics?
- A) Photoshop
- B) dd (disk dump)
- C) Microsoft Word
- D) Notepad

**Answer**: ______

**13.** What is slack space in digital forensics?
- A) Unused space on a hard drive
- B) Space between the end of a file and the end of its allocated cluster
- C) Space used by the operating system
- D) Space used for temporary files

**Answer**: ______

**14.** Which of the following is NOT a principle of digital forensics?
- A) Minimize changes to original evidence
- B) Document all actions taken
- C) Modify evidence to make it more readable
- D) Maintain chain of custody

**Answer**: ______

**15.** What does steganography involve in the context of digital forensics?
- A) Encrypting files
- B) Hiding data within other data
- C) Deleting files permanently
- D) Compressing files

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain why maintaining chain of custody is critical in digital forensics.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What is the difference between live forensics and static forensics?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** Why is it important to use forensically sound tools and methods?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** How can digital forensics help in incident response activities?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** What challenges does encryption present to digital forensics investigators?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **F** - Chain of custody is required for all investigations to ensure evidence integrity
2. **T** - Bit-by-bit copies preserve all data including deleted files and slack space
3. **F** - Digital evidence should never be modified; only copies should be analyzed
4. **T** - File carving can recover files based on file signatures and structure
5. **F** - RAM contains valuable information like running processes, network connections, and encryption keys

### Part B: Multiple Choice
6. **B** - To preserve original evidence while allowing analysis
7. **C** - SHA-256 is the current standard for forensic integrity verification
8. **C** - System memory (RAM) is most volatile and should be collected first
9. **B** - Writing data to the evidence device (prevents contamination)
10. **C** - NTFS (New Technology File System)
11. **D** - All of the above (timestamps, permissions, etc.)
12. **B** - dd (disk dump) command-line tool
13. **B** - Space between the end of a file and the end of its allocated cluster
14. **C** - Modify evidence to make it more readable (should never modify evidence)
15. **B** - Hiding data within other data

### Part C: Short Answer (Sample Answers)
16. Chain of custody provides legal proof that evidence has not been tampered with, altered, or contaminated from collection through analysis, ensuring its admissibility in legal proceedings.

17. Live forensics examines running systems to capture volatile data and active processes, while static forensics analyzes powered-down systems and their stored data.

18. Forensically sound tools ensure evidence integrity, prevent contamination, maintain reproducible results, and provide legally defensible analysis that can withstand court scrutiny.

19. Digital forensics helps incident response by determining attack vectors, identifying affected systems, recovering deleted malware, establishing timelines, and providing evidence for legal action.

20. Encryption can make data unreadable without proper keys, requiring investigators to use specialized techniques like memory analysis, key recovery, or exploiting implementation weaknesses.

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