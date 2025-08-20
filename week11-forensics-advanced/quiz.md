# Week 11 Quiz: Advanced Digital Forensics

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** Network packet analysis can reveal unencrypted passwords transmitted over the network.  
**Answer**: ______

**2.** Windows Registry contains information about user activities and system configurations.  
**Answer**: ______

**3.** Database forensics only involves examining active database records, not deleted data.  
**Answer**: ______

**4.** Web browser artifacts can provide evidence of user internet activity even in private browsing mode.  
**Answer**: ______

**5.** Timeline analysis helps establish the sequence of events during a security incident.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** Which network protocol analysis tool is most commonly used in forensics investigations?
- A) Nmap
- B) Wireshark
- C) Metasploit
- D) Nessus

**Answer**: ______

**7.** In Windows forensics, which registry hive contains user-specific settings?
- A) HKEY_LOCAL_MACHINE
- B) HKEY_CURRENT_USER
- C) HKEY_CLASSES_ROOT
- D) HKEY_USERS

**Answer**: ______

**8.** What type of information can be found in web browser history?
- A) Visited URLs and timestamps
- B) Downloaded files
- C) Stored passwords and form data
- D) All of the above

**Answer**: ______

**9.** Which database artifact often contains deleted records that can be forensically recovered?
- A) Transaction logs
- B) Index files
- C) Configuration files
- D) Backup files only

**Answer**: ______

**10.** In network forensics, what does a "packet capture" contain?
- A) Only source and destination IP addresses
- B) Complete network traffic including headers and payload
- C) Only encrypted data
- D) Only error messages

**Answer**: ______

**11.** Which Windows artifact shows recently accessed files?
- A) Event logs only
- B) Registry keys and link files
- C) System files only
- D) Network logs

**Answer**: ______

**12.** What is the primary challenge when analyzing encrypted network traffic?
- A) File size limitations
- B) Inability to see packet headers
- C) Content is unreadable without decryption keys
- D) Network speed issues

**Answer**: ______

**13.** In database forensics, what can transaction logs reveal?
- A) Only current database state
- B) Historical changes and potentially deleted data
- C) Only user login information
- D) Only database schema

**Answer**: ______

**14.** Which technique is most effective for recovering deleted database records?
- A) File carving
- B) Registry analysis
- C) Log file analysis and unallocated space examination
- D) Network packet capture

**Answer**: ______

**15.** What information can be extracted from web browser cache files?
- A) Previously viewed web pages
- B) Images and other media files
- C) Partial website content
- D) All of the above

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain how network forensics can help identify the source of a data breach.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What types of user activity evidence can be found in the Windows Registry?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** How can database transaction logs be useful in forensic investigations?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** What challenges do investigators face when analyzing web applications and their databases?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** Describe how timeline analysis contributes to understanding a security incident.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **T** - Unencrypted passwords can be visible in network packet captures
2. **T** - Registry contains extensive user activity and system configuration data
3. **F** - Database forensics includes examining deleted data in unallocated space and logs
4. **T** - Some artifacts remain even in private browsing mode (DNS cache, temporary files)
5. **T** - Timeline analysis establishes sequence and relationships between events

### Part B: Multiple Choice
6. **B** - Wireshark (network protocol analyzer)
7. **B** - HKEY_CURRENT_USER (user-specific settings)
8. **D** - All of the above (URLs, downloads, passwords, form data)
9. **A** - Transaction logs (contain record of all database changes)
10. **B** - Complete network traffic including headers and payload
11. **B** - Registry keys and link files (RecentDocs, LNK files)
12. **C** - Content is unreadable without decryption keys
13. **B** - Historical changes and potentially deleted data
14. **C** - Log file analysis and unallocated space examination
15. **D** - All of the above (pages, images, media, content)

### Part C: Short Answer (Sample Answers)
16. Network forensics can trace attack paths by analyzing packet flows, identifying malicious IP addresses, examining data exfiltration patterns, and reconstructing attacker communications to determine breach origin and methods.

17. Windows Registry contains evidence of recently accessed files, installed programs, USB device usage, network connections, user search terms, and system configuration changes that reveal user behavior patterns.

18. Database transaction logs record all data modifications including deletions and updates, allowing investigators to reconstruct data states, recover deleted records, and establish timelines of database activities.

19. Investigators face challenges with dynamic content, encrypted communications, complex application logic, distributed architectures, and the need to understand application-specific data structures and business logic.

20. Timeline analysis correlates events across multiple systems and data sources to establish attack progression, identify patient zero, determine attacker dwell time, and understand the full scope of incident impact.

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