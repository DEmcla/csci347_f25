# Week 12 Quiz: Memory Forensics and Malware Analysis

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** Memory dumps must be acquired from a powered-on system to capture volatile data.  
**Answer**: ______

**2.** Volatility Framework can analyze memory dumps from multiple operating systems.  
**Answer**: ______

**3.** Process injection techniques can be detected through memory analysis.  
**Answer**: ______

**4.** Rootkits always leave traces in memory that can be detected by standard tools.  
**Answer**: ______

**5.** Memory forensics can reveal network connections that are no longer active.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** What is the primary advantage of memory forensics over disk forensics?
- A) Memory analysis is faster
- B) Memory contains live system state and running processes
- C) Memory analysis requires fewer tools
- D) Memory is easier to acquire

**Answer**: ______

**7.** Which Volatility plugin is used to list running processes?
- A) pslist
- B) netstat
- C) filescan
- D) malfind

**Answer**: ______

**8.** What type of malware specifically targets system memory to avoid disk detection?
- A) Trojans
- B) Fileless malware
- C) Adware
- D) Ransomware

**Answer**: ______

**9.** In process hollowing, what does the malware do?
- A) Deletes the original process
- B) Creates a new process
- C) Replaces legitimate process code with malicious code
- D) Encrypts the process memory

**Answer**: ______

**10.** Which memory artifact can reveal recently typed passwords?
- A) Process list
- B) Network connections
- C) Keyboard buffer
- D) Registry keys

**Answer**: ______

**11.** What does the "malfind" Volatility plugin specifically look for?
- A) Network connections
- B) Hidden processes
- C) Injected code and suspicious memory regions
- D) File system artifacts

**Answer**: ______

**12.** Which technique do advanced rootkits use to hide from detection?
- A) SSDT (System Service Descriptor Table) hooking
- B) File compression
- C) Network encryption
- D) Log deletion

**Answer**: ______

**13.** What information can be extracted from a process's Virtual Address Descriptor (VAD) tree?
- A) Network connections only
- B) Memory regions, permissions, and mapped files
- C) CPU usage statistics
- D) Disk I/O operations

**Answer**: ______

**14.** Which type of memory analysis technique compares different process enumeration methods?
- A) String analysis
- B) Cross-view detection
- C) Hash analysis
- D) Timeline analysis

**Answer**: ______

**15.** What is a common indicator of process injection in memory analysis?
- A) High CPU usage
- B) Unusual memory permissions (RWX)
- C) Large file sizes
- D) Network timeouts

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain why memory analysis is crucial for detecting advanced persistent threats (APTs).

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What challenges do investigators face when analyzing encrypted memory dumps?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** How can memory forensics help identify the source of a security incident?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** What is the difference between user mode and kernel mode rootkits from a detection perspective?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** Describe how automated memory analysis pipelines improve incident response capabilities.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **T** - Memory dumps require a powered-on system to capture volatile data
2. **T** - Volatility supports Windows, Linux, macOS, and other operating systems
3. **T** - Process injection leaves detectable signatures in memory structures
4. **F** - Advanced rootkits can use sophisticated hiding techniques to avoid detection
5. **T** - Memory retains network connection artifacts even after connections close

### Part B: Multiple Choice
6. **B** - Memory contains live system state and running processes
7. **A** - pslist (lists running processes)
8. **B** - Fileless malware (operates entirely in memory)
9. **C** - Replaces legitimate process code with malicious code
10. **C** - Keyboard buffer (may contain recently typed text)
11. **C** - Injected code and suspicious memory regions
12. **A** - SSDT (System Service Descriptor Table) hooking
13. **B** - Memory regions, permissions, and mapped files
14. **B** - Cross-view detection (compares different enumeration methods)
15. **B** - Unusual memory permissions (RWX - Read/Write/Execute)

### Part C: Short Answer (Sample Answers)
16. APTs use sophisticated techniques like fileless malware and living-off-the-land tactics that primarily exist in memory, making memory analysis essential for detecting these advanced threats that avoid traditional disk-based detection.

17. Encrypted memory dumps require specialized techniques to extract keys, may have limited tool support, and can prevent access to critical evidence unless decryption keys are available or encryption can be bypassed.

18. Memory forensics can identify malicious processes, reveal attack vectors, extract network indicators of compromise, recover deleted artifacts, and establish attack timelines by analyzing the live system state at the time of acquisition.

19. User mode rootkits operate in application space and are easier to detect through standard process analysis, while kernel mode rootkits operate at the operating system level and require specialized detection techniques due to their privileged access.

20. Automated pipelines enable rapid analysis of large memory dumps, consistent application of analysis techniques, faster threat detection and response times, and scalable processing of multiple incidents simultaneously.

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