# Week 7 Quiz: Security Monitoring and SIEM

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** SIEM stands for Security Information and Event Management.  
**Answer**: ______

**2.** Log correlation is the process of identifying relationships between events across different systems.  
**Answer**: ______

**3.** False positives in security monitoring are preferable to false negatives.  
**Answer**: ______

**4.** Network traffic analysis only looks at packet headers, not payload content.  
**Answer**: ______

**5.** A Security Operations Center (SOC) typically operates only during business hours.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** What is the primary purpose of log normalization in SIEM systems?
- A) To reduce log file sizes
- B) To encrypt sensitive log data
- C) To convert logs into a standard format for analysis
- D) To delete old log entries

**Answer**: ______

**7.** Which of the following is NOT a common log source for security monitoring?
- A) Firewall logs
- B) DNS query logs
- C) Printer usage logs
- D) Authentication logs

**Answer**: ______

**8.** What does an IDS primarily do?
- A) Prevent all network attacks
- B) Detect and alert on suspicious activities
- C) Automatically block malicious traffic
- D) Encrypt network communications

**Answer**: ______

**9.** In network traffic analysis, what does DPI stand for?
- A) Data Protection Interface
- B) Deep Packet Inspection
- C) Direct Protocol Integration
- D) Dynamic Port Identification

**Answer**: ______

**10.** Which metric is most important for measuring SIEM effectiveness?
- A) Number of logs collected per day
- B) Storage capacity utilized
- C) Mean Time to Detection (MTTD)
- D) Number of dashboards created

**Answer**: ______

**11.** What is the difference between signature-based and anomaly-based detection?
- A) Signature-based is faster but anomaly-based is more accurate
- B) Signature-based detects known threats, anomaly-based detects unusual behavior
- C) There is no difference between them
- D) Signature-based works only on encrypted traffic

**Answer**: ______

**12.** Which protocol is commonly used for centralized log collection?
- A) HTTP
- B) FTP
- C) Syslog
- D) SMTP

**Answer**: ______

**13.** What is a baseline in security monitoring?
- A) The minimum security requirements
- B) Normal patterns of network and system behavior
- C) The lowest alert priority level
- D) Emergency response procedures

**Answer**: ______

**14.** Which of the following best describes threat hunting?
- A) Waiting for alerts to trigger
- B) Proactively searching for hidden threats
- C) Automatically blocking suspicious IPs
- D) Installing security patches

**Answer**: ______

**15.** What is the main advantage of using machine learning in security monitoring?
- A) It reduces hardware costs
- B) It eliminates the need for security analysts
- C) It can detect previously unknown attack patterns
- D) It makes systems completely secure

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain the difference between an IDS and an IPS.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** Why is log retention important for security monitoring and compliance?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** What are the key components of an effective security monitoring program?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** How does network segmentation improve security monitoring capabilities?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** Describe one challenge faced when implementing behavioral analysis in security monitoring.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **T** - Security Information and Event Management
2. **T** - Log correlation identifies relationships between events
3. **F** - False negatives (missed threats) are typically more dangerous than false positives
4. **F** - Deep packet inspection examines payload content as well
5. **F** - SOCs typically operate 24/7

### Part B: Multiple Choice
6. **C** - To convert logs into a standard format for analysis
7. **C** - Printer usage logs (not security-relevant)
8. **B** - Detect and alert on suspicious activities
9. **B** - Deep Packet Inspection
10. **C** - Mean Time to Detection (MTTD)
11. **B** - Signature-based detects known threats, anomaly-based detects unusual behavior
12. **C** - Syslog protocol
13. **B** - Normal patterns of network and system behavior
14. **B** - Proactively searching for hidden threats
15. **C** - It can detect previously unknown attack patterns

### Part C: Short Answer (Sample Answers)
16. IDS (Intrusion Detection System) monitors and alerts on threats but doesn't block them, while IPS (Intrusion Prevention System) actively blocks or prevents detected threats in real-time.

17. Log retention is essential for forensic investigations, compliance requirements, and trend analysis to understand attack patterns over extended periods.

18. Key components include log collection and aggregation, correlation and analysis, alerting and notification, incident response capabilities, and continuous monitoring and tuning.

19. Network segmentation creates distinct monitoring zones, making it easier to detect lateral movement and contain threats while reducing the volume of traffic to analyze.

20. One challenge is establishing accurate baselines for normal behavior, as user and system behaviors can vary significantly and change over time, leading to false positives.

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