# Week 13 Quiz: Mobile Device and Cloud Forensics

**Total Points**: 25 points  
**Time Limit**: 30 minutes  
**Format**: 5 True/False (1pt each), 10 Multiple Choice (1pt each), 5 Short Answer (2pts each)

---

## Part A: True/False Questions (5 points)
*1 point each. Write T for True or F for False.*

**1.** Android applications store data in SQLite databases that can be analyzed forensically.  
**Answer**: ______

**2.** iOS backups are always encrypted and cannot be analyzed without the device passcode.  
**Answer**: ______

**3.** Cloud synchronization can provide additional evidence not available on the physical device.  
**Answer**: ______

**4.** Jailbreaking an iPhone removes all security protections and makes forensic analysis easier.  
**Answer**: ______

**5.** Mobile app data is completely deleted when an app is uninstalled from a device.  
**Answer**: ______

---

## Part B: Multiple Choice Questions (10 points)
*1 point each. Choose the best answer.*

**6.** Which file system is commonly used by Android devices?
- A) NTFS
- B) HFS+
- C) ext4
- D) FAT32

**Answer**: ______

**7.** What type of data can typically be recovered from mobile device SMS databases?
- A) Message content only
- B) Sender/receiver phone numbers only
- C) Message content, timestamps, and contact information
- D) Only deleted messages

**Answer**: ______

**8.** In iOS forensics, what file format is commonly used for device backups?
- A) ZIP
- B) TAR
- C) Property List (plist)
- D) JSON

**Answer**: ______

**9.** Which cloud service is NOT commonly analyzed in mobile forensics?
- A) iCloud
- B) Google Drive
- C) Dropbox
- D) Blockchain networks

**Answer**: ______

**10.** What information can be extracted from mobile device WiFi connection logs?
- A) Only current connections
- B) Network names and connection timestamps
- C) Passwords for all networks
- D) Only failed connection attempts

**Answer**: ______

**11.** Which mobile forensics challenge is unique to encrypted devices?
- A) Physical damage
- B) Battery life limitations
- C) Inability to access locked bootloaders
- D) Network connectivity issues

**Answer**: ______

**12.** What can mobile app cache files reveal during forensic analysis?
- A) Source code of applications
- B) Previously viewed content and user interactions
- C) Developer credentials
- D) App store purchase history

**Answer**: ______

**13.** In Android forensics, where are application-specific data files typically stored?
- A) /system/app/
- B) /data/data/[package_name]/
- C) /sdcard/
- D) /cache/

**Answer**: ______

**14.** Which technique is most effective for analyzing cloud storage synchronization?
- A) Physical device imaging only
- B) Logical extraction combined with cloud account analysis
- C) Network packet capture only
- D) Operating system reinstallation

**Answer**: ______

**15.** What is a significant legal consideration when conducting mobile device forensics?
- A) Device warranty status
- B) Privacy laws and warrant requirements
- C) Battery level during acquisition
- D) Operating system version

**Answer**: ______

---

## Part C: Short Answer Questions (10 points)
*2 points each. Answer in 1-2 sentences.*

**16.** Explain how cloud storage synchronization can both help and complicate mobile forensics investigations.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**17.** What are the main differences between logical and physical extraction methods for mobile devices?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**18.** How can mobile messaging app data provide evidence in forensic investigations?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**19.** What challenges do investigators face when analyzing data from multiple mobile platforms (Android vs. iOS)?

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

**20.** Describe how mobile device location data can be valuable in forensic investigations.

**Answer**:
_____________________________________________________________________________
_____________________________________________________________________________

---

## Answer Key (Instructor Use Only)

### Part A: True/False
1. **T** - Android apps commonly use SQLite databases for local data storage
2. **F** - iOS backups can be encrypted or unencrypted depending on user settings
3. **T** - Cloud sync provides additional data sources and historical information
4. **F** - Jailbreaking provides more access but doesn't remove all security protections
5. **F** - App data may remain in unallocated space and can sometimes be recovered

### Part B: Multiple Choice
6. **C** - ext4 (Fourth Extended File System)
7. **C** - Message content, timestamps, and contact information
8. **C** - Property List (plist) format
9. **D** - Blockchain networks (not a traditional cloud storage service)
10. **B** - Network names and connection timestamps
11. **C** - Inability to access locked bootloaders
12. **B** - Previously viewed content and user interactions
13. **B** - /data/data/[package_name]/ (app-specific data directory)
14. **B** - Logical extraction combined with cloud account analysis
15. **B** - Privacy laws and warrant requirements

### Part C: Short Answer (Sample Answers)
16. Cloud synchronization helps by providing additional data sources and historical information that may not be on the device, but complicates investigations by requiring analysis of multiple platforms and dealing with different data formats and access controls.

17. Logical extraction accesses data through the device's operating system interfaces and file system, while physical extraction creates bit-by-bit copies of device storage, potentially recovering deleted data and bypassing some security protections.

18. Mobile messaging apps contain communication records, multimedia files, contact lists, and metadata that can establish relationships, timelines, and evidence of criminal activity or policy violations.

19. Investigators must deal with different file systems, data structures, security models, and forensic tools for each platform, requiring specialized knowledge and potentially different acquisition and analysis procedures.

20. Mobile location data can establish device presence at specific locations and times, track movement patterns, provide alibis or contradict statements, and help reconstruct events during investigations.

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