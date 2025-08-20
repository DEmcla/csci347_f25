# Week 10 Assignment: Digital Forensics Laboratory

**Due Date**: End of Week 10  
**Total Points**: 25  
**Estimated Time**: 3-4 hours  
**Submission**: Pull Request with forensics lab implementation

## 🎯 Assignment Overview

Build a comprehensive digital forensics laboratory that demonstrates proper evidence handling, analysis, and reporting. You'll create a forensics toolkit that can acquire evidence, maintain chain of custody, perform timeline analysis, and generate professional reports.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Evidence Acquisition & Preservation** (5 points)
2. **File System Analysis** (5 points)
3. **Timeline & Artifact Recovery** (5 points)
4. **Forensic Reporting** (5 points)
5. **Chain of Custody Management** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build a Python-based forensics platform with these components:

```python
# Core modules to implement
evidence_manager.py     # Evidence acquisition and preservation
filesystem_analyzer.py  # File system parsing and analysis
timeline_builder.py     # Event timeline reconstruction
artifact_extractor.py   # Deleted file and metadata recovery
forensic_reporter.py    # Professional report generation
```

### Required Libraries
```python
import hashlib
import sqlite3
from datetime import datetime
import os
import struct
from typing import Dict, List, Optional, Tuple
import json
import pandas as pd
from dataclasses import dataclass
```

## 📝 Detailed Requirements

### 1. Evidence Acquisition & Preservation (5 points)

Implement forensically sound evidence handling:

**Required Features:**
- **Disk imaging** with verification (simulate with file copying)
- **Hash verification** using multiple algorithms (MD5, SHA-256, SHA-512)
- **Write blocking** simulation to prevent evidence contamination
- **Evidence integrity** monitoring throughout analysis
- **Acquisition logging** with timestamps and operator information

**Deliverable:** `evidence_manager.py` with imaging and verification capabilities

### 2. File System Analysis (5 points)

Create comprehensive file system examination tools:

**Required Features:**
- **File system parsing** (simulate NTFS/ext4 structures)
- **Directory tree reconstruction** with deleted entries
- **File metadata extraction** (timestamps, permissions, size)
- **Slack space analysis** for hidden data
- **Master file table** simulation and analysis

**Deliverable:** `filesystem_analyzer.py` with parsing and analysis functions

### 3. Timeline & Artifact Recovery (5 points)

Build timeline reconstruction and artifact recovery:

**Required Features:**
- **Timeline generation** from file system timestamps
- **Deleted file recovery** using file signatures
- **File carving** for fragmented files
- **Registry artifact** simulation (Windows-style)
- **Browser history** reconstruction from databases

**Deliverable:** `timeline_builder.py` and `artifact_extractor.py`

### 4. Forensic Reporting (5 points)

Generate professional forensic investigation reports:

**Required Features:**
- **Executive summary** with key findings
- **Technical analysis** with detailed evidence
- **Timeline reports** in multiple formats
- **Evidence catalog** with hash verification
- **Chain of custody** documentation

**Deliverable:** `forensic_reporter.py` with multiple report formats

### 5. Chain of Custody Management (5 points)

Implement complete chain of custody tracking:

**Required Features:**
- **Evidence tracking** from acquisition to analysis
- **Operator logging** with authentication
- **Action auditing** with timestamps
- **Transfer documentation** between analysts
- **Integrity verification** at each step

**Deliverable:** Chain of custody system integrated across all modules

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── evidence_manager.py
│   ├── filesystem_analyzer.py
│   ├── timeline_builder.py
│   ├── artifact_extractor.py
│   ├── forensic_reporter.py
│   └── chain_of_custody.py
├── evidence/
│   ├── case_001/
│   │   ├── original_image.dd
│   │   ├── working_copy.dd
│   │   └── hash_verification.log
│   └── case_002/
├── reports/
│   ├── executive_summary.pdf
│   ├── technical_analysis.html
│   ├── timeline.csv
│   └── evidence_catalog.xlsx
└── README.md
```

### Sample Evidence Class
```python
@dataclass
class EvidenceItem:
    evidence_id: str
    case_number: str
    description: str
    source_location: str
    acquisition_date: datetime
    acquisition_method: str
    hash_md5: str
    hash_sha256: str
    file_size: int
    chain_of_custody: List[Dict]
    
    def verify_integrity(self) -> bool:
        """Verify evidence hasn't been tampered with"""
        current_hash = self.calculate_hash()
        return current_hash == self.hash_sha256
```

### Sample File System Entry
```python
@dataclass
class FileSystemEntry:
    inode: int
    filename: str
    file_path: str
    file_size: int
    created_time: datetime
    modified_time: datetime
    accessed_time: datetime
    deleted: bool
    file_type: str
    permissions: str
    
    def recover_deleted_file(self) -> bytes:
        """Attempt to recover deleted file data"""
        if self.deleted:
            return self.carve_from_unallocated_space()
        return None
```

### Timeline Event Structure
```python
@dataclass
class TimelineEvent:
    timestamp: datetime
    event_type: str  # file_created, file_modified, file_deleted, etc.
    source: str      # filesystem, registry, browser, etc.
    description: str
    file_path: str
    evidence_reference: str
    confidence: float  # 0-1 scale
    
    def to_timeline_format(self) -> Dict:
        """Convert to standard timeline format"""
        return {
            'date': self.timestamp.isoformat(),
            'time': self.timestamp.strftime('%H:%M:%S'),
            'timezone': 'UTC',
            'macb': self.determine_macb_type(),
            'source': self.source,
            'sourcetype': self.event_type,
            'type': self.file_type,
            'user': self.extract_user(),
            'host': self.extract_hostname(),
            'short': self.short_description(),
            'desc': self.description,
            'version': '2',
            'filename': self.file_path,
            'inode': self.get_inode(),
            'notes': self.additional_notes(),
            'format': 'l2tcsv',
            'extra': {}
        }
```

## 🧪 Testing Requirements

Your implementation must include:

### Forensic Validation Tests
- **Hash verification** accuracy across multiple algorithms
- **Timeline accuracy** with known test data
- **File recovery** success rate measurement
- **Chain of custody** integrity verification
- **Report generation** completeness testing

### Evidence Integrity Tests
- **Write protection** verification during analysis
- **Original evidence** preservation testing
- **Working copy** consistency verification
- **Metadata preservation** during processing
- **Audit trail** completeness validation

### Sample Test Cases
Create realistic test scenarios including:
- Simulated disk image with known files
- Deleted file recovery scenarios
- Registry-style artifact databases
- Browser history simulation
- Timeline correlation across multiple sources

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all Python forensics modules)
2. **Test Evidence** (simulated disk images and test data)
3. **Sample Reports** (generated from test cases)
4. **Documentation** (README.md with forensic procedures)
5. **Demo Video** (5-minute investigation walkthrough)

### README.md Must Include:
- **Forensic procedures** followed in implementation
- **Tool validation** methods and results
- **Known limitations** and accuracy considerations
- **Usage instructions** for each analysis module
- **Test case descriptions** and expected outcomes

## 📊 Grading Rubric (25 Points Total)

### 5-Point Scale Criteria

**Evidence Acquisition & Preservation (5 points)**
- **Excellent (5)**: Perfect forensic procedures, multiple hash algorithms, comprehensive logging, write protection
- **Proficient (4)**: Good evidence handling, adequate hashing, proper logging
- **Developing (3)**: Basic evidence management, simple hashing, limited logging
- **Needs Improvement (2)**: Poor evidence handling, weak verification, inadequate logging
- **Inadequate (1)**: Non-forensic procedures, no verification, missing key components

**File System Analysis (5 points)**
- **Excellent (5)**: Sophisticated parsing, accurate metadata extraction, slack space analysis, deleted file detection
- **Proficient (4)**: Good file system analysis, adequate metadata, basic deleted file handling
- **Developing (3)**: Simple file parsing, limited metadata, basic functionality
- **Needs Improvement (2)**: Poor parsing accuracy, missing metadata, significant limitations
- **Inadequate (1)**: Minimal file system support, major functionality gaps

**Timeline & Artifact Recovery (5 points)**
- **Excellent (5)**: Comprehensive timeline, advanced file carving, multiple artifact sources, high accuracy
- **Proficient (4)**: Good timeline generation, basic file carving, adequate artifacts
- **Developing (3)**: Simple timeline, limited recovery, basic artifacts
- **Needs Improvement (2)**: Poor timeline accuracy, weak recovery, minimal artifacts
- **Inadequate (1)**: Inadequate timeline, no recovery capabilities, missing artifacts

**Forensic Reporting (5 points)**
- **Excellent (5)**: Professional reports, multiple formats, executive summaries, comprehensive evidence catalogs
- **Proficient (4)**: Good reports, adequate formatting, clear presentations
- **Developing (3)**: Basic reports, simple formatting, limited detail
- **Needs Improvement (2)**: Poor report quality, inadequate formatting, missing information
- **Inadequate (1)**: Unprofessional reports, major gaps, unusable output

**Chain of Custody Management (5 points)**
- **Excellent (5)**: Complete custody tracking, operator authentication, comprehensive auditing, transfer documentation
- **Proficient (4)**: Good custody management, adequate tracking, basic auditing
- **Developing (3)**: Basic custody tracking, limited auditing, simple logging
- **Needs Improvement (2)**: Poor custody management, inadequate tracking, weak auditing
- **Inadequate (1)**: No proper custody procedures, missing documentation, unreliable tracking

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Bonus Opportunities (+2 points max)

- **Advanced File Carving**: Reconstruct fragmented files across multiple clusters
- **Network Artifacts**: Analyze network connection logs and packet traces
- **Encryption Handling**: Detect and document encrypted files and volumes
- **Mobile Simulation**: Add smartphone-style artifact analysis
- **Advanced Visualization**: Interactive timeline and file system browsers

## 💡 Tips for Success

1. **Study Real Tools**: Understand how Autopsy, FTK, and EnCase work
2. **Focus on Accuracy**: Forensic tools must be precise and reliable
3. **Document Everything**: Chain of custody is critical for legal validity
4. **Test Thoroughly**: Validate your tools with known test data
5. **Professional Reports**: Format matters for court presentation
6. **Follow Standards**: Adhere to NIST and ISO forensic guidelines

## 📚 Resources

- NIST SP 800-86: Computer Forensics Guidelines
- ISO/IEC 27037: Digital Evidence Guidelines
- Autopsy Digital Forensics Platform Documentation
- File System Forensics Analysis (Brian Carrier)
- Digital Forensics with Open Source Tools

---

**Build your forensic investigation platform with precision and integrity!** 🔍⚖️