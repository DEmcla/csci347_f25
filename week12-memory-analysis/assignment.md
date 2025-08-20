# Week 12 Assignment: Memory Forensics and Malware Analysis Platform

**Due**: End of Week 12 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Develop a comprehensive memory forensics and malware analysis platform that can analyze volatile memory dumps, detect sophisticated malware techniques, identify rootkits and process injection, and automate malware analysis workflows. Your solution should demonstrate advanced memory analysis capabilities and threat detection techniques.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Memory Dump Analysis** (5 points)
2. **Malware Detection & Classification** (5 points)
3. **Advanced Threat Investigation** (5 points)
4. **Process & Rootkit Analysis** (5 points)
5. **Automated Analysis Pipeline** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build a Python-based memory forensics platform:

```python
# Core modules to implement
memory_analyzer.py      # Core memory dump analysis
malware_detector.py     # Malware signature and behavior detection
threat_hunter.py        # Advanced threat hunting capabilities
rootkit_detector.py     # Rootkit and steganography detection
analysis_pipeline.py    # Automated analysis workflows
```

### Required Libraries
```python
import struct
import hashlib
from datetime import datetime
import re
import json
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
```

## 📝 Detailed Requirements

### 1. Memory Dump Analysis (5 points)

Implement core memory analysis capabilities:

**Required Features:**
- **Process enumeration** with parent-child relationships
- **Network connection** extraction and analysis
- **DLL and handle** enumeration for processes
- **Memory region** analysis (VAD tree simulation)
- **String extraction** with context and filtering

**Deliverable:** `memory_analyzer.py` with comprehensive memory parsing

### 2. Malware Detection & Classification (5 points)

Create advanced malware detection system:

**Required Features:**
- **YARA-style rule** engine for signature detection
- **Behavioral analysis** based on API calls and patterns
- **Packer detection** and unpacking indicators
- **Communication pattern** analysis for C2 detection
- **Malware family** classification using characteristics

**Deliverable:** `malware_detector.py` with detection and classification

### 3. Advanced Threat Investigation (5 points)

Build sophisticated threat hunting capabilities:

**Required Features:**
- **Process injection** detection (hollowing, DLL injection, APC)
- **Privilege escalation** technique identification
- **Lateral movement** indicator detection
- **Persistence mechanism** discovery
- **APT technique** mapping to MITRE ATT&CK framework

**Deliverable:** `threat_hunter.py` with advanced detection algorithms

### 4. Process & Rootkit Analysis (5 points)

Implement rootkit and steganography detection:

**Required Features:**
- **Hidden process** detection using multiple enumeration methods
- **SSDT hook** detection for kernel rootkits
- **Process hollowing** and code injection identification
- **Memory steganography** detection
- **Cross-view analysis** to identify discrepancies

**Deliverable:** `rootkit_detector.py` with anti-rootkit capabilities

### 5. Automated Analysis Pipeline (5 points)

Create comprehensive automation and reporting:

**Required Features:**
- **Multi-stage analysis** pipeline with dependency management
- **IOC extraction** and threat intelligence integration
- **Automated reporting** with executive and technical summaries
- **Similarity analysis** for malware family clustering
- **Batch processing** capabilities for multiple samples

**Deliverable:** `analysis_pipeline.py` with workflow automation

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── memory_analyzer.py
│   ├── malware_detector.py
│   ├── threat_hunter.py
│   ├── rootkit_detector.py
│   ├── analysis_pipeline.py
│   └── ioc_extractor.py
├── rules/
│   ├── malware_signatures.yara
│   ├── behavioral_rules.json
│   └── apt_indicators.json
├── samples/
│   ├── memory_dumps/
│   │   ├── sample1.dmp
│   │   ├── sample2.dmp
│   │   └── sample3.dmp
│   └── test_malware/
├── reports/
│   ├── analysis_001.html
│   ├── ioc_report.json
│   └── executive_summary.pdf
└── README.md
```

### Sample Process Analysis
```python
@dataclass
class Process:
    pid: int
    ppid: int
    name: str
    path: str
    command_line: str
    create_time: datetime
    exit_time: Optional[datetime]
    handles: int
    threads: int
    vad_regions: List[Dict]
    dlls_loaded: List[str]
    
    def is_suspicious(self) -> bool:
        """Detect suspicious process characteristics"""
        suspicious_indicators = []
        
        # Check for process hollowing
        if self.has_hollow_indicators():
            suspicious_indicators.append("Process hollowing detected")
        
        # Check for unusual parent-child relationships
        if self.has_suspicious_parent():
            suspicious_indicators.append("Suspicious parent process")
        
        # Check for code injection indicators
        if self.has_injection_indicators():
            suspicious_indicators.append("Code injection detected")
        
        return len(suspicious_indicators) > 0
    
    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract strings from process memory"""
        # Simulate string extraction from process memory regions
        strings = []
        for vad_region in self.vad_regions:
            if vad_region['protection'] & 0x04:  # Readable
                region_strings = self.extract_region_strings(vad_region)
                strings.extend(region_strings)
        return strings
```

### Sample Malware Detection
```python
class MalwareDetector:
    def __init__(self):
        self.yara_rules = self.load_yara_rules()
        self.behavioral_patterns = self.load_behavioral_patterns()
        self.family_signatures = self.load_family_signatures()
    
    def scan_process(self, process: Process) -> Dict:
        """Comprehensive malware scan of process"""
        results = {
            'pid': process.pid,
            'name': process.name,
            'signature_matches': [],
            'behavioral_indicators': [],
            'family_classification': None,
            'threat_score': 0
        }
        
        # YARA rule scanning
        for rule in self.yara_rules:
            if self.match_yara_rule(process, rule):
                results['signature_matches'].append(rule['name'])
        
        # Behavioral analysis
        behaviors = self.analyze_behavior(process)
        results['behavioral_indicators'] = behaviors
        
        # Family classification
        family = self.classify_family(process, results['signature_matches'], behaviors)
        results['family_classification'] = family
        
        # Calculate threat score
        results['threat_score'] = self.calculate_threat_score(results)
        
        return results
    
    def detect_packer(self, process: Process) -> Optional[str]:
        """Detect if process is packed/encrypted"""
        # Check entropy of executable sections
        entropy = self.calculate_entropy(process.memory_regions)
        
        # Check for packer signatures
        packer_sigs = ['UPX', 'ASPack', 'PECompact', 'Themida']
        for sig in packer_sigs:
            if self.find_signature(process, sig):
                return sig
        
        # High entropy might indicate packing
        if entropy > 7.5:
            return "Unknown Packer (High Entropy)"
        
        return None
```

### Sample Rootkit Detection
```python
class RootkitDetector:
    def detect_hidden_processes(self, process_list: List[Process]) -> List[Dict]:
        """Detect hidden processes using cross-view analysis"""
        hidden_processes = []
        
        # Get process lists from different enumeration methods
        pslist_pids = set(p.pid for p in process_list)
        psscan_pids = self.enumerate_psscan()
        thrdproc_pids = self.enumerate_thrdproc()
        
        # Find discrepancies
        for pid in psscan_pids.union(thrdproc_pids):
            if pid not in pslist_pids:
                hidden_process = self.get_process_details(pid)
                hidden_processes.append({
                    'pid': pid,
                    'detection_method': 'Cross-view analysis',
                    'process_info': hidden_process,
                    'confidence': 0.8
                })
        
        return hidden_processes
    
    def detect_ssdt_hooks(self) -> List[Dict]:
        """Detect System Service Descriptor Table hooks"""
        hooks = []
        
        # Simulate SSDT analysis
        ssdt_entries = self.get_ssdt_table()
        
        for entry in ssdt_entries:
            if self.is_ssdt_entry_hooked(entry):
                hooks.append({
                    'service_id': entry['id'],
                    'service_name': entry['name'],
                    'original_address': entry['original'],
                    'hooked_address': entry['current'],
                    'hooking_module': self.resolve_module(entry['current'])
                })
        
        return hooks
    
    def analyze_vad_anomalies(self, process: Process) -> List[Dict]:
        """Analyze VAD tree for anomalies indicating injection"""
        anomalies = []
        
        for vad in process.vad_regions:
            # Look for unusual memory permissions
            if vad['protection'] == 0x40:  # PAGE_EXECUTE_READWRITE
                anomalies.append({
                    'type': 'Suspicious Memory Permissions',
                    'address': vad['start_address'],
                    'size': vad['size'],
                    'protection': vad['protection'],
                    'description': 'RWX memory region indicates possible code injection'
                })
            
            # Check for private memory with no backing file
            if vad['type'] == 'Private' and not vad['mapped_file']:
                if self.contains_executable_code(vad):
                    anomalies.append({
                        'type': 'Injected Code',
                        'address': vad['start_address'],
                        'size': vad['size'],
                        'description': 'Private executable memory without backing file'
                    })
        
        return anomalies
```

## 🧪 Testing Requirements

Your implementation must include:

### Malware Detection Tests
- **Known malware** detection accuracy
- **Packer detection** validation with samples
- **False positive** rate measurement
- **Behavioral pattern** recognition testing
- **Family classification** accuracy assessment

### Rootkit Detection Tests
- **Hidden process** detection validation
- **Hook detection** accuracy testing
- **Injection technique** identification
- **Cross-view consistency** verification
- **Anti-evasion** technique effectiveness

### Performance and Accuracy Tests
Create comprehensive test suites including:
- Memory dumps with known malware infections
- Clean system baselines for false positive testing
- Rootkit-infected samples with known hiding techniques
- APT simulation scenarios with multi-stage attacks
- Performance benchmarks for large memory dumps

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all memory analysis modules)
2. **Test Memory Dumps** (simulated samples with known characteristics)
3. **Analysis Reports** (generated from test samples)
4. **Rule Sets** (YARA-style rules and behavioral patterns)
5. **Technical Documentation** (README.md with analysis methodologies)

### README.md Must Include:
- **Analysis techniques** used for each detection method
- **Rule development** process and validation
- **Accuracy metrics** and false positive rates
- **Performance benchmarks** and optimization notes
- **Known limitations** and future improvement areas

## 📊 Grading Rubric (25 Points Total)

### 5-Point Scale Criteria

**Memory Dump Analysis (5 points)**
- **Excellent (5)**: Comprehensive memory parsing, accurate process enumeration, detailed VAD analysis, string extraction
- **Proficient (4)**: Good memory analysis, adequate process details, basic VAD handling
- **Developing (3)**: Simple memory parsing, limited process information, basic functionality
- **Needs Improvement (2)**: Poor memory analysis, significant gaps, accuracy issues
- **Inadequate (1)**: Minimal memory capabilities, major functionality missing

**Malware Detection & Classification (5 points)**
- **Excellent (5)**: Sophisticated detection engine, high accuracy, comprehensive family classification, behavioral analysis
- **Proficient (4)**: Good detection capabilities, adequate accuracy, basic classification
- **Developing (3)**: Simple detection rules, limited accuracy, basic functionality
- **Needs Improvement (2)**: Poor detection rates, weak classification, significant limitations
- **Inadequate (1)**: Minimal detection capabilities, major accuracy issues

**Advanced Threat Investigation (5 points)**
- **Excellent (5)**: Advanced injection detection, comprehensive APT mapping, MITRE ATT&CK integration, high accuracy
- **Proficient (4)**: Good threat detection, adequate technique mapping, reasonable accuracy
- **Developing (3)**: Basic threat hunting, limited technique detection, simple functionality
- **Needs Improvement (2)**: Poor threat detection, weak technique mapping, low accuracy
- **Inadequate (1)**: Minimal threat hunting capabilities, major gaps

**Process & Rootkit Analysis (5 points)**
- **Excellent (5)**: Advanced rootkit detection, comprehensive hook analysis, cross-view validation, steganography detection
- **Proficient (4)**: Good rootkit detection, basic hook analysis, adequate cross-view
- **Developing (3)**: Simple rootkit detection, limited analysis, basic functionality
- **Needs Improvement (2)**: Poor rootkit detection, weak analysis, significant limitations
- **Inadequate (1)**: Minimal rootkit capabilities, major detection gaps

**Automated Analysis Pipeline (5 points)**
- **Excellent (5)**: Comprehensive automation, professional reporting, IOC extraction, batch processing, high reliability
- **Proficient (4)**: Good automation, adequate reporting, basic IOC extraction
- **Developing (3)**: Simple automation, limited reporting, basic functionality
- **Needs Improvement (2)**: Poor automation, weak reporting, significant limitations
- **Inadequate (1)**: Minimal automation capabilities, major functionality gaps

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Bonus Opportunities (+2 points max)

- **Machine Learning**: ML-based malware detection and classification
- **Hypervisor Detection**: Virtual machine and sandbox evasion detection
- **Advanced Visualization**: Interactive memory layout and process trees
- **Real-time Analysis**: Streaming memory analysis capabilities
- **Threat Intelligence**: Integration with external threat feeds

## 💡 Tips for Success

1. **Study Volatility**: Understand how professional tools work
2. **Test with Real Samples**: Use actual malware samples when possible (safely)
3. **Focus on Accuracy**: False positives are as bad as false negatives
4. **Document Techniques**: Explain your detection methodologies
5. **Optimize Performance**: Memory analysis can be resource-intensive
6. **Validate Results**: Cross-check findings with known analysis tools

## 📚 Resources & Required Tools

### Open Source Tools (All Free)
- **Volatility 3** - https://github.com/volatilityfoundation/volatility3
- **YARA** - https://github.com/VirusTotal/yara (BSD 3-Clause License)
- **MITRE ATT&CK** - https://attack.mitre.org/ (Apache 2.0 License)
- **Python Libraries** - pandas, matplotlib, numpy (all free)

### Reference Materials
- The Art of Memory Forensics (Michael Hale Ligh)
- Volatility Framework Documentation
- YARA Rule Writing Guide
- MITRE ATT&CK Framework
- Practical Malware Analysis (Michael Sikorski)
- Rootkits and Bootkits (Alex Matrosov)

### 🚨 IMPORTANT: Tool Access Issues

**If you encounter ANY issues accessing these tools** (installation problems, licensing concerns, broken links, etc.), **please contact the instructor IMMEDIATELY**. We will:
- Provide alternative free tools
- Update the assignment directions
- Ensure no student faces barriers to completing the assignment

**Do not struggle in silence** - reach out as soon as you encounter any access problems!

---

**Uncover the secrets hidden in volatile memory!** 🧠🔍