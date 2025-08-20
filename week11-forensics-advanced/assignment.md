# Week 11 Assignment: Advanced Multi-Source Forensic Analysis

**Due**: End of Week 11 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Develop an advanced forensic analysis platform capable of investigating complex multi-source evidence including network traffic, database artifacts, web applications, and system logs. Your solution should demonstrate sophisticated correlation techniques, advanced artifact recovery, and comprehensive incident reconstruction capabilities.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Network Forensics Analysis** (5 points)
2. **Database Forensics & Recovery** (5 points)
3. **Web Application Investigation** (5 points)
4. **Cross-Source Correlation** (5 points)
5. **Advanced Timeline Reconstruction** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build a Python-based advanced forensics platform:

```python
# Core modules to implement
network_analyzer.py     # Network packet and flow analysis
database_forensics.py   # Database artifact recovery and analysis
webapp_investigator.py  # Web application log and session analysis
correlation_engine.py   # Cross-source evidence correlation
timeline_correlator.py  # Advanced timeline reconstruction
```

### Required Libraries
```python
import scapy.all as scapy
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
import matplotlib.pyplot as plt
import networkx as nx
```

## 📝 Detailed Requirements

### 1. Network Forensics Analysis (5 points)

Implement comprehensive network traffic analysis:

**Required Features:**
- **Packet capture** parsing and analysis (using simulated PCAP data)
- **Protocol analysis** (HTTP, DNS, TCP, UDP traffic patterns)
- **Connection tracking** and session reconstruction
- **Suspicious activity** detection (port scans, data exfiltration)
- **Network timeline** generation with traffic flow visualization

**Deliverable:** `network_analyzer.py` with packet analysis and visualization

### 2. Database Forensics & Recovery (5 points)

Create advanced database investigation capabilities:

**Required Features:**
- **Transaction log** analysis and rollback simulation
- **Deleted record** recovery from unallocated space
- **Schema reconstruction** from fragments
- **User activity** tracking through database logs
- **Data modification** timeline with before/after comparisons

**Deliverable:** `database_forensics.py` with recovery and analysis functions

### 3. Web Application Investigation (5 points)

Build web application forensic analysis tools:

**Required Features:**
- **Web server log** parsing and analysis (Apache/Nginx format)
- **Session tracking** and user behavior analysis
- **Attack pattern** detection (SQL injection, XSS attempts)
- **File upload** analysis and malware detection simulation
- **Application timeline** reconstruction from multiple log sources

**Deliverable:** `webapp_investigator.py` with log analysis and attack detection

### 4. Cross-Source Correlation (5 points)

Implement evidence correlation across different sources:

**Required Features:**
- **Timestamp synchronization** across different systems
- **User activity** correlation between network, database, and web logs
- **Attack chain** reconstruction linking multiple evidence sources
- **Confidence scoring** for correlation matches
- **Relationship mapping** between different types of evidence

**Deliverable:** `correlation_engine.py` with advanced correlation algorithms

### 5. Advanced Timeline Reconstruction (5 points)

Create comprehensive timeline analysis with correlation:

**Required Features:**
- **Multi-source timeline** integration (network, database, web, system)
- **Event clustering** to identify related activities
- **Gap analysis** to detect missing or destroyed evidence
- **Pattern recognition** for recurring suspicious activities
- **Interactive visualization** of complex timelines

**Deliverable:** `timeline_correlator.py` with advanced visualization

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── network_analyzer.py
│   ├── database_forensics.py
│   ├── webapp_investigator.py
│   ├── correlation_engine.py
│   ├── timeline_correlator.py
│   └── evidence_parser.py
├── data/
│   ├── network/
│   │   ├── packets.pcap (simulated)
│   │   └── flow_data.csv
│   ├── database/
│   │   ├── transaction_log.sql
│   │   └── user_activity.db
│   ├── webapp/
│   │   ├── access.log
│   │   ├── error.log
│   │   └── application.log
│   └── system/
│       ├── syslog.txt
│       └── event_log.csv
├── analysis/
│   ├── correlation_results.json
│   ├── timeline.html
│   └── investigation_report.pdf
└── README.md
```

### Sample Network Analysis
```python
@dataclass
class NetworkConnection:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: datetime
    end_time: Optional[datetime]
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    
    def duration(self) -> timedelta:
        if self.end_time:
            return self.end_time - self.start_time
        return timedelta(0)
    
    def is_suspicious(self) -> bool:
        """Detect suspicious connection patterns"""
        # High data transfer
        if self.bytes_sent > 100_000_000:  # 100MB
            return True
        # Unusual ports
        if self.dst_port in [4444, 5555, 6666, 31337]:
            return True
        # Long-duration connections
        if self.duration().total_seconds() > 3600:  # 1 hour
            return True
        return False
```

### Sample Database Recovery
```python
class DatabaseForensics:
    def recover_deleted_records(self, db_path: str, table: str) -> List[Dict]:
        """Recover deleted records from unallocated space"""
        recovered_records = []
        
        # Simulate scanning unallocated database pages
        with open(db_path, 'rb') as f:
            content = f.read()
            
        # Look for record fragments using schema patterns
        record_pattern = self.build_record_pattern(table)
        matches = re.finditer(record_pattern, content)
        
        for match in matches:
            record_data = self.parse_record_fragment(match.group())
            if record_data and self.validate_record(record_data):
                recovered_records.append(record_data)
        
        return recovered_records
    
    def analyze_transaction_log(self, log_path: str) -> List[Dict]:
        """Analyze database transaction logs for user activity"""
        transactions = []
        
        with open(log_path, 'r') as f:
            for line in f:
                if 'BEGIN TRANSACTION' in line or 'COMMIT' in line or 'ROLLBACK' in line:
                    tx_info = self.parse_transaction_line(line)
                    transactions.append(tx_info)
        
        return self.correlate_transactions(transactions)
```

### Sample Correlation Engine
```python
class CorrelationEngine:
    def correlate_events(self, events: List[Dict]) -> List[Dict]:
        """Correlate events across different sources"""
        correlations = []
        
        # Group events by timestamp windows
        time_windows = self.create_time_windows(events, window_size=300)  # 5-minute windows
        
        for window in time_windows:
            # Find related events within the same time window
            related_events = self.find_related_events(window)
            
            if len(related_events) > 1:
                correlation = {
                    'correlation_id': self.generate_correlation_id(),
                    'time_window': window['start_time'],
                    'events': related_events,
                    'confidence_score': self.calculate_confidence(related_events),
                    'attack_pattern': self.identify_attack_pattern(related_events),
                    'affected_systems': self.extract_affected_systems(related_events)
                }
                correlations.append(correlation)
        
        return correlations
    
    def find_related_events(self, events: List[Dict]) -> List[Dict]:
        """Find events that are likely related"""
        related = []
        
        # Group by common attributes
        ip_groups = self.group_by_attribute(events, 'source_ip')
        user_groups = self.group_by_attribute(events, 'username')
        
        # Find events with shared IPs or users
        for group in ip_groups.values():
            if len(group) > 1:
                related.extend(group)
        
        for group in user_groups.values():
            if len(group) > 1:
                related.extend(group)
        
        return list(set(related))
```

## 🧪 Testing Requirements

Your implementation must include:

### Advanced Analysis Tests
- **Network pattern** detection accuracy
- **Database recovery** success rate validation
- **Web attack** detection verification
- **Correlation accuracy** with known test scenarios
- **Timeline precision** across multiple sources

### Cross-Validation Tests
- **Multi-source consistency** checking
- **Timeline synchronization** accuracy
- **Evidence relationship** validation
- **Attack pattern** recognition testing
- **False positive** rate measurement

### Complex Scenario Testing
Create sophisticated test scenarios including:
- Multi-stage cyber attack simulation
- Database manipulation with log covering
- Network exfiltration with timing analysis
- Web application compromise investigation
- Insider threat detection scenarios

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all forensics analysis modules)
2. **Test Data Sets** (simulated network, database, and web evidence)
3. **Analysis Results** (correlation reports and timelines)
4. **Documentation** (README.md with analysis methodologies)
5. **Case Study** (detailed investigation of complex scenario)

### README.md Must Include:
- **Analysis methodologies** used for each evidence type
- **Correlation algorithms** and confidence scoring explanations
- **Tool validation** results and accuracy metrics
- **Complex scenario** investigation walkthrough
- **Limitations** and areas for improvement

## 📊 Grading Rubric (25 Points Total)

### 5-Point Scale Criteria

**Network Forensics Analysis (5 points)**
- **Excellent (5)**: Comprehensive packet analysis, protocol reconstruction, sophisticated attack detection, visualization
- **Proficient (4)**: Good network analysis, adequate protocol handling, basic attack detection
- **Developing (3)**: Simple packet parsing, limited protocol analysis, basic functionality
- **Needs Improvement (2)**: Poor network analysis, significant limitations, accuracy issues
- **Inadequate (1)**: Minimal network capabilities, major functionality gaps

**Database Forensics & Recovery (5 points)**
- **Excellent (5)**: Advanced recovery techniques, transaction analysis, comprehensive user tracking, high accuracy
- **Proficient (4)**: Good recovery capabilities, basic transaction analysis, adequate tracking
- **Developing (3)**: Simple recovery, limited transaction analysis, basic functionality
- **Needs Improvement (2)**: Poor recovery rates, inadequate analysis, significant limitations
- **Inadequate (1)**: Minimal database forensics, major gaps in functionality

**Web Application Investigation (5 points)**
- **Excellent (5)**: Sophisticated log analysis, comprehensive attack detection, session tracking, multiple log sources
- **Proficient (4)**: Good log parsing, basic attack detection, adequate session analysis
- **Developing (3)**: Simple log analysis, limited attack detection, basic functionality
- **Needs Improvement (2)**: Poor log parsing, weak attack detection, significant limitations
- **Inadequate (1)**: Minimal web forensics, major functionality gaps

**Cross-Source Correlation (5 points)**
- **Excellent (5)**: Advanced correlation algorithms, high accuracy, comprehensive relationship mapping, confidence scoring
- **Proficient (4)**: Good correlation capabilities, adequate accuracy, basic relationship mapping
- **Developing (3)**: Simple correlation, limited accuracy, basic relationships
- **Needs Improvement (2)**: Poor correlation quality, low accuracy, weak relationships
- **Inadequate (1)**: Minimal correlation capabilities, major accuracy issues

**Advanced Timeline Reconstruction (5 points)**
- **Excellent (5)**: Sophisticated timeline integration, event clustering, pattern recognition, interactive visualization
- **Proficient (4)**: Good timeline reconstruction, basic clustering, adequate visualization
- **Developing (3)**: Simple timeline creation, limited integration, basic visualization
- **Needs Improvement (2)**: Poor timeline quality, weak integration, inadequate visualization
- **Inadequate (1)**: Minimal timeline capabilities, major gaps in functionality

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Bonus Opportunities (+2 points max)

- **Machine Learning**: Anomaly detection using ML algorithms
- **Advanced Visualization**: 3D network topology and timeline views
- **Real-time Analysis**: Streaming analysis capabilities
- **Threat Intelligence**: Integration with threat feeds for attribution
- **Automated Reporting**: AI-generated investigation summaries

## 💡 Tips for Success

1. **Study Real Cases**: Research actual forensic investigations
2. **Focus on Correlation**: The power is in connecting evidence
3. **Validate Accuracy**: Test correlation algorithms thoroughly  
4. **Visual Presentation**: Complex data needs clear visualization
5. **Document Methodology**: Explain your analysis approaches
6. **Handle Edge Cases**: Real evidence is messy and incomplete

## 📚 Resources

- Network Forensics: Tracking Hackers (Sherri Davidoff)
- Database Forensics (Paul Wright)
- Web Application Security Testing (OWASP)
- Incident Response & Computer Forensics (Mandia)
- Advanced Persistent Threat Analysis Guidelines

---

**Master the art of advanced multi-source forensic investigation!** 🕵️‍♂️💻