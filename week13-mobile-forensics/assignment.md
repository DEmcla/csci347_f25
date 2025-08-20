# Week 13 Assignment: Mobile Device and Cloud Forensics Platform

**Due**: End of Week 13 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Develop a comprehensive mobile device and cloud forensics platform capable of analyzing Android and iOS devices, extracting application data, investigating cloud storage synchronization, and correlating evidence across multiple platforms. Your solution should demonstrate understanding of mobile security models, cloud forensics challenges, and cross-platform investigation techniques.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Mobile Device Analysis** (5 points)
2. **Application Data Extraction** (5 points)
3. **Cloud Storage Investigation** (5 points)
4. **Cross-Platform Correlation** (5 points)
5. **Mobile Forensics Reporting** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build a Python-based mobile forensics platform:

```python
# Core modules to implement
android_analyzer.py     # Android device and app analysis
ios_analyzer.py         # iOS device and backup analysis
cloud_investigator.py   # Cloud storage and sync analysis
mobile_correlator.py    # Cross-platform evidence correlation
forensics_reporter.py   # Mobile-specific report generation
```

### Required Libraries
```python
import sqlite3
import json
import plistlib
from datetime import datetime, timezone
import hashlib
import base64
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
import pandas as pd
import xml.etree.ElementTree as ET
from pathlib import Path
```

## 📝 Detailed Requirements

### 1. Mobile Device Analysis (5 points)

Implement comprehensive mobile device examination:

**Required Features:**
- **Android analysis** including SQLite databases, shared preferences, and app data
- **iOS analysis** including plist files, keychain items, and backup structures
- **Device information** extraction (IMEI, serial numbers, OS versions)
- **Communication analysis** (SMS, call logs, contacts with timeline)
- **Location data** extraction and mapping

**Deliverable:** `android_analyzer.py` and `ios_analyzer.py` with device analysis capabilities

### 2. Application Data Extraction (5 points)

Create sophisticated app data analysis tools:

**Required Features:**
- **Social media** artifact extraction (messages, photos, contacts)
- **Messaging app** analysis (WhatsApp, Telegram, Signal simulation)
- **Browser history** and cache analysis across multiple browsers
- **Email client** data extraction and analysis
- **Financial app** transaction and account data recovery

**Deliverable:** App-specific analyzers with data extraction and parsing

### 3. Cloud Storage Investigation (5 points)

Build cloud forensics investigation capabilities:

**Required Features:**
- **Cloud sync** analysis (iCloud, Google Drive, Dropbox, OneDrive)
- **File synchronization** timeline and conflict resolution
- **Shared folder** and collaboration analysis
- **Cloud backup** examination and recovery
- **Cross-device** synchronization pattern analysis

**Deliverable:** `cloud_investigator.py` with multi-platform cloud analysis

### 4. Cross-Platform Correlation (5 points)

Implement evidence correlation across mobile and cloud platforms:

**Required Features:**
- **Account linking** across platforms and services
- **Timeline correlation** between device and cloud activities
- **Data consistency** verification across platforms
- **Communication correlation** across different apps and services
- **Behavioral pattern** analysis across multiple data sources

**Deliverable:** `mobile_correlator.py` with sophisticated correlation algorithms

### 5. Mobile Forensics Reporting (5 points)

Generate comprehensive mobile forensics reports:

**Required Features:**
- **Executive summary** with key findings and impact
- **Technical analysis** with detailed evidence presentation
- **Timeline visualization** with multi-source event correlation
- **Communication analysis** with contact networks and patterns
- **Privacy assessment** and data exposure analysis

**Deliverable:** `forensics_reporter.py` with mobile-specific reporting

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── android_analyzer.py
│   ├── ios_analyzer.py
│   ├── cloud_investigator.py
│   ├── mobile_correlator.py
│   ├── forensics_reporter.py
│   └── app_analyzers/
│       ├── whatsapp_analyzer.py
│       ├── browser_analyzer.py
│       ├── social_media_analyzer.py
│       └── email_analyzer.py
├── data/
│   ├── android_samples/
│   │   ├── contacts.db
│   │   ├── sms.db
│   │   └── app_data/
│   ├── ios_samples/
│   │   ├── manifest.plist
│   │   ├── info.plist
│   │   └── backup_files/
│   └── cloud_samples/
│       ├── sync_logs/
│       └── shared_folders/
├── reports/
│   ├── mobile_investigation.html
│   ├── timeline_analysis.pdf
│   └── privacy_assessment.json
└── README.md
```

### Sample Android Analysis
```python
@dataclass
class AndroidApp:
    package_name: str
    app_name: str
    version: str
    install_date: datetime
    permissions: List[str]
    data_directory: str
    databases: List[str]
    shared_prefs: Dict[str, Any]
    
    def analyze_database(self, db_path: str) -> List[Dict]:
        """Analyze SQLite database for app artifacts"""
        artifacts = []
        
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            # Get all table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                
                # Skip system tables
                if table_name.startswith('sqlite_'):
                    continue
                
                # Analyze table content
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                
                # Get column names
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = [col[1] for col in cursor.fetchall()]
                
                # Convert to structured data
                for row in rows:
                    artifact = dict(zip(columns, row))
                    artifact['_table'] = table_name
                    artifact['_timestamp'] = datetime.now().isoformat()
                    artifacts.append(artifact)
        
        return artifacts
    
    def extract_communications(self) -> Dict[str, List]:
        """Extract communication artifacts from app"""
        communications = {
            'messages': [],
            'calls': [],
            'contacts': []
        }
        
        # Look for common communication patterns
        for db in self.databases:
            if 'message' in db.lower() or 'sms' in db.lower():
                communications['messages'].extend(self.extract_messages(db))
            elif 'call' in db.lower():
                communications['calls'].extend(self.extract_calls(db))
            elif 'contact' in db.lower():
                communications['contacts'].extend(self.extract_contacts(db))
        
        return communications
```

### Sample iOS Analysis
```python
class iOSAnalyzer:
    def __init__(self, backup_path: str):
        self.backup_path = Path(backup_path)
        self.manifest = self.parse_manifest()
        self.info_plist = self.parse_info_plist()
    
    def parse_manifest(self) -> Dict:
        """Parse iOS backup manifest"""
        manifest_path = self.backup_path / 'Manifest.plist'
        
        if manifest_path.exists():
            with open(manifest_path, 'rb') as f:
                return plistlib.load(f)
        return {}
    
    def analyze_keychain(self) -> List[Dict]:
        """Analyze keychain items from backup"""
        keychain_items = []
        
        # Look for keychain database
        keychain_path = self.find_file_by_domain('KeychainDomain')
        
        if keychain_path:
            # Simulate keychain analysis
            with sqlite3.connect(keychain_path) as conn:
                cursor = conn.cursor()
                
                # Extract stored credentials
                query = """
                SELECT service, account, created_date, modified_date
                FROM keychain_items
                WHERE accessible = 1
                """
                
                for row in cursor.execute(query):
                    keychain_items.append({
                        'service': row[0],
                        'account': row[1],
                        'created': row[2],
                        'modified': row[3],
                        'type': 'credential'
                    })
        
        return keychain_items
    
    def extract_location_data(self) -> List[Dict]:
        """Extract location data from iOS backup"""
        locations = []
        
        # Look for location databases
        location_files = [
            'consolidated.db',
            'cache_encryptedA.db',
            'locationd_cache_encryptedA.db'
        ]
        
        for filename in location_files:
            db_path = self.find_file_by_name(filename)
            if db_path:
                locations.extend(self.parse_location_db(db_path))
        
        return locations
    
    def analyze_app_data(self, bundle_id: str) -> Dict:
        """Analyze specific iOS app data"""
        app_data = {
            'bundle_id': bundle_id,
            'documents': [],
            'preferences': {},
            'databases': [],
            'caches': []
        }
        
        # Find app container
        app_path = self.find_app_container(bundle_id)
        
        if app_path:
            # Analyze app documents
            docs_path = app_path / 'Documents'
            if docs_path.exists():
                app_data['documents'] = self.enumerate_files(docs_path)
            
            # Analyze app preferences
            prefs_path = app_path / 'Library' / 'Preferences'
            if prefs_path.exists():
                app_data['preferences'] = self.parse_preferences(prefs_path)
            
            # Find SQLite databases
            for db_file in app_path.rglob('*.sqlite*'):
                app_data['databases'].append(str(db_file))
        
        return app_data
```

### Sample Cloud Investigation
```python
class CloudInvestigator:
    def __init__(self):
        self.sync_logs = []
        self.file_versions = {}
        self.sharing_activities = []
    
    def analyze_sync_patterns(self, sync_data: List[Dict]) -> Dict:
        """Analyze cloud synchronization patterns"""
        patterns = {
            'sync_frequency': {},
            'device_activity': {},
            'conflict_resolution': [],
            'large_transfers': [],
            'suspicious_activity': []
        }
        
        for event in sync_data:
            # Analyze sync frequency per device
            device_id = event.get('device_id')
            if device_id not in patterns['sync_frequency']:
                patterns['sync_frequency'][device_id] = 0
            patterns['sync_frequency'][device_id] += 1
            
            # Check for large file transfers
            file_size = event.get('file_size', 0)
            if file_size > 100_000_000:  # 100MB
                patterns['large_transfers'].append(event)
            
            # Detect unusual activity patterns
            if self.is_suspicious_activity(event):
                patterns['suspicious_activity'].append(event)
        
        return patterns
    
    def reconstruct_file_history(self, file_path: str) -> List[Dict]:
        """Reconstruct file modification history across devices"""
        history = []
        
        # Simulate file version tracking
        versions = self.file_versions.get(file_path, [])
        
        for version in versions:
            history.append({
                'timestamp': version['modified_date'],
                'device': version['device_id'],
                'action': version['action'],
                'file_size': version['size'],
                'hash': version['content_hash'],
                'conflict': version.get('conflict_resolution', False)
            })
        
        # Sort by timestamp
        return sorted(history, key=lambda x: x['timestamp'])
    
    def analyze_sharing_patterns(self) -> Dict:
        """Analyze file sharing and collaboration patterns"""
        sharing_analysis = {
            'public_shares': [],
            'private_shares': [],
            'collaboration_networks': {},
            'access_patterns': {}
        }
        
        for activity in self.sharing_activities:
            # Classify sharing type
            if activity.get('public_access'):
                sharing_analysis['public_shares'].append(activity)
            else:
                sharing_analysis['private_shares'].append(activity)
            
            # Build collaboration networks
            owner = activity.get('owner')
            collaborators = activity.get('shared_with', [])
            
            if owner not in sharing_analysis['collaboration_networks']:
                sharing_analysis['collaboration_networks'][owner] = set()
            
            sharing_analysis['collaboration_networks'][owner].update(collaborators)
        
        return sharing_analysis
```

## 🧪 Testing Requirements

Your implementation must include:

### Mobile Platform Tests
- **Android database** parsing accuracy
- **iOS backup** extraction validation
- **App data** recovery completeness
- **Communication** artifact extraction
- **Location data** accuracy verification

### Cloud Analysis Tests
- **Sync pattern** detection validation
- **File history** reconstruction accuracy
- **Sharing analysis** completeness
- **Cross-platform** consistency verification
- **Timeline correlation** accuracy

### Integration Testing
Create comprehensive test scenarios including:
- Multi-device user scenarios with Android and iOS
- Cloud synchronization across multiple services
- Communication across different platforms and apps
- Privacy exposure analysis across platforms
- Timeline correlation validation with known events

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all mobile forensics modules)
2. **Test Data Sets** (simulated mobile and cloud data)
3. **Analysis Reports** (generated from test scenarios)
4. **App Analyzer Plugins** (for major mobile applications)
5. **Documentation** (README.md with analysis methodologies)

### README.md Must Include:
- **Mobile forensics** methodologies and approaches
- **App data extraction** techniques and limitations
- **Cloud investigation** procedures and challenges
- **Cross-platform correlation** algorithms
- **Privacy considerations** and legal compliance notes

## 📊 Grading Rubric (25 Points Total)

### 5-Point Scale Criteria

**Mobile Device Analysis (5 points)**
- **Excellent (5)**: Comprehensive Android/iOS analysis, accurate database parsing, complete communication extraction, location analysis
- **Proficient (4)**: Good mobile analysis, adequate database handling, basic communication extraction
- **Developing (3)**: Simple mobile parsing, limited database analysis, basic functionality
- **Needs Improvement (2)**: Poor mobile analysis, significant limitations, accuracy issues
- **Inadequate (1)**: Minimal mobile capabilities, major functionality gaps

**Application Data Extraction (5 points)**
- **Excellent (5)**: Sophisticated app analysis, comprehensive data extraction, multiple app support, high accuracy
- **Proficient (4)**: Good app analysis, adequate extraction, reasonable app coverage
- **Developing (3)**: Basic app analysis, limited extraction, few apps supported
- **Needs Improvement (2)**: Poor app analysis, weak extraction, significant limitations
- **Inadequate (1)**: Minimal app support, major extraction failures

**Cloud Storage Investigation (5 points)**
- **Excellent (5)**: Advanced cloud analysis, comprehensive sync investigation, multi-platform support, sharing analysis
- **Proficient (4)**: Good cloud investigation, adequate sync analysis, basic sharing detection
- **Developing (3)**: Simple cloud analysis, limited sync investigation, basic functionality
- **Needs Improvement (2)**: Poor cloud analysis, weak sync investigation, significant gaps
- **Inadequate (1)**: Minimal cloud capabilities, major investigation gaps

**Cross-Platform Correlation (5 points)**
- **Excellent (5)**: Advanced correlation algorithms, comprehensive account linking, accurate timeline correlation, behavioral analysis
- **Proficient (4)**: Good correlation capabilities, adequate linking, reasonable accuracy
- **Developing (3)**: Basic correlation, limited linking, simple functionality
- **Needs Improvement (2)**: Poor correlation quality, weak linking, low accuracy
- **Inadequate (1)**: Minimal correlation capabilities, major accuracy issues

**Mobile Forensics Reporting (5 points)**
- **Excellent (5)**: Professional reports, comprehensive analysis, excellent visualizations, privacy assessments, executive summaries
- **Proficient (4)**: Good reports, adequate analysis, decent visualizations, basic privacy notes
- **Developing (3)**: Basic reports, limited analysis, simple visualizations
- **Needs Improvement (2)**: Poor report quality, inadequate analysis, weak visualizations
- **Inadequate (1)**: Unprofessional reports, major gaps in analysis and presentation

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Bonus Opportunities (+2 points max)

- **Advanced Encryption**: Handle encrypted mobile databases and keychain analysis
- **Real-time Monitoring**: Live mobile device monitoring capabilities
- **Machine Learning**: Behavioral pattern recognition using ML
- **Privacy Dashboard**: Comprehensive privacy exposure visualization
- **Legal Compliance**: GDPR/CCPA compliance checking for extracted data

## 💡 Tips for Success

1. **Study Real Apps**: Understand how popular apps store data
2. **Focus on Privacy**: Mobile devices contain highly sensitive information
3. **Test Cross-Platform**: Ensure correlation works across different platforms
4. **Document Limitations**: Mobile forensics has many technical and legal constraints
5. **Validate Timelines**: Timezone handling is critical for accurate correlation
6. **Consider Encryption**: Modern mobile devices use extensive encryption

## 📚 Resources & Required Tools

### Open Source Tools (All Free)
- **SQLite3** - Python standard library (public domain)
- **plistlib** - Python standard library (free)
- **biplist** - https://github.com/wooster/biplist (MIT License)
- **Pandas** - https://pandas.pydata.org/ (BSD 3-Clause License)
- **Python Libraries** - json, datetime, hashlib (all free standard library)

### Reference Materials
- NIST SP 800-101r1: Guidelines for Mobile Device Forensics
- iOS Security Guide (Apple)
- Android Security Documentation (Google)
- Mobile Forensics Investigating Digital Evidence
- Practical Mobile Forensics (Satish Bommisetty)
- Cloud Security and Privacy (Tim Mather)

### 🚨 IMPORTANT: Tool Access Issues

**If you encounter ANY issues accessing these tools** (installation problems, licensing concerns, broken links, etc.), **please contact the instructor IMMEDIATELY**. We will:
- Provide alternative free tools
- Update the assignment directions
- Ensure no student faces barriers to completing the assignment

**Do not struggle in silence** - reach out as soon as you encounter any access problems!

---

**Unlock the secrets of mobile devices and cloud storage!** 📱☁️