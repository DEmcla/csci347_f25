# Week 12 Tutorial: Memory Forensics and Malware Analysis

**Estimated Time**: 3-4 hours (broken into 4 modules)  
**Prerequisites**: Understanding of operating system internals, basic forensics concepts

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Module 1** (45 min): Analyzed memory dumps with Volatility 3
2. **Module 2** (60 min): Detected and analyzed malware in memory
3. **Module 3** (45 min): Investigated process injection and rootkits
4. **Module 4** (60 min): Built automated memory analysis workflows

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Module 1: Memory Analysis Fundamentals ✅ Checkpoint 1
- [ ] Module 2: Malware Detection and Analysis ✅ Checkpoint 2  
- [ ] Module 3: Advanced Threat Investigation ✅ Checkpoint 3
- [ ] Module 4: Automated Analysis Pipeline ✅ Checkpoint 4

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Install required packages
pip install volatility3 yara-python pefile capstone

# Create working directory
mkdir week12-work
cd week12-work

# Download sample memory image (for tutorial purposes)
# Note: In production, you'd work with actual memory dumps
```

---

## 📘 Module 1: Memory Analysis Fundamentals (45 minutes)

**Learning Objective**: Master core memory forensics techniques with Volatility

**What you'll build**: Memory dump analyzer for Windows systems

### Step 1: Memory Dump Analysis Framework

Create a new file `memory_analyzer.py`:

```python
import os
import json
import hashlib
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class Process:
    """Represents a process in memory"""
    pid: int
    ppid: int
    name: str
    create_time: Optional[str]
    handles: int
    threads: int
    cmdline: str
    
@dataclass
class NetworkConnection:
    """Represents a network connection"""
    pid: int
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str

@dataclass
class MemoryArtifact:
    """Represents a memory artifact"""
    artifact_type: str
    data: Dict
    timestamp: str
    suspicious: bool
    description: str

class MemoryAnalyzer:
    """Memory forensics analyzer using Volatility concepts"""
    
    def __init__(self, memory_image: str = None):
        self.memory_image = memory_image
        self.processes: List[Process] = []
        self.connections: List[NetworkConnection] = []
        self.artifacts: List[MemoryArtifact] = []
        self.suspicious_indicators = []
    
    def analyze_processes(self) -> List[Process]:
        """Analyze running processes in memory"""
        # Simulated process analysis (in production, use Volatility)
        sample_processes = [
            Process(4, 0, "System", "2024-01-15 08:00:00", 500, 120, ""),
            Process(368, 4, "smss.exe", "2024-01-15 08:00:01", 30, 2, ""),
            Process(456, 368, "csrss.exe", "2024-01-15 08:00:02", 400, 10, ""),
            Process(512, 368, "wininit.exe", "2024-01-15 08:00:02", 80, 3, ""),
            Process(520, 456, "winlogon.exe", "2024-01-15 08:00:02", 120, 4, ""),
            Process(668, 512, "services.exe", "2024-01-15 08:00:03", 250, 8, ""),
            Process(676, 512, "lsass.exe", "2024-01-15 08:00:03", 600, 6, ""),
            Process(1234, 668, "svchost.exe", "2024-01-15 08:00:10", 150, 5, "-k NetworkService"),
            Process(1456, 668, "svchost.exe", "2024-01-15 08:00:11", 200, 7, "-k LocalService"),
            Process(2048, 520, "explorer.exe", "2024-01-15 08:05:00", 800, 25, ""),
            Process(3456, 2048, "chrome.exe", "2024-01-15 09:15:00", 400, 30, "https://suspicious-site.com"),
            Process(4567, 1, "malware.exe", "2024-01-15 10:30:00", 50, 2, ""),  # Suspicious
            Process(5678, 4567, "cmd.exe", "2024-01-15 10:30:05", 20, 1, "powershell -enc BASE64..."),  # Suspicious
        ]
        
        self.processes = sample_processes
        
        # Analyze for suspicious processes
        for proc in self.processes:
            # Check for suspicious parent-child relationships
            if proc.name == "cmd.exe" and proc.ppid not in [self._get_pid_by_name("explorer.exe"), 
                                                              self._get_pid_by_name("winlogon.exe")]:
                self.suspicious_indicators.append(f"Suspicious parent for cmd.exe: PID {proc.ppid}")
            
            # Check for suspicious process names
            suspicious_names = ["malware.exe", "rootkit.exe", "backdoor.exe"]
            if any(susp in proc.name.lower() for susp in suspicious_names):
                self.suspicious_indicators.append(f"Suspicious process name: {proc.name}")
            
            # Check for hidden or injected processes
            if proc.ppid == 1 and proc.name not in ["init", "systemd"]:
                self.suspicious_indicators.append(f"Orphaned process: {proc.name} (PID: {proc.pid})")
        
        return self.processes
    
    def _get_pid_by_name(self, name: str) -> Optional[int]:
        """Get PID by process name"""
        for proc in self.processes:
            if proc.name == name:
                return proc.pid
        return None
    
    def analyze_network_connections(self) -> List[NetworkConnection]:
        """Analyze network connections"""
        # Simulated network analysis
        sample_connections = [
            NetworkConnection(1234, "TCP", "192.168.1.100", 49152, "8.8.8.8", 53, "ESTABLISHED"),
            NetworkConnection(3456, "TCP", "192.168.1.100", 49153, "142.250.80.46", 443, "ESTABLISHED"),
            NetworkConnection(4567, "TCP", "192.168.1.100", 49154, "185.45.67.89", 4444, "ESTABLISHED"),  # Suspicious
            NetworkConnection(676, "TCP", "0.0.0.0", 445, "0.0.0.0", 0, "LISTENING"),
            NetworkConnection(668, "TCP", "0.0.0.0", 135, "0.0.0.0", 0, "LISTENING"),
        ]
        
        self.connections = sample_connections
        
        # Check for suspicious connections
        for conn in self.connections:
            # Check for suspicious ports
            suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
            if conn.remote_port in suspicious_ports or conn.local_port in suspicious_ports:
                self.suspicious_indicators.append(
                    f"Connection to suspicious port: {conn.remote_addr}:{conn.remote_port}"
                )
            
            # Check for connections from suspicious processes
            suspicious_pids = [4567, 5678]
            if conn.pid in suspicious_pids:
                self.suspicious_indicators.append(
                    f"Network connection from suspicious process PID {conn.pid}"
                )
        
        return self.connections
    
    def extract_strings(self, min_length: int = 4) -> List[str]:
        """Extract strings from memory (simulated)"""
        # In production, this would extract actual strings from memory
        sample_strings = [
            "C:\\Windows\\System32\\cmd.exe",
            "powershell.exe -ExecutionPolicy Bypass",
            "http://malicious-c2-server.com/beacon",
            "SELECT * FROM users WHERE password =",
            "BEGIN RSA PRIVATE KEY",
            "password123",
            "admin:admin",
            "\\Device\\HarddiskVolume2\\malware.exe"
        ]
        
        # Filter for interesting strings
        interesting_strings = []
        keywords = ["password", "key", "token", "secret", "http", "powershell", "cmd.exe"]
        
        for string in sample_strings:
            if any(keyword in string.lower() for keyword in keywords):
                interesting_strings.append(string)
        
        return interesting_strings
    
    def detect_code_injection(self) -> List[Dict]:
        """Detect potential code injection"""
        injections = []
        
        # Check for process hollowing indicators
        for proc in self.processes:
            # Simulated VAD (Virtual Address Descriptor) analysis
            if proc.name in ["svchost.exe", "explorer.exe"]:
                # Check for unusual memory regions
                injection = {
                    "process": proc.name,
                    "pid": proc.pid,
                    "type": "Process Hollowing",
                    "description": "Suspicious memory regions detected",
                    "severity": "HIGH"
                }
                
                # Simulate checking for RWX permissions
                if proc.pid == 1234:  # Example suspicious svchost
                    injections.append(injection)
        
        return injections
    
    def analyze_registry_keys(self) -> List[Dict]:
        """Analyze registry keys in memory"""
        # Simulated registry analysis
        registry_artifacts = [
            {
                "key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "Malware",
                "data": "C:\\Users\\Public\\malware.exe",
                "suspicious": True
            },
            {
                "key": "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
                "value": "(Default)",
                "data": "C:\\Windows\\System32\\cmd.exe /c malware.exe",
                "suspicious": True
            }
        ]
        
        for artifact in registry_artifacts:
            if artifact["suspicious"]:
                self.suspicious_indicators.append(
                    f"Suspicious registry key: {artifact['key']} -> {artifact['data']}"
                )
        
        return registry_artifacts
    
    def generate_timeline(self) -> List[Dict]:
        """Generate timeline of events"""
        timeline = []
        
        # Add process creation times
        for proc in self.processes:
            if proc.create_time:
                timeline.append({
                    "timestamp": proc.create_time,
                    "event": "Process Created",
                    "details": f"{proc.name} (PID: {proc.pid})",
                    "suspicious": proc.name in ["malware.exe", "rootkit.exe"]
                })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline
    
    def generate_report(self) -> Dict:
        """Generate comprehensive analysis report"""
        report = {
            "summary": {
                "total_processes": len(self.processes),
                "total_connections": len(self.connections),
                "suspicious_indicators": len(self.suspicious_indicators),
                "timestamp": datetime.now().isoformat()
            },
            "suspicious_processes": [],
            "network_indicators": [],
            "code_injections": self.detect_code_injection(),
            "registry_artifacts": self.analyze_registry_keys(),
            "suspicious_strings": self.extract_strings(),
            "timeline": self.generate_timeline(),
            "recommendations": []
        }
        
        # Add suspicious processes
        for proc in self.processes:
            if any(proc.name in indicator for indicator in self.suspicious_indicators):
                report["suspicious_processes"].append({
                    "pid": proc.pid,
                    "name": proc.name,
                    "parent": proc.ppid,
                    "cmdline": proc.cmdline
                })
        
        # Add network indicators
        for conn in self.connections:
            if conn.remote_port in [4444, 5555, 6666]:
                report["network_indicators"].append({
                    "pid": conn.pid,
                    "remote": f"{conn.remote_addr}:{conn.remote_port}",
                    "state": conn.state
                })
        
        # Generate recommendations
        if report["summary"]["suspicious_indicators"] > 0:
            report["recommendations"].append("Isolate system immediately")
            report["recommendations"].append("Collect additional forensic evidence")
            report["recommendations"].append("Check for lateral movement")
        
        return report

# Demo the memory analyzer
if __name__ == "__main__":
    print("🧠 MEMORY FORENSICS ANALYZER")
    print("="*60)
    
    analyzer = MemoryAnalyzer("memory.dmp")
    
    # Analyze processes
    print("\n📋 Analyzing Processes...")
    processes = analyzer.analyze_processes()
    print(f"Found {len(processes)} processes")
    
    # Show process tree
    print("\n🌳 Process Tree:")
    for proc in processes[:10]:  # Show first 10
        indent = "  " * (0 if proc.ppid == 0 else 1)
        print(f"{indent}[{proc.pid}] {proc.name}")
    
    # Analyze network
    print("\n🌐 Analyzing Network Connections...")
    connections = analyzer.analyze_network_connections()
    print(f"Found {len(connections)} connections")
    
    for conn in connections:
        if conn.state == "ESTABLISHED":
            print(f"  PID {conn.pid}: {conn.local_addr}:{conn.local_port} -> {conn.remote_addr}:{conn.remote_port}")
    
    # Check for injections
    print("\n💉 Checking for Code Injection...")
    injections = analyzer.detect_code_injection()
    if injections:
        for inj in injections:
            print(f"  ⚠️ {inj['type']} in {inj['process']} (PID: {inj['pid']})")
    
    # Generate report
    report = analyzer.generate_report()
    
    print("\n📊 ANALYSIS REPORT")
    print("="*60)
    print(f"Suspicious Indicators: {report['summary']['suspicious_indicators']}")
    
    if analyzer.suspicious_indicators:
        print("\n⚠️ Suspicious Findings:")
        for indicator in analyzer.suspicious_indicators[:5]:  # Show first 5
            print(f"  - {indicator}")
    
    if report["recommendations"]:
        print("\n💡 Recommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
```

**Run it:**
```bash
python memory_analyzer.py
```

### 💡 Key Concepts Learned

**Before moving to Module 2, make sure you understand:**

1. **Process Analysis**: Parent-child relationships and suspicious processes
2. **Network Connections**: Identifying C2 communications  
3. **Memory Artifacts**: Registry keys, strings, and other evidence
4. **Timeline Generation**: Reconstructing event sequences

### ✅ Checkpoint 1 Complete!
You can now perform basic memory forensics. Ready for Module 2?

---

## 📘 Module 2: Malware Detection and Analysis (60 minutes)

**Learning Objective**: Detect and analyze malware behavior in memory

**What you'll build**: Malware detection engine with behavioral analysis

### Step 1: Malware Detection Framework

Create `malware_detector.py`:

```python
import re
import hashlib
from typing import List, Dict, Set
from dataclasses import dataclass
from enum import Enum

class MalwareType(Enum):
    """Types of malware"""
    ROOTKIT = "Rootkit"
    TROJAN = "Trojan"
    RANSOMWARE = "Ransomware"
    CRYPTOMINER = "Cryptocurrency Miner"
    BACKDOOR = "Backdoor"
    KEYLOGGER = "Keylogger"
    SPYWARE = "Spyware"
    WORM = "Worm"

@dataclass
class MalwareIndicator:
    """Represents a malware indicator"""
    indicator_type: str  # behavior, signature, network, file
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    confidence: float  # 0-1
    malware_family: Optional[str] = None

class MalwareDetector:
    """Malware detection and analysis engine"""
    
    def __init__(self):
        self.indicators: List[MalwareIndicator] = []
        self.yara_rules = self._load_yara_rules()
        self.behavioral_patterns = self._load_behavioral_patterns()
        self.iocs = self._load_iocs()  # Indicators of Compromise
    
    def _load_yara_rules(self) -> Dict:
        """Load YARA-like rules for malware detection"""
        return {
            "ransomware_strings": {
                "strings": [
                    "Your files have been encrypted",
                    "Bitcoin wallet",
                    "Pay ransom",
                    ".encrypted",
                    "DECRYPT_INSTRUCTIONS"
                ],
                "malware_type": MalwareType.RANSOMWARE
            },
            "cryptominer_strings": {
                "strings": [
                    "stratum+tcp://",
                    "monero",
                    "xmrig",
                    "nicehash",
                    "mining.pool"
                ],
                "malware_type": MalwareType.CRYPTOMINER
            },
            "backdoor_strings": {
                "strings": [
                    "reverse_tcp",
                    "bind_shell",
                    "meterpreter",
                    "LHOST=",
                    "nc.exe -e"
                ],
                "malware_type": MalwareType.BACKDOOR
            },
            "keylogger_strings": {
                "strings": [
                    "GetAsyncKeyState",
                    "SetWindowsHookEx",
                    "keylog.txt",
                    "WH_KEYBOARD_LL"
                ],
                "malware_type": MalwareType.KEYLOGGER
            }
        }
    
    def _load_behavioral_patterns(self) -> Dict:
        """Load behavioral patterns for detection"""
        return {
            "process_injection": {
                "patterns": [
                    "CreateRemoteThread",
                    "WriteProcessMemory",
                    "VirtualAllocEx",
                    "SetThreadContext"
                ],
                "severity": "HIGH"
            },
            "persistence": {
                "patterns": [
                    "Registry Run key modification",
                    "Scheduled task creation",
                    "Service installation",
                    "WMI event subscription"
                ],
                "severity": "MEDIUM"
            },
            "defense_evasion": {
                "patterns": [
                    "Process hollowing",
                    "DLL side-loading",
                    "Living off the land",
                    "Anti-debugging techniques"
                ],
                "severity": "HIGH"
            },
            "data_exfiltration": {
                "patterns": [
                    "Large outbound transfers",
                    "DNS tunneling",
                    "Cloud storage uploads",
                    "FTP connections"
                ],
                "severity": "CRITICAL"
            }
        }
    
    def _load_iocs(self) -> Dict:
        """Load known Indicators of Compromise"""
        return {
            "domains": [
                "evil-c2-server.com",
                "malware-distribution.net",
                "ransomware-payment.org"
            ],
            "ips": [
                "185.45.67.89",
                "23.45.67.89",
                "192.168.1.254"
            ],
            "hashes": {
                "d41d8cd98f00b204e9800998ecf8427e": "Known malware hash",
                "e3b0c44298fc1c149afbf4c8996fb924": "Suspicious file"
            },
            "filenames": [
                "malware.exe",
                "rootkit.sys",
                "backdoor.dll",
                "keylog.dat"
            ]
        }
    
    def scan_memory_strings(self, strings: List[str]) -> List[MalwareIndicator]:
        """Scan strings for malware indicators"""
        detected = []
        
        for rule_name, rule in self.yara_rules.items():
            matches = 0
            for pattern in rule["strings"]:
                for string in strings:
                    if pattern.lower() in string.lower():
                        matches += 1
            
            if matches > 0:
                confidence = min(matches / len(rule["strings"]), 1.0)
                indicator = MalwareIndicator(
                    indicator_type="signature",
                    description=f"Detected {rule['malware_type'].value} indicators",
                    severity="HIGH" if confidence > 0.5 else "MEDIUM",
                    confidence=confidence,
                    malware_family=rule["malware_type"].value
                )
                detected.append(indicator)
        
        return detected
    
    def analyze_process_behavior(self, process_data: Dict) -> List[MalwareIndicator]:
        """Analyze process behavior for malware"""
        detected = []
        
        # Check for suspicious API calls
        if "api_calls" in process_data:
            for pattern_name, pattern_data in self.behavioral_patterns.items():
                matching_apis = [api for api in process_data["api_calls"] 
                                if any(p in api for p in pattern_data["patterns"])]
                
                if matching_apis:
                    indicator = MalwareIndicator(
                        indicator_type="behavior",
                        description=f"Detected {pattern_name.replace('_', ' ')} behavior",
                        severity=pattern_data["severity"],
                        confidence=len(matching_apis) / len(pattern_data["patterns"])
                    )
                    detected.append(indicator)
        
        # Check for suspicious network behavior
        if "network_connections" in process_data:
            for conn in process_data["network_connections"]:
                # Check against known bad IPs/domains
                if conn in self.iocs["ips"] or conn in self.iocs["domains"]:
                    indicator = MalwareIndicator(
                        indicator_type="network",
                        description=f"Connection to known malicious host: {conn}",
                        severity="CRITICAL",
                        confidence=1.0
                    )
                    detected.append(indicator)
        
        return detected
    
    def detect_rootkit(self, process_list: List[Dict], driver_list: List[str]) -> List[MalwareIndicator]:
        """Detect rootkit indicators"""
        rootkit_indicators = []
        
        # Check for hidden processes
        # In real implementation, compare different process enumeration methods
        hidden_pids = set()  # PIDs visible in one method but not another
        
        # Check for suspicious drivers
        suspicious_drivers = [
            "rootkit.sys",
            "hacker.sys",
            "hide.sys"
        ]
        
        for driver in driver_list:
            if any(susp in driver.lower() for susp in suspicious_drivers):
                rootkit_indicators.append(
                    MalwareIndicator(
                        indicator_type="file",
                        description=f"Suspicious driver detected: {driver}",
                        severity="CRITICAL",
                        confidence=0.9,
                        malware_family="Rootkit"
                    )
                )
        
        # Check for SSDT hooks (System Service Descriptor Table)
        # This would check for modifications to system call table
        
        return rootkit_indicators
    
    def analyze_ransomware_artifacts(self, filesystem_changes: List[Dict]) -> List[MalwareIndicator]:
        """Detect ransomware activity"""
        ransomware_indicators = []
        
        # Check for mass file encryption
        encrypted_extensions = [".locked", ".encrypted", ".enc", ".cry", ".lokd"]
        encrypted_files = 0
        
        for change in filesystem_changes:
            if any(ext in change.get("filename", "") for ext in encrypted_extensions):
                encrypted_files += 1
        
        if encrypted_files > 10:
            ransomware_indicators.append(
                MalwareIndicator(
                    indicator_type="behavior",
                    description=f"Mass file encryption detected: {encrypted_files} files",
                    severity="CRITICAL",
                    confidence=min(encrypted_files / 100, 1.0),
                    malware_family="Ransomware"
                )
            )
        
        # Check for ransom notes
        ransom_note_names = ["README.txt", "DECRYPT_INSTRUCTIONS.txt", "HOW_TO_DECRYPT.html"]
        for change in filesystem_changes:
            if any(note in change.get("filename", "") for note in ransom_note_names):
                ransomware_indicators.append(
                    MalwareIndicator(
                        indicator_type="file",
                        description=f"Ransom note detected: {change['filename']}",
                        severity="CRITICAL",
                        confidence=0.95,
                        malware_family="Ransomware"
                    )
                )
        
        return ransomware_indicators
    
    def calculate_threat_score(self) -> float:
        """Calculate overall threat score"""
        if not self.indicators:
            return 0.0
        
        severity_weights = {
            "LOW": 0.25,
            "MEDIUM": 0.5,
            "HIGH": 0.75,
            "CRITICAL": 1.0
        }
        
        total_score = sum(
            severity_weights.get(ind.severity, 0) * ind.confidence 
            for ind in self.indicators
        )
        
        # Normalize to 0-100 scale
        return min((total_score / len(self.indicators)) * 100, 100)
    
    def generate_detection_report(self) -> Dict:
        """Generate malware detection report"""
        malware_families = {}
        for ind in self.indicators:
            if ind.malware_family:
                if ind.malware_family not in malware_families:
                    malware_families[ind.malware_family] = 0
                malware_families[ind.malware_family] += 1
        
        return {
            "threat_score": self.calculate_threat_score(),
            "total_indicators": len(self.indicators),
            "critical_indicators": len([i for i in self.indicators if i.severity == "CRITICAL"]),
            "detected_families": list(malware_families.keys()),
            "top_threats": sorted(self.indicators, key=lambda x: x.confidence, reverse=True)[:5],
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        if self.calculate_threat_score() > 75:
            recommendations.append("IMMEDIATE ACTION: Isolate system from network")
            recommendations.append("Initiate incident response procedures")
        
        malware_types = set(ind.malware_family for ind in self.indicators if ind.malware_family)
        
        if "Ransomware" in malware_types:
            recommendations.append("Backup critical data immediately")
            recommendations.append("Do not pay ransom")
            recommendations.append("Check for available decryption tools")
        
        if "Rootkit" in malware_types:
            recommendations.append("Boot from external media for analysis")
            recommendations.append("Use rootkit scanner tools")
        
        if "Backdoor" in malware_types:
            recommendations.append("Check all network connections")
            recommendations.append("Review firewall rules")
        
        return recommendations

# Demo the malware detector
if __name__ == "__main__":
    detector = MalwareDetector()
    
    print("🦠 MALWARE DETECTION ENGINE")
    print("="*60)
    
    # Simulate memory strings
    memory_strings = [
        "Your files have been encrypted",
        "Send Bitcoin to wallet: 1A2B3C4D5E",
        "stratum+tcp://pool.minexmr.com:4444",
        "CreateRemoteThread",
        "WriteProcessMemory",
        "nc.exe -e cmd.exe",
        "DECRYPT_INSTRUCTIONS.txt"
    ]
    
    # Scan strings
    print("\n🔍 Scanning Memory Strings...")
    string_indicators = detector.scan_memory_strings(memory_strings)
    detector.indicators.extend(string_indicators)
    
    # Analyze process behavior
    print("🔍 Analyzing Process Behavior...")
    process_data = {
        "api_calls": [
            "CreateRemoteThread",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "SetWindowsHookEx"
        ],
        "network_connections": [
            "185.45.67.89",
            "evil-c2-server.com"
        ]
    }
    
    behavior_indicators = detector.analyze_process_behavior(process_data)
    detector.indicators.extend(behavior_indicators)
    
    # Check for ransomware
    print("🔍 Checking for Ransomware...")
    filesystem_changes = [
        {"filename": "document.docx.encrypted"},
        {"filename": "photo.jpg.locked"},
        {"filename": "DECRYPT_INSTRUCTIONS.txt"},
        {"filename": "database.db.enc"}
    ]
    
    ransomware_indicators = detector.analyze_ransomware_artifacts(filesystem_changes)
    detector.indicators.extend(ransomware_indicators)
    
    # Generate report
    report = detector.generate_detection_report()
    
    print("\n📊 DETECTION REPORT")
    print("="*60)
    print(f"Threat Score: {report['threat_score']:.1f}/100")
    print(f"Total Indicators: {report['total_indicators']}")
    print(f"Critical Indicators: {report['critical_indicators']}")
    
    if report["detected_families"]:
        print(f"\n🦠 Detected Malware Families:")
        for family in report["detected_families"]:
            print(f"  - {family}")
    
    if report["top_threats"]:
        print(f"\n⚠️ Top Threats:")
        for i, threat in enumerate(report["top_threats"], 1):
            print(f"  {i}. [{threat.severity}] {threat.description}")
            print(f"     Confidence: {threat.confidence:.1%}")
    
    if report["recommendations"]:
        print(f"\n💡 Recommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
```

---

## 📘 Module 3: Advanced Threat Investigation (45 minutes)

**Learning Objective**: Investigate sophisticated threats like rootkits and APTs

**What you'll build**: Advanced threat hunting system

Create `threat_hunter.py`:

```python
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
import hashlib
import struct

@dataclass
class HiddenProcess:
    """Represents a potentially hidden process"""
    pid: int
    name: str
    detection_method: str
    confidence: float

class ThreatHunter:
    """Advanced threat hunting and investigation"""
    
    def __init__(self):
        self.findings: List[Dict] = []
        self.ioc_matches: List[Dict] = []
    
    def hunt_process_injection(self, processes: List[Dict]) -> List[Dict]:
        """Hunt for process injection techniques"""
        injection_findings = []
        
        # Check for hollowing indicators
        for proc in processes:
            # Check VAD (Virtual Address Descriptor) permissions
            if self._check_suspicious_vad(proc):
                injection_findings.append({
                    "technique": "Process Hollowing",
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "confidence": 0.8,
                    "description": "Process image doesn't match on-disk file"
                })
            
            # Check for reflective DLL injection
            if self._check_reflective_dll(proc):
                injection_findings.append({
                    "technique": "Reflective DLL Injection",
                    "process": proc.get("name"),
                    "pid": proc.get("pid"),
                    "confidence": 0.7,
                    "description": "Unsigned DLL loaded in memory"
                })
        
        return injection_findings
    
    def _check_suspicious_vad(self, process: Dict) -> bool:
        """Check for suspicious memory regions"""
        # Simulated check - in reality would analyze VAD tree
        suspicious_processes = ["svchost.exe", "explorer.exe", "csrss.exe"]
        return process.get("name") in suspicious_processes and process.get("pid", 0) > 5000
    
    def _check_reflective_dll(self, process: Dict) -> bool:
        """Check for reflective DLL injection"""
        # Simulated check - would analyze loaded modules
        return "suspicious_module" in process.get("modules", [])
    
    def detect_lateral_movement(self, network_events: List[Dict]) -> List[Dict]:
        """Detect lateral movement indicators"""
        lateral_movement = []
        
        # Check for suspicious authentication patterns
        failed_auths = {}
        successful_auths = {}
        
        for event in network_events:
            if event.get("type") == "authentication":
                target = event.get("target_host")
                source = event.get("source_host")
                
                if event.get("status") == "failed":
                    if source not in failed_auths:
                        failed_auths[source] = []
                    failed_auths[source].append(target)
                else:
                    if source not in successful_auths:
                        successful_auths[source] = []
                    successful_auths[source].append(target)
        
        # Detect password spraying
        for source, targets in failed_auths.items():
            if len(set(targets)) > 5:  # Multiple targets from same source
                lateral_movement.append({
                    "technique": "Password Spraying",
                    "source": source,
                    "targets": list(set(targets)),
                    "confidence": 0.8
                })
        
        # Detect successful auth after failures
        for source in failed_auths:
            if source in successful_auths:
                lateral_movement.append({
                    "technique": "Credential Access",
                    "source": source,
                    "confidence": 0.7,
                    "description": "Successful auth after multiple failures"
                })
        
        return lateral_movement
    
    def analyze_persistence_mechanisms(self, registry: Dict, services: List[str]) -> List[Dict]:
        """Analyze persistence mechanisms"""
        persistence = []
        
        # Check autoruns
        autorun_keys = [
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        ]
        
        for key in autorun_keys:
            if key in registry:
                for value in registry[key]:
                    if self._is_suspicious_path(value):
                        persistence.append({
                            "method": "Registry Autorun",
                            "location": key,
                            "value": value,
                            "confidence": 0.7
                        })
        
        # Check services
        suspicious_service_names = ["WindowsUpdate2", "SystemService", "MicrosoftUpdate"]
        for service in services:
            if any(susp in service for susp in suspicious_service_names):
                persistence.append({
                    "method": "Service Installation",
                    "name": service,
                    "confidence": 0.8
                })
        
        return persistence
    
    def _is_suspicious_path(self, path: str) -> bool:
        """Check if path is suspicious"""
        suspicious_locations = [
            "\\Users\\Public\\",
            "\\ProgramData\\",
            "\\Windows\\Temp\\",
            "\\AppData\\Local\\Temp\\"
        ]
        return any(loc in path for loc in suspicious_locations)
    
    def hunt_apts(self, all_data: Dict) -> List[Dict]:
        """Hunt for APT indicators"""
        apt_indicators = []
        
        # Check for known APT TTPs (Tactics, Techniques, Procedures)
        apt_patterns = {
            "APT28": {
                "tools": ["x-agent", "x-tunnel", "sofacy"],
                "domains": ["nato-news.com", "0day.su"],
                "techniques": ["spearphishing", "watering_hole"]
            },
            "APT29": {
                "tools": ["seaduke", "hammertoss", "cosmicduke"],
                "domains": ["microsoftoutlook.net", "pandorasong.com"],
                "techniques": ["supply_chain", "steganography"]
            }
        }
        
        # Check for APT tools
        for apt_name, apt_data in apt_patterns.items():
            matches = 0
            matched_indicators = []
            
            # Check processes
            if "processes" in all_data:
                for proc in all_data["processes"]:
                    if any(tool in proc.get("name", "").lower() for tool in apt_data["tools"]):
                        matches += 1
                        matched_indicators.append(f"Tool: {proc['name']}")
            
            # Check network
            if "network" in all_data:
                for conn in all_data["network"]:
                    if any(domain in conn.get("domain", "") for domain in apt_data["domains"]):
                        matches += 1
                        matched_indicators.append(f"C2 Domain: {conn['domain']}")
            
            if matches > 0:
                apt_indicators.append({
                    "apt_group": apt_name,
                    "confidence": min(matches * 0.3, 0.9),
                    "indicators": matched_indicators
                })
        
        return apt_indicators

# Demo the threat hunter
if __name__ == "__main__":
    hunter = ThreatHunter()
    
    print("🎯 ADVANCED THREAT HUNTER")
    print("="*60)
    
    # Hunt for injection
    print("\n🔍 Hunting Process Injection...")
    processes = [
        {"name": "svchost.exe", "pid": 6789, "modules": ["suspicious_module"]},
        {"name": "explorer.exe", "pid": 7890, "modules": []},
        {"name": "chrome.exe", "pid": 4567, "modules": []}
    ]
    
    injections = hunter.hunt_process_injection(processes)
    if injections:
        print(f"Found {len(injections)} injection indicators:")
        for inj in injections:
            print(f"  - {inj['technique']} in {inj['process']} (PID: {inj['pid']})")
    
    # Detect lateral movement
    print("\n🔍 Detecting Lateral Movement...")
    network_events = [
        {"type": "authentication", "source_host": "192.168.1.100", 
         "target_host": "192.168.1.101", "status": "failed"},
        {"type": "authentication", "source_host": "192.168.1.100", 
         "target_host": "192.168.1.102", "status": "failed"},
        {"type": "authentication", "source_host": "192.168.1.100", 
         "target_host": "192.168.1.103", "status": "failed"},
        {"type": "authentication", "source_host": "192.168.1.100", 
         "target_host": "192.168.1.104", "status": "failed"},
        {"type": "authentication", "source_host": "192.168.1.100", 
         "target_host": "192.168.1.105", "status": "failed"},
        {"type": "authentication", "source_host": "192.168.1.100", 
         "target_host": "192.168.1.105", "status": "success"},
    ]
    
    lateral = hunter.detect_lateral_movement(network_events)
    if lateral:
        print(f"Found {len(lateral)} lateral movement indicators:")
        for lat in lateral:
            print(f"  - {lat['technique']} from {lat.get('source', 'unknown')}")
    
    # Check persistence
    print("\n🔍 Analyzing Persistence...")
    registry = {
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": [
            "C:\\Windows\\System32\\notepad.exe",
            "C:\\Users\\Public\\malware.exe"
        ]
    }
    services = ["WindowsUpdate2", "LegitService", "SystemService"]
    
    persistence = hunter.analyze_persistence_mechanisms(registry, services)
    if persistence:
        print(f"Found {len(persistence)} persistence mechanisms:")
        for pers in persistence:
            print(f"  - {pers['method']}: {pers.get('name', pers.get('value', ''))}")
    
    # Hunt APTs
    print("\n🔍 Hunting APT Groups...")
    all_data = {
        "processes": [
            {"name": "x-agent.exe"},
            {"name": "chrome.exe"}
        ],
        "network": [
            {"domain": "nato-news.com"},
            {"domain": "google.com"}
        ]
    }
    
    apts = hunter.hunt_apts(all_data)
    if apts:
        print(f"Potential APT activity detected:")
        for apt in apts:
            print(f"  - {apt['apt_group']} (Confidence: {apt['confidence']:.1%})")
            for indicator in apt['indicators']:
                print(f"    • {indicator}")
```

---

## 📘 Module 4: Automated Analysis Pipeline (60 minutes)

**Learning Objective**: Build automated memory analysis workflows

**What you'll build**: Automated pipeline for memory forensics

Create `automated_pipeline.py`:

```python
import json
import os
from typing import Dict, List, Any
from datetime import datetime
import concurrent.futures
from dataclasses import dataclass, asdict

@dataclass
class AnalysisTask:
    """Represents an analysis task"""
    task_id: str
    task_type: str
    status: str  # pending, running, completed, failed
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    results: Optional[Dict] = None
    error: Optional[str] = None

class AutomatedPipeline:
    """Automated memory forensics pipeline"""
    
    def __init__(self, output_dir: str = "analysis_output"):
        self.output_dir = output_dir
        self.tasks: List[AnalysisTask] = []
        self.analyzers = {
            "memory": MemoryAnalyzer(),
            "malware": MalwareDetector(),
            "threat": ThreatHunter()
        }
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def add_task(self, task_type: str) -> str:
        """Add analysis task to pipeline"""
        task_id = f"{task_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        task = AnalysisTask(
            task_id=task_id,
            task_type=task_type,
            status="pending"
        )
        self.tasks.append(task)
        return task_id
    
    def run_pipeline(self, memory_dump: str) -> Dict:
        """Run complete analysis pipeline"""
        print(f"\n🚀 Starting Automated Analysis Pipeline")
        print(f"   Memory Dump: {memory_dump}")
        print(f"   Output Directory: {self.output_dir}")
        print("="*60)
        
        pipeline_start = datetime.now()
        results = {
            "memory_dump": memory_dump,
            "start_time": pipeline_start.isoformat(),
            "phases": {}
        }
        
        # Phase 1: Initial Memory Analysis
        print("\n📋 Phase 1: Initial Memory Analysis")
        memory_results = self._run_memory_analysis(memory_dump)
        results["phases"]["memory_analysis"] = memory_results
        
        # Phase 2: Malware Detection
        print("\n🦠 Phase 2: Malware Detection")
        malware_results = self._run_malware_detection(memory_results)
        results["phases"]["malware_detection"] = malware_results
        
        # Phase 3: Threat Hunting
        print("\n🎯 Phase 3: Advanced Threat Hunting")
        threat_results = self._run_threat_hunting(memory_results, malware_results)
        results["phases"]["threat_hunting"] = threat_results
        
        # Phase 4: Generate Reports
        print("\n📊 Phase 4: Report Generation")
        report_results = self._generate_reports(results)
        results["phases"]["reporting"] = report_results
        
        # Calculate execution time
        pipeline_end = datetime.now()
        results["end_time"] = pipeline_end.isoformat()
        results["total_duration"] = str(pipeline_end - pipeline_start)
        
        # Save final results
        self._save_results(results)
        
        print("\n✅ Pipeline Completed Successfully")
        print(f"   Total Duration: {results['total_duration']}")
        print(f"   Reports saved to: {self.output_dir}")
        
        return results
    
    def _run_memory_analysis(self, memory_dump: str) -> Dict:
        """Run memory analysis phase"""
        analyzer = self.analyzers["memory"]
        
        # Analyze processes
        processes = analyzer.analyze_processes()
        
        # Analyze network
        connections = analyzer.analyze_network_connections()
        
        # Extract artifacts
        strings = analyzer.extract_strings()
        registry = analyzer.analyze_registry_keys()
        
        return {
            "processes": len(processes),
            "connections": len(connections),
            "suspicious_indicators": len(analyzer.suspicious_indicators),
            "extracted_strings": len(strings),
            "registry_artifacts": len(registry),
            "raw_data": {
                "processes": [asdict(p) for p in processes[:10]],  # Sample
                "connections": [asdict(c) for c in connections[:10]],
                "strings": strings[:20]
            }
        }
    
    def _run_malware_detection(self, memory_results: Dict) -> Dict:
        """Run malware detection phase"""
        detector = self.analyzers["malware"]
        
        # Scan strings
        strings = memory_results.get("raw_data", {}).get("strings", [])
        string_indicators = detector.scan_memory_strings(strings)
        detector.indicators.extend(string_indicators)
        
        # Generate detection report
        report = detector.generate_detection_report()
        
        return {
            "threat_score": report["threat_score"],
            "total_indicators": report["total_indicators"],
            "critical_indicators": report["critical_indicators"],
            "detected_families": report["detected_families"],
            "recommendations": report["recommendations"]
        }
    
    def _run_threat_hunting(self, memory_results: Dict, malware_results: Dict) -> Dict:
        """Run threat hunting phase"""
        hunter = self.analyzers["threat"]
        
        # Hunt for injection
        processes = memory_results.get("raw_data", {}).get("processes", [])
        injections = hunter.hunt_process_injection(processes)
        
        # Combine findings
        findings = {
            "injection_techniques": len(injections),
            "high_confidence_threats": len([i for i in injections if i.get("confidence", 0) > 0.7]),
            "apt_indicators": 0,  # Would be populated with real APT hunting
            "lateral_movement": 0  # Would be populated with network analysis
        }
        
        return findings
    
    def _generate_reports(self, results: Dict) -> Dict:
        """Generate analysis reports"""
        reports_generated = []
        
        # Executive Summary
        exec_summary = self._create_executive_summary(results)
        exec_path = os.path.join(self.output_dir, "executive_summary.json")
        with open(exec_path, 'w') as f:
            json.dump(exec_summary, f, indent=2)
        reports_generated.append("executive_summary.json")
        
        # Technical Report
        tech_report = self._create_technical_report(results)
        tech_path = os.path.join(self.output_dir, "technical_report.json")
        with open(tech_path, 'w') as f:
            json.dump(tech_report, f, indent=2)
        reports_generated.append("technical_report.json")
        
        # IOCs Report
        iocs = self._extract_iocs(results)
        ioc_path = os.path.join(self.output_dir, "iocs.json")
        with open(ioc_path, 'w') as f:
            json.dump(iocs, f, indent=2)
        reports_generated.append("iocs.json")
        
        return {
            "reports_generated": reports_generated,
            "output_directory": self.output_dir
        }
    
    def _create_executive_summary(self, results: Dict) -> Dict:
        """Create executive summary report"""
        malware = results["phases"]["malware_detection"]
        threat = results["phases"]["threat_hunting"]
        
        risk_level = "CRITICAL" if malware["threat_score"] > 75 else \
                     "HIGH" if malware["threat_score"] > 50 else \
                     "MEDIUM" if malware["threat_score"] > 25 else "LOW"
        
        return {
            "analysis_date": results["start_time"],
            "risk_level": risk_level,
            "threat_score": malware["threat_score"],
            "key_findings": {
                "malware_families_detected": malware["detected_families"],
                "critical_indicators": malware["critical_indicators"],
                "injection_techniques": threat["injection_techniques"]
            },
            "immediate_actions": malware["recommendations"][:3] if malware["recommendations"] else [],
            "executive_summary": f"Analysis revealed {risk_level} risk level with threat score of {malware['threat_score']:.1f}/100"
        }
    
    def _create_technical_report(self, results: Dict) -> Dict:
        """Create detailed technical report"""
        return {
            "metadata": {
                "analysis_start": results["start_time"],
                "analysis_end": results["end_time"],
                "duration": results["total_duration"],
                "memory_dump": results["memory_dump"]
            },
            "analysis_phases": results["phases"],
            "detailed_findings": {
                "memory_artifacts": results["phases"]["memory_analysis"],
                "malware_analysis": results["phases"]["malware_detection"],
                "threat_hunting": results["phases"]["threat_hunting"]
            }
        }
    
    def _extract_iocs(self, results: Dict) -> Dict:
        """Extract IOCs from analysis"""
        iocs = {
            "domains": [],
            "ips": [],
            "hashes": [],
            "filenames": [],
            "registry_keys": []
        }
        
        # Extract from memory analysis
        if "raw_data" in results["phases"]["memory_analysis"]:
            connections = results["phases"]["memory_analysis"]["raw_data"].get("connections", [])
            for conn in connections:
                if conn.get("remote_addr"):
                    iocs["ips"].append(conn["remote_addr"])
        
        return iocs
    
    def _save_results(self, results: Dict):
        """Save complete results"""
        results_path = os.path.join(self.output_dir, "complete_analysis.json")
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Create summary file
        summary_path = os.path.join(self.output_dir, "summary.txt")
        with open(summary_path, 'w') as f:
            f.write("MEMORY FORENSICS ANALYSIS SUMMARY\n")
            f.write("="*50 + "\n\n")
            f.write(f"Analysis Date: {results['start_time']}\n")
            f.write(f"Duration: {results['total_duration']}\n\n")
            
            malware = results["phases"]["malware_detection"]
            f.write(f"Threat Score: {malware['threat_score']:.1f}/100\n")
            f.write(f"Critical Indicators: {malware['critical_indicators']}\n")
            
            if malware['detected_families']:
                f.write(f"\nDetected Malware Families:\n")
                for family in malware['detected_families']:
                    f.write(f"  - {family}\n")
            
            if malware['recommendations']:
                f.write(f"\nRecommendations:\n")
                for rec in malware['recommendations']:
                    f.write(f"  - {rec}\n")

# Demo the automated pipeline
if __name__ == "__main__":
    # Import the analyzers (in production these would be in separate modules)
    from memory_analyzer import MemoryAnalyzer
    from malware_detector import MalwareDetector
    from threat_hunter import ThreatHunter
    
    # Create pipeline
    pipeline = AutomatedPipeline("forensics_output")
    
    # Run automated analysis
    results = pipeline.run_pipeline("sample_memory.dmp")
    
    print("\n📈 ANALYSIS SUMMARY")
    print("="*60)
    
    # Display key metrics
    malware_phase = results["phases"]["malware_detection"]
    print(f"Threat Score: {malware_phase['threat_score']:.1f}/100")
    print(f"Critical Indicators: {malware_phase['critical_indicators']}")
    print(f"Total Indicators: {malware_phase['total_indicators']}")
    
    if malware_phase["detected_families"]:
        print(f"\nDetected Malware:")
        for family in malware_phase["detected_families"]:
            print(f"  - {family}")
    
    print(f"\n📁 Reports saved to: {pipeline.output_dir}")
    print("  - executive_summary.json")
    print("  - technical_report.json")
    print("  - iocs.json")
    print("  - complete_analysis.json")
```

---

## ✅ Tutorial Completion Checklist

After completing all modules, verify your understanding:

- [ ] You can analyze memory dumps for processes and network connections
- [ ] You understand malware detection techniques and behavioral analysis
- [ ] You can identify process injection and rootkit techniques
- [ ] You know how to hunt for APT indicators and lateral movement
- [ ] You can build automated analysis pipelines
- [ ] You understand memory artifact extraction and IOC generation

## 🚀 Ready for the Assignment?

Great! Now you have all the tools for advanced memory forensics. The assignment will combine these concepts into a comprehensive investigation.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **Memory Analysis Fundamentals** with process and network investigation
2. **Malware Detection** using signatures and behavioral patterns
3. **Process Injection Techniques** including hollowing and reflective DLL
4. **APT Hunting** and lateral movement detection
5. **Automated Pipelines** for scalable memory forensics
6. **IOC Extraction** and threat intelligence generation
7. **Report Generation** for technical and executive audiences

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!