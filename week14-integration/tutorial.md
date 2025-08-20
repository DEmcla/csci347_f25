# Week 14 Tutorial: Integration and Incident Response

**Estimated Time**: 3-4 hours (broken into 4 modules)  
**Prerequisites**: All previous weeks completed, understanding of security and forensics concepts

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Module 1** (45 min): Built integrated incident response framework
2. **Module 2** (60 min): Created threat hunting and detection platform
3. **Module 3** (45 min): Developed security orchestration automation
4. **Module 4** (60 min): Designed comprehensive security dashboard

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Module 1: Incident Response Framework ✅ Checkpoint 1
- [ ] Module 2: Threat Hunting Platform ✅ Checkpoint 2  
- [ ] Module 3: Security Orchestration ✅ Checkpoint 3
- [ ] Module 4: Security Operations Dashboard ✅ Checkpoint 4

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Install required packages
pip install fastapi uvicorn sqlalchemy psutil scapy requests

# Create working directory
mkdir week14-work
cd week14-work
```

---

## 📘 Module 1: Incident Response Framework (45 minutes)

**Learning Objective**: Build comprehensive incident response system

**What you'll build**: NIST-aligned incident response framework with automation

### Step 1: Incident Response Core Framework

Create a new file `incident_response.py`:

```python
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib
import uuid

class IncidentSeverity(Enum):
    """Incident severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class IncidentStatus(Enum):
    """Incident status states"""
    NEW = "new"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"

class IncidentCategory(Enum):
    """NIST incident categories"""
    MALWARE = "malware"
    DENIAL_OF_SERVICE = "denial_of_service"
    WEB_APPLICATION_ATTACK = "web_application_attack"
    BRUTE_FORCE = "brute_force"
    DATA_BREACH = "data_breach"
    INSIDER_THREAT = "insider_threat"
    SOCIAL_ENGINEERING = "social_engineering"
    UNAUTHORIZED_ACCESS = "unauthorized_access"

@dataclass
class Evidence:
    """Digital evidence item"""
    evidence_id: str
    evidence_type: str  # file, network, memory, disk
    source_system: str
    collection_time: datetime
    hash_md5: str
    hash_sha256: str
    file_path: Optional[str] = None
    chain_of_custody: List[str] = field(default_factory=list)
    analysis_status: str = "pending"

@dataclass
class IOC:
    """Indicator of Compromise"""
    ioc_type: str  # ip, domain, hash, registry_key
    value: str
    confidence: float  # 0-1
    source: str
    first_seen: datetime
    last_seen: datetime
    threat_types: List[str] = field(default_factory=list)

@dataclass
class Incident:
    """Security incident"""
    incident_id: str
    title: str
    description: str
    category: IncidentCategory
    severity: IncidentSeverity
    status: IncidentStatus
    created_time: datetime
    assigned_analyst: Optional[str] = None
    affected_systems: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    iocs: List[IOC] = field(default_factory=list)
    timeline: List[Dict] = field(default_factory=list)
    containment_actions: List[str] = field(default_factory=list)
    lessons_learned: Optional[str] = None

class IncidentResponseFramework:
    """NIST-aligned incident response framework"""
    
    def __init__(self):
        self.incidents: Dict[str, Incident] = {}
        self.playbooks = self._load_playbooks()
        self.escalation_matrix = self._load_escalation_matrix()
        self.notification_templates = self._load_notification_templates()
    
    def _load_playbooks(self) -> Dict:
        """Load incident response playbooks"""
        return {
            IncidentCategory.MALWARE: {
                "preparation": [
                    "Verify antivirus is up to date",
                    "Ensure incident response team is available",
                    "Prepare forensics toolkit"
                ],
                "identification": [
                    "Analyze malware sample",
                    "Identify affected systems",
                    "Determine attack vector",
                    "Extract IOCs"
                ],
                "containment": [
                    "Isolate infected systems",
                    "Block malicious IOCs",
                    "Preserve evidence",
                    "Update security controls"
                ],
                "eradication": [
                    "Remove malware from systems",
                    "Patch vulnerabilities",
                    "Update signatures",
                    "Strengthen security controls"
                ],
                "recovery": [
                    "Restore systems from clean backups",
                    "Monitor for reinfection",
                    "Validate system integrity",
                    "Resume normal operations"
                ],
                "lessons_learned": [
                    "Document incident details",
                    "Identify improvement areas",
                    "Update procedures",
                    "Provide training"
                ]
            },
            IncidentCategory.DATA_BREACH: {
                "preparation": [
                    "Review data classification",
                    "Verify encryption status",
                    "Prepare legal notifications"
                ],
                "identification": [
                    "Determine data accessed",
                    "Identify attack method",
                    "Assess data sensitivity",
                    "Document timeline"
                ],
                "containment": [
                    "Revoke compromised credentials",
                    "Block attack vectors",
                    "Preserve evidence",
                    "Notify stakeholders"
                ],
                "eradication": [
                    "Remove attacker access",
                    "Patch vulnerabilities",
                    "Reset credentials",
                    "Implement additional controls"
                ],
                "recovery": [
                    "Restore affected systems",
                    "Monitor for continued access",
                    "Validate security controls",
                    "Resume operations"
                ],
                "lessons_learned": [
                    "Document breach details",
                    "Update security policies",
                    "Provide additional training",
                    "Improve monitoring"
                ]
            }
        }
    
    def _load_escalation_matrix(self) -> Dict:
        """Load escalation matrix"""
        return {
            IncidentSeverity.LOW: {
                "notification_time": 60,  # minutes
                "escalation_time": 240,  # 4 hours
                "stakeholders": ["security_analyst", "shift_supervisor"]
            },
            IncidentSeverity.MEDIUM: {
                "notification_time": 30,
                "escalation_time": 120,  # 2 hours
                "stakeholders": ["security_manager", "it_manager"]
            },
            IncidentSeverity.HIGH: {
                "notification_time": 15,
                "escalation_time": 60,  # 1 hour
                "stakeholders": ["ciso", "cto", "legal"]
            },
            IncidentSeverity.CRITICAL: {
                "notification_time": 5,
                "escalation_time": 30,
                "stakeholders": ["ceo", "ciso", "cto", "legal", "pr"]
            }
        }
    
    def _load_notification_templates(self) -> Dict:
        """Load notification templates"""
        return {
            "initial_notification": """
SECURITY INCIDENT NOTIFICATION

Incident ID: {incident_id}
Severity: {severity}
Category: {category}
Title: {title}

Description:
{description}

Affected Systems:
{affected_systems}

Next Steps:
- Incident assigned to {analyst}
- Containment actions in progress
- Regular updates will be provided

Contact: Security Operations Center
""",
            "status_update": """
INCIDENT STATUS UPDATE

Incident ID: {incident_id}
Status: {status}
Last Updated: {timestamp}

Recent Actions:
{recent_actions}

Next Steps:
{next_steps}

Estimated Resolution: {eta}
""",
            "incident_closed": """
INCIDENT CLOSURE NOTIFICATION

Incident ID: {incident_id}
Final Status: CLOSED
Resolution Time: {resolution_time}

Summary:
{summary}

Actions Taken:
{actions_taken}

Lessons Learned:
{lessons_learned}

Post-Incident Review scheduled for: {review_date}
"""
        }
    
    def create_incident(self, title: str, description: str, 
                       category: IncidentCategory, severity: IncidentSeverity,
                       affected_systems: List[str] = None) -> str:
        """Create new security incident"""
        incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
        
        incident = Incident(
            incident_id=incident_id,
            title=title,
            description=description,
            category=category,
            severity=severity,
            status=IncidentStatus.NEW,
            created_time=datetime.now(),
            affected_systems=affected_systems or []
        )
        
        # Add to incident timeline
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "incident_created",
            "details": f"Incident created with severity {severity.name}",
            "actor": "system"
        })
        
        self.incidents[incident_id] = incident
        
        # Auto-assign based on severity
        self._auto_assign_incident(incident)
        
        # Send notifications
        self._send_notifications(incident, "initial_notification")
        
        print(f"✅ Created incident {incident_id}")
        return incident_id
    
    def _auto_assign_incident(self, incident: Incident):
        """Auto-assign incident based on severity and availability"""
        # Simulated assignment logic
        if incident.severity == IncidentSeverity.CRITICAL:
            incident.assigned_analyst = "senior_analyst_1"
        elif incident.severity == IncidentSeverity.HIGH:
            incident.assigned_analyst = "analyst_2"
        else:
            incident.assigned_analyst = "analyst_3"
        
        incident.status = IncidentStatus.ASSIGNED
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "incident_assigned",
            "details": f"Assigned to {incident.assigned_analyst}",
            "actor": "system"
        })
    
    def add_evidence(self, incident_id: str, evidence_type: str, 
                    source_system: str, file_path: str = None) -> str:
        """Add evidence to incident"""
        if incident_id not in self.incidents:
            raise ValueError(f"Incident {incident_id} not found")
        
        evidence_id = f"EVD-{str(uuid.uuid4())[:8].upper()}"
        
        # Calculate hashes (simulated)
        content = f"{evidence_type}{source_system}{file_path}{datetime.now()}"
        md5_hash = hashlib.md5(content.encode()).hexdigest()
        sha256_hash = hashlib.sha256(content.encode()).hexdigest()
        
        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            source_system=source_system,
            collection_time=datetime.now(),
            hash_md5=md5_hash,
            hash_sha256=sha256_hash,
            file_path=file_path,
            chain_of_custody=[f"collected_by_system_{datetime.now()}"]
        )
        
        self.incidents[incident_id].evidence.append(evidence)
        
        # Update timeline
        self.incidents[incident_id].timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "evidence_added",
            "details": f"Added {evidence_type} evidence from {source_system}",
            "actor": "system"
        })
        
        return evidence_id
    
    def add_ioc(self, incident_id: str, ioc_type: str, value: str, 
                confidence: float, source: str) -> None:
        """Add IOC to incident"""
        if incident_id not in self.incidents:
            raise ValueError(f"Incident {incident_id} not found")
        
        ioc = IOC(
            ioc_type=ioc_type,
            value=value,
            confidence=confidence,
            source=source,
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        
        self.incidents[incident_id].iocs.append(ioc)
        
        # Update timeline
        self.incidents[incident_id].timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "ioc_added",
            "details": f"Added {ioc_type} IOC: {value}",
            "actor": "analyst"
        })
    
    def update_incident_status(self, incident_id: str, new_status: IncidentStatus,
                              notes: str = None) -> None:
        """Update incident status"""
        if incident_id not in self.incidents:
            raise ValueError(f"Incident {incident_id} not found")
        
        incident = self.incidents[incident_id]
        old_status = incident.status
        incident.status = new_status
        
        # Update timeline
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": "status_updated",
            "details": f"Status changed from {old_status.value} to {new_status.value}",
            "notes": notes,
            "actor": incident.assigned_analyst or "system"
        })
        
        # Send status update notification
        self._send_notifications(incident, "status_update")
        
        print(f"✅ Updated incident {incident_id} status to {new_status.value}")
    
    def execute_playbook_step(self, incident_id: str, phase: str) -> List[str]:
        """Execute playbook step for incident"""
        if incident_id not in self.incidents:
            raise ValueError(f"Incident {incident_id} not found")
        
        incident = self.incidents[incident_id]
        category_playbook = self.playbooks.get(incident.category, {})
        phase_steps = category_playbook.get(phase, [])
        
        # Update timeline
        incident.timeline.append({
            "timestamp": datetime.now().isoformat(),
            "action": f"playbook_{phase}",
            "details": f"Executing {phase} phase ({len(phase_steps)} steps)",
            "actor": incident.assigned_analyst
        })
        
        return phase_steps
    
    def _send_notifications(self, incident: Incident, template_type: str):
        """Send incident notifications"""
        template = self.notification_templates.get(template_type, "")
        escalation = self.escalation_matrix.get(incident.severity, {})
        
        stakeholders = escalation.get("stakeholders", [])
        
        # Format notification (simulated)
        notification = template.format(
            incident_id=incident.incident_id,
            severity=incident.severity.name,
            category=incident.category.value,
            title=incident.title,
            description=incident.description,
            affected_systems="\n".join(incident.affected_systems) or "None specified",
            analyst=incident.assigned_analyst or "Unassigned",
            status=incident.status.value,
            timestamp=datetime.now().isoformat()
        )
        
        print(f"📧 Sending notification to: {', '.join(stakeholders)}")
        # In production, would send actual emails/alerts
    
    def generate_incident_report(self, incident_id: str) -> Dict:
        """Generate comprehensive incident report"""
        if incident_id not in self.incidents:
            raise ValueError(f"Incident {incident_id} not found")
        
        incident = self.incidents[incident_id]
        
        report = {
            "incident_summary": {
                "id": incident.incident_id,
                "title": incident.title,
                "category": incident.category.value,
                "severity": incident.severity.name,
                "status": incident.status.value,
                "created": incident.created_time.isoformat(),
                "analyst": incident.assigned_analyst
            },
            "affected_systems": incident.affected_systems,
            "evidence_collected": len(incident.evidence),
            "iocs_identified": len(incident.iocs),
            "timeline_events": len(incident.timeline),
            "detailed_timeline": incident.timeline,
            "evidence_details": [
                {
                    "id": e.evidence_id,
                    "type": e.evidence_type,
                    "source": e.source_system,
                    "md5": e.hash_md5,
                    "sha256": e.hash_sha256
                } for e in incident.evidence
            ],
            "ioc_details": [
                {
                    "type": ioc.ioc_type,
                    "value": ioc.value,
                    "confidence": ioc.confidence,
                    "source": ioc.source
                } for ioc in incident.iocs
            ]
        }
        
        return report
    
    def get_active_incidents(self) -> List[Incident]:
        """Get all active incidents"""
        active_statuses = [IncidentStatus.NEW, IncidentStatus.ASSIGNED, 
                          IncidentStatus.IN_PROGRESS, IncidentStatus.CONTAINED]
        return [inc for inc in self.incidents.values() if inc.status in active_statuses]
    
    def get_dashboard_metrics(self) -> Dict:
        """Get incident response dashboard metrics"""
        total_incidents = len(self.incidents)
        active_incidents = len(self.get_active_incidents())
        
        severity_counts = {}
        status_counts = {}
        
        for incident in self.incidents.values():
            # Count by severity
            sev = incident.severity.name
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            # Count by status
            status = incident.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_incidents": total_incidents,
            "active_incidents": active_incidents,
            "severity_distribution": severity_counts,
            "status_distribution": status_counts,
            "avg_response_time": "2.5 hours",  # Would be calculated
            "sla_compliance": "94%"  # Would be calculated
        }

# Demo the incident response framework
if __name__ == "__main__":
    print("🚨 INCIDENT RESPONSE FRAMEWORK")
    print("="*60)
    
    ir = IncidentResponseFramework()
    
    # Create sample incidents
    print("\n📋 Creating Sample Incidents...")
    
    # Critical malware incident
    inc1 = ir.create_incident(
        title="Ransomware Detected on File Server",
        description="Ransomware encryption detected on FILESERVER-01 with .locked extensions",
        category=IncidentCategory.MALWARE,
        severity=IncidentSeverity.CRITICAL,
        affected_systems=["FILESERVER-01", "BACKUP-SRV"]
    )
    
    # Medium data breach incident
    inc2 = ir.create_incident(
        title="Unauthorized Database Access",
        description="Suspicious queries detected against customer database",
        category=IncidentCategory.DATA_BREACH,
        severity=IncidentSeverity.MEDIUM,
        affected_systems=["DB-SERVER-02"]
    )
    
    # Add evidence
    print("\n🔍 Adding Evidence...")
    ir.add_evidence(inc1, "memory_dump", "FILESERVER-01", "/evidence/memory.dmp")
    ir.add_evidence(inc1, "disk_image", "FILESERVER-01", "/evidence/disk.dd")
    
    # Add IOCs
    print("\n🎯 Adding IOCs...")
    ir.add_ioc(inc1, "file_hash", "a1b2c3d4e5f6", 0.9, "malware_analysis")
    ir.add_ioc(inc1, "ip_address", "192.168.1.100", 0.8, "network_logs")
    
    # Execute playbook
    print("\n📚 Executing Playbook...")
    containment_steps = ir.execute_playbook_step(inc1, "containment")
    print(f"Containment steps for malware incident:")
    for step in containment_steps:
        print(f"  - {step}")
    
    # Update status
    print("\n🔄 Updating Incident Status...")
    ir.update_incident_status(inc1, IncidentStatus.CONTAINED, 
                             "Systems isolated, evidence preserved")
    
    # Generate metrics
    print("\n📊 Dashboard Metrics:")
    metrics = ir.get_dashboard_metrics()
    print(f"  Total Incidents: {metrics['total_incidents']}")
    print(f"  Active Incidents: {metrics['active_incidents']}")
    print(f"  Severity Distribution: {metrics['severity_distribution']}")
    
    # Generate incident report
    print(f"\n📄 Generating Incident Report for {inc1}...")
    report = ir.generate_incident_report(inc1)
    print(f"  Evidence Items: {report['evidence_collected']}")
    print(f"  IOCs Identified: {report['iocs_identified']}")
    print(f"  Timeline Events: {report['timeline_events']}")
```

**Run it:**
```bash
python incident_response.py
```

### 💡 Key Concepts Learned

**Before moving to Module 2, make sure you understand:**

1. **NIST Incident Response Process**: Preparation → Detection → Containment → Eradication → Recovery → Lessons Learned
2. **Evidence Management**: Chain of custody and forensic integrity
3. **IOC Tracking**: Indicators of Compromise for threat hunting
4. **Escalation Procedures**: Severity-based notification workflows

### ✅ Checkpoint 1 Complete!
You can now manage security incidents systematically. Ready for Module 2?

---

## 📘 Module 2: Threat Hunting Platform (60 minutes)

**Learning Objective**: Build proactive threat hunting and detection platform

**What you'll build**: Integrated threat hunting system with behavioral analytics

### Step 1: Threat Hunting Engine

Create `threat_hunting.py`:

```python
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import re
import statistics
import hashlib

class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

class HuntType(Enum):
    """Types of threat hunting"""
    BEHAVIORAL = "behavioral"
    SIGNATURE = "signature"
    ANOMALY = "anomaly"
    IOC = "ioc"
    TTP = "ttp"  # Tactics, Techniques, Procedures

@dataclass
class ThreatHypothesis:
    """Threat hunting hypothesis"""
    hypothesis_id: str
    title: str
    description: str
    hunt_type: HuntType
    mitre_tactics: List[str]
    data_sources: List[str]
    queries: List[str]
    expected_results: str
    created_by: str
    created_time: datetime

@dataclass
class HuntResult:
    """Results from threat hunting"""
    hunt_id: str
    hypothesis_id: str
    threat_level: ThreatLevel
    findings: List[Dict]
    false_positives: int
    true_positives: int
    indicators: List[str]
    recommendations: List[str]
    timestamp: datetime

class ThreatHuntingPlatform:
    """Proactive threat hunting platform"""
    
    def __init__(self):
        self.hypotheses: Dict[str, ThreatHypothesis] = {}
        self.hunt_results: Dict[str, HuntResult] = {}
        self.behavioral_baselines = {}
        self.ioc_feeds = self._load_ioc_feeds()
        self.mitre_techniques = self._load_mitre_techniques()
    
    def _load_ioc_feeds(self) -> Dict:
        """Load threat intelligence IOC feeds"""
        return {
            "malware_domains": [
                "malicious-c2.com",
                "evil-domain.net",
                "bad-actor-site.org"
            ],
            "suspicious_ips": [
                "192.168.100.100",
                "10.0.0.250",
                "172.16.1.50"
            ],
            "file_hashes": {
                "a1b2c3d4e5f6": "Known malware family X",
                "f6e5d4c3b2a1": "Ransomware variant Y",
                "1234567890ab": "Banking trojan Z"
            },
            "registry_keys": [
                "HKLM\\SOFTWARE\\BadActor",
                "HKCU\\Software\\Malware\\Config"
            ]
        }
    
    def _load_mitre_techniques(self) -> Dict:
        """Load MITRE ATT&CK techniques"""
        return {
            "T1055": {
                "name": "Process Injection",
                "tactics": ["Defense Evasion", "Privilege Escalation"],
                "data_sources": ["Process", "Windows Registry", "File"],
                "detections": ["CreateRemoteThread", "WriteProcessMemory"]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactics": ["Execution"],
                "data_sources": ["Process", "Command"],
                "detections": ["powershell.exe", "cmd.exe", "wscript.exe"]
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "tactics": ["Discovery"],
                "data_sources": ["File", "Process"],
                "detections": ["dir", "ls", "find", "Get-ChildItem"]
            },
            "T1105": {
                "name": "Ingress Tool Transfer",
                "tactics": ["Command And Control"],
                "data_sources": ["Network Traffic", "File"],
                "detections": ["wget", "curl", "certutil", "bitsadmin"]
            }
        }
    
    def create_hypothesis(self, title: str, description: str, hunt_type: HuntType,
                         mitre_tactics: List[str], data_sources: List[str],
                         queries: List[str], expected_results: str) -> str:
        """Create new threat hunting hypothesis"""
        hypothesis_id = f"HUNT-{datetime.now().strftime('%Y%m%d')}-{len(self.hypotheses)+1:03d}"
        
        hypothesis = ThreatHypothesis(
            hypothesis_id=hypothesis_id,
            title=title,
            description=description,
            hunt_type=hunt_type,
            mitre_tactics=mitre_tactics,
            data_sources=data_sources,
            queries=queries,
            expected_results=expected_results,
            created_by="threat_hunter",
            created_time=datetime.now()
        )
        
        self.hypotheses[hypothesis_id] = hypothesis
        print(f"✅ Created hunting hypothesis {hypothesis_id}")
        return hypothesis_id
    
    def hunt_behavioral_anomalies(self, data_source: str) -> List[Dict]:
        """Hunt for behavioral anomalies"""
        # Simulated behavioral analysis
        anomalies = []
        
        # Login patterns
        if data_source == "authentication_logs":
            login_data = self._generate_sample_auth_data()
            
            # Detect unusual login times
            unusual_times = []
            for entry in login_data:
                hour = entry["timestamp"].hour
                if hour < 6 or hour > 22:  # Outside normal hours
                    unusual_times.append(entry)
            
            if len(unusual_times) > 5:
                anomalies.append({
                    "type": "unusual_login_times",
                    "count": len(unusual_times),
                    "details": f"{len(unusual_times)} logins outside normal hours",
                    "users": list(set(entry["user"] for entry in unusual_times)),
                    "severity": "medium"
                })
        
        # Network traffic patterns
        elif data_source == "network_logs":
            network_data = self._generate_sample_network_data()
            
            # Detect data exfiltration patterns
            large_transfers = [entry for entry in network_data if entry["bytes"] > 10000000]  # >10MB
            
            if len(large_transfers) > 10:
                anomalies.append({
                    "type": "large_data_transfers",
                    "count": len(large_transfers),
                    "details": f"{len(large_transfers)} large outbound transfers detected",
                    "destinations": list(set(entry["destination"] for entry in large_transfers)),
                    "severity": "high"
                })
        
        return anomalies
    
    def hunt_ioc_matches(self, data_source: str) -> List[Dict]:
        """Hunt for IOC matches"""
        matches = []
        
        if data_source == "dns_logs":
            # Simulated DNS data
            dns_queries = [
                {"domain": "google.com", "timestamp": datetime.now()},
                {"domain": "malicious-c2.com", "timestamp": datetime.now()},
                {"domain": "facebook.com", "timestamp": datetime.now()},
                {"domain": "evil-domain.net", "timestamp": datetime.now()}
            ]
            
            # Check against malicious domains
            for query in dns_queries:
                if query["domain"] in self.ioc_feeds["malware_domains"]:
                    matches.append({
                        "type": "malicious_domain",
                        "ioc": query["domain"],
                        "timestamp": query["timestamp"].isoformat(),
                        "confidence": 0.9
                    })
        
        elif data_source == "network_connections":
            # Simulated network connections
            connections = [
                {"dest_ip": "8.8.8.8", "port": 53},
                {"dest_ip": "192.168.100.100", "port": 4444},
                {"dest_ip": "172.16.1.50", "port": 443}
            ]
            
            # Check against suspicious IPs
            for conn in connections:
                if conn["dest_ip"] in self.ioc_feeds["suspicious_ips"]:
                    matches.append({
                        "type": "suspicious_ip",
                        "ioc": conn["dest_ip"],
                        "port": conn["port"],
                        "confidence": 0.8
                    })
        
        return matches
    
    def hunt_mitre_techniques(self, technique_id: str, data_source: str) -> List[Dict]:
        """Hunt for specific MITRE techniques"""
        if technique_id not in self.mitre_techniques:
            return []
        
        technique = self.mitre_techniques[technique_id]
        detections = []
        
        # Process injection (T1055)
        if technique_id == "T1055" and data_source == "process_logs":
            # Simulated process data
            processes = [
                {"name": "svchost.exe", "command": "CreateRemoteThread", "pid": 1234},
                {"name": "notepad.exe", "command": "WriteFile", "pid": 5678},
                {"name": "malware.exe", "command": "WriteProcessMemory", "pid": 9999}
            ]
            
            for process in processes:
                if any(det in process["command"] for det in technique["detections"]):
                    detections.append({
                        "technique": technique_id,
                        "process": process["name"],
                        "command": process["command"],
                        "pid": process["pid"],
                        "confidence": 0.7
                    })
        
        # Command execution (T1059)
        elif technique_id == "T1059" and data_source == "command_logs":
            # Simulated command logs
            commands = [
                {"process": "powershell.exe", "command": "Get-Process", "user": "admin"},
                {"process": "cmd.exe", "command": "net user hacker password123 /add", "user": "system"},
                {"process": "wscript.exe", "command": "malicious_script.vbs", "user": "user1"}
            ]
            
            for cmd in commands:
                if any(det in cmd["process"] for det in technique["detections"]):
                    # Check for suspicious commands
                    suspicious_keywords = ["net user", "add", "password", "script"]
                    if any(keyword in cmd["command"].lower() for keyword in suspicious_keywords):
                        detections.append({
                            "technique": technique_id,
                            "process": cmd["process"],
                            "command": cmd["command"],
                            "user": cmd["user"],
                            "confidence": 0.8
                        })
        
        return detections
    
    def hunt_lateral_movement(self) -> List[Dict]:
        """Hunt for lateral movement indicators"""
        lateral_movement = []
        
        # Simulated authentication patterns
        auth_events = self._generate_sample_auth_data()
        
        # Group by user
        user_logins = {}
        for event in auth_events:
            user = event["user"]
            if user not in user_logins:
                user_logins[user] = []
            user_logins[user].append(event)
        
        # Detect rapid authentication across multiple systems
        for user, logins in user_logins.items():
            if len(logins) > 10:  # Many authentication events
                unique_systems = set(login["source_host"] for login in logins)
                if len(unique_systems) > 5:  # Across many systems
                    lateral_movement.append({
                        "user": user,
                        "login_count": len(logins),
                        "unique_systems": len(unique_systems),
                        "systems": list(unique_systems),
                        "time_span": "2 hours",
                        "confidence": 0.75
                    })
        
        return lateral_movement
    
    def hunt_privilege_escalation(self) -> List[Dict]:
        """Hunt for privilege escalation attempts"""
        escalation_attempts = []
        
        # Simulated privileged operations
        priv_events = [
            {"user": "user1", "action": "runas_admin", "target": "cmd.exe"},
            {"user": "user2", "action": "su_root", "target": "/bin/bash"},
            {"user": "guest", "action": "add_local_admin", "target": "hacker_account"},
            {"user": "service_account", "action": "token_manipulation", "target": "SYSTEM"}
        ]
        
        # Check for suspicious privilege operations
        suspicious_actions = ["add_local_admin", "token_manipulation", "runas_admin"]
        low_priv_users = ["guest", "user1", "user2"]
        
        for event in priv_events:
            if event["action"] in suspicious_actions and event["user"] in low_priv_users:
                escalation_attempts.append({
                    "user": event["user"],
                    "action": event["action"],
                    "target": event["target"],
                    "risk": "high" if event["user"] == "guest" else "medium",
                    "confidence": 0.8
                })
        
        return escalation_attempts
    
    def _generate_sample_auth_data(self) -> List[Dict]:
        """Generate sample authentication data"""
        base_time = datetime.now() - timedelta(hours=24)
        auth_data = []
        
        users = ["user1", "user2", "admin", "guest", "service_account"]
        hosts = ["workstation1", "server1", "server2", "database", "fileserver"]
        
        for i in range(50):
            auth_data.append({
                "user": users[i % len(users)],
                "source_host": hosts[i % len(hosts)],
                "timestamp": base_time + timedelta(minutes=i*15),
                "success": i % 10 != 0  # 90% success rate
            })
        
        return auth_data
    
    def _generate_sample_network_data(self) -> List[Dict]:
        """Generate sample network traffic data"""
        network_data = []
        destinations = ["8.8.8.8", "1.1.1.1", "192.168.100.100", "10.0.0.1"]
        
        for i in range(100):
            network_data.append({
                "destination": destinations[i % len(destinations)],
                "bytes": (i * 1000000) % 50000000,  # Varying sizes up to 50MB
                "timestamp": datetime.now() - timedelta(minutes=i*5),
                "protocol": "TCP"
            })
        
        return network_data
    
    def execute_hunt(self, hypothesis_id: str) -> str:
        """Execute threat hunting hypothesis"""
        if hypothesis_id not in self.hypotheses:
            raise ValueError(f"Hypothesis {hypothesis_id} not found")
        
        hypothesis = self.hypotheses[hypothesis_id]
        hunt_id = f"EXEC-{hypothesis_id}-{datetime.now().strftime('%H%M%S')}"
        
        findings = []
        indicators = []
        threat_level = ThreatLevel.INFO
        
        # Execute based on hunt type
        if hypothesis.hunt_type == HuntType.BEHAVIORAL:
            for data_source in hypothesis.data_sources:
                anomalies = self.hunt_behavioral_anomalies(data_source)
                findings.extend(anomalies)
        
        elif hypothesis.hunt_type == HuntType.IOC:
            for data_source in hypothesis.data_sources:
                ioc_matches = self.hunt_ioc_matches(data_source)
                findings.extend(ioc_matches)
                indicators.extend([match["ioc"] for match in ioc_matches])
        
        elif hypothesis.hunt_type == HuntType.TTP:
            # Extract MITRE technique from queries
            for query in hypothesis.queries:
                if "T10" in query:  # MITRE technique format
                    technique = query.split()[0]  # First word
                    for data_source in hypothesis.data_sources:
                        ttp_detections = self.hunt_mitre_techniques(technique, data_source)
                        findings.extend(ttp_detections)
        
        # Determine threat level based on findings
        if len(findings) > 10:
            threat_level = ThreatLevel.HIGH
        elif len(findings) > 5:
            threat_level = ThreatLevel.MEDIUM
        elif len(findings) > 0:
            threat_level = ThreatLevel.LOW
        
        # Calculate true/false positives (simulated)
        true_positives = int(len(findings) * 0.7)  # 70% accuracy
        false_positives = len(findings) - true_positives
        
        # Generate recommendations
        recommendations = []
        if threat_level.value >= ThreatLevel.MEDIUM.value:
            recommendations.append("Investigate findings immediately")
            recommendations.append("Consider creating incident")
        if len(indicators) > 0:
            recommendations.append("Add indicators to blocklists")
        
        # Store results
        result = HuntResult(
            hunt_id=hunt_id,
            hypothesis_id=hypothesis_id,
            threat_level=threat_level,
            findings=findings,
            false_positives=false_positives,
            true_positives=true_positives,
            indicators=indicators,
            recommendations=recommendations,
            timestamp=datetime.now()
        )
        
        self.hunt_results[hunt_id] = result
        
        print(f"✅ Completed hunt {hunt_id}")
        print(f"   Threat Level: {threat_level.name}")
        print(f"   Findings: {len(findings)}")
        print(f"   True Positives: {true_positives}")
        
        return hunt_id
    
    def generate_hunt_report(self, hunt_id: str) -> Dict:
        """Generate hunting report"""
        if hunt_id not in self.hunt_results:
            raise ValueError(f"Hunt result {hunt_id} not found")
        
        result = self.hunt_results[hunt_id]
        hypothesis = self.hypotheses[result.hypothesis_id]
        
        return {
            "hunt_summary": {
                "hunt_id": hunt_id,
                "hypothesis": hypothesis.title,
                "hunt_type": hypothesis.hunt_type.value,
                "threat_level": result.threat_level.name,
                "execution_time": result.timestamp.isoformat()
            },
            "findings": {
                "total_findings": len(result.findings),
                "true_positives": result.true_positives,
                "false_positives": result.false_positives,
                "accuracy": f"{(result.true_positives/len(result.findings)*100):.1f}%" if result.findings else "N/A"
            },
            "indicators": result.indicators,
            "recommendations": result.recommendations,
            "detailed_findings": result.findings
        }

# Demo the threat hunting platform
if __name__ == "__main__":
    print("🎯 THREAT HUNTING PLATFORM")
    print("="*60)
    
    platform = ThreatHuntingPlatform()
    
    # Create hunting hypotheses
    print("\n📝 Creating Hunting Hypotheses...")
    
    # Behavioral anomaly hunt
    h1 = platform.create_hypothesis(
        title="Unusual Login Patterns",
        description="Hunt for authentication anomalies indicating compromise",
        hunt_type=HuntType.BEHAVIORAL,
        mitre_tactics=["Initial Access"],
        data_sources=["authentication_logs"],
        queries=["SELECT * FROM auth_logs WHERE hour < 6 OR hour > 22"],
        expected_results="Identify compromised accounts"
    )
    
    # IOC hunt
    h2 = platform.create_hypothesis(
        title="Known Malicious Infrastructure",
        description="Hunt for connections to known bad domains/IPs",
        hunt_type=HuntType.IOC,
        mitre_tactics=["Command And Control"],
        data_sources=["dns_logs", "network_connections"],
        queries=["SELECT * FROM dns WHERE domain IN (ioc_domains)"],
        expected_results="Detect C2 communications"
    )
    
    # MITRE technique hunt
    h3 = platform.create_hypothesis(
        title="Process Injection Techniques",
        description="Hunt for process injection indicators",
        hunt_type=HuntType.TTP,
        mitre_tactics=["Defense Evasion"],
        data_sources=["process_logs"],
        queries=["T1055 process_injection"],
        expected_results="Detect advanced malware"
    )
    
    # Execute hunts
    print("\n🔍 Executing Threat Hunts...")
    
    hunt1 = platform.execute_hunt(h1)
    hunt2 = platform.execute_hunt(h2)
    hunt3 = platform.execute_hunt(h3)
    
    # Additional hunting techniques
    print("\n🕵️ Running Specialized Hunts...")
    
    lateral_movement = platform.hunt_lateral_movement()
    if lateral_movement:
        print(f"  Lateral Movement: {len(lateral_movement)} indicators")
    
    privilege_escalation = platform.hunt_privilege_escalation()
    if privilege_escalation:
        print(f"  Privilege Escalation: {len(privilege_escalation)} attempts")
    
    # Generate reports
    print("\n📊 Hunt Reports:")
    for hunt_id in [hunt1, hunt2, hunt3]:
        report = platform.generate_hunt_report(hunt_id)
        print(f"\n{report['hunt_summary']['hypothesis']}:")
        print(f"  Threat Level: {report['hunt_summary']['threat_level']}")
        print(f"  Findings: {report['findings']['total_findings']}")
        print(f"  Accuracy: {report['findings']['accuracy']}")
```

---

## 📘 Module 3: Security Orchestration (45 minutes)

**Learning Objective**: Automate security operations and response

**What you'll build**: SOAR (Security Orchestration, Automation, and Response) system

Create `security_orchestration.py`:

```python
from typing import Dict, List, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import time
import threading

class ActionStatus(Enum):
    """Action execution status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"

class TriggerType(Enum):
    """Event trigger types"""
    ALERT = "alert"
    INCIDENT = "incident"
    IOC = "ioc"
    THRESHOLD = "threshold"
    SCHEDULED = "scheduled"

@dataclass
class PlaybookAction:
    """Automated playbook action"""
    action_id: str
    name: str
    action_type: str  # api_call, command, notification, analysis
    parameters: Dict[str, Any]
    timeout: int = 300  # seconds
    retry_count: int = 3
    on_success: List[str] = field(default_factory=list)  # Next action IDs
    on_failure: List[str] = field(default_factory=list)

@dataclass
class Playbook:
    """Security automation playbook"""
    playbook_id: str
    name: str
    description: str
    trigger_type: TriggerType
    trigger_conditions: Dict[str, Any]
    actions: List[PlaybookAction]
    enabled: bool = True

@dataclass
class ExecutionResult:
    """Playbook execution result"""
    execution_id: str
    playbook_id: str
    start_time: datetime
    end_time: datetime
    status: ActionStatus
    actions_executed: List[Dict]
    outputs: Dict[str, Any]
    errors: List[str] = field(default_factory=list)

class SecurityOrchestrationPlatform:
    """SOAR platform for security automation"""
    
    def __init__(self):
        self.playbooks: Dict[str, Playbook] = {}
        self.executions: Dict[str, ExecutionResult] = {}
        self.connectors = self._initialize_connectors()
        self.active_executions = {}
        
        # Built-in actions
        self.action_handlers = {
            "block_ip": self._block_ip,
            "quarantine_file": self._quarantine_file,
            "send_notification": self._send_notification,
            "create_incident": self._create_incident,
            "run_scan": self._run_scan,
            "collect_evidence": self._collect_evidence,
            "update_ioc_list": self._update_ioc_list,
            "isolate_system": self._isolate_system
        }
    
    def _initialize_connectors(self) -> Dict:
        """Initialize integrations with security tools"""
        return {
            "firewall": {
                "type": "network_security",
                "api_endpoint": "https://firewall.company.com/api",
                "capabilities": ["block_ip", "create_rule", "get_logs"]
            },
            "edr": {
                "type": "endpoint_security", 
                "api_endpoint": "https://edr.company.com/api",
                "capabilities": ["quarantine_file", "isolate_host", "collect_forensics"]
            },
            "siem": {
                "type": "security_monitoring",
                "api_endpoint": "https://siem.company.com/api",
                "capabilities": ["create_case", "run_query", "get_events"]
            },
            "email": {
                "type": "communication",
                "api_endpoint": "smtp.company.com",
                "capabilities": ["send_notification", "send_alert"]
            }
        }
    
    def create_playbook(self, name: str, description: str, trigger_type: TriggerType,
                       trigger_conditions: Dict[str, Any]) -> str:
        """Create new security playbook"""
        playbook_id = f"PB-{datetime.now().strftime('%Y%m%d')}-{len(self.playbooks)+1:03d}"
        
        playbook = Playbook(
            playbook_id=playbook_id,
            name=name,
            description=description,
            trigger_type=trigger_type,
            trigger_conditions=trigger_conditions,
            actions=[]
        )
        
        self.playbooks[playbook_id] = playbook
        print(f"✅ Created playbook {playbook_id}: {name}")
        return playbook_id
    
    def add_action(self, playbook_id: str, name: str, action_type: str,
                   parameters: Dict[str, Any], on_success: List[str] = None,
                   on_failure: List[str] = None) -> str:
        """Add action to playbook"""
        if playbook_id not in self.playbooks:
            raise ValueError(f"Playbook {playbook_id} not found")
        
        action_id = f"ACT-{len(self.playbooks[playbook_id].actions)+1:03d}"
        
        action = PlaybookAction(
            action_id=action_id,
            name=name,
            action_type=action_type,
            parameters=parameters,
            on_success=on_success or [],
            on_failure=on_failure or []
        )
        
        self.playbooks[playbook_id].actions.append(action)
        return action_id
    
    def trigger_playbook(self, trigger_event: Dict[str, Any]) -> List[str]:
        """Check triggers and execute matching playbooks"""
        triggered_playbooks = []
        
        for playbook_id, playbook in self.playbooks.items():
            if not playbook.enabled:
                continue
                
            if self._check_trigger_conditions(playbook, trigger_event):
                execution_id = self._execute_playbook(playbook_id, trigger_event)
                triggered_playbooks.append(execution_id)
        
        return triggered_playbooks
    
    def _check_trigger_conditions(self, playbook: Playbook, event: Dict[str, Any]) -> bool:
        """Check if event matches playbook trigger conditions"""
        # Check trigger type
        if event.get("type") != playbook.trigger_type.value:
            return False
        
        # Check specific conditions
        conditions = playbook.trigger_conditions
        
        for key, expected_value in conditions.items():
            if key not in event:
                return False
            
            event_value = event[key]
            
            # Handle different comparison types
            if isinstance(expected_value, dict):
                if "operator" in expected_value:
                    op = expected_value["operator"]
                    value = expected_value["value"]
                    
                    if op == "equals" and event_value != value:
                        return False
                    elif op == "contains" and value not in str(event_value):
                        return False
                    elif op == "greater_than" and event_value <= value:
                        return False
                    elif op == "in_list" and event_value not in value:
                        return False
            else:
                if event_value != expected_value:
                    return False
        
        return True
    
    def _execute_playbook(self, playbook_id: str, trigger_event: Dict[str, Any]) -> str:
        """Execute playbook asynchronously"""
        execution_id = f"EXEC-{playbook_id}-{datetime.now().strftime('%H%M%S')}"
        
        # Start execution in background thread
        thread = threading.Thread(
            target=self._run_playbook,
            args=(execution_id, playbook_id, trigger_event)
        )
        thread.daemon = True
        thread.start()
        
        return execution_id
    
    def _run_playbook(self, execution_id: str, playbook_id: str, trigger_event: Dict[str, Any]):
        """Run playbook execution"""
        playbook = self.playbooks[playbook_id]
        
        execution = ExecutionResult(
            execution_id=execution_id,
            playbook_id=playbook_id,
            start_time=datetime.now(),
            end_time=datetime.now(),
            status=ActionStatus.RUNNING,
            actions_executed=[],
            outputs={"trigger_event": trigger_event}
        )
        
        self.executions[execution_id] = execution
        self.active_executions[execution_id] = execution
        
        print(f"🚀 Starting playbook execution {execution_id}")
        
        try:
            # Execute actions in sequence
            current_actions = [playbook.actions[0]] if playbook.actions else []
            
            while current_actions:
                next_actions = []
                
                for action in current_actions:
                    result = self._execute_action(action, execution.outputs)
                    
                    execution.actions_executed.append({
                        "action_id": action.action_id,
                        "name": action.name,
                        "status": result["status"],
                        "output": result.get("output", {}),
                        "timestamp": datetime.now().isoformat()
                    })
                    
                    # Update execution outputs
                    execution.outputs[action.action_id] = result.get("output", {})
                    
                    # Determine next actions
                    if result["status"] == ActionStatus.SUCCESS:
                        next_action_ids = action.on_success
                    else:
                        next_action_ids = action.on_failure
                        execution.errors.append(f"Action {action.name} failed: {result.get('error')}")
                    
                    # Find next actions
                    for next_id in next_action_ids:
                        next_action = next(
                            (a for a in playbook.actions if a.action_id == next_id),
                            None
                        )
                        if next_action:
                            next_actions.append(next_action)
                
                current_actions = next_actions
            
            execution.status = ActionStatus.SUCCESS if not execution.errors else ActionStatus.FAILED
            
        except Exception as e:
            execution.status = ActionStatus.FAILED
            execution.errors.append(str(e))
        
        finally:
            execution.end_time = datetime.now()
            if execution_id in self.active_executions:
                del self.active_executions[execution_id]
            
            print(f"✅ Completed playbook execution {execution_id} with status {execution.status.value}")
    
    def _execute_action(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict:
        """Execute individual playbook action"""
        print(f"  🔧 Executing action: {action.name}")
        
        try:
            # Get action handler
            handler = self.action_handlers.get(action.action_type)
            if not handler:
                return {
                    "status": ActionStatus.FAILED,
                    "error": f"No handler for action type {action.action_type}"
                }
            
            # Execute with timeout
            start_time = time.time()
            result = handler(action.parameters, context)
            execution_time = time.time() - start_time
            
            if execution_time > action.timeout:
                return {
                    "status": ActionStatus.TIMEOUT,
                    "error": f"Action timed out after {execution_time:.1f} seconds"
                }
            
            return {
                "status": ActionStatus.SUCCESS,
                "output": result,
                "execution_time": execution_time
            }
            
        except Exception as e:
            return {
                "status": ActionStatus.FAILED,
                "error": str(e)
            }
    
    # Action handlers
    def _block_ip(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Block IP address on firewall"""
        ip_address = params.get("ip_address")
        duration = params.get("duration", 3600)  # 1 hour default
        
        # Simulate API call to firewall
        time.sleep(1)  # Simulate network delay
        
        return {
            "action": "block_ip",
            "ip_address": ip_address,
            "duration": duration,
            "rule_id": f"RULE-{hash(ip_address) % 10000}",
            "status": "blocked"
        }
    
    def _quarantine_file(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Quarantine malicious file"""
        file_hash = params.get("file_hash")
        systems = params.get("systems", [])
        
        time.sleep(2)  # Simulate EDR operation
        
        return {
            "action": "quarantine_file",
            "file_hash": file_hash,
            "systems_affected": len(systems),
            "quarantine_id": f"QID-{hash(file_hash) % 10000}",
            "status": "quarantined"
        }
    
    def _send_notification(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Send notification/alert"""
        recipients = params.get("recipients", [])
        subject = params.get("subject", "Security Alert")
        message = params.get("message", "")
        
        return {
            "action": "send_notification",
            "recipients": recipients,
            "subject": subject,
            "sent_at": datetime.now().isoformat()
        }
    
    def _create_incident(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Create security incident"""
        title = params.get("title", "Automated Incident")
        severity = params.get("severity", "medium")
        
        incident_id = f"INC-AUTO-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        return {
            "action": "create_incident",
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
            "created_at": datetime.now().isoformat()
        }
    
    def _run_scan(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Run security scan"""
        scan_type = params.get("scan_type", "vulnerability")
        targets = params.get("targets", [])
        
        time.sleep(5)  # Simulate scan time
        
        return {
            "action": "run_scan",
            "scan_type": scan_type,
            "targets": targets,
            "scan_id": f"SCAN-{hash(str(targets)) % 10000}",
            "findings": f"{len(targets) * 2} vulnerabilities found"
        }
    
    def _collect_evidence(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Collect forensic evidence"""
        evidence_type = params.get("evidence_type", "memory")
        systems = params.get("systems", [])
        
        time.sleep(3)  # Simulate collection time
        
        return {
            "action": "collect_evidence",
            "evidence_type": evidence_type,
            "systems": systems,
            "evidence_id": f"EVD-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "collected_at": datetime.now().isoformat()
        }
    
    def _update_ioc_list(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Update IOC lists"""
        iocs = params.get("iocs", [])
        action = params.get("action", "add")  # add or remove
        
        return {
            "action": "update_ioc_list",
            "ioc_count": len(iocs),
            "list_action": action,
            "updated_at": datetime.now().isoformat()
        }
    
    def _isolate_system(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict:
        """Isolate compromised system"""
        systems = params.get("systems", [])
        
        time.sleep(2)  # Simulate isolation
        
        return {
            "action": "isolate_system",
            "systems": systems,
            "isolated_at": datetime.now().isoformat()
        }
    
    def get_execution_status(self, execution_id: str) -> Dict:
        """Get playbook execution status"""
        if execution_id not in self.executions:
            return {"error": "Execution not found"}
        
        execution = self.executions[execution_id]
        
        return {
            "execution_id": execution_id,
            "playbook_id": execution.playbook_id,
            "status": execution.status.value,
            "start_time": execution.start_time.isoformat(),
            "end_time": execution.end_time.isoformat(),
            "duration": str(execution.end_time - execution.start_time),
            "actions_executed": len(execution.actions_executed),
            "errors": execution.errors,
            "is_running": execution_id in self.active_executions
        }
    
    def get_platform_metrics(self) -> Dict:
        """Get SOAR platform metrics"""
        total_executions = len(self.executions)
        successful_executions = len([e for e in self.executions.values() 
                                    if e.status == ActionStatus.SUCCESS])
        active_executions = len(self.active_executions)
        
        return {
            "total_playbooks": len(self.playbooks),
            "enabled_playbooks": len([p for p in self.playbooks.values() if p.enabled]),
            "total_executions": total_executions,
            "successful_executions": successful_executions,
            "success_rate": f"{(successful_executions/total_executions*100):.1f}%" if total_executions > 0 else "0%",
            "active_executions": active_executions,
            "connectors": len(self.connectors)
        }

# Demo the SOAR platform
if __name__ == "__main__":
    print("🤖 SECURITY ORCHESTRATION PLATFORM")
    print("="*60)
    
    soar = SecurityOrchestrationPlatform()
    
    # Create malware response playbook
    print("\n📚 Creating Malware Response Playbook...")
    pb1 = soar.create_playbook(
        name="Malware Incident Response",
        description="Automated response to malware detection",
        trigger_type=TriggerType.ALERT,
        trigger_conditions={
            "alert_type": "malware_detected",
            "severity": {"operator": "greater_than", "value": 7}
        }
    )
    
    # Add actions to playbook
    act1 = soar.add_action(pb1, "Quarantine File", "quarantine_file", 
                          {"file_hash": "${trigger_event.file_hash}", 
                           "systems": "${trigger_event.affected_systems}"})
    
    act2 = soar.add_action(pb1, "Block C2 IP", "block_ip",
                          {"ip_address": "${trigger_event.c2_ip}", 
                           "duration": 86400})
    
    act3 = soar.add_action(pb1, "Create Incident", "create_incident",
                          {"title": "Malware Detection: ${trigger_event.malware_family}",
                           "severity": "high"})
    
    act4 = soar.add_action(pb1, "Send Alert", "send_notification",
                          {"recipients": ["security-team@company.com"],
                           "subject": "URGENT: Malware Detected",
                           "message": "Malware ${trigger_event.malware_family} detected and contained"})
    
    # Create data breach playbook
    print("\n📚 Creating Data Breach Playbook...")
    pb2 = soar.create_playbook(
        name="Data Breach Response",
        description="Automated response to data breach",
        trigger_type=TriggerType.INCIDENT,
        trigger_conditions={
            "category": "data_breach",
            "severity": {"operator": "in_list", "value": ["high", "critical"]}
        }
    )
    
    soar.add_action(pb2, "Isolate Systems", "isolate_system",
                   {"systems": "${trigger_event.affected_systems}"})
    
    soar.add_action(pb2, "Collect Evidence", "collect_evidence",
                   {"evidence_type": "disk_image", 
                    "systems": "${trigger_event.affected_systems}"})
    
    soar.add_action(pb2, "Executive Notification", "send_notification",
                   {"recipients": ["ciso@company.com", "legal@company.com"],
                    "subject": "CRITICAL: Data Breach Detected"})
    
    # Trigger playbooks with sample events
    print("\n🚨 Triggering Playbook Executions...")
    
    # Malware detection event
    malware_event = {
        "type": "alert",
        "alert_type": "malware_detected",
        "severity": 9,
        "file_hash": "a1b2c3d4e5f6",
        "malware_family": "Ransomware.Generic",
        "c2_ip": "192.168.100.100",
        "affected_systems": ["workstation-01", "server-02"]
    }
    
    executions1 = soar.trigger_playbook(malware_event)
    print(f"  Triggered {len(executions1)} playbooks for malware event")
    
    # Data breach event
    breach_event = {
        "type": "incident",
        "category": "data_breach",
        "severity": "critical",
        "affected_systems": ["database-01", "web-server-01"],
        "data_types": ["customer_data", "payment_info"]
    }
    
    executions2 = soar.trigger_playbook(breach_event)
    print(f"  Triggered {len(executions2)} playbooks for breach event")
    
    # Wait for executions to complete
    print("\n⏱️ Waiting for executions to complete...")
    time.sleep(8)
    
    # Check execution results
    print("\n📊 Execution Results:")
    for execution_id in executions1 + executions2:
        status = soar.get_execution_status(execution_id)
        print(f"  {execution_id}: {status['status']} ({status['actions_executed']} actions)")
    
    # Platform metrics
    print("\n📈 Platform Metrics:")
    metrics = soar.get_platform_metrics()
    for key, value in metrics.items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
```

---

## 📘 Module 4: Security Operations Dashboard (60 minutes)

**Learning Objective**: Create comprehensive security operations center dashboard

**What you'll build**: Real-time SOC dashboard with integrated metrics

Create `security_dashboard.py`:

```python
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import random

class DashboardWidget(Enum):
    """Dashboard widget types"""
    METRIC = "metric"
    CHART = "chart"
    TABLE = "table"
    ALERT = "alert"
    MAP = "map"

@dataclass
class SecurityMetric:
    """Security metric/KPI"""
    metric_id: str
    name: str
    description: str
    current_value: float
    target_value: float
    unit: str
    trend: str  # up, down, stable
    category: str
    timestamp: datetime
    
    @property
    def performance_percentage(self) -> float:
        """Calculate performance as percentage of target"""
        if self.target_value > 0:
            return min((self.current_value / self.target_value) * 100, 100)
        return 0
    
    @property
    def status(self) -> str:
        """Determine metric status"""
        perf = self.performance_percentage
        if perf >= 90:
            return "excellent"
        elif perf >= 75:
            return "good"
        elif perf >= 50:
            return "warning"
        else:
            return "critical"

@dataclass
class DashboardWidget:
    """Dashboard widget configuration"""
    widget_id: str
    title: str
    widget_type: str
    size: str  # small, medium, large
    position: Dict[str, int]  # x, y coordinates
    data_source: str
    refresh_interval: int  # seconds
    configuration: Dict[str, Any] = field(default_factory=dict)

class SecurityDashboard:
    """Security Operations Center Dashboard"""
    
    def __init__(self):
        self.widgets: Dict[str, DashboardWidget] = {}
        self.metrics: Dict[str, SecurityMetric] = {}
        self.alerts: List[Dict] = []
        self.incidents: List[Dict] = []
        self.threat_feed = []
        
        # Initialize with default metrics
        self._initialize_default_metrics()
        self._initialize_sample_data()
    
    def _initialize_default_metrics(self):
        """Initialize default security metrics"""
        default_metrics = [
            {
                "metric_id": "mttr",
                "name": "Mean Time to Response",
                "description": "Average time to respond to incidents",
                "current_value": 45,
                "target_value": 30,
                "unit": "minutes",
                "category": "incident_response"
            },
            {
                "metric_id": "mttd",
                "name": "Mean Time to Detect",
                "description": "Average time to detect security incidents",
                "current_value": 120,
                "target_value": 60,
                "unit": "minutes",
                "category": "detection"
            },
            {
                "metric_id": "alert_volume",
                "name": "Daily Alert Volume",
                "description": "Number of security alerts per day",
                "current_value": 1247,
                "target_value": 800,
                "unit": "alerts",
                "category": "monitoring"
            },
            {
                "metric_id": "false_positive_rate",
                "name": "False Positive Rate",
                "description": "Percentage of alerts that are false positives",
                "current_value": 23,
                "target_value": 15,
                "unit": "%",
                "category": "monitoring"
            },
            {
                "metric_id": "patch_compliance",
                "name": "Patch Compliance",
                "description": "Percentage of systems with current patches",
                "current_value": 87,
                "target_value": 95,
                "unit": "%",
                "category": "vulnerability_management"
            },
            {
                "metric_id": "backup_success",
                "name": "Backup Success Rate",
                "description": "Percentage of successful backups",
                "current_value": 98,
                "target_value": 99,
                "unit": "%",
                "category": "business_continuity"
            },
            {
                "metric_id": "security_training",
                "name": "Security Training Completion",
                "description": "Employee security training completion rate",
                "current_value": 89,
                "target_value": 95,
                "unit": "%",
                "category": "security_awareness"
            },
            {
                "metric_id": "vulnerability_age",
                "name": "Average Vulnerability Age",
                "description": "Average age of unpatched vulnerabilities",
                "current_value": 28,
                "target_value": 14,
                "unit": "days",
                "category": "vulnerability_management"
            }
        ]
        
        for metric_data in default_metrics:
            trend = random.choice(["up", "down", "stable"])
            
            metric = SecurityMetric(
                metric_id=metric_data["metric_id"],
                name=metric_data["name"],
                description=metric_data["description"],
                current_value=metric_data["current_value"],
                target_value=metric_data["target_value"],
                unit=metric_data["unit"],
                trend=trend,
                category=metric_data["category"],
                timestamp=datetime.now()
            )
            
            self.metrics[metric.metric_id] = metric
    
    def _initialize_sample_data(self):
        """Initialize sample dashboard data"""
        # Sample alerts
        self.alerts = [
            {
                "alert_id": "ALT-001",
                "timestamp": datetime.now() - timedelta(minutes=15),
                "severity": "high",
                "title": "Suspicious PowerShell Activity",
                "description": "Encoded PowerShell command detected on WORKSTATION-05",
                "source": "EDR",
                "status": "open"
            },
            {
                "alert_id": "ALT-002", 
                "timestamp": datetime.now() - timedelta(minutes=32),
                "severity": "medium",
                "title": "Multiple Failed Logins",
                "description": "15 failed login attempts from IP 192.168.1.150",
                "source": "SIEM",
                "status": "investigating"
            },
            {
                "alert_id": "ALT-003",
                "timestamp": datetime.now() - timedelta(hours=2),
                "severity": "critical",
                "title": "Malware Detection",
                "description": "Trojan.Generic detected on SERVER-03",
                "source": "Antivirus",
                "status": "contained"
            }
        ]
        
        # Sample incidents
        self.incidents = [
            {
                "incident_id": "INC-20240117-001",
                "title": "Data Exfiltration Attempt",
                "severity": "high",
                "status": "investigating",
                "created": datetime.now() - timedelta(hours=4),
                "analyst": "Jane Smith",
                "affected_systems": 3
            },
            {
                "incident_id": "INC-20240117-002",
                "title": "Phishing Campaign",
                "severity": "medium",
                "status": "contained",
                "created": datetime.now() - timedelta(hours=8),
                "analyst": "John Doe",
                "affected_systems": 12
            }
        ]
        
        # Sample threat intelligence
        self.threat_feed = [
            {
                "ioc": "malicious-domain.com",
                "type": "domain",
                "threat_type": "C2",
                "confidence": 0.95,
                "first_seen": datetime.now() - timedelta(hours=6),
                "source": "Threat Intelligence Feed"
            },
            {
                "ioc": "192.168.100.50",
                "type": "ip",
                "threat_type": "scanning",
                "confidence": 0.8,
                "first_seen": datetime.now() - timedelta(hours=12),
                "source": "Internal Detection"
            }
        ]
    
    def add_widget(self, title: str, widget_type: str, size: str, 
                   position: Dict[str, int], data_source: str,
                   refresh_interval: int = 300) -> str:
        """Add widget to dashboard"""
        widget_id = f"WID-{len(self.widgets)+1:03d}"
        
        widget = DashboardWidget(
            widget_id=widget_id,
            title=title,
            widget_type=widget_type,
            size=size,
            position=position,
            data_source=data_source,
            refresh_interval=refresh_interval
        )
        
        self.widgets[widget_id] = widget
        return widget_id
    
    def get_security_overview(self) -> Dict:
        """Get high-level security overview"""
        # Count alerts by severity
        alert_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for alert in self.alerts:
            severity = alert.get("severity", "low")
            alert_counts[severity] = alert_counts.get(severity, 0) + 1
        
        # Count incidents by status
        incident_counts = {"new": 0, "investigating": 0, "contained": 0, "closed": 0}
        for incident in self.incidents:
            status = incident.get("status", "new")
            incident_counts[status] = incident_counts.get(status, 0) + 1
        
        # Calculate overall health score
        metric_scores = []
        for metric in self.metrics.values():
            if metric.category in ["incident_response", "detection", "monitoring"]:
                metric_scores.append(metric.performance_percentage)
        
        health_score = sum(metric_scores) / len(metric_scores) if metric_scores else 0
        
        return {
            "health_score": round(health_score, 1),
            "total_alerts": len(self.alerts),
            "alert_breakdown": alert_counts,
            "total_incidents": len(self.incidents),
            "incident_breakdown": incident_counts,
            "active_threats": len(self.threat_feed),
            "last_updated": datetime.now().isoformat()
        }
    
    def get_metrics_by_category(self, category: str = None) -> Dict:
        """Get metrics grouped by category"""
        if category:
            filtered_metrics = {k: v for k, v in self.metrics.items() 
                              if v.category == category}
        else:
            filtered_metrics = self.metrics
        
        # Group by category
        categories = {}
        for metric in filtered_metrics.values():
            cat = metric.category
            if cat not in categories:
                categories[cat] = []
            
            categories[cat].append({
                "name": metric.name,
                "current_value": metric.current_value,
                "target_value": metric.target_value,
                "unit": metric.unit,
                "performance": metric.performance_percentage,
                "status": metric.status,
                "trend": metric.trend
            })
        
        return categories
    
    def get_threat_intelligence_summary(self) -> Dict:
        """Get threat intelligence summary"""
        # Group IOCs by type
        ioc_types = {}
        for threat in self.threat_feed:
            ioc_type = threat["type"]
            if ioc_type not in ioc_types:
                ioc_types[ioc_type] = 0
            ioc_types[ioc_type] += 1
        
        # Group by threat type
        threat_types = {}
        for threat in self.threat_feed:
            threat_type = threat["threat_type"]
            if threat_type not in threat_types:
                threat_types[threat_type] = 0
            threat_types[threat_type] += 1
        
        # Recent threats (last 24 hours)
        recent_threats = [
            threat for threat in self.threat_feed 
            if threat["first_seen"] > datetime.now() - timedelta(hours=24)
        ]
        
        return {
            "total_iocs": len(self.threat_feed),
            "ioc_types": ioc_types,
            "threat_types": threat_types,
            "recent_threats": len(recent_threats),
            "high_confidence_threats": len([t for t in self.threat_feed if t["confidence"] > 0.8])
        }
    
    def get_incident_metrics(self) -> Dict:
        """Get incident response metrics"""
        # Calculate response times (simulated)
        response_times = []
        resolution_times = []
        
        for incident in self.incidents:
            # Simulated response time (0.5-4 hours)
            response_time = random.uniform(0.5, 4)
            response_times.append(response_time)
            
            # Simulated resolution time (2-48 hours)
            if incident["status"] in ["closed", "contained"]:
                resolution_time = random.uniform(2, 48)
                resolution_times.append(resolution_time)
        
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else 0
        
        return {
            "total_incidents": len(self.incidents),
            "open_incidents": len([i for i in self.incidents if i["status"] != "closed"]),
            "avg_response_time": round(avg_response_time, 1),
            "avg_resolution_time": round(avg_resolution_time, 1),
            "incidents_by_severity": {
                "critical": len([i for i in self.incidents if i["severity"] == "critical"]),
                "high": len([i for i in self.incidents if i["severity"] == "high"]),
                "medium": len([i for i in self.incidents if i["severity"] == "medium"]),
                "low": len([i for i in self.incidents if i["severity"] == "low"])
            }
        }
    
    def get_alert_analytics(self) -> Dict:
        """Get alert analytics and trends"""
        # Group alerts by source
        alert_sources = {}
        for alert in self.alerts:
            source = alert["source"]
            if source not in alert_sources:
                alert_sources[source] = 0
            alert_sources[source] += 1
        
        # Calculate time-based metrics
        last_hour_alerts = len([
            a for a in self.alerts 
            if a["timestamp"] > datetime.now() - timedelta(hours=1)
        ])
        
        last_24h_alerts = len([
            a for a in self.alerts 
            if a["timestamp"] > datetime.now() - timedelta(hours=24)
        ])
        
        return {
            "total_alerts": len(self.alerts),
            "last_hour": last_hour_alerts,
            "last_24_hours": last_24h_alerts,
            "alert_sources": alert_sources,
            "open_alerts": len([a for a in self.alerts if a["status"] == "open"]),
            "avg_alerts_per_hour": round(last_24h_alerts / 24, 1)
        }
    
    def generate_executive_summary(self) -> Dict:
        """Generate executive summary for leadership"""
        overview = self.get_security_overview()
        incident_metrics = self.get_incident_metrics()
        
        # Calculate key trends
        critical_metrics = [
            m for m in self.metrics.values() 
            if m.status == "critical"
        ]
        
        improving_metrics = [
            m for m in self.metrics.values() 
            if m.trend == "up" and m.category in ["incident_response", "detection"]
        ]
        
        return {
            "security_posture": {
                "overall_health": overview["health_score"],
                "status": "good" if overview["health_score"] > 80 else 
                         "warning" if overview["health_score"] > 60 else "critical"
            },
            "key_metrics": {
                "active_incidents": incident_metrics["open_incidents"],
                "critical_alerts": overview["alert_breakdown"]["critical"],
                "response_time": f"{incident_metrics['avg_response_time']} hours",
                "resolution_time": f"{incident_metrics['avg_resolution_time']} hours"
            },
            "concerns": [
                f"{len(critical_metrics)} metrics below acceptable levels",
                f"{overview['alert_breakdown']['critical']} critical alerts active"
            ] if critical_metrics else [],
            "improvements": [
                f"{len(improving_metrics)} security metrics showing improvement"
            ] if improving_metrics else [],
            "recommendations": [
                "Focus on reducing false positive rate",
                "Improve patch management compliance", 
                "Enhance security training completion"
            ]
        }
    
    def render_dashboard(self) -> str:
        """Render dashboard as text-based display"""
        output = []
        output.append("=" * 80)
        output.append("SECURITY OPERATIONS CENTER DASHBOARD")
        output.append("=" * 80)
        
        # Overview section
        overview = self.get_security_overview()
        output.append(f"\n🎯 SECURITY OVERVIEW")
        output.append(f"   Overall Health Score: {overview['health_score']}/100")
        output.append(f"   Total Alerts: {overview['total_alerts']} " +
                     f"(Critical: {overview['alert_breakdown']['critical']}, " +
                     f"High: {overview['alert_breakdown']['high']})")
        output.append(f"   Active Incidents: {overview['incident_breakdown']['investigating']}")
        
        # Key metrics
        output.append(f"\n📊 KEY METRICS")
        priority_metrics = ["mttr", "mttd", "false_positive_rate", "patch_compliance"]
        for metric_id in priority_metrics:
            if metric_id in self.metrics:
                metric = self.metrics[metric_id]
                status_icon = {"excellent": "🟢", "good": "🟡", "warning": "🟠", "critical": "🔴"}
                trend_icon = {"up": "↗️", "down": "↘️", "stable": "→"}
                
                output.append(f"   {status_icon.get(metric.status, '❓')} " +
                             f"{metric.name}: {metric.current_value}{metric.unit} " +
                             f"(Target: {metric.target_value}{metric.unit}) " +
                             f"{trend_icon.get(metric.trend, '')}")
        
        # Recent alerts
        output.append(f"\n🚨 RECENT ALERTS")
        recent_alerts = sorted(self.alerts, key=lambda x: x["timestamp"], reverse=True)[:3]
        for alert in recent_alerts:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            age = datetime.now() - alert["timestamp"]
            age_str = f"{int(age.total_seconds() // 60)}m ago"
            
            output.append(f"   {severity_icon.get(alert['severity'], '❓')} " +
                         f"[{alert['alert_id']}] {alert['title']} ({age_str})")
        
        # Active incidents
        output.append(f"\n📋 ACTIVE INCIDENTS")
        active_incidents = [i for i in self.incidents if i["status"] != "closed"]
        for incident in active_incidents:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            age = datetime.now() - incident["created"]
            age_str = f"{int(age.total_seconds() // 3600)}h ago"
            
            output.append(f"   {severity_icon.get(incident['severity'], '❓')} " +
                         f"[{incident['incident_id']}] {incident['title']} " +
                         f"({incident['analyst']}, {age_str})")
        
        # Threat intelligence
        output.append(f"\n🎯 THREAT INTELLIGENCE")
        ti_summary = self.get_threat_intelligence_summary()
        output.append(f"   Total IOCs: {ti_summary['total_iocs']}")
        output.append(f"   High Confidence: {ti_summary['high_confidence_threats']}")
        output.append(f"   Recent (24h): {ti_summary['recent_threats']}")
        
        output.append(f"\n" + "=" * 80)
        output.append(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return "\n".join(output)

# Demo the security dashboard
if __name__ == "__main__":
    print("📊 SECURITY OPERATIONS DASHBOARD")
    print("="*80)
    
    dashboard = SecurityDashboard()
    
    # Add dashboard widgets
    print("\n🔧 Configuring Dashboard Widgets...")
    
    dashboard.add_widget("Security Overview", "metric", "large", 
                        {"x": 0, "y": 0}, "security_metrics")
    
    dashboard.add_widget("Alert Volume", "chart", "medium", 
                        {"x": 1, "y": 0}, "alert_analytics")
    
    dashboard.add_widget("Incident Status", "table", "medium", 
                        {"x": 0, "y": 1}, "incident_metrics")
    
    dashboard.add_widget("Threat Feed", "table", "small", 
                        {"x": 1, "y": 1}, "threat_intelligence")
    
    print(f"Added {len(dashboard.widgets)} widgets to dashboard")
    
    # Display dashboard
    print("\n" + dashboard.render_dashboard())
    
    # Generate executive summary
    print("\n📋 EXECUTIVE SUMMARY")
    print("="*80)
    
    summary = dashboard.generate_executive_summary()
    
    print(f"\n🎯 Security Posture: {summary['security_posture']['status'].upper()}")
    print(f"   Overall Health: {summary['security_posture']['overall_health']}/100")
    
    print(f"\n📊 Key Metrics:")
    for metric, value in summary['key_metrics'].items():
        print(f"   {metric.replace('_', ' ').title()}: {value}")
    
    if summary.get("concerns"):
        print(f"\n⚠️ Areas of Concern:")
        for concern in summary["concerns"]:
            print(f"   - {concern}")
    
    if summary.get("improvements"):
        print(f"\n✅ Improvements:")
        for improvement in summary["improvements"]:
            print(f"   - {improvement}")
    
    print(f"\n💡 Recommendations:")
    for rec in summary["recommendations"]:
        print(f"   - {rec}")
```

---

## ✅ Tutorial Completion Checklist

After completing all modules, verify your understanding:

- [ ] You can build NIST-aligned incident response frameworks
- [ ] You understand threat hunting methodologies and automation
- [ ] You can create SOAR playbooks for security orchestration
- [ ] You know how to design comprehensive security dashboards
- [ ] You can integrate multiple security tools and data sources
- [ ] You understand executive reporting and security metrics

## 🚀 Ready for Your Capstone Project!

Excellent! You now have all the foundation needed to create your comprehensive capstone project. You've learned:

1. **Incident Response** with NIST-aligned processes
2. **Threat Hunting** with behavioral and IOC-based detection
3. **Security Orchestration** with automated response playbooks
4. **Dashboard Development** with integrated security metrics
5. **Tool Integration** across the security stack

**Next step**: Review [capstone-project.md](capstone-project.md) for project options and requirements.

## 💡 Key Integration Concepts Learned

1. **NIST Incident Response Lifecycle** with evidence management
2. **Proactive Threat Hunting** using MITRE ATT&CK framework
3. **SOAR Automation** with playbook-driven responses
4. **Security Metrics and KPIs** for program measurement
5. **Executive Dashboards** for leadership visibility
6. **Cross-Platform Integration** of security tools
7. **Real-Time Monitoring** and alerting systems

---

**Congratulations!** 🎉 You've completed all tutorial modules and are ready to demonstrate your comprehensive cybersecurity and digital forensics skills through your capstone project!

**Questions?** Check the troubleshooting section or ask in Canvas discussions!