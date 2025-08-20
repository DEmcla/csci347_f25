# Week 6 Assignment: Enterprise Network Security Infrastructure

**Due**: End of Week 6 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Design and implement a complete enterprise network security infrastructure that integrates firewall protection, network segmentation, VPN access, intrusion detection, and network access control. Your implementation should demonstrate mastery of network security architecture, policy enforcement, and threat detection learned this week.

## 📋 Requirements

### Core Functionality (70 points)

Your network security infrastructure must implement these components:

#### 1. Advanced Firewall Configuration (20 points)
- **Multi-zone firewall** with DMZ, Internal, and Guest networks
- **Application-layer filtering** with deep packet inspection rules
- **Threat intelligence integration** blocking known malicious IPs
- **Traffic shaping** and bandwidth management policies

#### 2. Network Segmentation Implementation (20 points)
- **VLAN-based segmentation** with at least 5 distinct segments
- **Inter-VLAN routing policies** with deny-by-default approach
- **Network isolation** preventing lateral movement
- **Microsegmentation** for critical assets

#### 3. VPN and Remote Access (15 points)
- **Site-to-site VPN** connecting multiple locations
- **Remote access VPN** with certificate-based authentication
- **Split tunneling** configuration for optimized traffic flow
- **VPN monitoring** and connection logging

#### 4. Intrusion Detection and Prevention (15 points)
- **Network IDS/IPS deployment** with custom rule sets
- **Behavioral analysis** detecting anomalous network patterns
- **Automated response** to high-severity threats
- **Alert correlation** and incident prioritization

### Documentation and Architecture (20 points)

Create comprehensive network security documentation:

```
network_security_design.md    # Architecture overview and design decisions
firewall_ruleset.json        # Complete firewall rule configuration
network_diagram.png          # Visual network topology with security zones
security_policies.md         # Network security policies and procedures
implementation_guide.md      # Step-by-step implementation instructions
testing_procedures.md        # Security validation and testing methods
```

### Security Validation (10 points)

- **Penetration testing** against implemented security controls
- **Compliance checking** against security frameworks (NIST, CIS)
- **Performance impact assessment** of security measures
- **Security control effectiveness verification**

## 🔧 Technical Specifications

### Required Tools and Technologies
```bash
# Firewall Platform
pfSense or equivalent (VyOS, IPFire, OPNsense)

# Network Simulation
GNS3, EVE-NG, or VirtualBox/VMware

# IDS/IPS Platform  
Suricata, Snort, or Security Onion

# Network Analysis
Wireshark, tcpdump, nmap, hping3

# Automation and Scripting
Python 3.x with libraries:
- scapy (packet manipulation)
- netmiko (network automation) 
- requests (API integration)
- paramiko (SSH automation)
```

### Network Architecture Requirements
```
Enterprise Network Topology:

┌─────────────────┐    ┌─────────────────┐
│   Internet      │    │   Branch Office │
│                 │    │   192.168.100.x │
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          │ Site-to-Site VPN     │
          │                      │
┌─────────┴───────┐              │
│   Edge Firewall │              │
│   203.0.113.x   │              │
└─────────┬───────┘              │
          │                      │
┌─────────┴───────┐              │
│   Core Switch   │              │
│   VLAN Trunking │              │
└─────────┬───────┘              │
          │                      │
    ┌─────┴─────┬─────┬─────┬─────┴─────┬─────┐
    │           │     │     │           │     │
┌───▼───┐ ┌───▼───┐ ┌▼───┐ ┌▼───┐ ┌───▼───┐ ┌▼───┐
│DMZ    │ │Server │ │Work│ │Guest│ │IoT    │ │Mgmt│
│VLAN100│ │VLAN20 │ │V30 │ │V40 │ │VLAN50 │ │V10 │
│Web/DNS│ │Apps/DB│ │User│ │WiFi│ │Sensors│ │Admin│
└───────┘ └───────┘ └────┘ └────┘ └───────┘ └────┘
```

## 📝 Detailed Requirements

### 1. Advanced Firewall Implementation

Create `enterprise_firewall.py` for automated firewall management:

```python
#!/usr/bin/env python3
"""
Enterprise Firewall Management System
Advanced firewall configuration with threat intelligence
"""

import json
import requests
import ipaddress
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class FirewallRule:
    id: int
    name: str
    action: str  # allow, block, reject
    interface: str
    protocol: str  # tcp, udp, icmp, any
    source: str
    destination: str
    port: Optional[str] = None
    log: bool = True
    description: str = ""
    created_at: datetime = datetime.now()
    priority: int = 1000

class ThreatIntelligence:
    def __init__(self):
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.last_update = None
    
    def update_threat_feeds(self):
        """Update threat intelligence feeds"""
        # Simulate threat intelligence feed update
        sample_malicious_ips = [
            "203.0.113.100",
            "198.51.100.50", 
            "192.0.2.75",
            "10.255.255.1"
        ]
        
        sample_malicious_domains = [
            "malware-command.com",
            "phishing-site.net",
            "botnet-c2.org"
        ]
        
        self.malicious_ips.update(sample_malicious_ips)
        self.malicious_domains.update(sample_malicious_domains)
        self.last_update = datetime.now()
        
        print(f"✅ Updated threat intelligence: {len(self.malicious_ips)} IPs, {len(self.malicious_domains)} domains")

class EnterpriseFirewall:
    def __init__(self):
        self.rules = []
        self.threat_intel = ThreatIntelligence()
        self.rule_id_counter = 1
        
    def create_zone_based_rules(self):
        """Create comprehensive zone-based firewall rules"""
        
        # Network zones
        zones = {
            'INTERNET': '0.0.0.0/0',
            'DMZ': '192.168.100.0/24',
            'SERVERS': '192.168.20.0/24', 
            'WORKSTATIONS': '192.168.30.0/24',
            'GUEST': '192.168.40.0/24',
            'IOT': '192.168.50.0/24',
            'MANAGEMENT': '192.168.10.0/24'
        }
        
        rules = [
            # === INBOUND RULES (Internet -> Internal) ===
            FirewallRule(
                self._get_rule_id(), "Allow Inbound Web Traffic", "allow", "wan",
                "tcp", "any", zones['DMZ'], "80,443",
                description="Allow public access to web servers in DMZ"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Allow Inbound VPN", "allow", "wan",
                "udp", "any", zones['DMZ'], "1194,51820",
                description="Allow OpenVPN and WireGuard connections"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Block Threat Intelligence IPs", "block", "wan",
                "any", "threat_intel_alias", "any", "",
                description="Block traffic from known malicious IPs",
                priority=100
            ),
            
            # === DMZ RULES ===
            FirewallRule(
                self._get_rule_id(), "DMZ Web Server Outbound", "allow", "dmz",
                "tcp", zones['DMZ'], "any", "80,443,53",
                description="Allow DMZ servers to access internet for updates"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Block DMZ to Internal", "block", "dmz", 
                "any", zones['DMZ'], f"{zones['SERVERS']},{zones['WORKSTATIONS']}", "",
                description="Prevent DMZ servers from accessing internal networks"
            ),
            
            # === SERVER ZONE RULES ===
            FirewallRule(
                self._get_rule_id(), "Server Database Access", "allow", "servers",
                "tcp", zones['SERVERS'], zones['SERVERS'], "3306,5432,1521",
                description="Allow inter-server database communications"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Server Management Access", "allow", "servers",
                "tcp", zones['MANAGEMENT'], zones['SERVERS'], "22,3389,5985",
                description="Allow management access to servers"
            ),
            
            # === WORKSTATION RULES ===
            FirewallRule(
                self._get_rule_id(), "Workstation Internet Access", "allow", "workstations",
                "any", zones['WORKSTATIONS'], "!" + zones['WORKSTATIONS'], "",
                description="Allow workstations to access internet (not internal networks)"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Workstation to Servers", "allow", "workstations",
                "tcp", zones['WORKSTATIONS'], zones['SERVERS'], "80,443,445",
                description="Allow workstation access to internal servers"
            ),
            
            # === GUEST NETWORK RULES ===
            FirewallRule(
                self._get_rule_id(), "Guest Internet Only", "allow", "guest",
                "tcp", zones['GUEST'], "any", "80,443",
                description="Allow guest devices internet access only"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Block Guest Internal Access", "block", "guest",
                "any", zones['GUEST'], f"{zones['SERVERS']},{zones['WORKSTATIONS']},{zones['IOT']},{zones['MANAGEMENT']}", "",
                description="Block guest access to all internal networks"
            ),
            
            # === IOT DEVICE RULES ===
            FirewallRule(
                self._get_rule_id(), "IoT Cloud Communication", "allow", "iot",
                "tcp", zones['IOT'], "any", "443,8883",
                description="Allow IoT devices to communicate with cloud services"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Block IoT Lateral Movement", "block", "iot",
                "any", zones['IOT'], f"{zones['WORKSTATIONS']},{zones['SERVERS']}", "",
                description="Prevent IoT devices from accessing user/server networks"
            ),
            
            # === MANAGEMENT NETWORK RULES ===
            FirewallRule(
                self._get_rule_id(), "Management Full Access", "allow", "management", 
                "any", zones['MANAGEMENT'], "any", "",
                description="Allow management network full access for administration"
            ),
            
            # === SECURITY RULES ===
            FirewallRule(
                self._get_rule_id(), "Block Tor Traffic", "block", "any",
                "tcp", "any", "any", "9001,9030,9051",
                description="Block Tor network traffic"
            ),
            
            FirewallRule(
                self._get_rule_id(), "Rate Limit SSH", "allow", "any",
                "tcp", "any", "any", "22",
                description="Rate limit SSH connections to prevent brute force",
                priority=500
            ),
            
            # === DEFAULT DENY ===
            FirewallRule(
                self._get_rule_id(), "Default Deny All", "block", "any",
                "any", "any", "any", "",
                description="Default deny rule - log all blocked traffic",
                priority=9999
            )
        ]
        
        self.rules.extend(rules)
        return rules
    
    def _get_rule_id(self):
        """Generate unique rule ID"""
        rule_id = self.rule_id_counter
        self.rule_id_counter += 1
        return rule_id
    
    def apply_threat_intelligence(self):
        """Apply threat intelligence to firewall rules"""
        self.threat_intel.update_threat_feeds()
        
        # Create rule to block malicious IPs
        if self.threat_intel.malicious_ips:
            threat_rule = FirewallRule(
                self._get_rule_id(), "Block Threat Intel IPs", "block", "wan",
                "any", ",".join(self.threat_intel.malicious_ips), "any", "",
                description=f"Block {len(self.threat_intel.malicious_ips)} known malicious IPs",
                priority=50
            )
            self.rules.append(threat_rule)
    
    def generate_firewall_config(self):
        """Generate complete firewall configuration"""
        config = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_rules': len(self.rules),
                'zones': [
                    'INTERNET', 'DMZ', 'SERVERS', 'WORKSTATIONS', 
                    'GUEST', 'IOT', 'MANAGEMENT'
                ]
            },
            'rules': []
        }
        
        # Sort rules by priority
        sorted_rules = sorted(self.rules, key=lambda r: r.priority)
        
        for rule in sorted_rules:
            rule_dict = {
                'id': rule.id,
                'name': rule.name,
                'action': rule.action,
                'interface': rule.interface,
                'protocol': rule.protocol,
                'source': rule.source,
                'destination': rule.destination,
                'port': rule.port,
                'log': rule.log,
                'description': rule.description,
                'priority': rule.priority
            }
            config['rules'].append(rule_dict)
        
        return config
    
    def export_configuration(self, filename="firewall_config.json"):
        """Export firewall configuration to file"""
        config = self.generate_firewall_config()
        
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Firewall configuration exported to {filename}")
        return filename

def main():
    print("🔥 Enterprise Firewall Configuration")
    print("=" * 35)
    
    firewall = EnterpriseFirewall()
    
    # Create zone-based rules
    rules = firewall.create_zone_based_rules()
    print(f"Created {len(rules)} zone-based firewall rules")
    
    # Apply threat intelligence
    firewall.apply_threat_intelligence()
    
    # Export configuration
    config_file = firewall.export_configuration()
    
    print(f"\n📊 Firewall Configuration Summary:")
    print(f"   Total Rules: {len(firewall.rules)}")
    print(f"   Security Zones: 7")
    print(f"   Threat Intel Rules: {len([r for r in firewall.rules if 'threat' in r.name.lower()])}")
    
    return firewall

if __name__ == "__main__":
    main()
```

### 2. Network Segmentation Architecture

Create `network_segmentation.py`:

```python
#!/usr/bin/env python3
"""
Network Segmentation Implementation
VLAN-based network isolation and microsegmentation
"""

import json
import ipaddress
from dataclasses import dataclass, asdict
from typing import List, Dict, Set
from enum import Enum

class SecurityLevel(Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"

@dataclass
class NetworkSegment:
    vlan_id: int
    name: str
    network: str
    gateway: str
    security_level: SecurityLevel
    allowed_services: List[str]
    access_control_list: List[str]
    dhcp_enabled: bool = True
    monitoring_level: str = "standard"

class NetworkSegmentationManager:
    def __init__(self):
        self.segments = {}
        self.routing_policies = []
        self.access_matrix = {}
    
    def create_enterprise_segments(self):
        """Create comprehensive network segmentation"""
        
        segments = [
            NetworkSegment(
                vlan_id=10,
                name="Management",
                network="192.168.10.0/24",
                gateway="192.168.10.1",
                security_level=SecurityLevel.RESTRICTED,
                allowed_services=["SSH", "HTTPS", "SNMP", "NTP"],
                access_control_list=["admin_only", "mfa_required"],
                monitoring_level="high"
            ),
            
            NetworkSegment(
                vlan_id=20,
                name="Servers",
                network="192.168.20.0/24", 
                gateway="192.168.20.1",
                security_level=SecurityLevel.CONFIDENTIAL,
                allowed_services=["HTTP", "HTTPS", "SSH", "Database"],
                access_control_list=["internal_only", "authenticated"],
                monitoring_level="high"
            ),
            
            NetworkSegment(
                vlan_id=30,
                name="Workstations",
                network="192.168.30.0/24",
                gateway="192.168.30.1", 
                security_level=SecurityLevel.INTERNAL,
                allowed_services=["HTTP", "HTTPS", "DNS", "DHCP", "SMB"],
                access_control_list=["domain_joined", "av_required"],
                monitoring_level="standard"
            ),
            
            NetworkSegment(
                vlan_id=40,
                name="Guest",
                network="192.168.40.0/24",
                gateway="192.168.40.1",
                security_level=SecurityLevel.PUBLIC,
                allowed_services=["HTTP", "HTTPS", "DNS"],
                access_control_list=["internet_only", "bandwidth_limited"],
                monitoring_level="high"
            ),
            
            NetworkSegment(
                vlan_id=50,
                name="IoT",
                network="192.168.50.0/24",
                gateway="192.168.50.1",
                security_level=SecurityLevel.INTERNAL,
                allowed_services=["HTTP", "HTTPS", "MQTT", "CoAP"],
                access_control_list=["iot_profile", "isolated"],
                monitoring_level="high"
            ),
            
            NetworkSegment(
                vlan_id=60,
                name="VoIP",
                network="192.168.60.0/24",
                gateway="192.168.60.1",
                security_level=SecurityLevel.INTERNAL,
                allowed_services=["SIP", "RTP", "DHCP"],
                access_control_list=["qos_priority", "voice_vlan"],
                monitoring_level="standard"
            ),
            
            NetworkSegment(
                vlan_id=70,
                name="Security",
                network="192.168.70.0/24",
                gateway="192.168.70.1",
                security_level=SecurityLevel.RESTRICTED,
                allowed_services=["HTTPS", "Syslog", "SNMP"],
                access_control_list=["security_team_only"],
                monitoring_level="maximum"
            ),
            
            NetworkSegment(
                vlan_id=100,
                name="DMZ",
                network="192.168.100.0/24",
                gateway="192.168.100.1",
                security_level=SecurityLevel.PUBLIC,
                allowed_services=["HTTP", "HTTPS", "DNS", "SMTP"],
                access_control_list=["public_facing", "hardened"],
                monitoring_level="maximum"
            )
        ]
        
        for segment in segments:
            self.segments[segment.vlan_id] = segment
        
        return segments
    
    def create_access_matrix(self):
        """Create network access control matrix"""
        
        # Define access relationships between segments
        access_rules = {
            # Management can access everything
            10: [20, 30, 40, 50, 60, 70, 100],
            
            # Servers can access other servers and management
            20: [10, 20],
            
            # Workstations can access servers, VoIP, and internet
            30: [20, 60, "INTERNET"],
            
            # Guest can only access internet
            40: ["INTERNET"],
            
            # IoT can access specific cloud services only
            50: ["INTERNET_LIMITED"],
            
            # VoIP can access VoIP infrastructure
            60: [10, 60],
            
            # Security can access everything for monitoring
            70: [10, 20, 30, 40, 50, 60, 100],
            
            # DMZ can access internet and specific internal services
            100: [20, "INTERNET"]
        }
        
        self.access_matrix = access_rules
        return access_rules
    
    def generate_routing_policies(self):
        """Generate inter-VLAN routing policies"""
        
        policies = []
        
        for source_vlan, allowed_vlans in self.access_matrix.items():
            source_segment = self.segments.get(source_vlan)
            if not source_segment:
                continue
                
            for target in allowed_vlans:
                if isinstance(target, int) and target in self.segments:
                    target_segment = self.segments[target]
                    
                    policy = {
                        'source': source_segment.name,
                        'source_network': source_segment.network,
                        'destination': target_segment.name,
                        'destination_network': target_segment.network,
                        'action': 'permit',
                        'services': self._get_allowed_services(source_segment, target_segment),
                        'conditions': self._get_access_conditions(source_segment, target_segment)
                    }
                    
                elif target == "INTERNET":
                    policy = {
                        'source': source_segment.name,
                        'source_network': source_segment.network,
                        'destination': 'Internet',
                        'destination_network': '0.0.0.0/0',
                        'action': 'permit',
                        'services': ['HTTP', 'HTTPS', 'DNS'],
                        'conditions': ['stateful_inspection', 'content_filtering']
                    }
                    
                elif target == "INTERNET_LIMITED":
                    policy = {
                        'source': source_segment.name,
                        'source_network': source_segment.network,
                        'destination': 'Internet_Limited',
                        'destination_network': 'specific_cloud_services',
                        'action': 'permit',
                        'services': ['HTTPS', 'MQTT'],
                        'conditions': ['whitelist_only', 'deep_inspection']
                    }
                
                policies.append(policy)
        
        # Add default deny policies
        for source_vlan in self.segments.keys():
            for target_vlan in self.segments.keys():
                if source_vlan != target_vlan and target_vlan not in self.access_matrix.get(source_vlan, []):
                    source_segment = self.segments[source_vlan]
                    target_segment = self.segments[target_vlan]
                    
                    deny_policy = {
                        'source': source_segment.name,
                        'source_network': source_segment.network,
                        'destination': target_segment.name,
                        'destination_network': target_segment.network,
                        'action': 'deny',
                        'services': ['ANY'],
                        'conditions': ['log_blocked_traffic']
                    }
                    policies.append(deny_policy)
        
        self.routing_policies = policies
        return policies
    
    def _get_allowed_services(self, source_segment, target_segment):
        """Determine allowed services between segments"""
        if target_segment.name == "Servers":
            return ["HTTP", "HTTPS", "Database"]
        elif target_segment.name == "Management":
            return ["SSH", "HTTPS", "SNMP"]
        else:
            return ["HTTP", "HTTPS"]
    
    def _get_access_conditions(self, source_segment, target_segment):
        """Determine access conditions between segments"""
        conditions = []
        
        if source_segment.security_level.value in ["restricted", "confidential"]:
            conditions.append("authentication_required")
        
        if target_segment.security_level.value == "restricted":
            conditions.append("mfa_required")
        
        conditions.append("stateful_inspection")
        return conditions
    
    def create_microsegmentation_rules(self):
        """Create microsegmentation rules for critical assets"""
        
        microsegmentation_rules = [
            {
                'name': 'Database Server Isolation',
                'source': 'any',
                'destination': '192.168.20.10',  # Database server
                'allowed_sources': ['192.168.20.0/24', '192.168.30.0/24'],
                'allowed_ports': [3306, 5432],
                'conditions': ['application_authentication', 'encrypted_connection']
            },
            
            {
                'name': 'Domain Controller Protection',
                'source': 'any',
                'destination': '192.168.20.5',  # Domain controller
                'allowed_sources': ['192.168.30.0/24'],
                'allowed_ports': [389, 636, 88, 53],
                'conditions': ['domain_member_only', 'kerberos_auth']
            },
            
            {
                'name': 'Security Tools Isolation',
                'source': 'any',
                'destination': '192.168.70.0/24',
                'allowed_sources': ['192.168.10.0/24'],
                'allowed_ports': [443, 8443],
                'conditions': ['admin_role_required', 'privileged_access']
            }
        ]
        
        return microsegmentation_rules
    
    def export_segmentation_config(self, filename="network_segmentation.json"):
        """Export complete segmentation configuration"""
        
        config = {
            'metadata': {
                'created_at': datetime.now().isoformat(),
                'total_segments': len(self.segments),
                'total_policies': len(self.routing_policies)
            },
            'segments': [asdict(segment) for segment in self.segments.values()],
            'access_matrix': self.access_matrix,
            'routing_policies': self.routing_policies,
            'microsegmentation_rules': self.create_microsegmentation_rules()
        }
        
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2, default=str)
        
        print(f"✅ Network segmentation configuration exported to {filename}")
        return filename

def main():
    print("🏷️  Network Segmentation Implementation")
    print("=" * 40)
    
    segmentation = NetworkSegmentationManager()
    
    # Create network segments
    segments = segmentation.create_enterprise_segments()
    print(f"Created {len(segments)} network segments")
    
    # Create access matrix
    access_matrix = segmentation.create_access_matrix()
    print(f"Defined access relationships for {len(access_matrix)} segments")
    
    # Generate routing policies
    policies = segmentation.generate_routing_policies()
    print(f"Generated {len(policies)} routing policies")
    
    # Export configuration
    config_file = segmentation.export_segmentation_config()
    
    print(f"\n📊 Segmentation Summary:")
    for segment in segments:
        print(f"   VLAN {segment.vlan_id}: {segment.name} ({segment.network}) - {segment.security_level.value}")

if __name__ == "__main__":
    main()
```

### 3. Comprehensive Testing and Validation

Create `security_validation_suite.py`:

```python
#!/usr/bin/env python3
"""
Network Security Validation Suite
Comprehensive testing of network security controls
"""

import subprocess
import socket
import time
import json
import threading
from scapy.all import *
import requests
from concurrent.futures import ThreadPoolExecutor

class NetworkSecurityValidator:
    def __init__(self):
        self.test_results = []
        self.target_networks = {
            'dmz': '192.168.100.0/24',
            'servers': '192.168.20.0/24',
            'workstations': '192.168.30.0/24',
            'guest': '192.168.40.0/24',
            'iot': '192.168.50.0/24',
            'management': '192.168.10.0/24'
        }
    
    def test_firewall_rules(self):
        """Test firewall rule effectiveness"""
        print("🔥 Testing Firewall Rules...")
        
        tests = [
            {
                'name': 'DMZ Web Access',
                'target': '192.168.100.10',
                'port': 80,
                'expected': 'allow',
                'description': 'Public should access DMZ web servers'
            },
            {
                'name': 'Internal Server Direct Access',
                'target': '192.168.20.10',
                'port': 3306,
                'expected': 'block',
                'description': 'External should not access internal database'
            },
            {
                'name': 'Guest Network Isolation',
                'target': '192.168.20.10',
                'port': 445,
                'source': '192.168.40.50',
                'expected': 'block',
                'description': 'Guest devices should not access internal servers'
            },
            {
                'name': 'Management Network Access',
                'target': '192.168.10.5',
                'port': 22,
                'source': '192.168.30.15',
                'expected': 'allow',
                'description': 'Workstations should access management for admin'
            }
        ]
        
        for test in tests:
            result = self._test_network_connectivity(test)
            self.test_results.append(result)
            
            status = "✅" if result['passed'] else "❌"
            print(f"   {status} {test['name']}: {result['status']}")
    
    def test_vlan_isolation(self):
        """Test VLAN isolation effectiveness"""
        print("🏷️  Testing VLAN Isolation...")
        
        isolation_tests = [
            {
                'name': 'Guest-to-Internal Isolation',
                'source_vlan': 'guest',
                'target_vlan': 'servers',
                'expected': 'isolated'
            },
            {
                'name': 'IoT-to-Workstation Isolation', 
                'source_vlan': 'iot',
                'target_vlan': 'workstations',
                'expected': 'isolated'
            },
            {
                'name': 'DMZ-to-Internal Isolation',
                'source_vlan': 'dmz', 
                'target_vlan': 'servers',
                'expected': 'limited'
            },
            {
                'name': 'Management Access',
                'source_vlan': 'management',
                'target_vlan': 'servers',
                'expected': 'allowed'
            }
        ]
        
        for test in isolation_tests:
            result = self._test_vlan_isolation(test)
            self.test_results.append(result)
            
            status = "✅" if result['passed'] else "❌"
            print(f"   {status} {test['name']}: {result['status']}")
    
    def test_intrusion_detection(self):
        """Test IDS/IPS detection capabilities"""
        print("🔍 Testing Intrusion Detection...")
        
        # Simulate various attack patterns
        attack_tests = [
            {
                'name': 'Port Scan Detection',
                'attack_type': 'port_scan',
                'target': '192.168.20.10',
                'expected': 'detected'
            },
            {
                'name': 'SQL Injection Detection',
                'attack_type': 'web_attack',
                'target': '192.168.100.10',
                'payload': "'; DROP TABLE users; --",
                'expected': 'detected'
            },
            {
                'name': 'Brute Force Detection',
                'attack_type': 'brute_force',
                'target': '192.168.20.5',
                'port': 22,
                'expected': 'detected'
            },
            {
                'name': 'Malware Communication',
                'attack_type': 'c2_communication',
                'target': 'malware-c2.example.com',
                'expected': 'blocked'
            }
        ]
        
        for test in attack_tests:
            result = self._test_intrusion_detection(test)
            self.test_results.append(result)
            
            status = "✅" if result['passed'] else "❌"
            print(f"   {status} {test['name']}: {result['status']}")
    
    def test_vpn_security(self):
        """Test VPN security and functionality"""
        print("🔐 Testing VPN Security...")
        
        vpn_tests = [
            {
                'name': 'VPN Authentication',
                'test_type': 'auth_test',
                'expected': 'certificate_required'
            },
            {
                'name': 'VPN Encryption',
                'test_type': 'encryption_test',
                'expected': 'strong_encryption'
            },
            {
                'name': 'Split Tunneling',
                'test_type': 'routing_test',
                'expected': 'configured'
            },
            {
                'name': 'VPN Kill Switch',
                'test_type': 'failsafe_test',
                'expected': 'active'
            }
        ]
        
        for test in vpn_tests:
            result = self._test_vpn_functionality(test)
            self.test_results.append(result)
            
            status = "✅" if result['passed'] else "❌"
            print(f"   {status} {test['name']}: {result['status']}")
    
    def test_network_access_control(self):
        """Test NAC policy enforcement"""
        print("🔐 Testing Network Access Control...")
        
        nac_tests = [
            {
                'name': 'Device Registration',
                'device_type': 'unregistered',
                'expected': 'quarantine'
            },
            {
                'name': 'Compliance Enforcement',
                'device_type': 'non_compliant',
                'expected': 'limited_access'
            },
            {
                'name': 'Device Authentication',
                'device_type': 'registered',
                'expected': 'full_access'
            },
            {
                'name': 'Policy Update',
                'test_type': 'policy_change',
                'expected': 'enforced'
            }
        ]
        
        for test in nac_tests:
            result = self._test_nac_policy(test)
            self.test_results.append(result)
            
            status = "✅" if result['passed'] else "❌"
            print(f"   {status} {test['name']}: {result['status']}")
    
    def _test_network_connectivity(self, test):
        """Test network connectivity with timeout"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((test['target'], test['port']))
            sock.close()
            
            is_reachable = (result == 0)
            expected_reachable = (test['expected'] == 'allow')
            
            passed = (is_reachable == expected_reachable)
            status = f"Connection {'succeeded' if is_reachable else 'failed'} as expected"
            
            return {
                'test_name': test['name'],
                'passed': passed,
                'status': status,
                'details': f"Target: {test['target']}:{test['port']}"
            }
            
        except Exception as e:
            return {
                'test_name': test['name'],
                'passed': False,
                'status': f"Test error: {str(e)}",
                'details': test['description']
            }
    
    def _test_vlan_isolation(self, test):
        """Test VLAN isolation between networks"""
        # Simulate VLAN isolation testing
        # In real implementation, this would use network tools
        
        isolation_map = {
            ('guest', 'servers'): 'isolated',
            ('iot', 'workstations'): 'isolated',
            ('dmz', 'servers'): 'limited',
            ('management', 'servers'): 'allowed'
        }
        
        key = (test['source_vlan'], test['target_vlan'])
        actual_isolation = isolation_map.get(key, 'unknown')
        
        passed = (actual_isolation == test['expected'])
        status = f"Isolation level: {actual_isolation}"
        
        return {
            'test_name': test['name'],
            'passed': passed,
            'status': status,
            'details': f"{test['source_vlan']} -> {test['target_vlan']}"
        }
    
    def _test_intrusion_detection(self, test):
        """Test IDS detection capabilities"""
        # Simulate IDS testing
        # In real implementation, this would generate attack traffic
        
        detection_results = {
            'port_scan': 'detected',
            'web_attack': 'detected',
            'brute_force': 'detected',
            'c2_communication': 'blocked'
        }
        
        actual_result = detection_results.get(test['attack_type'], 'unknown')
        passed = (actual_result == test['expected'])
        status = f"Attack {actual_result}"
        
        return {
            'test_name': test['name'],
            'passed': passed,
            'status': status,
            'details': f"Attack type: {test['attack_type']}"
        }
    
    def _test_vpn_functionality(self, test):
        """Test VPN functionality and security"""
        # Simulate VPN testing
        vpn_results = {
            'auth_test': 'certificate_required',
            'encryption_test': 'strong_encryption',
            'routing_test': 'configured',
            'failsafe_test': 'active'
        }
        
        actual_result = vpn_results.get(test['test_type'], 'unknown')
        passed = (actual_result == test['expected'])
        status = f"VPN feature {actual_result}"
        
        return {
            'test_name': test['name'],
            'passed': passed,
            'status': status,
            'details': f"Test type: {test['test_type']}"
        }
    
    def _test_nac_policy(self, test):
        """Test NAC policy enforcement"""
        # Simulate NAC testing
        nac_results = {
            'unregistered': 'quarantine',
            'non_compliant': 'limited_access',
            'registered': 'full_access',
            'policy_change': 'enforced'
        }
        
        key = test.get('device_type', test.get('test_type'))
        actual_result = nac_results.get(key, 'unknown')
        passed = (actual_result == test['expected'])
        status = f"Policy result: {actual_result}"
        
        return {
            'test_name': test['name'],
            'passed': passed,
            'status': status,
            'details': f"Test scenario: {key}"
        }
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r['passed']])
        failed_tests = total_tests - passed_tests
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'success_rate': f"{(passed_tests/total_tests)*100:.1f}%"
            },
            'test_results': self.test_results,
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self):
        """Generate security recommendations based on test results"""
        recommendations = []
        
        failed_tests = [r for r in self.test_results if not r['passed']]
        
        if failed_tests:
            recommendations.append("Review and fix failed security controls")
            
        if len(failed_tests) > len(self.test_results) * 0.2:
            recommendations.append("Consider comprehensive security architecture review")
        
        recommendations.extend([
            "Implement continuous security monitoring",
            "Regular security control testing and validation",
            "Update threat intelligence feeds regularly",
            "Conduct regular penetration testing",
            "Review and update security policies quarterly"
        ])
        
        return recommendations

def main():
    print("🧪 Network Security Validation Suite")
    print("=" * 40)
    
    validator = NetworkSecurityValidator()
    
    # Run all tests
    validator.test_firewall_rules()
    print()
    validator.test_vlan_isolation()
    print()
    validator.test_intrusion_detection()
    print()
    validator.test_vpn_security()
    print()
    validator.test_network_access_control()
    
    # Generate report
    report = validator.generate_test_report()
    
    print(f"\n📊 Test Results Summary:")
    print(f"   Total Tests: {report['summary']['total_tests']}")
    print(f"   Passed: {report['summary']['passed']} ✅")
    print(f"   Failed: {report['summary']['failed']} ❌")
    print(f"   Success Rate: {report['summary']['success_rate']}")
    
    if report['summary']['failed'] > 0:
        print(f"\n🔧 Recommendations:")
        for rec in report['recommendations'][:3]:
            print(f"   • {rec}")
    
    # Export detailed report
    with open('security_validation_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Detailed report saved to security_validation_report.json")

if __name__ == "__main__":
    main()
```

## 📊 Grading Rubric (100 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|---------|
| **Firewall Configuration** | 20% | 20 points |
| **Network Segmentation** | 20% | 20 points |
| **VPN Implementation** | 15% | 15 points |
| **Intrusion Detection** | 15% | 15 points |
| **Documentation** | 20% | 20 points |
| **Security Validation** | 10% | 10 points |

### 5-Point Scale Criteria

**Firewall Configuration (20 points)**
- **Excellent (20)**: Comprehensive multi-zone firewall, threat intelligence, application-layer filtering
- **Proficient (16)**: Good firewall setup, most security zones configured
- **Developing (12)**: Basic firewall rules, some zones missing
- **Needs Improvement (8)**: Limited firewall configuration
- **Inadequate (4)**: Poor or non-functional firewall setup
- **No Submission (0)**: Missing or no attempt

**Network Segmentation (20 points)**
- **Excellent (20)**: Complete VLAN segmentation, microsegmentation, proper isolation
- **Proficient (16)**: Good segmentation design, minor isolation issues
- **Developing (12)**: Basic VLAN setup, limited isolation
- **Needs Improvement (8)**: Segmentation present but ineffective
- **Inadequate (4)**: Poor or no network segmentation
- **No Submission (0)**: Missing or no attempt

**VPN Implementation (15 points)**
- **Excellent (15)**: Multiple VPN types, strong authentication, monitoring
- **Proficient (12)**: Good VPN setup, certificate-based auth
- **Developing (9)**: Basic VPN functionality
- **Needs Improvement (6)**: Limited VPN capabilities
- **Inadequate (3)**: Poor or non-functional VPN
- **No Submission (0)**: Missing or no attempt

**Intrusion Detection (15 points)**
- **Excellent (15)**: Advanced IDS/IPS with custom rules, automated response
- **Proficient (12)**: Good IDS setup with monitoring
- **Developing (9)**: Basic intrusion detection
- **Needs Improvement (6)**: Limited detection capabilities
- **Inadequate (3)**: Poor or no intrusion detection
- **No Submission (0)**: Missing or no attempt

**Documentation (20 points)**
- **Excellent (20)**: Comprehensive documentation, diagrams, procedures
- **Proficient (16)**: Good documentation covering most aspects
- **Developing (12)**: Basic documentation, some gaps
- **Needs Improvement (8)**: Limited documentation
- **Inadequate (4)**: Poor or minimal documentation
- **No Submission (0)**: Missing or no attempt

**Security Validation (10 points)**
- **Excellent (10)**: Thorough testing, penetration testing, compliance checking
- **Proficient (8)**: Good testing coverage
- **Developing (6)**: Basic security validation
- **Needs Improvement (4)**: Limited testing
- **Inadequate (2)**: Poor or no validation
- **No Submission (0)**: Missing or no attempt

### Grade Scale
- **90-100 points (A)**: Enterprise-ready network security infrastructure
- **80-89 points (B)**: Good implementation, minor issues
- **70-79 points (C)**: Satisfactory, meets basic requirements
- **60-69 points (D)**: Below expectations, significant issues
- **Below 60 points (F)**: Unsatisfactory, major problems

## 🚀 Bonus Opportunities (+5 points each)

### 1. Zero Trust Network Architecture
Implement zero trust principles:
```python
def implement_zero_trust():
    """Implement zero trust network architecture"""
    # Continuous device verification
    # Micro-segmentation for all assets
    # Encrypted communication everywhere
```

### 2. Security Orchestration and Response
Add automated incident response:
```python
def security_orchestration():
    """Automated security incident response"""
    # Threat detection correlation
    # Automated containment actions
    # Integration with security tools
```

### 3. Network Security Analytics
Implement advanced analytics:
```python
def network_analytics():
    """Advanced network security analytics"""
    # Behavioral baseline analysis
    # Machine learning threat detection
    # Predictive security insights
```

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **Complete firewall configuration with all security zones**
- [ ] **VLAN segmentation implemented and tested**
- [ ] **VPN solutions configured and functional**
- [ ] **IDS/IPS deployed with custom rules**
- [ ] **NAC policies defined and enforced**
- [ ] **Network diagram accurately represents topology**
- [ ] **All security controls tested and validated**
- [ ] **Comprehensive documentation provided**
- [ ] **Security validation report generated**

### Testing Your Network Security Infrastructure

```bash
# Test firewall effectiveness
nmap -sS -O target_network
python security_validation_suite.py

# Validate VLAN isolation
# Connect to different VLANs and test connectivity

# Test VPN functionality
# Connect via VPN and verify access controls

# Validate IDS detection
# Generate test attacks and verify alerts

# Test NAC policies
# Connect different device types and verify access levels
```

## 📚 Resources and References

### Documentation
- **pfSense Documentation**: https://docs.netgate.com/pfsense/en/latest/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **CIS Controls**: https://www.cisecurity.org/controls/

### Security Standards
- **NIST SP 800-41**: Guidelines on Firewalls and Firewall Policy
- **NIST SP 800-46**: Guide to Enterprise Telework and Remote Access Security
- **ISO 27001**: Information Security Management

### Example Implementation Structure
```python
# Main implementation files
enterprise_firewall.py          # Firewall configuration
network_segmentation.py         # VLAN and segmentation
vpn_management.py              # VPN implementation
ids_management.py              # Intrusion detection
nac_system.py                  # Network access control
security_validation_suite.py   # Testing and validation

# Configuration files
firewall_config.json           # Firewall rules export
network_segmentation.json      # Segmentation config
security_policies.md           # Security policies
implementation_guide.md        # Setup instructions
```

## ❓ Frequently Asked Questions

**Q: What firewall platform should I use?**  
A: pfSense is recommended for this assignment, but other platforms like OPNsense, VyOS, or IPFire are acceptable.

**Q: How many VLANs should I implement?**  
A: Minimum 5 VLANs as specified, but more comprehensive segmentation will score higher.

**Q: Do I need real hardware for this assignment?**  
A: No, virtual environments (VirtualBox, VMware, GNS3) are acceptable and recommended.

**Q: How should I demonstrate IDS functionality?**  
A: Use simulated attacks, captured traffic, or IDS test tools to show detection capabilities.

**Q: What level of documentation is expected?**  
A: Professional-level documentation including architecture diagrams, configuration guides, and security policies.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Would this network security infrastructure protect an enterprise environment?**
2. **Are all network segments properly isolated and controlled?**
3. **Can the security controls detect and respond to common attack vectors?**
4. **Is the documentation sufficient for operations and maintenance?**
5. **Have all security controls been tested and validated?**

---

**Need Help?**
- Review the network security tutorial materials
- Test your configuration with network scanning tools
- Check Canvas discussions for implementation guidance
- Attend office hours for architecture review and troubleshooting

**Good luck!** This assignment will give you comprehensive experience with enterprise network security infrastructure design and implementation.