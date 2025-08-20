# Week 9 Tutorial: Security Architecture and Risk Management

**Estimated Time**: 3-4 hours (broken into 4 modules)  
**Prerequisites**: Completed required readings, understanding of basic security concepts

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Module 1** (45 min): Implemented a threat modeling process using STRIDE
2. **Module 2** (60 min): Built a risk assessment calculator
3. **Module 3** (45 min): Created security controls mapping to frameworks
4. **Module 4** (60 min): Developed security metrics and KPI dashboard

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Module 1: Threat Modeling with STRIDE ✅ Checkpoint 1
- [ ] Module 2: Risk Assessment Calculator ✅ Checkpoint 2  
- [ ] Module 3: Security Controls Mapping ✅ Checkpoint 3
- [ ] Module 4: Security Metrics Dashboard ✅ Checkpoint 4

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Install required packages
pip install pandas matplotlib tabulate colorama

# Create working directory
mkdir week9-work
cd week9-work
```

---

## 📘 Module 1: Threat Modeling with STRIDE (45 minutes)

**Learning Objective**: Understand and apply the STRIDE threat modeling methodology

**What you'll build**: STRIDE threat analyzer for a web application

### Step 1: Understanding STRIDE

Create a new file `stride_analyzer.py`:

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
import json

class ThreatCategory(Enum):
    """STRIDE threat categories"""
    SPOOFING = "Spoofing Identity"
    TAMPERING = "Tampering with Data"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"

@dataclass
class Asset:
    """Represents a system asset to analyze"""
    name: str
    asset_type: str  # data_store, process, external_entity, data_flow
    description: str
    sensitivity: int  # 1-5 scale
    exposure: int  # 1-5 scale

@dataclass
class Threat:
    """Represents an identified threat"""
    asset: str
    category: ThreatCategory
    description: str
    likelihood: int  # 1-5 scale
    impact: int  # 1-5 scale
    mitigation: Optional[str] = None
    
    @property
    def risk_score(self) -> int:
        """Calculate risk score (likelihood * impact)"""
        return self.likelihood * self.impact
    
    @property
    def risk_level(self) -> str:
        """Determine risk level based on score"""
        score = self.risk_score
        if score >= 20:
            return "CRITICAL"
        elif score >= 15:
            return "HIGH"
        elif score >= 10:
            return "MEDIUM"
        elif score >= 5:
            return "LOW"
        return "MINIMAL"

class STRIDEAnalyzer:
    """STRIDE threat modeling analyzer"""
    
    def __init__(self):
        self.assets: List[Asset] = []
        self.threats: List[Threat] = []
        self.threat_patterns = self._load_threat_patterns()
    
    def _load_threat_patterns(self) -> Dict:
        """Load common threat patterns for each STRIDE category"""
        return {
            ThreatCategory.SPOOFING: [
                "Weak authentication mechanisms",
                "Missing multi-factor authentication",
                "Session hijacking vulnerabilities",
                "Credential stuffing attacks"
            ],
            ThreatCategory.TAMPERING: [
                "Unvalidated input",
                "SQL injection vulnerabilities",
                "Missing integrity checks",
                "Insecure direct object references"
            ],
            ThreatCategory.REPUDIATION: [
                "Insufficient logging",
                "Missing audit trails",
                "Lack of non-repudiation controls",
                "Inadequate timestamp validation"
            ],
            ThreatCategory.INFO_DISCLOSURE: [
                "Sensitive data in logs",
                "Unencrypted data transmission",
                "Missing access controls",
                "Information leakage in error messages"
            ],
            ThreatCategory.DENIAL_OF_SERVICE: [
                "Resource exhaustion vulnerabilities",
                "Missing rate limiting",
                "Unhandled exceptions",
                "Memory leaks"
            ],
            ThreatCategory.ELEVATION_OF_PRIVILEGE: [
                "Privilege escalation vulnerabilities",
                "Missing authorization checks",
                "Insecure deserialization",
                "Buffer overflow vulnerabilities"
            ]
        }
    
    def add_asset(self, asset: Asset):
        """Add an asset to analyze"""
        self.assets.append(asset)
        print(f"✅ Added asset: {asset.name}")
    
    def analyze_asset(self, asset: Asset) -> List[Threat]:
        """Analyze an asset for STRIDE threats"""
        identified_threats = []
        
        # Check each STRIDE category
        for category in ThreatCategory:
            threats = self._identify_threats_for_category(asset, category)
            identified_threats.extend(threats)
        
        return identified_threats
    
    def _identify_threats_for_category(self, asset: Asset, category: ThreatCategory) -> List[Threat]:
        """Identify threats for a specific STRIDE category"""
        threats = []
        
        # Asset type specific threat analysis
        if asset.asset_type == "data_store":
            if category == ThreatCategory.TAMPERING:
                threat = Threat(
                    asset=asset.name,
                    category=category,
                    description=f"Unauthorized modification of {asset.name} data",
                    likelihood=3 if asset.exposure >= 3 else 2,
                    impact=asset.sensitivity,
                    mitigation="Implement database access controls and encryption"
                )
                threats.append(threat)
            
            elif category == ThreatCategory.INFO_DISCLOSURE:
                threat = Threat(
                    asset=asset.name,
                    category=category,
                    description=f"Unauthorized access to {asset.name} sensitive data",
                    likelihood=asset.exposure,
                    impact=asset.sensitivity,
                    mitigation="Encrypt data at rest and implement access controls"
                )
                threats.append(threat)
        
        elif asset.asset_type == "process":
            if category == ThreatCategory.SPOOFING:
                threat = Threat(
                    asset=asset.name,
                    category=category,
                    description=f"Identity spoofing in {asset.name} process",
                    likelihood=3,
                    impact=4,
                    mitigation="Implement strong authentication and session management"
                )
                threats.append(threat)
            
            elif category == ThreatCategory.ELEVATION_OF_PRIVILEGE:
                threat = Threat(
                    asset=asset.name,
                    category=category,
                    description=f"Privilege escalation in {asset.name}",
                    likelihood=2 if asset.exposure < 3 else 4,
                    impact=5,
                    mitigation="Implement proper authorization checks and principle of least privilege"
                )
                threats.append(threat)
        
        elif asset.asset_type == "data_flow":
            if category == ThreatCategory.TAMPERING:
                threat = Threat(
                    asset=asset.name,
                    category=category,
                    description=f"Man-in-the-middle attack on {asset.name}",
                    likelihood=asset.exposure,
                    impact=4,
                    mitigation="Implement TLS/SSL encryption and certificate pinning"
                )
                threats.append(threat)
        
        return threats
    
    def run_analysis(self):
        """Run STRIDE analysis on all assets"""
        print("\n🔍 Running STRIDE Analysis...")
        print("="*60)
        
        for asset in self.assets:
            threats = self.analyze_asset(asset)
            self.threats.extend(threats)
            
            print(f"\n📦 Asset: {asset.name} ({asset.asset_type})")
            print(f"   Sensitivity: {asset.sensitivity}/5, Exposure: {asset.exposure}/5")
            print(f"   Threats identified: {len(threats)}")
            
            for threat in threats:
                print(f"   - {threat.category.value}: {threat.risk_level} risk")
    
    def generate_report(self) -> Dict:
        """Generate threat modeling report"""
        report = {
            "summary": {
                "total_assets": len(self.assets),
                "total_threats": len(self.threats),
                "critical_threats": len([t for t in self.threats if t.risk_level == "CRITICAL"]),
                "high_threats": len([t for t in self.threats if t.risk_level == "HIGH"])
            },
            "threats_by_category": {},
            "top_risks": [],
            "recommendations": []
        }
        
        # Group threats by category
        for category in ThreatCategory:
            category_threats = [t for t in self.threats if t.category == category]
            report["threats_by_category"][category.value] = len(category_threats)
        
        # Top risks
        sorted_threats = sorted(self.threats, key=lambda t: t.risk_score, reverse=True)
        report["top_risks"] = [
            {
                "asset": t.asset,
                "threat": t.description,
                "risk_level": t.risk_level,
                "mitigation": t.mitigation
            }
            for t in sorted_threats[:5]
        ]
        
        return report

# Demo the STRIDE analyzer
if __name__ == "__main__":
    analyzer = STRIDEAnalyzer()
    
    # Add sample assets for a web application
    assets = [
        Asset("User Database", "data_store", "Stores user credentials and PII", 5, 3),
        Asset("Authentication Service", "process", "Handles user login/logout", 4, 5),
        Asset("API Gateway", "process", "Routes and authorizes API requests", 4, 5),
        Asset("Payment Data", "data_store", "Stores credit card information", 5, 2),
        Asset("Client-Server Communication", "data_flow", "HTTPS API calls", 4, 4),
        Asset("Admin Panel", "process", "Administrative interface", 5, 3)
    ]
    
    for asset in assets:
        analyzer.add_asset(asset)
    
    # Run analysis
    analyzer.run_analysis()
    
    # Generate report
    report = analyzer.generate_report()
    
    print("\n📊 THREAT MODELING REPORT")
    print("="*60)
    print(f"Total Assets Analyzed: {report['summary']['total_assets']}")
    print(f"Total Threats Identified: {report['summary']['total_threats']}")
    print(f"Critical Threats: {report['summary']['critical_threats']}")
    print(f"High Risk Threats: {report['summary']['high_threats']}")
    
    print("\n🎯 Top Risks:")
    for i, risk in enumerate(report['top_risks'], 1):
        print(f"{i}. [{risk['risk_level']}] {risk['asset']}")
        print(f"   Threat: {risk['threat']}")
        print(f"   Mitigation: {risk['mitigation']}")
```

**Run it:**
```bash
python stride_analyzer.py
```

### 💡 Key Concepts Learned

**Before moving to Module 2, make sure you understand:**

1. **STRIDE Categories**: Each letter represents a threat type
2. **Asset Classification**: Different asset types have different vulnerabilities  
3. **Risk Scoring**: Likelihood × Impact = Risk Score
4. **Threat Prioritization**: Focus on highest risks first

### ✅ Checkpoint 1 Complete!
You can now perform STRIDE threat modeling. Ready for Module 2?

---

## 📘 Module 2: Risk Assessment Calculator (60 minutes)

**Learning Objective**: Build a quantitative risk assessment system

**What you'll build**: Risk calculator with financial impact analysis

### Step 1: Risk Assessment Framework

Create `risk_calculator.py`:

```python
from dataclasses import dataclass
from typing import List, Dict, Optional
from enum import Enum
import json
from datetime import datetime

class RiskCategory(Enum):
    """Risk categories"""
    TECHNICAL = "Technical"
    COMPLIANCE = "Compliance"
    OPERATIONAL = "Operational"
    FINANCIAL = "Financial"
    REPUTATIONAL = "Reputational"

@dataclass
class RiskScenario:
    """Represents a risk scenario"""
    name: str
    category: RiskCategory
    description: str
    threat_event_frequency: float  # Events per year
    single_loss_expectancy: float  # $ per event
    current_controls: List[str]
    control_effectiveness: float  # 0-1 scale
    
    @property
    def annual_rate_of_occurrence(self) -> float:
        """Calculate ARO with control effectiveness"""
        return self.threat_event_frequency * (1 - self.control_effectiveness)
    
    @property
    def annual_loss_expectancy(self) -> float:
        """Calculate ALE (ARO × SLE)"""
        return self.annual_rate_of_occurrence * self.single_loss_expectancy
    
    @property
    def risk_rating(self) -> str:
        """Determine risk rating based on ALE"""
        ale = self.annual_loss_expectancy
        if ale >= 1000000:
            return "CRITICAL"
        elif ale >= 500000:
            return "HIGH"
        elif ale >= 100000:
            return "MEDIUM"
        elif ale >= 10000:
            return "LOW"
        return "MINIMAL"

@dataclass
class SecurityControl:
    """Represents a security control"""
    name: str
    cost: float  # Annual cost
    effectiveness: float  # Risk reduction percentage (0-1)
    implementation_time: int  # Days
    maintenance_effort: str  # Low/Medium/High

class RiskCalculator:
    """Quantitative risk assessment calculator"""
    
    def __init__(self):
        self.scenarios: List[RiskScenario] = []
        self.controls: List[SecurityControl] = []
        self.organization_revenue = 10000000  # Default $10M
    
    def add_scenario(self, scenario: RiskScenario):
        """Add a risk scenario"""
        self.scenarios.append(scenario)
        print(f"✅ Added scenario: {scenario.name}")
    
    def add_control(self, control: SecurityControl):
        """Add a security control option"""
        self.controls.append(control)
        print(f"✅ Added control: {control.name}")
    
    def calculate_total_risk(self) -> float:
        """Calculate total annual loss expectancy"""
        return sum(scenario.annual_loss_expectancy for scenario in self.scenarios)
    
    def calculate_risk_percentage(self) -> float:
        """Calculate risk as percentage of revenue"""
        total_risk = self.calculate_total_risk()
        return (total_risk / self.organization_revenue) * 100
    
    def evaluate_control_roi(self, control: SecurityControl, scenarios: List[RiskScenario]) -> Dict:
        """Evaluate ROI for implementing a control"""
        # Calculate risk reduction
        risk_reduction = 0
        for scenario in scenarios:
            current_ale = scenario.annual_loss_expectancy
            # Apply control effectiveness
            new_aro = scenario.threat_event_frequency * (1 - control.effectiveness)
            new_ale = new_aro * scenario.single_loss_expectancy
            risk_reduction += (current_ale - new_ale)
        
        # Calculate ROI
        roi = ((risk_reduction - control.cost) / control.cost) * 100 if control.cost > 0 else 0
        payback_period = control.cost / risk_reduction if risk_reduction > 0 else float('inf')
        
        return {
            "control": control.name,
            "annual_cost": control.cost,
            "risk_reduction": risk_reduction,
            "roi_percentage": roi,
            "payback_months": payback_period * 12 if payback_period != float('inf') else None,
            "net_benefit": risk_reduction - control.cost
        }
    
    def prioritize_controls(self) -> List[Dict]:
        """Prioritize controls by ROI"""
        control_evaluations = []
        
        for control in self.controls:
            evaluation = self.evaluate_control_roi(control, self.scenarios)
            control_evaluations.append(evaluation)
        
        # Sort by net benefit
        control_evaluations.sort(key=lambda x: x['net_benefit'], reverse=True)
        
        return control_evaluations
    
    def generate_risk_matrix(self) -> Dict:
        """Generate risk matrix data"""
        matrix = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "minimal": []
        }
        
        for scenario in self.scenarios:
            rating = scenario.risk_rating.lower()
            matrix[rating].append({
                "name": scenario.name,
                "ale": scenario.annual_loss_expectancy,
                "frequency": scenario.annual_rate_of_occurrence
            })
        
        return matrix
    
    def monte_carlo_simulation(self, iterations: int = 1000) -> Dict:
        """Run Monte Carlo simulation for risk analysis"""
        import random
        
        results = []
        
        for _ in range(iterations):
            total_loss = 0
            
            for scenario in self.scenarios:
                # Simulate occurrence
                events = 0
                for _ in range(12):  # Monthly simulation
                    if random.random() < (scenario.annual_rate_of_occurrence / 12):
                        events += 1
                
                # Calculate loss with variation (±20%)
                if events > 0:
                    variation = random.uniform(0.8, 1.2)
                    loss = events * scenario.single_loss_expectancy * variation
                    total_loss += loss
            
            results.append(total_loss)
        
        results.sort()
        
        return {
            "min_loss": min(results),
            "max_loss": max(results),
            "average_loss": sum(results) / len(results),
            "percentile_50": results[int(len(results) * 0.5)],
            "percentile_95": results[int(len(results) * 0.95)],
            "percentile_99": results[int(len(results) * 0.99)]
        }

# Demo the risk calculator
if __name__ == "__main__":
    calculator = RiskCalculator()
    
    # Add risk scenarios
    scenarios = [
        RiskScenario(
            name="Data Breach",
            category=RiskCategory.TECHNICAL,
            description="Customer data exposure",
            threat_event_frequency=0.5,  # Once every 2 years
            single_loss_expectancy=2000000,  # $2M per breach
            current_controls=["Firewall", "Basic encryption"],
            control_effectiveness=0.3
        ),
        RiskScenario(
            name="Ransomware Attack",
            category=RiskCategory.TECHNICAL,
            description="Systems encrypted by ransomware",
            threat_event_frequency=1.0,  # Once per year
            single_loss_expectancy=500000,  # $500K per incident
            current_controls=["Antivirus", "Backups"],
            control_effectiveness=0.5
        ),
        RiskScenario(
            name="GDPR Violation",
            category=RiskCategory.COMPLIANCE,
            description="Non-compliance with data protection",
            threat_event_frequency=0.3,
            single_loss_expectancy=1000000,
            current_controls=["Privacy policy"],
            control_effectiveness=0.2
        ),
        RiskScenario(
            name="Service Outage",
            category=RiskCategory.OPERATIONAL,
            description="Critical system downtime",
            threat_event_frequency=4.0,  # Quarterly
            single_loss_expectancy=50000,
            current_controls=["Basic monitoring"],
            control_effectiveness=0.4
        )
    ]
    
    for scenario in scenarios:
        calculator.add_scenario(scenario)
    
    # Add security controls
    controls = [
        SecurityControl(
            name="Advanced EDR Solution",
            cost=100000,
            effectiveness=0.7,
            implementation_time=30,
            maintenance_effort="Medium"
        ),
        SecurityControl(
            name="Zero Trust Architecture",
            cost=250000,
            effectiveness=0.8,
            implementation_time=180,
            maintenance_effort="High"
        ),
        SecurityControl(
            name="Security Awareness Training",
            cost=30000,
            effectiveness=0.4,
            implementation_time=14,
            maintenance_effort="Low"
        ),
        SecurityControl(
            name="DLP Solution",
            cost=75000,
            effectiveness=0.6,
            implementation_time=45,
            maintenance_effort="Medium"
        )
    ]
    
    for control in controls:
        calculator.add_control(control)
    
    # Calculate risks
    print("\n📊 RISK ASSESSMENT REPORT")
    print("="*60)
    
    total_risk = calculator.calculate_total_risk()
    risk_percentage = calculator.calculate_risk_percentage()
    
    print(f"Total Annual Loss Expectancy: ${total_risk:,.2f}")
    print(f"Risk as % of Revenue: {risk_percentage:.2f}%")
    
    print("\n🎲 Risk Scenarios:")
    for scenario in calculator.scenarios:
        print(f"\n{scenario.name} ({scenario.category.value})")
        print(f"  ALE: ${scenario.annual_loss_expectancy:,.2f}")
        print(f"  ARO: {scenario.annual_rate_of_occurrence:.2f} events/year")
        print(f"  Rating: {scenario.risk_rating}")
    
    # Control prioritization
    print("\n🛡️ Control Prioritization (by ROI):")
    priorities = calculator.prioritize_controls()
    for i, control in enumerate(priorities[:3], 1):
        print(f"\n{i}. {control['control']}")
        print(f"   Cost: ${control['annual_cost']:,.2f}")
        print(f"   Risk Reduction: ${control['risk_reduction']:,.2f}")
        print(f"   ROI: {control['roi_percentage']:.1f}%")
        if control['payback_months']:
            print(f"   Payback: {control['payback_months']:.1f} months")
    
    # Monte Carlo simulation
    print("\n🎰 Monte Carlo Simulation (1000 iterations):")
    simulation = calculator.monte_carlo_simulation()
    print(f"  Minimum Loss: ${simulation['min_loss']:,.2f}")
    print(f"  Average Loss: ${simulation['average_loss']:,.2f}")
    print(f"  95th Percentile: ${simulation['percentile_95']:,.2f}")
    print(f"  99th Percentile: ${simulation['percentile_99']:,.2f}")
    print(f"  Maximum Loss: ${simulation['max_loss']:,.2f}")
```

**Run it:**
```bash
python risk_calculator.py
```

---

## 📘 Module 3: Security Controls Mapping (45 minutes)

**Learning Objective**: Map security controls to compliance frameworks

**What you'll build**: Framework mapper for NIST, ISO 27001, and CIS

Create `framework_mapper.py`:

```python
from typing import Dict, List, Set
from dataclasses import dataclass
import json

@dataclass
class ControlMapping:
    """Maps controls across frameworks"""
    control_id: str
    control_name: str
    nist_csf: List[str]  # NIST CSF subcategories
    iso_27001: List[str]  # ISO 27001 controls
    cis_controls: List[str]  # CIS Controls
    implementation_status: str  # Not Started, In Progress, Implemented
    maturity_level: int  # 1-5 scale

class FrameworkMapper:
    """Security framework control mapper"""
    
    def __init__(self):
        self.mappings: List[ControlMapping] = []
        self.frameworks = {
            "NIST CSF": self._load_nist_framework(),
            "ISO 27001": self._load_iso_framework(),
            "CIS": self._load_cis_framework()
        }
    
    def _load_nist_framework(self) -> Dict:
        """Load NIST CSF categories"""
        return {
            "ID": {
                "name": "Identify",
                "categories": ["Asset Management", "Risk Assessment", "Governance"]
            },
            "PR": {
                "name": "Protect",
                "categories": ["Access Control", "Data Security", "Training"]
            },
            "DE": {
                "name": "Detect",
                "categories": ["Anomalies", "Monitoring", "Detection Processes"]
            },
            "RS": {
                "name": "Respond",
                "categories": ["Response Planning", "Communications", "Mitigation"]
            },
            "RC": {
                "name": "Recover",
                "categories": ["Recovery Planning", "Improvements", "Communications"]
            }
        }
    
    def _load_iso_framework(self) -> Dict:
        """Load ISO 27001 domains"""
        return {
            "A.5": "Information Security Policies",
            "A.6": "Organization of Information Security",
            "A.7": "Human Resource Security",
            "A.8": "Asset Management",
            "A.9": "Access Control",
            "A.10": "Cryptography",
            "A.11": "Physical Security",
            "A.12": "Operations Security",
            "A.13": "Communications Security",
            "A.14": "System Development",
            "A.15": "Supplier Relationships",
            "A.16": "Incident Management",
            "A.17": "Business Continuity",
            "A.18": "Compliance"
        }
    
    def _load_cis_framework(self) -> Dict:
        """Load CIS Controls"""
        return {
            "1": "Inventory and Control of Enterprise Assets",
            "2": "Inventory and Control of Software Assets",
            "3": "Data Protection",
            "4": "Secure Configuration",
            "5": "Account Management",
            "6": "Access Control Management",
            "7": "Continuous Vulnerability Management",
            "8": "Audit Log Management",
            "9": "Email and Web Browser Protections",
            "10": "Malware Defenses",
            "11": "Data Recovery",
            "12": "Network Infrastructure Management",
            "13": "Network Monitoring",
            "14": "Security Awareness Training",
            "15": "Service Provider Management",
            "16": "Application Security",
            "17": "Incident Response Management",
            "18": "Penetration Testing"
        }
    
    def add_control_mapping(self, mapping: ControlMapping):
        """Add a control mapping"""
        self.mappings.append(mapping)
    
    def get_framework_coverage(self, framework: str) -> Dict:
        """Calculate coverage for a specific framework"""
        if framework == "NIST CSF":
            total_categories = 23  # NIST has 23 subcategories
            covered = set()
            for mapping in self.mappings:
                if mapping.implementation_status == "Implemented":
                    covered.update(mapping.nist_csf)
            coverage = (len(covered) / total_categories) * 100
            
        elif framework == "ISO 27001":
            total_controls = 114  # ISO 27001 has 114 controls
            covered = set()
            for mapping in self.mappings:
                if mapping.implementation_status == "Implemented":
                    covered.update(mapping.iso_27001)
            coverage = (len(covered) / total_controls) * 100
            
        elif framework == "CIS":
            total_controls = 18  # CIS has 18 controls
            covered = set()
            for mapping in self.mappings:
                if mapping.implementation_status == "Implemented":
                    covered.update(mapping.cis_controls)
            coverage = (len(covered) / total_controls) * 100
        else:
            coverage = 0
        
        return {
            "framework": framework,
            "coverage_percentage": coverage,
            "implemented_controls": len([m for m in self.mappings if m.implementation_status == "Implemented"]),
            "in_progress_controls": len([m for m in self.mappings if m.implementation_status == "In Progress"]),
            "not_started_controls": len([m for m in self.mappings if m.implementation_status == "Not Started"])
        }
    
    def identify_gaps(self) -> List[str]:
        """Identify control gaps across frameworks"""
        gaps = []
        
        # Check NIST gaps
        nist_implemented = set()
        for mapping in self.mappings:
            if mapping.implementation_status == "Implemented":
                nist_implemented.update(mapping.nist_csf)
        
        nist_functions = ["ID", "PR", "DE", "RS", "RC"]
        for function in nist_functions:
            if not any(control.startswith(function) for control in nist_implemented):
                gaps.append(f"NIST CSF: No controls for {self.frameworks['NIST CSF'][function]['name']} function")
        
        # Check maturity gaps
        low_maturity = [m for m in self.mappings if m.maturity_level < 3]
        if low_maturity:
            gaps.append(f"Maturity: {len(low_maturity)} controls have low maturity (<3)")
        
        return gaps
    
    def generate_compliance_report(self) -> Dict:
        """Generate compliance mapping report"""
        report = {
            "summary": {
                "total_controls": len(self.mappings),
                "average_maturity": sum(m.maturity_level for m in self.mappings) / len(self.mappings) if self.mappings else 0
            },
            "framework_coverage": {},
            "gaps": self.identify_gaps(),
            "recommendations": []
        }
        
        # Calculate coverage for each framework
        for framework in ["NIST CSF", "ISO 27001", "CIS"]:
            report["framework_coverage"][framework] = self.get_framework_coverage(framework)
        
        # Generate recommendations
        if report["summary"]["average_maturity"] < 3:
            report["recommendations"].append("Focus on improving control maturity levels")
        
        not_started = [m for m in self.mappings if m.implementation_status == "Not Started"]
        if len(not_started) > 5:
            report["recommendations"].append(f"Prioritize implementation of {len(not_started)} controls not yet started")
        
        return report

# Demo the framework mapper
if __name__ == "__main__":
    mapper = FrameworkMapper()
    
    # Add sample control mappings
    controls = [
        ControlMapping(
            control_id="AC-001",
            control_name="Multi-Factor Authentication",
            nist_csf=["PR.AC-1", "PR.AC-7"],
            iso_27001=["A.9.4.2", "A.9.2.1"],
            cis_controls=["6.3", "6.5"],
            implementation_status="Implemented",
            maturity_level=4
        ),
        ControlMapping(
            control_id="DS-001",
            control_name="Data Encryption at Rest",
            nist_csf=["PR.DS-1", "PR.DS-5"],
            iso_27001=["A.10.1.1", "A.8.2.3"],
            cis_controls=["3.1", "3.11"],
            implementation_status="Implemented",
            maturity_level=3
        ),
        ControlMapping(
            control_id="IR-001",
            control_name="Incident Response Plan",
            nist_csf=["RS.RP-1", "RS.CO-1"],
            iso_27001=["A.16.1.1", "A.16.1.2"],
            cis_controls=["17.1", "17.2"],
            implementation_status="In Progress",
            maturity_level=2
        ),
        ControlMapping(
            control_id="VM-001",
            control_name="Vulnerability Scanning",
            nist_csf=["DE.CM-8", "PR.IP-12"],
            iso_27001=["A.12.6.1"],
            cis_controls=["7.1", "7.2"],
            implementation_status="Implemented",
            maturity_level=3
        ),
        ControlMapping(
            control_id="BC-001",
            control_name="Business Continuity Plan",
            nist_csf=["RC.RP-1", "RC.CO-1"],
            iso_27001=["A.17.1.1", "A.17.1.2"],
            cis_controls=["11.1", "11.2"],
            implementation_status="Not Started",
            maturity_level=1
        )
    ]
    
    for control in controls:
        mapper.add_control_mapping(control)
    
    # Generate report
    report = mapper.generate_compliance_report()
    
    print("📋 COMPLIANCE MAPPING REPORT")
    print("="*60)
    print(f"Total Controls: {report['summary']['total_controls']}")
    print(f"Average Maturity: {report['summary']['average_maturity']:.1f}/5")
    
    print("\n📊 Framework Coverage:")
    for framework, coverage in report['framework_coverage'].items():
        print(f"\n{framework}:")
        print(f"  Coverage: {coverage['coverage_percentage']:.1f}%")
        print(f"  Implemented: {coverage['implemented_controls']}")
        print(f"  In Progress: {coverage['in_progress_controls']}")
        print(f"  Not Started: {coverage['not_started_controls']}")
    
    print("\n⚠️ Identified Gaps:")
    for gap in report['gaps']:
        print(f"  - {gap}")
    
    print("\n💡 Recommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec}")
```

---

## 📘 Module 4: Security Metrics Dashboard (60 minutes)

**Learning Objective**: Create KPIs and metrics for security program

**What you'll build**: Security metrics dashboard with visualizations

Create `security_metrics.py`:

```python
from typing import Dict, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import random

@dataclass
class SecurityMetric:
    """Represents a security metric/KPI"""
    name: str
    category: str
    current_value: float
    target_value: float
    unit: str
    trend: str  # up, down, stable
    
    @property
    def performance(self) -> float:
        """Calculate performance percentage"""
        if self.target_value > 0:
            return (self.current_value / self.target_value) * 100
        return 0
    
    @property
    def status(self) -> str:
        """Determine metric status"""
        perf = self.performance
        if perf >= 90:
            return "GREEN"
        elif perf >= 70:
            return "YELLOW"
        return "RED"

class SecurityDashboard:
    """Security metrics dashboard"""
    
    def __init__(self):
        self.metrics: List[SecurityMetric] = []
        self.historical_data = {}
    
    def add_metric(self, metric: SecurityMetric):
        """Add a metric to track"""
        self.metrics.append(metric)
    
    def calculate_security_score(self) -> float:
        """Calculate overall security score"""
        if not self.metrics:
            return 0
        
        total_score = sum(min(m.performance, 100) for m in self.metrics)
        return total_score / len(self.metrics)
    
    def get_metrics_by_status(self) -> Dict:
        """Group metrics by status"""
        status_groups = {"GREEN": [], "YELLOW": [], "RED": []}
        
        for metric in self.metrics:
            status_groups[metric.status].append(metric)
        
        return status_groups
    
    def generate_executive_summary(self) -> Dict:
        """Generate executive summary"""
        status_groups = self.get_metrics_by_status()
        
        return {
            "overall_score": self.calculate_security_score(),
            "total_metrics": len(self.metrics),
            "green_metrics": len(status_groups["GREEN"]),
            "yellow_metrics": len(status_groups["YELLOW"]),
            "red_metrics": len(status_groups["RED"]),
            "critical_items": [m.name for m in status_groups["RED"]],
            "trending_up": len([m for m in self.metrics if m.trend == "up"]),
            "trending_down": len([m for m in self.metrics if m.trend == "down"])
        }
    
    def display_dashboard(self):
        """Display the dashboard"""
        print("\n🎯 SECURITY METRICS DASHBOARD")
        print("="*70)
        
        # Executive summary
        summary = self.generate_executive_summary()
        score = summary['overall_score']
        
        print(f"\n📊 Overall Security Score: {score:.1f}%")
        print(f"   Status Distribution: 🟢 {summary['green_metrics']} | 🟡 {summary['yellow_metrics']} | 🔴 {summary['red_metrics']}")
        
        # Category breakdown
        categories = {}
        for metric in self.metrics:
            if metric.category not in categories:
                categories[metric.category] = []
            categories[metric.category].append(metric)
        
        print("\n📈 Metrics by Category:")
        for category, metrics in categories.items():
            avg_performance = sum(m.performance for m in metrics) / len(metrics)
            print(f"\n{category} (Avg: {avg_performance:.1f}%)")
            
            for metric in metrics:
                status_icon = {"GREEN": "🟢", "YELLOW": "🟡", "RED": "🔴"}[metric.status]
                trend_icon = {"up": "↗️", "down": "↘️", "stable": "→"}[metric.trend]
                
                print(f"  {status_icon} {metric.name}: {metric.current_value:.1f}{metric.unit}/{metric.target_value:.1f}{metric.unit} ({metric.performance:.1f}%) {trend_icon}")
        
        # Critical items
        if summary['critical_items']:
            print("\n⚠️ Critical Items Requiring Attention:")
            for item in summary['critical_items']:
                print(f"  - {item}")
        
        # Recommendations
        print("\n💡 Recommendations:")
        if summary['red_metrics'] > 0:
            print(f"  - Address {summary['red_metrics']} red metrics immediately")
        if summary['trending_down'] > 3:
            print(f"  - Investigate {summary['trending_down']} metrics trending downward")
        if score < 70:
            print("  - Overall security posture needs improvement")

# Demo the dashboard
if __name__ == "__main__":
    dashboard = SecurityDashboard()
    
    # Add security metrics
    metrics = [
        # Preventive Metrics
        SecurityMetric("Patch Compliance", "Preventive", 85, 95, "%", "up"),
        SecurityMetric("Security Training Completion", "Preventive", 72, 90, "%", "stable"),
        SecurityMetric("MFA Adoption", "Preventive", 93, 100, "%", "up"),
        SecurityMetric("Vulnerability Scan Coverage", "Preventive", 88, 95, "%", "up"),
        
        # Detective Metrics
        SecurityMetric("Mean Time to Detect (MTTD)", "Detective", 4.5, 2, "hours", "down"),
        SecurityMetric("Security Alert Resolution", "Detective", 82, 90, "%", "stable"),
        SecurityMetric("Log Collection Coverage", "Detective", 76, 85, "%", "up"),
        
        # Responsive Metrics
        SecurityMetric("Mean Time to Respond (MTTR)", "Responsive", 2.1, 1, "hours", "down"),
        SecurityMetric("Incident Closure Rate", "Responsive", 94, 95, "%", "stable"),
        SecurityMetric("Recovery Time Objective", "Responsive", 4, 4, "hours", "stable"),
        
        # Compliance Metrics
        SecurityMetric("Policy Compliance", "Compliance", 91, 95, "%", "up"),
        SecurityMetric("Audit Finding Closure", "Compliance", 67, 90, "%", "down"),
        SecurityMetric("Privacy Controls", "Compliance", 88, 95, "%", "stable"),
        
        # Risk Metrics
        SecurityMetric("Risk Assessment Coverage", "Risk", 45, 80, "%", "down"),
        SecurityMetric("Critical Asset Protection", "Risk", 92, 95, "%", "up"),
        SecurityMetric("Third-Party Risk Reviews", "Risk", 78, 85, "%", "stable")
    ]
    
    for metric in metrics:
        dashboard.add_metric(metric)
    
    # Display dashboard
    dashboard.display_dashboard()
    
    # Generate trend analysis
    print("\n📊 TREND ANALYSIS")
    print("="*70)
    
    improving = [m for m in dashboard.metrics if m.trend == "up" and m.status != "GREEN"]
    declining = [m for m in dashboard.metrics if m.trend == "down"]
    
    if improving:
        print("\n✅ Improving Metrics:")
        for metric in improving:
            print(f"  - {metric.name}: {metric.current_value:.1f}{metric.unit} (Target: {metric.target_value:.1f}{metric.unit})")
    
    if declining:
        print("\n⚠️ Declining Metrics:")
        for metric in declining:
            print(f"  - {metric.name}: {metric.current_value:.1f}{metric.unit} (Target: {metric.target_value:.1f}{metric.unit})")
```

---

## ✅ Tutorial Completion Checklist

After completing all modules, verify your understanding:

- [ ] You can perform STRIDE threat modeling on system assets
- [ ] You understand quantitative risk assessment (ALE, SLE, ARO)
- [ ] You can map controls to multiple compliance frameworks
- [ ] You know how to calculate control ROI and prioritize investments
- [ ] You can create and track security KPIs and metrics
- [ ] You understand risk matrices and Monte Carlo simulations

## 🚀 Ready for the Assignment?

Great! Now you have all the tools to design an enterprise security program. The assignment will combine these concepts into a comprehensive security architecture.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **STRIDE Threat Modeling** for systematic threat identification
2. **Quantitative Risk Assessment** with financial impact analysis
3. **Framework Mapping** across NIST, ISO 27001, and CIS Controls
4. **Control ROI Analysis** for investment prioritization
5. **Security Metrics and KPIs** for program measurement
6. **Risk Simulation** using Monte Carlo methods
7. **Executive Dashboards** for security visibility

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!