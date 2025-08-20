# Week 9 Assignment: Enterprise Security Architecture Design

**Due**: End of Week 9 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Design and implement a comprehensive enterprise security architecture that demonstrates risk-based decision making, threat modeling, security controls integration, and program metrics. Your solution should showcase understanding of security frameworks (NIST, ISO 27001, CIS Controls) and practical application of security architecture principles.

## 📋 Learning Outcomes

This assignment assesses your ability to:

1. **Threat Modeling & Risk Assessment** (5 points)
2. **Security Framework Integration** (5 points) 
3. **Security Controls Implementation** (5 points)
4. **Metrics & Dashboard Development** (5 points)
5. **Architecture Documentation** (5 points)

## 🔧 Technical Requirements

### Required Implementation
Build a Python-based security architecture system with these components:

```python
# Core modules to implement
threat_modeling.py      # STRIDE analysis & risk calculator
framework_mapper.py     # NIST/ISO/CIS controls mapping
security_dashboard.py   # Metrics and KPI visualization
architecture_report.py  # Documentation generator
```

### Required Libraries
```python
import pandas as pd
import matplotlib.pyplot as plt
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional
import json
```

## 📝 Detailed Requirements

### 1. Threat Modeling & Risk Assessment (5 points)

Implement a STRIDE-based threat modeling system:

**Required Features:**
- **Asset identification** with classification levels
- **STRIDE threat analysis** for each asset type
- **Quantitative risk calculation** (ALE = SLE × ARO)
- **Risk prioritization** with business impact scoring
- **Threat model visualization** showing attack vectors

**Deliverable:** `threat_modeling.py` with classes for Asset, Threat, and RiskCalculator

### 2. Security Framework Integration (5 points)

Create a control mapping system across multiple frameworks:

**Required Features:**
- **NIST CSF mapping** (Identify, Protect, Detect, Respond, Recover)
- **ISO 27001 controls** mapping to business processes
- **CIS Controls** implementation prioritization 
- **Gap analysis** identifying missing controls
- **Compliance reporting** for multiple standards

**Deliverable:** `framework_mapper.py` with comprehensive control mappings

### 3. Security Controls Implementation (5 points)

Design and implement security control automation:

**Required Features:**
- **Control effectiveness** measurement and scoring
- **Implementation cost** analysis and ROI calculation
- **Control dependencies** and prerequisite mapping
- **Automated control** deployment simulation
- **Control testing** and validation framework

**Deliverable:** `security_controls.py` with control implementation logic

### 4. Metrics & Dashboard Development (5 points)

Build executive and operational security dashboards:

**Required Features:**
- **Executive dashboard** with business risk metrics
- **Operational dashboard** with technical KPIs
- **Trend analysis** showing security posture over time
- **Alert system** for metric threshold breaches
- **Custom reporting** for different stakeholder needs

**Deliverable:** `security_dashboard.py` with visualization capabilities

### 5. Architecture Documentation (5 points)

Create comprehensive security architecture documentation:

**Required Features:**
- **Architecture diagrams** showing security layers
- **Risk register** with treatment decisions
- **Security policies** and procedure templates
- **Implementation roadmap** with timelines
- **Executive summary** with business justification

**Deliverable:** `architecture_report.py` generating professional documentation

## 💻 Implementation Guidelines

### System Architecture
```
├── src/
│   ├── threat_modeling.py
│   ├── framework_mapper.py
│   ├── security_controls.py
│   ├── security_dashboard.py
│   └── architecture_report.py
├── data/
│   ├── assets.json
│   ├── threats.json
│   ├── controls.json
│   └── metrics.json
├── reports/
│   ├── executive_summary.pdf
│   ├── technical_report.html
│   └── risk_register.xlsx
└── README.md
```

### Sample Asset Definition
```python
@dataclass
class Asset:
    asset_id: str
    name: str
    asset_type: str  # data, system, facility, personnel
    business_value: int  # 1-5 scale
    confidentiality: int  # 1-5 scale
    integrity: int  # 1-5 scale
    availability: int  # 1-5 scale
    owner: str
    custodian: str
```

### Sample Threat Analysis
```python
def analyze_stride_threats(asset: Asset) -> List[Threat]:
    """
    Analyze asset for STRIDE threats
    Returns prioritized threat list with risk scores
    """
    threats = []
    
    # Analyze each STRIDE category
    for category in StrideCategory:
        threat_scenarios = identify_threat_scenarios(asset, category)
        for scenario in threat_scenarios:
            risk_score = calculate_risk(scenario.likelihood, scenario.impact)
            threats.append(Threat(asset.asset_id, category, scenario, risk_score))
    
    return sorted(threats, key=lambda t: t.risk_score, reverse=True)
```

## 🧪 Testing Requirements

Your implementation must include:

### Unit Tests
- **Threat calculation** accuracy verification
- **Risk scoring** algorithm validation
- **Control mapping** completeness checks
- **Dashboard data** integrity testing
- **Report generation** functionality testing

### Integration Tests
- **End-to-end workflow** from assets to reports
- **Framework integration** across NIST/ISO/CIS
- **Dashboard updates** reflecting control changes
- **Multi-scenario** risk analysis validation

### Sample Test Data
Provide realistic test data including:
- 20+ enterprise assets across different types
- 50+ mapped security controls
- 100+ threat scenarios with risk scores
- 30+ security metrics with historical data

## 📤 Submission Requirements

### Required Files
1. **Source Code** (all Python files)
2. **Documentation** (README.md with usage instructions)
3. **Test Suite** (test files with sample data)
4. **Sample Reports** (generated architecture documentation)
5. **Demo Video** (5-minute walkthrough of key features)

### README.md Must Include:
- **Installation instructions** with dependencies
- **Usage examples** for each major component
- **Architecture decisions** and design rationale
- **Framework mapping** explanation
- **Known limitations** and future improvements

## 📊 Grading Rubric (25 Points Total)

### 5-Point Scale Criteria

**Threat Modeling & Risk Assessment (5 points)**
- **Excellent (5)**: Complete STRIDE implementation, accurate risk calculations, sophisticated threat scenarios
- **Proficient (4)**: Good threat modeling, mostly accurate calculations, adequate scenarios
- **Developing (3)**: Basic threat identification, simple risk scoring, limited scenarios
- **Needs Improvement (2)**: Incomplete threat analysis, calculation errors, unrealistic scenarios
- **Inadequate (1)**: Major gaps in threat modeling, significant errors, minimal scenarios

**Security Framework Integration (5 points)**
- **Excellent (5)**: Comprehensive mapping across all frameworks, accurate control relationships, gap analysis
- **Proficient (4)**: Good framework mapping, minor gaps, basic control relationships
- **Developing (3)**: Limited framework coverage, some mapping errors, basic functionality
- **Needs Improvement (2)**: Incomplete mapping, significant errors, poor framework understanding
- **Inadequate (1)**: Minimal framework integration, major errors, missing core components

**Security Controls Implementation (5 points)**
- **Excellent (5)**: Sophisticated control logic, ROI analysis, dependency tracking, automation features
- **Proficient (4)**: Good control implementation, basic ROI, some automation
- **Developing (3)**: Basic controls, limited analysis, manual processes
- **Needs Improvement (2)**: Simple controls, poor analysis, minimal functionality
- **Inadequate (1)**: Inadequate control implementation, major functionality gaps

**Metrics & Dashboard Development (5 points)**
- **Excellent (5)**: Professional dashboards, comprehensive metrics, excellent visualizations, alerting
- **Proficient (4)**: Good dashboards, adequate metrics, decent visualizations
- **Developing (3)**: Basic dashboards, limited metrics, simple visualizations
- **Needs Improvement (2)**: Poor dashboards, few metrics, inadequate visualizations
- **Inadequate (1)**: Minimal dashboard functionality, missing key metrics

**Architecture Documentation (5 points)**
- **Excellent (5)**: Comprehensive documentation, professional diagrams, executive summaries, implementation guides
- **Proficient (4)**: Good documentation, adequate diagrams, clear explanations
- **Developing (3)**: Basic documentation, simple diagrams, limited detail
- **Needs Improvement (2)**: Poor documentation, inadequate diagrams, unclear explanations
- **Inadequate (1)**: Minimal documentation, missing key components, unprofessional presentation

### Grade Scale:
- **A**: 23-25 points (92-100%)
- **B**: 20-22 points (80-91%)
- **C**: 18-19 points (72-79%)
- **D**: 15-17 points (60-71%)
- **F**: Below 15 points (<60%)

## 🚀 Bonus Opportunities (+2 points max)

- **Advanced Visualization**: Interactive dashboards with drill-down capabilities
- **Machine Learning**: Anomaly detection for security metrics
- **API Integration**: Connect to real security tools (simulated)
- **Mobile Dashboard**: Responsive design for mobile access
- **Advanced Analytics**: Predictive risk modeling

## 💡 Tips for Success

1. **Start with Assets**: Define your enterprise asset inventory first
2. **Use Real Examples**: Base threats on actual security incidents
3. **Framework Research**: Study real NIST/ISO implementations
4. **Visual Design**: Create professional-looking dashboards
5. **Test Thoroughly**: Validate calculations with manual checks
6. **Document Well**: Clear explanation increases points significantly

## 📚 Resources

- NIST Cybersecurity Framework v1.1
- ISO 27001:2013 Control Set
- CIS Controls Version 8
- FAIR Risk Assessment Methodology
- STRIDE Threat Modeling Guide

---

**Good luck building your enterprise security architecture!** 🏗️🔒