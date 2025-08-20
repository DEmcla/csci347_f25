# Week 7 Assignment: Enterprise SIEM and Security Operations Center

**Due**: End of Week 7 (see Canvas for exact deadline)  
**Points**: 25 points  
**Submission**: Upload to Canvas

## 🎯 Assignment Overview

Build a comprehensive Security Information and Event Management (SIEM) system with automated threat detection, real-time monitoring dashboards, and incident response capabilities. Your implementation should demonstrate mastery of log analysis, security monitoring, threat hunting, and SOC operations learned this week.

## 📋 Requirements

### Core Functionality (70 points)

Your SIEM system must implement these components:

#### 1. Centralized Log Management (20 points)
- **ELK Stack deployment** (Elasticsearch, Logstash, Kibana) with optimized configuration
- **Multi-source log ingestion** from network devices, servers, and security tools
- **Log normalization and enrichment** with threat intelligence and geolocation
- **Data retention policies** with automated archival and cleanup

#### 2. Advanced Threat Detection (25 points)
- **Suricata IDS integration** with custom enterprise rules
- **Behavioral anomaly detection** using statistical analysis
- **Threat correlation engine** linking related security events
- **Machine learning-based detection** for advanced threats

#### 3. Security Monitoring Dashboards (15 points)
- **SOC overview dashboard** with real-time threat landscape
- **Threat hunting interface** with advanced search and visualization
- **Incident response dashboard** for active investigation tracking
- **Executive reporting dashboard** with KPIs and trends

#### 4. Automated Alerting and Response (10 points)
- **Multi-tier alert system** (critical, high, medium, low priority)
- **Alert correlation** to reduce false positives and noise
- **Automated response actions** (blocking IPs, isolating hosts)
- **Notification system** (email, Slack, SMS) with escalation policies

### Security Operations Center (SOC) Interface (20 points)

Create a comprehensive SOC interface with these features:

```
/soc-dashboard           - Main SOC monitoring interface
/threat-hunting          - Advanced threat hunting tools
/incident-management     - Active incident tracking and response
/threat-intelligence     - TI feeds and IOC management
/playbooks              - Incident response playbooks
/compliance-reports     - Security compliance and audit reports
/system-health          - SIEM system health and performance
```

### SOAR Integration (10 points)

- **Security Orchestration** with automated playbook execution
- **Threat intelligence enrichment** from multiple feeds
- **Case management** with investigation workflows
- **Integration APIs** for external security tools

## 🔧 Technical Specifications

### Required Technologies
```python
# SIEM Technology Stack
- Elasticsearch: Search and analytics engine
- Logstash: Data processing pipeline
- Kibana: Data visualization and dashboards
- Suricata: Network intrusion detection
- Python: Automation and custom analytics
- Flask: SOC web interface
- Redis: Caching and session management
- PostgreSQL: Case management database
```

### Architecture Requirements
```
SIEM Architecture:
├── Data Ingestion Layer
│   ├── Syslog Collectors
│   ├── File Beat Agents
│   ├── API Integrations
│   └── Database Connectors
├── Data Processing Layer
│   ├── Logstash Pipelines
│   ├── Normalization Rules
│   ├── Enrichment Services
│   └── Correlation Engine
├── Storage Layer
│   ├── Elasticsearch Cluster
│   ├── Hot/Warm/Cold Architecture
│   └── Backup and Archival
├── Analytics Layer
│   ├── Real-time Detection
│   ├── ML-based Analysis
│   ├── Threat Intelligence
│   └── Behavioral Analytics
└── Presentation Layer
    ├── Kibana Dashboards
    ├── Custom SOC Interface
    ├── Mobile App
    └── API Endpoints
```

### File Structure
```
enterprise_siem/
├── elk_stack/
│   ├── elasticsearch/
│   │   ├── config/
│   │   └── templates/
│   ├── logstash/
│   │   ├── pipelines/
│   │   ├── patterns/
│   │   └── dictionaries/
│   └── kibana/
│       ├── dashboards/
│       └── visualizations/
├── detection_engine/
│   ├── suricata_rules/
│   ├── behavioral_detection.py
│   ├── correlation_engine.py
│   └── ml_detection.py
├── soc_interface/
│   ├── app.py
│   ├── templates/
│   ├── static/
│   └── api/
├── automation/
│   ├── alert_processor.py
│   ├── incident_response.py
│   ├── threat_intel.py
│   └── playbooks/
├── config/
│   ├── siem_config.yaml
│   ├── alert_rules.json
│   └── threat_feeds.json
└── scripts/
    ├── deployment.py
    ├── backup.py
    └── maintenance.py
```

## 📝 Detailed Requirements

### 1. SIEM Core Engine
```python
class SIEMEngine:
    def __init__(self, config_file="siem_config.yaml"):
        self.config = self.load_config(config_file)
        self.es_client = Elasticsearch(self.config['elasticsearch']['hosts'])
        self.detection_rules = self.load_detection_rules()
        self.threat_intel = ThreatIntelligenceManager()
        
    def process_security_event(self, event):
        """
        Process incoming security event through SIEM pipeline
        
        Args:
            event (dict): Raw security event data
            
        Returns:
            dict: Processed event with enrichments and analysis
        """
        # Normalize event format
        normalized_event = self.normalize_event(event)
        
        # Enrich with threat intelligence
        enriched_event = self.threat_intel.enrich_event(normalized_event)
        
        # Apply detection rules
        detection_results = self.apply_detection_rules(enriched_event)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(enriched_event, detection_results)
        
        # Create final event
        final_event = {
            **enriched_event,
            'detection_results': detection_results,
            'risk_score': risk_score,
            'risk_level': self.get_risk_level(risk_score),
            'processed_at': datetime.utcnow().isoformat()
        }
        
        # Store in Elasticsearch
        self.store_event(final_event)
        
        # Trigger alerts if necessary
        if risk_score >= self.config['alerting']['threshold']:
            self.trigger_alert(final_event)
        
        return final_event
    
    def apply_detection_rules(self, event):
        """Apply security detection rules to event"""
        matches = []
        
        for rule in self.detection_rules:
            if self.evaluate_rule(rule, event):
                matches.append({
                    'rule_id': rule['id'],
                    'rule_name': rule['name'],
                    'severity': rule['severity'],
                    'category': rule['category'],
                    'confidence': rule.get('confidence', 0.8)
                })
        
        return matches
    
    def calculate_risk_score(self, event, detections):
        """Calculate composite risk score for event"""
        base_score = 0
        
        # Base score from detections
        for detection in detections:
            severity_scores = {'low': 25, 'medium': 50, 'high': 75, 'critical': 100}
            base_score += severity_scores.get(detection['severity'], 0)
        
        # Threat intelligence multiplier
        if event.get('threat_intel', {}).get('reputation') == 'malicious':
            base_score *= 1.5
        
        # Source/destination analysis
        if self.is_external_ip(event.get('src_ip')):
            base_score += 10
        if self.is_critical_asset(event.get('dest_ip')):
            base_score += 20
        
        # Time-based factors
        if self.is_off_hours(event.get('@timestamp')):
            base_score += 15
        
        # Volume-based factors  
        recent_events = self.count_recent_events(
            event.get('src_ip'), 
            timeframe_minutes=10
        )
        if recent_events > 50:
            base_score += 25
        
        return min(base_score, 100)  # Cap at 100
```

### 2. Advanced Threat Detection
```python
class ThreatDetectionEngine:
    def __init__(self, siem_engine):
        self.siem = siem_engine
        self.ml_models = self.load_ml_models()
        self.behavioral_baselines = self.load_baselines()
        
    def detect_anomalous_behavior(self, user_id, time_window='24h'):
        """
        Detect anomalous user behavior using machine learning
        
        Args:
            user_id (str): User identifier
            time_window (str): Analysis time window
            
        Returns:
            dict: Anomaly detection results
        """
        # Get user activity baseline
        baseline = self.behavioral_baselines.get(user_id)
        if not baseline:
            baseline = self.calculate_user_baseline(user_id)
        
        # Get recent user activity
        recent_activity = self.get_user_activity(user_id, time_window)
        
        # Apply ML models
        anomaly_scores = {}
        for model_name, model in self.ml_models.items():
            score = model.predict_anomaly(recent_activity, baseline)
            anomaly_scores[model_name] = score
        
        # Calculate composite anomaly score
        composite_score = sum(anomaly_scores.values()) / len(anomaly_scores)
        
        return {
            'user_id': user_id,
            'composite_anomaly_score': composite_score,
            'model_scores': anomaly_scores,
            'is_anomalous': composite_score > 0.7,
            'anomaly_indicators': self.get_anomaly_indicators(recent_activity, baseline)
        }
    
    def detect_lateral_movement(self, source_ip, time_window='1h'):
        """Detect potential lateral movement patterns"""
        # Get network connections from source
        connections = self.get_network_connections(source_ip, time_window)
        
        # Analyze connection patterns
        unique_destinations = set([conn['dest_ip'] for conn in connections])
        unique_ports = set([conn['dest_port'] for conn in connections])
        
        # Check for lateral movement indicators
        lateral_movement_score = 0
        indicators = []
        
        # Multiple internal destinations
        if len(unique_destinations) > 10:
            lateral_movement_score += 30
            indicators.append(f"Connected to {len(unique_destinations)} internal hosts")
        
        # Administrative protocols
        admin_ports = [22, 23, 135, 139, 445, 3389, 5985, 5986]
        admin_connections = [p for p in unique_ports if p in admin_ports]
        if admin_connections:
            lateral_movement_score += 25
            indicators.append(f"Used administrative protocols: {admin_connections}")
        
        # Rapid progression through network
        timeline = sorted(connections, key=lambda x: x['timestamp'])
        if len(timeline) > 20:  # High volume of connections
            lateral_movement_score += 20
            indicators.append("High volume of network connections")
        
        return {
            'source_ip': source_ip,
            'lateral_movement_score': lateral_movement_score,
            'risk_level': 'high' if lateral_movement_score > 50 else 'medium' if lateral_movement_score > 25 else 'low',
            'indicators': indicators,
            'affected_hosts': list(unique_destinations),
            'timeline': timeline[-10:]  # Last 10 connections
        }
    
    def correlate_security_events(self, time_window='1h'):
        """Correlate related security events to identify campaigns"""
        # Get recent high-risk events
        events = self.siem.get_events_by_risk_level('high', time_window)
        
        # Group events by common attributes
        correlations = self.find_event_correlations(events)
        
        # Identify potential attack campaigns
        campaigns = []
        for correlation in correlations:
            if len(correlation['events']) >= 3:  # Minimum events for campaign
                campaign = {
                    'campaign_id': self.generate_campaign_id(),
                    'events': correlation['events'],
                    'common_attributes': correlation['attributes'],
                    'severity': self.calculate_campaign_severity(correlation['events']),
                    'attack_vector': self.identify_attack_vector(correlation['events']),
                    'timeline': self.build_attack_timeline(correlation['events'])
                }
                campaigns.append(campaign)
        
        return campaigns
```

### 3. SOC Interface Implementation
```python
from flask import Flask, render_template, request, jsonify, session
import json
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

class SOCInterface:
    def __init__(self, siem_engine):
        self.siem = siem_engine
        self.setup_routes()
    
    def setup_routes(self):
        """Setup Flask routes for SOC interface"""
        
        @app.route('/soc-dashboard')
        def soc_dashboard():
            """Main SOC monitoring dashboard"""
            # Get current threat statistics
            stats = {
                'active_alerts': self.get_active_alerts_count(),
                'events_last_hour': self.get_recent_events_count(hours=1),
                'top_threats': self.get_top_threats(),
                'system_health': self.get_system_health(),
                'threat_level': self.get_current_threat_level()
            }
            return render_template('soc_dashboard.html', stats=stats)
        
        @app.route('/api/realtime-threats')
        def realtime_threats():
            """API endpoint for real-time threat data"""
            threats = self.siem.get_recent_threats(minutes=5)
            return jsonify({
                'timestamp': datetime.utcnow().isoformat(),
                'threats': threats,
                'total_count': len(threats)
            })
        
        @app.route('/threat-hunting')
        def threat_hunting():
            """Advanced threat hunting interface"""
            # Get threat hunting queries and results
            saved_queries = self.get_saved_hunt_queries()
            return render_template('threat_hunting.html', queries=saved_queries)
        
        @app.route('/api/hunt', methods=['POST'])
        def execute_hunt():
            """Execute threat hunting query"""
            query = request.json.get('query')
            time_range = request.json.get('time_range', '24h')
            
            results = self.siem.execute_hunt_query(query, time_range)
            return jsonify({
                'results': results,
                'query': query,
                'execution_time': datetime.utcnow().isoformat()
            })
        
        @app.route('/incident-management')
        def incident_management():
            """Incident response dashboard"""
            incidents = self.get_active_incidents()
            return render_template('incident_management.html', incidents=incidents)
        
        @app.route('/api/incidents/<incident_id>', methods=['PUT'])
        def update_incident(incident_id):
            """Update incident status and details"""
            update_data = request.json
            success = self.update_incident_record(incident_id, update_data)
            return jsonify({'success': success})
    
    def get_active_alerts_count(self):
        """Get count of currently active alerts"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": "now-24h"}}},
                        {"terms": {"alert_status": ["new", "investigating"]}}
                    ]
                }
            }
        }
        result = self.siem.es_client.count(index="security-alerts-*", body=query)
        return result['count']
    
    def get_top_threats(self, limit=10):
        """Get top threats by frequency and severity"""
        query = {
            "size": 0,
            "query": {
                "range": {"@timestamp": {"gte": "now-24h"}}
            },
            "aggs": {
                "top_threats": {
                    "terms": {
                        "field": "alert.signature.keyword",
                        "size": limit,
                        "order": {"avg_risk_score": "desc"}
                    },
                    "aggs": {
                        "avg_risk_score": {
                            "avg": {"field": "risk_score"}
                        },
                        "unique_sources": {
                            "cardinality": {"field": "src_ip"}
                        }
                    }
                }
            }
        }
        
        result = self.siem.es_client.search(index="security-events-*", body=query)
        threats = []
        
        for bucket in result['aggregations']['top_threats']['buckets']:
            threats.append({
                'name': bucket['key'],
                'count': bucket['doc_count'],
                'avg_risk_score': round(bucket['avg_risk_score']['value'], 2),
                'unique_sources': bucket['unique_sources']['value']
            })
        
        return threats
```

## 💻 Example Implementation

### Security Event Processor
```python
import asyncio
import json
from datetime import datetime

class SecurityEventProcessor:
    def __init__(self, siem_engine):
        self.siem = siem_engine
        self.processing_queue = asyncio.Queue()
        
    async def process_events_continuously(self):
        """Continuously process security events"""
        while True:
            try:
                # Get events from queue
                event_batch = await self.get_event_batch()
                
                # Process events in parallel
                tasks = [
                    self.process_single_event(event) 
                    for event in event_batch
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Handle any processing errors
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        await self.handle_processing_error(event_batch[i], result)
                
            except Exception as e:
                print(f"Error in event processing loop: {e}")
                await asyncio.sleep(5)  # Brief pause before retrying
    
    async def process_single_event(self, event):
        """Process a single security event"""
        try:
            # Apply SIEM processing pipeline
            processed_event = self.siem.process_security_event(event)
            
            # Check for immediate response requirements
            if processed_event['risk_level'] == 'critical':
                await self.trigger_immediate_response(processed_event)
            
            return processed_event
            
        except Exception as e:
            raise Exception(f"Failed to process event: {e}")
    
    async def trigger_immediate_response(self, event):
        """Trigger immediate response for critical events"""
        # Create incident
        incident_id = await self.create_security_incident(event)
        
        # Send notifications
        await self.send_critical_alert(event, incident_id)
        
        # Execute automated response
        if event.get('auto_response_enabled', True):
            await self.execute_automated_response(event)

if __name__ == '__main__':
    # Example usage
    siem = SIEMEngine()
    processor = SecurityEventProcessor(siem)
    
    # Start event processing
    asyncio.run(processor.process_events_continuously())
```

## 📊 Grading Rubric (100 Points Total)

### Component Breakdown

| Component | Weight | Points |
|-----------|---------|---------|
| **Log Management (ELK Stack)** | 20% | 20 points |
| **Threat Detection** | 25% | 25 points |
| **Security Dashboards** | 15% | 15 points |
| **Automated Alerting** | 10% | 10 points |
| **SOC Interface** | 20% | 20 points |
| **SOAR Integration** | 10% | 10 points |

### 5-Point Scale Criteria

**Log Management (20 points)**
- **Excellent (20)**: Complete ELK deployment, multi-source ingestion, advanced processing
- **Proficient (16)**: Good ELK setup, basic log processing, most sources configured
- **Developing (12)**: Basic ELK functionality, limited log sources
- **Needs Improvement (8)**: ELK partially working, significant configuration issues
- **Inadequate (4)**: Poor ELK setup, major functionality problems
- **No Submission (0)**: Missing or no attempt

**Threat Detection (25 points)**
- **Excellent (25)**: Advanced detection rules, ML integration, behavioral analysis, correlation
- **Proficient (20)**: Good detection capabilities, custom rules, basic correlation
- **Developing (15)**: Basic detection rules, limited advanced features
- **Needs Improvement (10)**: Simple detection, high false positive rate
- **Inadequate (5)**: Poor detection capabilities, major gaps
- **No Submission (0)**: Missing or no attempt

**Security Dashboards (15 points)**
- **Excellent (15)**: Comprehensive dashboards, excellent visualization, real-time updates
- **Proficient (12)**: Good dashboards, adequate visualization
- **Developing (9)**: Basic dashboards, limited functionality
- **Needs Improvement (6)**: Simple dashboards, poor usability
- **Inadequate (3)**: Minimal or non-functional dashboards
- **No Submission (0)**: Missing or no attempt

**Automated Alerting (10 points)**
- **Excellent (10)**: Multi-tier alerting, correlation, automated response, escalation
- **Proficient (8)**: Good alerting system, basic automation
- **Developing (6)**: Basic alerting functionality
- **Needs Improvement (4)**: Limited alerting capabilities
- **Inadequate (2)**: Poor or no alerting
- **No Submission (0)**: Missing or no attempt

**SOC Interface (20 points)**
- **Excellent (20)**: Professional SOC interface, comprehensive features, excellent UX
- **Proficient (16)**: Good SOC interface, most features functional
- **Developing (12)**: Basic SOC interface, adequate functionality
- **Needs Improvement (8)**: Limited interface features, poor usability
- **Inadequate (4)**: Minimal or broken interface
- **No Submission (0)**: Missing or no attempt

**SOAR Integration (10 points)**
- **Excellent (10)**: Full SOAR capabilities, playbook automation, orchestration
- **Proficient (8)**: Good automation features, basic orchestration
- **Developing (6)**: Basic automation capabilities
- **Needs Improvement (4)**: Limited automation
- **Inadequate (2)**: Minimal or no automation
- **No Submission (0)**: Missing or no attempt

### Grade Scale
- **90-100 points (A)**: Enterprise-ready SIEM and SOC platform
- **80-89 points (B)**: Good implementation, minor feature gaps
- **70-79 points (C)**: Satisfactory, meets basic SIEM requirements
- **60-69 points (D)**: Below expectations, significant limitations
- **Below 60 points (F)**: Unsatisfactory, major functionality issues

## 🚀 Bonus Opportunities (+5 points each)

### 1. Advanced Machine Learning
Implement sophisticated ML-based threat detection:
```python
def advanced_ml_detection(events):
    """Advanced ML-based anomaly and threat detection"""
    # Implement ensemble methods, deep learning
    # Behavioral profiling with unsupervised learning
    # Advanced feature engineering for security events
```

### 2. Threat Intelligence Platform (TIP)
Build comprehensive threat intelligence management:
```python
def threat_intelligence_platform():
    """Comprehensive threat intelligence platform"""
    # STIX/TAXII integration
    # IOC management and sharing
    # Automated threat hunting based on TI
```

### 3. Mobile SOC Application
Create mobile application for SOC analysts:
```python
def mobile_soc_app():
    """Mobile application for SOC operations"""
    # Real-time alerts and notifications
    # Remote incident response capabilities
    # Dashboard access for mobile devices
```

## 📋 Submission Checklist

Before submitting, verify:

- [ ] **ELK Stack deployed and configured for security monitoring**
- [ ] **Multiple log sources integrated and normalized**
- [ ] **Advanced threat detection rules implemented and tested**
- [ ] **Security dashboards functional with real-time data**
- [ ] **Automated alerting system responding to threats**
- [ ] **SOC interface provides comprehensive security operations**
- [ ] **SOAR capabilities automate incident response**
- [ ] **System performance optimized for high-volume processing**
- [ ] **Documentation includes architecture diagrams and SOPs**
- [ ] **Compliance reporting capabilities functional**

### Testing Your SIEM System
```bash
# Test ELK Stack
curl -X GET "localhost:9200/_cluster/health"
curl -X GET "localhost:5601/api/status"

# Test log ingestion
echo "test security event" | logger -p local0.info

# Test alerting
python3 simulate_security_events.py

# Test dashboards
curl -X GET "localhost:5601/api/saved_objects/_find?type=dashboard"

# Performance testing
python3 load_test_siem.py
```

## 📚 Resources and References

### Documentation
- **Elastic Stack Documentation**: https://www.elastic.co/guide/index.html
- **Suricata User Guide**: https://suricata.readthedocs.io/en/latest/
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework

### Security Standards
- **SANS SIEM Implementation**: https://www.sans.org/white-papers/siem/
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **OWASP Logging Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

## ❓ Frequently Asked Questions

**Q: How should I handle the high volume of security events in ELK?**  
A: Implement proper indexing strategies, use hot/warm/cold architecture, and optimize Logstash pipelines for performance.

**Q: What's the best approach for reducing false positives in alerting?**  
A: Use correlation rules, implement alert scoring, tune detection thresholds, and maintain threat intelligence feeds.

**Q: How do I ensure SIEM system scalability?**  
A: Design for horizontal scaling, implement proper resource monitoring, use appropriate hardware sizing, and optimize query performance.

**Q: Should I implement custom detection rules or use commercial rule sets?**  
A: Use both - commercial rules for baseline coverage and custom rules for environment-specific threats and business logic.

**Q: How do I measure SIEM effectiveness?**  
A: Track metrics like mean time to detection (MTTD), mean time to response (MTTR), alert accuracy, and coverage of the kill chain.

## 🔍 Self-Assessment Questions

Before submitting, ask yourself:

1. **Can this SIEM detect advanced persistent threats and insider threats?**
2. **Are the dashboards actionable for SOC analysts during incident response?**
3. **Does the alerting system provide appropriate context for investigation?**
4. **Can the system handle the expected volume of security events?**
5. **Are the automated responses appropriate and safe for the environment?**

---

**Need Help?**
- Review the SIEM tutorial materials and ELK Stack documentation
- Test your system with realistic security event volumes
- Check Canvas discussions for implementation strategies
- Attend office hours for architecture and performance optimization

**Good luck!** This assignment will give you hands-on experience with enterprise-grade SIEM systems used in modern Security Operations Centers.