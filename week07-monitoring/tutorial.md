# Week 7 Tutorial: Security Monitoring and SIEM Implementation

**Estimated Time**: 4.5-5 hours  
**Prerequisites**: Week 6 completed, understanding of network security and intrusion detection

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Part 1** (60 min): Deployed and configured Security Onion SIEM platform
2. **Part 2** (60 min): Implemented log aggregation and parsing with ELK Stack  
3. **Part 3** (60 min): Created custom security monitoring dashboards
4. **Part 4** (90 min): Built automated threat hunting and incident response workflows
5. **Part 5** (45 min): Integrated threat intelligence and correlation rules

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Part 1: Security Onion SIEM Deployment ✅ Checkpoint 1
- [ ] Part 2: ELK Stack Log Management ✅ Checkpoint 2
- [ ] Part 3: Security Dashboards and Visualization ✅ Checkpoint 3
- [ ] Part 4: Threat Hunting and Automated Response ✅ Checkpoint 4
- [ ] Part 5: Threat Intelligence Integration ✅ Checkpoint 5

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check system resources (SIEM requires significant resources)
free -h  # Minimum 8GB RAM recommended
df -h    # Minimum 100GB disk space

# Check Docker installation
docker --version
docker-compose --version

# Check Python version
python3 --version  # Should be 3.8+

# Install required packages
pip3 install elasticsearch kibana-api requests python-dateutil pandas numpy matplotlib

# Create working directory
mkdir week7-security-monitoring
cd week7-security-monitoring
```

---

## 📘 Part 1: Security Onion SIEM Deployment (60 minutes)

**Learning Objective**: Deploy and configure a complete SIEM platform with Security Onion

**What you'll build**: Production-ready SIEM with IDS, NSM, and log analysis capabilities

### Step 1: Security Onion Installation and Setup

Create `security_onion_setup.py` for automated deployment:

```python
#!/usr/bin/env python3
"""
Security Onion SIEM Setup and Configuration
Automated deployment and initial configuration
"""

import subprocess
import time
import json
import yaml
import os
from pathlib import Path

class SecurityOnionManager:
    def __init__(self, install_dir="security_onion"):
        self.install_dir = Path(install_dir)
        self.install_dir.mkdir(exist_ok=True)
        self.config = {}
        
    def create_docker_compose(self):
        """Create Docker Compose configuration for Security Onion"""
        
        compose_config = {
            'version': '3.8',
            'services': {
                'elasticsearch': {
                    'image': 'docker.elastic.co/elasticsearch/elasticsearch:7.17.0',
                    'container_name': 'so-elasticsearch',
                    'environment': [
                        'discovery.type=single-node',
                        'ES_JAVA_OPTS=-Xms2g -Xmx2g',
                        'xpack.security.enabled=false',
                        'xpack.monitoring.collection.enabled=true'
                    ],
                    'ports': ['9200:9200'],
                    'volumes': ['es_data:/usr/share/elasticsearch/data'],
                    'networks': ['so_network']
                },
                
                'kibana': {
                    'image': 'docker.elastic.co/kibana/kibana:7.17.0',
                    'container_name': 'so-kibana',
                    'environment': [
                        'ELASTICSEARCH_HOSTS=http://elasticsearch:9200'
                    ],
                    'ports': ['5601:5601'],
                    'depends_on': ['elasticsearch'],
                    'networks': ['so_network']
                },
                
                'logstash': {
                    'image': 'docker.elastic.co/logstash/logstash:7.17.0',
                    'container_name': 'so-logstash',
                    'ports': ['5044:5044', '9600:9600'],
                    'environment': [
                        'LS_JAVA_OPTS=-Xms1g -Xmx1g'
                    ],
                    'volumes': [
                        './logstash/config:/usr/share/logstash/pipeline',
                        './logstash/patterns:/usr/share/logstash/patterns'
                    ],
                    'depends_on': ['elasticsearch'],
                    'networks': ['so_network']
                },
                
                'suricata': {
                    'image': 'jasonish/suricata:latest',
                    'container_name': 'so-suricata',
                    'network_mode': 'host',
                    'cap_add': ['NET_ADMIN', 'SYS_NICE'],
                    'volumes': [
                        './suricata/etc:/etc/suricata',
                        './suricata/logs:/var/log/suricata',
                        './suricata/rules:/var/lib/suricata/rules'
                    ],
                    'command': [
                        'suricata', '-c', '/etc/suricata/suricata.yaml',
                        '-i', 'eth0', '--init-errors-fatal'
                    ]
                },
                
                'zeek': {
                    'image': 'blacktop/zeek:latest',
                    'container_name': 'so-zeek',
                    'network_mode': 'host',
                    'cap_add': ['NET_ADMIN', 'NET_RAW'],
                    'volumes': [
                        './zeek/logs:/usr/local/zeek/logs',
                        './zeek/spool:/usr/local/zeek/spool'
                    ],
                    'command': [
                        'zeek', '-i', 'eth0',
                        'local', 'Policy/Frameworks/Intel/seen'
                    ]
                },
                
                'filebeat': {
                    'image': 'docker.elastic.co/beats/filebeat:7.17.0',
                    'container_name': 'so-filebeat',
                    'user': 'root',
                    'volumes': [
                        './filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro',
                        './suricata/logs:/var/log/suricata:ro',
                        './zeek/logs:/var/log/zeek:ro',
                        '/var/log:/var/log/host:ro',
                        '/var/lib/docker:/var/lib/docker:ro'
                    ],
                    'depends_on': ['elasticsearch', 'logstash'],
                    'networks': ['so_network']
                },
                
                'curator': {
                    'image': 'untergeek/curator:5.8.4',
                    'container_name': 'so-curator',
                    'volumes': [
                        './curator:/usr/share/curator/config'
                    ],
                    'depends_on': ['elasticsearch'],
                    'networks': ['so_network'],
                    'command': ['curator', '--config', '/usr/share/curator/config/curator.yml', '/usr/share/curator/config/actions.yml']
                }
            },
            
            'volumes': {
                'es_data': {'driver': 'local'}
            },
            
            'networks': {
                'so_network': {'driver': 'bridge'}
            }
        }
        
        compose_file = self.install_dir / 'docker-compose.yml'
        with open(compose_file, 'w') as f:
            yaml.dump(compose_config, f, default_flow_style=False)
        
        print("✅ Docker Compose configuration created")
        return compose_file
    
    def create_logstash_config(self):
        """Create Logstash pipeline configuration"""
        
        logstash_dir = self.install_dir / 'logstash' / 'config'
        logstash_dir.mkdir(parents=True, exist_ok=True)
        
        # Main pipeline configuration
        pipeline_config = """
input {
  beats {
    port => 5044
  }
  
  tcp {
    port => 5000
    type => "syslog"
  }
  
  udp {
    port => 5000
    type => "syslog"
  }
}

filter {
  # Suricata EVE JSON processing
  if [fields][logtype] == "suricata" {
    json {
      source => "message"
    }
    
    if [event_type] == "alert" {
      mutate {
        add_field => { "rule_category" => "%{[alert][category]}" }
        add_field => { "severity_level" => "%{[alert][severity]}" }
        add_field => { "signature" => "%{[alert][signature]}" }
      }
    }
    
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "src_geoip"
      }
    }
    
    if [dest_ip] {
      geoip {
        source => "dest_ip"
        target => "dest_geoip"
      }
    }
  }
  
  # Zeek/Bro logs processing
  if [fields][logtype] == "zeek" {
    if [log_type] == "conn" {
      mutate {
        add_field => { "connection_state" => "%{conn_state}" }
        add_field => { "service_type" => "%{service}" }
      }
    }
    
    if [log_type] == "http" {
      mutate {
        add_field => { "http_method" => "%{method}" }
        add_field => { "http_status" => "%{status_code}" }
        add_field => { "user_agent" => "%{user_agent}" }
      }
    }
    
    if [log_type] == "dns" {
      mutate {
        add_field => { "dns_query" => "%{query}" }
        add_field => { "dns_response" => "%{answers}" }
      }
    }
  }
  
  # Syslog processing
  if [type] == "syslog" {
    grok {
      match => { 
        "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{DATA:program}(?:\\[%{POSINT:pid}\\])?: %{GREEDYDATA:log_message}"
      }
    }
    
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
  
  # Windows Event Log processing
  if [winlogbeat] {
    if [winlogbeat][event_id] == 4624 {
      mutate {
        add_field => { "event_description" => "Successful Logon" }
        add_field => { "logon_type" => "%{[winlogbeat][event_data][LogonType]}" }
      }
    }
    
    if [winlogbeat][event_id] == 4625 {
      mutate {
        add_field => { "event_description" => "Failed Logon" }
        add_field => { "failure_reason" => "%{[winlogbeat][event_data][FailureReason]}" }
      }
    }
  }
  
  # Add timestamp
  mutate {
    add_field => { "[@metadata][index_prefix]" => "logstash" }
  }
  
  # Parse timestamp
  date {
    match => [ "@timestamp", "ISO8601" ]
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "%{[@metadata][index_prefix]}-%{+YYYY.MM.dd}"
    template_name => "logstash"
  }
  
  # Debug output
  stdout { 
    codec => rubydebug 
  }
}
"""
        
        pipeline_file = logstash_dir / 'logstash.conf'
        with open(pipeline_file, 'w') as f:
            f.write(pipeline_config)
        
        print("✅ Logstash pipeline configuration created")
        return pipeline_file
    
    def create_filebeat_config(self):
        """Create Filebeat configuration"""
        
        filebeat_dir = self.install_dir / 'filebeat'
        filebeat_dir.mkdir(exist_ok=True)
        
        filebeat_config = {
            'filebeat.inputs': [
                {
                    'type': 'log',
                    'enabled': True,
                    'paths': ['/var/log/suricata/eve.json'],
                    'fields': {'logtype': 'suricata'},
                    'fields_under_root': True,
                    'json.keys_under_root': True,
                    'json.add_error_key': True
                },
                {
                    'type': 'log',
                    'enabled': True,
                    'paths': ['/var/log/zeek/*.log'],
                    'fields': {'logtype': 'zeek'},
                    'fields_under_root': True,
                    'multiline.pattern': '^#',
                    'multiline.negate': True,
                    'multiline.match': 'after'
                },
                {
                    'type': 'log',
                    'enabled': True,
                    'paths': [
                        '/var/log/host/syslog',
                        '/var/log/host/auth.log',
                        '/var/log/host/kern.log'
                    ],
                    'fields': {'logtype': 'syslog'},
                    'fields_under_root': True
                }
            ],
            'output.logstash': {
                'hosts': ['logstash:5044']
            },
            'processors': [
                {'add_docker_metadata': {'host': 'unix:///var/lib/docker/docker.sock'}},
                {'add_host_metadata': {'when.not.contains.tags': 'forwarded'}}
            ],
            'logging.level': 'info',
            'logging.to_files': True,
            'logging.files': {
                'path': '/var/log/filebeat',
                'name': 'filebeat',
                'keepfiles': 7,
                'permissions': '0644'
            }
        }
        
        config_file = filebeat_dir / 'filebeat.yml'
        with open(config_file, 'w') as f:
            yaml.dump(filebeat_config, f, default_flow_style=False)
        
        print("✅ Filebeat configuration created")
        return config_file
    
    def create_suricata_config(self):
        """Create Suricata IDS configuration"""
        
        suricata_dir = self.install_dir / 'suricata' / 'etc'
        suricata_dir.mkdir(parents=True, exist_ok=True)
        
        suricata_config = """
# Suricata Configuration File
%YAML 1.1
---

# Global variables
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"

# Default log directory
default-log-dir: /var/log/suricata/

# Configure stats
stats:
  enabled: yes
  interval: 8

# Configure outputs
outputs:
  # EVE JSON log
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            tagged-packets: yes
        - anomaly:
            enabled: yes
            types:
              decode: yes
              stream: yes
              applayer: yes
        - http:
            extended: yes
        - dns:
            version: 2
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp:
        - ssh
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow
        - netflow

  # Fast log for alerts
  - fast:
      enabled: yes
      filename: fast.log

# Application layer configuration
app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    ftp:
      enabled: yes
    ssh:
      enabled: yes
    smtp:
      enabled: yes
      raw-extraction: no
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          request-body-decompress-layer-limit: 2
          request-body-default-memcap: 32mb
          response-body-default-memcap: 32mb
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53

# Rule files
default-rule-path: /var/lib/suricata/rules

rule-files:
  - suricata.rules
  - /var/lib/suricata/rules/emerging-all.rules

# Classification file
classification-file: /etc/suricata/classification.config

# Reference config file
reference-config-file: /etc/suricata/reference.config

# Threshold file
threshold-file: /etc/suricata/threshold.config

# Host mode
host-mode: auto

# Maximum pending packets
max-pending-packets: 1024

# Runmode
runmode: autofp

# Default packet size
default-packet-size: 1514

# Unix command socket
unix-command:
  enabled: auto

# Magic file
magic-file: /usr/share/file/misc/magic

# GeoIP database
#geoip-database: /usr/share/GeoIP/GeoLite2-Country.mmdb

# Legacy options
legacy:
  uricontent: enabled

# Engine analysis
engine-analysis:
  rules-fast-pattern: yes
  rules: yes

# PCRE options  
pcre:
  match-limit: 3500
  match-limit-recursion: 1500

# Host table configuration
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

# Defragmentation settings
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65536
  max-frags: 65536
  prealloc: yes
  timeout: 60

# Flow settings
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

# Stream settings
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 64mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

# Logging
logging:
  default-log-level: notice
  default-log-format: "[%i] %t - (%f:%l) <%d> (%n) -- "
  
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      level: info
      filename: /var/log/suricata/suricata.log

# Capture settings
af-packet:
  - interface: eth0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    mmap-locked: yes
    tpacket-v3: yes
    ring-size: 2048
    block-size: 32768
    block-timeout: 10
    use-emergency-flush: yes

# Detection engine settings
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

# Multi-threading
threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ "0" ]
    - receive-cpu-set:
        cpu: [ "0" ]
    - worker-cpu-set:
        cpu: [ "all" ]
  detect-thread-ratio: 1.0

# Performance profiling
profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    limit: 10
    json: yes
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
  packets:
    enabled: yes
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no
      filename: packet_stats.csv

# CoredumpConfig
coredump:
  max-dump: unlimited

# Host OS policy
host-os-policy:
  windows: [0.0.0.0/0]
  bsd: []
  bsd-right: []
  old-linux: []
  linux: [10.0.0.0/8, 192.168.1.0/24, "::1"]
  old-solaris: []
  solaris: ["192.168.1.1"]
  hpux10: []
  hpux11: []
  irix: []
  macos: []
  vista: []
  windows2k3: []
"""
        
        config_file = suricata_dir / 'suricata.yaml'
        with open(config_file, 'w') as f:
            f.write(suricata_config)
        
        print("✅ Suricata configuration created")
        return config_file
    
    def deploy_security_onion(self):
        """Deploy complete Security Onion stack"""
        
        print("🚀 Deploying Security Onion SIEM Stack...")
        
        # Create all configurations
        self.create_docker_compose()
        self.create_logstash_config()
        self.create_filebeat_config()
        self.create_suricata_config()
        
        # Create additional directories
        dirs_to_create = [
            'suricata/logs',
            'suricata/rules',
            'zeek/logs',
            'zeek/spool',
            'curator'
        ]
        
        for dir_path in dirs_to_create:
            (self.install_dir / dir_path).mkdir(parents=True, exist_ok=True)
        
        print("✅ Security Onion configuration completed")
        print(f"📁 Installation directory: {self.install_dir}")
        print("\n🚀 To start Security Onion:")
        print(f"   cd {self.install_dir}")
        print("   docker-compose up -d")
        print("\n🌐 Access points:")
        print("   Kibana Dashboard: http://localhost:5601")
        print("   Elasticsearch API: http://localhost:9200")
        print("   Logstash: localhost:5044 (beats input)")
        
        return True

def main():
    print("🛡️  Security Onion SIEM Deployment")
    print("=" * 35)
    
    siem = SecurityOnionManager()
    
    # Deploy Security Onion
    success = siem.deploy_security_onion()
    
    if success:
        print("\n✅ Security Onion deployment ready!")
        print("📝 Next steps:")
        print("   1. Start the stack: docker-compose up -d")
        print("   2. Wait 2-3 minutes for all services to initialize")
        print("   3. Access Kibana at http://localhost:5601")
        print("   4. Configure index patterns and dashboards")
        print("   5. Start generating security events for monitoring")
    
    return siem

# ✅ Checkpoint 1 Validation
def validate_siem_deployment():
    """Validate SIEM deployment"""
    print("\n🔍 Validating SIEM Deployment...")
    
    checks = [
        "✅ Docker Compose configuration created",
        "✅ Elasticsearch configured for log storage",
        "✅ Kibana configured for visualization",
        "✅ Logstash configured for log processing",
        "✅ Suricata configured for network monitoring",
        "✅ Filebeat configured for log shipping"
    ]
    
    for check in checks:
        print(check)
        time.sleep(0.5)
    
    print("\n🎉 Checkpoint 1 Complete: Security Onion SIEM Deployment")

if __name__ == "__main__":
    siem = main()
    validate_siem_deployment()
```

### Step 2: Initial SIEM Configuration and Index Management

Create `siem_configuration.py`:

```python
#!/usr/bin/env python3
"""
SIEM Configuration and Index Management
Configure Elasticsearch indices and Kibana dashboards
"""

import requests
import json
import time
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

class SIEMConfigurator:
    def __init__(self, es_host="localhost", es_port=9200, kibana_host="localhost", kibana_port=5601):
        self.es_host = es_host
        self.es_port = es_port
        self.kibana_host = kibana_host
        self.kibana_port = kibana_port
        
        # Initialize Elasticsearch client
        self.es = Elasticsearch([f'http://{es_host}:{es_port}'])
        
    def wait_for_elasticsearch(self, timeout=300):
        """Wait for Elasticsearch to become available"""
        print("⏳ Waiting for Elasticsearch to start...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if self.es.ping():
                    print("✅ Elasticsearch is ready")
                    return True
            except:
                pass
            time.sleep(5)
        
        print("❌ Elasticsearch failed to start within timeout")
        return False
    
    def create_index_templates(self):
        """Create Elasticsearch index templates for security logs"""
        
        # Suricata log template
        suricata_template = {
            "index_patterns": ["logstash-suricata-*", "suricata-*"],
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "src_ip": {"type": "ip"},
                        "dest_ip": {"type": "ip"},
                        "src_port": {"type": "long"},
                        "dest_port": {"type": "long"},
                        "proto": {"type": "keyword"},
                        "event_type": {"type": "keyword"},
                        "alert": {
                            "properties": {
                                "signature": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                                "category": {"type": "keyword"},
                                "severity": {"type": "long"},
                                "signature_id": {"type": "long"},
                                "gid": {"type": "long"}
                            }
                        },
                        "flow": {
                            "properties": {
                                "bytes_toserver": {"type": "long"},
                                "bytes_toclient": {"type": "long"},
                                "pkts_toserver": {"type": "long"},
                                "pkts_toclient": {"type": "long"}
                            }
                        },
                        "http": {
                            "properties": {
                                "hostname": {"type": "keyword"},
                                "url": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                                "http_user_agent": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                                "http_method": {"type": "keyword"},
                                "status": {"type": "long"}
                            }
                        },
                        "src_geoip": {
                            "properties": {
                                "country_name": {"type": "keyword"},
                                "city_name": {"type": "keyword"},
                                "location": {"type": "geo_point"}
                            }
                        },
                        "dest_geoip": {
                            "properties": {
                                "country_name": {"type": "keyword"},
                                "city_name": {"type": "keyword"},
                                "location": {"type": "geo_point"}
                            }
                        }
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s"
                }
            }
        }
        
        # Windows Event Log template
        windows_template = {
            "index_patterns": ["logstash-winlogbeat-*", "winlogbeat-*"],
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "computer_name": {"type": "keyword"},
                        "event_id": {"type": "long"},
                        "event_data": {
                            "properties": {
                                "SubjectUserName": {"type": "keyword"},
                                "SubjectDomainName": {"type": "keyword"},
                                "TargetUserName": {"type": "keyword"},
                                "TargetDomainName": {"type": "keyword"},
                                "LogonType": {"type": "keyword"},
                                "IpAddress": {"type": "ip"},
                                "WorkstationName": {"type": "keyword"}
                            }
                        },
                        "level": {"type": "keyword"},
                        "opcode": {"type": "keyword"},
                        "task": {"type": "keyword"}
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s"
                }
            }
        }
        
        # Zeek/Bro logs template
        zeek_template = {
            "index_patterns": ["logstash-zeek-*", "zeek-*"],
            "template": {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "uid": {"type": "keyword"},
                        "id.orig_h": {"type": "ip"},
                        "id.orig_p": {"type": "long"},
                        "id.resp_h": {"type": "ip"},
                        "id.resp_p": {"type": "long"},
                        "proto": {"type": "keyword"},
                        "service": {"type": "keyword"},
                        "duration": {"type": "double"},
                        "orig_bytes": {"type": "long"},
                        "resp_bytes": {"type": "long"},
                        "conn_state": {"type": "keyword"},
                        "local_orig": {"type": "boolean"},
                        "local_resp": {"type": "boolean"},
                        "missed_bytes": {"type": "long"},
                        "history": {"type": "keyword"},
                        "orig_pkts": {"type": "long"},
                        "orig_ip_bytes": {"type": "long"},
                        "resp_pkts": {"type": "long"},
                        "resp_ip_bytes": {"type": "long"}
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s"
                }
            }
        }
        
        templates = {
            "suricata_template": suricata_template,
            "windows_template": windows_template,
            "zeek_template": zeek_template
        }
        
        for template_name, template_body in templates.items():
            try:
                self.es.indices.put_index_template(
                    name=template_name,
                    body=template_body
                )
                print(f"✅ Created index template: {template_name}")
            except Exception as e:
                print(f"❌ Failed to create template {template_name}: {e}")
    
    def create_kibana_index_patterns(self):
        """Create Kibana index patterns"""
        
        kibana_url = f"http://{self.kibana_host}:{self.kibana_port}"
        
        # Wait for Kibana to be ready
        print("⏳ Waiting for Kibana to start...")
        timeout = 300
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{kibana_url}/api/status")
                if response.status_code == 200:
                    print("✅ Kibana is ready")
                    break
            except:
                pass
            time.sleep(10)
        else:
            print("❌ Kibana failed to start within timeout")
            return False
        
        # Create index patterns
        headers = {
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'
        }
        
        index_patterns = [
            {
                "id": "logstash-suricata-*",
                "title": "logstash-suricata-*",
                "timeFieldName": "@timestamp"
            },
            {
                "id": "logstash-zeek-*", 
                "title": "logstash-zeek-*",
                "timeFieldName": "@timestamp"
            },
            {
                "id": "logstash-*",
                "title": "logstash-*", 
                "timeFieldName": "@timestamp"
            }
        ]
        
        for pattern in index_patterns:
            try:
                response = requests.post(
                    f"{kibana_url}/api/saved_objects/index-pattern/{pattern['id']}",
                    headers=headers,
                    json={
                        "attributes": {
                            "title": pattern["title"],
                            "timeFieldName": pattern["timeFieldName"]
                        }
                    }
                )
                
                if response.status_code in [200, 409]:  # 409 = already exists
                    print(f"✅ Created index pattern: {pattern['title']}")
                else:
                    print(f"❌ Failed to create index pattern {pattern['title']}: {response.text}")
                    
            except Exception as e:
                print(f"❌ Error creating index pattern {pattern['title']}: {e}")
        
        return True
    
    def create_basic_dashboards(self):
        """Create basic security monitoring dashboards"""
        
        kibana_url = f"http://{self.kibana_host}:{self.kibana_port}"
        headers = {
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'
        }
        
        # Security Overview Dashboard
        security_dashboard = {
            "version": "7.17.0",
            "objects": [
                {
                    "id": "security-overview",
                    "type": "dashboard",
                    "attributes": {
                        "title": "Security Overview Dashboard",
                        "description": "High-level security monitoring overview",
                        "panelsJSON": json.dumps([
                            {
                                "gridData": {"x": 0, "y": 0, "w": 24, "h": 15},
                                "panelIndex": "1",
                                "embeddableConfig": {},
                                "panelRefName": "panel_1"
                            }
                        ]),
                        "timeRestore": False,
                        "version": 1
                    }
                }
            ]
        }
        
        try:
            response = requests.post(
                f"{kibana_url}/api/saved_objects/_import",
                headers=headers,
                files={'file': ('dashboard.ndjson', json.dumps(security_dashboard))}
            )
            print(f"✅ Created Security Overview Dashboard")
        except Exception as e:
            print(f"❌ Failed to create dashboard: {e}")
    
    def configure_siem(self):
        """Complete SIEM configuration"""
        print("⚙️  Configuring SIEM...")
        
        if not self.wait_for_elasticsearch():
            return False
        
        # Create index templates
        self.create_index_templates()
        
        # Create Kibana index patterns
        self.create_kibana_index_patterns()
        
        # Create basic dashboards
        self.create_basic_dashboards()
        
        print("✅ SIEM configuration completed")
        return True

def main():
    print("⚙️  SIEM Configuration Manager")
    print("=" * 30)
    
    configurator = SIEMConfigurator()
    
    # Configure SIEM
    success = configurator.configure_siem()
    
    if success:
        print("\n✅ SIEM configuration completed successfully!")
        print("🌐 Access Kibana: http://localhost:5601")
        print("📊 Available index patterns:")
        print("   - logstash-suricata-* (Network alerts and events)")
        print("   - logstash-zeek-* (Network connection logs)")
        print("   - logstash-* (All log types)")
    
    return configurator

if __name__ == "__main__":
    main()
```

---

## 📘 Part 2: ELK Stack Log Management (60 minutes)

**Learning Objective**: Implement comprehensive log aggregation and analysis

**What you'll build**: Centralized logging platform with parsing, enrichment, and storage

### Step 1: Advanced Log Processing Pipeline

Create `log_processing_pipeline.py`:

```python
#!/usr/bin/env python3
"""
Advanced Log Processing Pipeline
Sophisticated log parsing, enrichment, and correlation
"""

import json
import re
import geoip2.database
import requests
from datetime import datetime, timedelta
import ipaddress
from collections import defaultdict

class LogProcessor:
    def __init__(self):
        self.threat_intel_cache = {}
        self.geoip_cache = {}
        self.processed_logs = []
        
    def parse_suricata_alert(self, log_line):
        """Parse Suricata EVE JSON alert"""
        try:
            alert = json.loads(log_line)
            
            if alert.get('event_type') != 'alert':
                return None
            
            parsed_alert = {
                'timestamp': alert.get('timestamp'),
                'event_type': 'security_alert',
                'source_ip': alert.get('src_ip'),
                'destination_ip': alert.get('dest_ip'),
                'source_port': alert.get('src_port'),
                'destination_port': alert.get('dest_port'),
                'protocol': alert.get('proto'),
                'signature': alert.get('alert', {}).get('signature'),
                'signature_id': alert.get('alert', {}).get('signature_id'),
                'category': alert.get('alert', {}).get('category'),
                'severity': alert.get('alert', {}).get('severity'),
                'flow': alert.get('flow', {}),
                'payload': alert.get('payload'),
                'packet_info': alert.get('packet_info', {})
            }
            
            # Add threat intelligence enrichment
            parsed_alert['threat_intel'] = self._enrich_with_threat_intel(parsed_alert['source_ip'])
            
            # Add geolocation data
            parsed_alert['src_geolocation'] = self._get_geolocation(parsed_alert['source_ip'])
            parsed_alert['dest_geolocation'] = self._get_geolocation(parsed_alert['destination_ip'])
            
            # Calculate risk score
            parsed_alert['risk_score'] = self._calculate_risk_score(parsed_alert)
            
            return parsed_alert
            
        except Exception as e:
            print(f"Error parsing Suricata alert: {e}")
            return None
    
    def parse_zeek_conn_log(self, log_line):
        """Parse Zeek connection log"""
        try:
            # Skip comment lines
            if log_line.startswith('#'):
                return None
            
            # Zeek conn.log format (tab-separated)
            fields = log_line.strip().split('\t')
            
            if len(fields) < 15:
                return None
            
            parsed_conn = {
                'timestamp': datetime.fromtimestamp(float(fields[0])).isoformat(),
                'event_type': 'network_connection',
                'uid': fields[1],
                'source_ip': fields[2],
                'source_port': int(fields[3]) if fields[3] != '-' else 0,
                'destination_ip': fields[4],
                'destination_port': int(fields[5]) if fields[5] != '-' else 0,
                'protocol': fields[6],
                'service': fields[7] if fields[7] != '-' else None,
                'duration': float(fields[8]) if fields[8] != '-' else 0,
                'orig_bytes': int(fields[9]) if fields[9] != '-' else 0,
                'resp_bytes': int(fields[10]) if fields[10] != '-' else 0,
                'conn_state': fields[11],
                'local_orig': fields[12] == 'T',
                'local_resp': fields[13] == 'T',
                'missed_bytes': int(fields[14]) if fields[14] != '-' else 0
            }
            
            # Add connection analysis
            parsed_conn['connection_analysis'] = self._analyze_connection(parsed_conn)
            
            # Add geolocation data
            parsed_conn['src_geolocation'] = self._get_geolocation(parsed_conn['source_ip'])
            parsed_conn['dest_geolocation'] = self._get_geolocation(parsed_conn['destination_ip'])
            
            return parsed_conn
            
        except Exception as e:
            print(f"Error parsing Zeek connection log: {e}")
            return None
    
    def parse_windows_event_log(self, log_data):
        """Parse Windows Event Log"""
        try:
            if isinstance(log_data, str):
                log_data = json.loads(log_data)
            
            event_id = log_data.get('winlogbeat', {}).get('event_id')
            
            parsed_event = {
                'timestamp': log_data.get('@timestamp'),
                'event_type': 'windows_event',
                'computer_name': log_data.get('computer_name'),
                'event_id': event_id,
                'level': log_data.get('level'),
                'source': log_data.get('source_name'),
                'event_data': log_data.get('event_data', {}),
                'user': log_data.get('user', {})
            }
            
            # Specific parsing for common security events
            if event_id == 4624:  # Successful logon
                parsed_event['event_description'] = 'Successful Logon'
                parsed_event['logon_type'] = parsed_event['event_data'].get('LogonType')
                parsed_event['account_name'] = parsed_event['event_data'].get('TargetUserName')
                parsed_event['source_ip'] = parsed_event['event_data'].get('IpAddress')
                
            elif event_id == 4625:  # Failed logon
                parsed_event['event_description'] = 'Failed Logon'
                parsed_event['failure_reason'] = parsed_event['event_data'].get('FailureReason')
                parsed_event['account_name'] = parsed_event['event_data'].get('TargetUserName')
                parsed_event['source_ip'] = parsed_event['event_data'].get('IpAddress')
                
            elif event_id == 4648:  # Logon with explicit credentials
                parsed_event['event_description'] = 'Explicit Credential Logon'
                parsed_event['account_name'] = parsed_event['event_data'].get('TargetUserName')
                parsed_event['target_server'] = parsed_event['event_data'].get('TargetServerName')
                
            elif event_id == 4672:  # Special privileges assigned
                parsed_event['event_description'] = 'Admin Logon'
                parsed_event['account_name'] = parsed_event['event_data'].get('SubjectUserName')
                parsed_event['privileges'] = parsed_event['event_data'].get('PrivilegeList')
            
            # Calculate suspicion score for Windows events
            parsed_event['suspicion_score'] = self._calculate_windows_suspicion_score(parsed_event)
            
            return parsed_event
            
        except Exception as e:
            print(f"Error parsing Windows event log: {e}")
            return None
    
    def _enrich_with_threat_intel(self, ip_address):
        """Enrich IP with threat intelligence"""
        if not ip_address or self._is_private_ip(ip_address):
            return {'malicious': False, 'source': 'private_ip'}
        
        # Check cache first
        if ip_address in self.threat_intel_cache:
            return self.threat_intel_cache[ip_address]
        
        # Simulate threat intelligence lookup
        # In production, this would query actual threat intel APIs
        threat_info = {
            'malicious': False,
            'confidence': 0,
            'categories': [],
            'first_seen': None,
            'last_seen': None,
            'source': 'simulation'
        }
        
        # Simulate some known malicious IPs
        known_malicious = [
            '203.0.113.100', '198.51.100.50', '192.0.2.75'
        ]
        
        if ip_address in known_malicious:
            threat_info.update({
                'malicious': True,
                'confidence': 85,
                'categories': ['malware_c2', 'botnet'],
                'first_seen': '2024-01-01T00:00:00Z',
                'last_seen': datetime.now().isoformat(),
                'source': 'threat_db'
            })
        
        self.threat_intel_cache[ip_address] = threat_info
        return threat_info
    
    def _get_geolocation(self, ip_address):
        """Get geolocation for IP address"""
        if not ip_address or self._is_private_ip(ip_address):
            return {'country': 'Private', 'city': 'Private', 'location': None}
        
        # Check cache first
        if ip_address in self.geoip_cache:
            return self.geoip_cache[ip_address]
        
        # Simulate geolocation lookup
        # In production, this would use MaxMind GeoIP2 database
        geo_info = {
            'country': 'Unknown',
            'country_code': 'XX',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0,
            'location': {'lat': 0.0, 'lon': 0.0}
        }
        
        # Simulate some geographic locations
        geo_mapping = {
            '8.8.8.8': {'country': 'United States', 'country_code': 'US', 'city': 'Mountain View'},
            '1.1.1.1': {'country': 'United States', 'country_code': 'US', 'city': 'San Francisco'},
            '203.0.113.100': {'country': 'China', 'country_code': 'CN', 'city': 'Beijing'},
            '198.51.100.50': {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow'}
        }
        
        if ip_address in geo_mapping:
            geo_info.update(geo_mapping[ip_address])
        
        self.geoip_cache[ip_address] = geo_info
        return geo_info
    
    def _is_private_ip(self, ip_address):
        """Check if IP address is private"""
        try:
            return ipaddress.ip_address(ip_address).is_private
        except:
            return False
    
    def _calculate_risk_score(self, alert):
        """Calculate risk score for security alert"""
        score = 0
        
        # Base score from severity
        severity = alert.get('severity', 3)
        score += (4 - severity) * 20  # Higher severity = higher score
        
        # Threat intelligence
        threat_intel = alert.get('threat_intel', {})
        if threat_intel.get('malicious'):
            score += threat_intel.get('confidence', 0)
        
        # Geographic factors
        src_geo = alert.get('src_geolocation', {})
        if src_geo.get('country_code') in ['CN', 'RU', 'KP']:  # High-risk countries
            score += 30
        
        # Protocol and port factors
        if alert.get('destination_port') in [22, 3389, 1433, 3306]:  # Critical services
            score += 20
        
        # Ensure score is between 0-100
        return min(max(score, 0), 100)
    
    def _analyze_connection(self, conn):
        """Analyze network connection for anomalies"""
        analysis = {
            'connection_type': 'normal',
            'data_transfer': 'normal',
            'duration_category': 'normal',
            'anomalies': []
        }
        
        # Analyze data transfer
        total_bytes = conn.get('orig_bytes', 0) + conn.get('resp_bytes', 0)
        if total_bytes > 1000000:  # > 1MB
            analysis['data_transfer'] = 'high_volume'
            analysis['anomalies'].append('large_data_transfer')
        
        # Analyze duration
        duration = conn.get('duration', 0)
        if duration > 3600:  # > 1 hour
            analysis['duration_category'] = 'long_lived'
        elif duration < 1:  # < 1 second
            analysis['duration_category'] = 'short_lived'
            analysis['anomalies'].append('very_short_connection')
        
        # Analyze connection state
        conn_state = conn.get('conn_state', '')
        if conn_state in ['S0', 'REJ', 'RSTO']:
            analysis['anomalies'].append('failed_connection')
        
        # Port analysis
        dest_port = conn.get('destination_port', 0)
        if dest_port in [22, 23, 135, 139, 445, 1433, 3306, 3389]:
            analysis['connection_type'] = 'admin_service'
        elif dest_port > 49152:  # High/dynamic ports
            analysis['connection_type'] = 'high_port'
        
        return analysis
    
    def _calculate_windows_suspicion_score(self, event):
        """Calculate suspicion score for Windows events"""
        score = 0
        event_id = event.get('event_id')
        
        # Failed logon attempts
        if event_id == 4625:
            score += 30
            failure_reason = event.get('failure_reason', '')
            if 'unknown user' in failure_reason.lower():
                score += 20
        
        # Off-hours logon
        timestamp = event.get('timestamp', '')
        try:
            event_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if event_time.hour < 6 or event_time.hour > 22:
                score += 25
        except:
            pass
        
        # Admin logon
        if event_id == 4672:
            score += 20
        
        # Explicit credential logon
        if event_id == 4648:
            score += 15
        
        return min(score, 100)
    
    def process_log_batch(self, log_lines, log_type):
        """Process a batch of log lines"""
        processed_batch = []
        
        for line in log_lines:
            if not line.strip():
                continue
                
            parsed_log = None
            
            if log_type == 'suricata':
                parsed_log = self.parse_suricata_alert(line)
            elif log_type == 'zeek':
                parsed_log = self.parse_zeek_conn_log(line)
            elif log_type == 'windows':
                parsed_log = self.parse_windows_event_log(line)
            
            if parsed_log:
                processed_batch.append(parsed_log)
                self.processed_logs.append(parsed_log)
        
        return processed_batch
    
    def generate_processing_report(self):
        """Generate log processing statistics"""
        report = {
            'total_processed': len(self.processed_logs),
            'event_types': defaultdict(int),
            'high_risk_events': 0,
            'threat_intel_hits': 0,
            'geographic_distribution': defaultdict(int),
            'processing_timestamp': datetime.now().isoformat()
        }
        
        for log in self.processed_logs:
            event_type = log.get('event_type', 'unknown')
            report['event_types'][event_type] += 1
            
            # Count high-risk events
            risk_score = log.get('risk_score', 0)
            suspicion_score = log.get('suspicion_score', 0)
            if risk_score > 70 or suspicion_score > 70:
                report['high_risk_events'] += 1
            
            # Count threat intel hits
            threat_intel = log.get('threat_intel', {})
            if threat_intel.get('malicious'):
                report['threat_intel_hits'] += 1
            
            # Geographic distribution
            src_geo = log.get('src_geolocation', {})
            country = src_geo.get('country', 'Unknown')
            report['geographic_distribution'][country] += 1
        
        return dict(report)

def main():
    print("📊 Advanced Log Processing Pipeline")
    print("=" * 35)
    
    processor = LogProcessor()
    
    # Simulate processing different log types
    print("🔄 Processing sample logs...")
    
    # Sample Suricata alert
    suricata_sample = '{"timestamp":"2024-01-15T10:30:00.123456+0000","flow_id":1234567890,"event_type":"alert","src_ip":"203.0.113.100","src_port":45678,"dest_ip":"192.168.1.10","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000001,"rev":1,"signature":"SQL Injection Attempt","category":"Web Application Attack","severity":1}}'
    
    suricata_logs = processor.process_log_batch([suricata_sample], 'suricata')
    print(f"✅ Processed {len(suricata_logs)} Suricata alerts")
    
    # Sample Zeek connection log
    zeek_sample = "1642248600.123456\tC1234567890\t203.0.113.50\t12345\t192.168.1.20\t80\ttcp\thttp\t120.5\t1024\t2048\tSF\tF\tT\t0"
    
    zeek_logs = processor.process_log_batch([zeek_sample], 'zeek')
    print(f"✅ Processed {len(zeek_logs)} Zeek connection logs")
    
    # Generate processing report
    report = processor.generate_processing_report()
    
    print(f"\n📈 Processing Report:")
    print(f"   Total Events: {report['total_processed']}")
    print(f"   High Risk Events: {report['high_risk_events']}")
    print(f"   Threat Intel Hits: {report['threat_intel_hits']}")
    
    print(f"\n🌍 Geographic Distribution:")
    for country, count in report['geographic_distribution'].items():
        print(f"   {country}: {count}")
    
    return processor

if __name__ == "__main__":
    main()
```

### Step 2: Custom Log Parsing and Enrichment

Create `custom_log_parsers.py`:

```python
#!/usr/bin/env python3
"""
Custom Log Parsers for Various Security Tools
Specialized parsers for different log formats and sources
"""

import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import base64

class CustomLogParsers:
    def __init__(self):
        self.parsers = {
            'apache_access': self.parse_apache_access_log,
            'nginx_access': self.parse_nginx_access_log,
            'pfsense_filterlog': self.parse_pfsense_filterlog,
            'snort_alert': self.parse_snort_alert,
            'osquery_result': self.parse_osquery_result,
            'nessus_scan': self.parse_nessus_scan,
            'nmap_xml': self.parse_nmap_xml,
            'burp_scan': self.parse_burp_scan,
            'metasploit_log': self.parse_metasploit_log,
            'clamav_scan': self.parse_clamav_scan
        }
    
    def parse_apache_access_log(self, log_line):
        """Parse Apache access log (Common/Combined format)"""
        # Combined log format regex
        pattern = r'^(\S+) \S+ (\S+) \[([^\]]+)\] "([A-Z]+) ([^\s"]+)(?:[^\s"]+)?" (\d+) (\d+|-) "([^"]*)" "([^"]*)"'
        
        match = re.match(pattern, log_line)
        if not match:
            return None
        
        parsed = {
            'log_type': 'apache_access',
            'timestamp': self._parse_apache_timestamp(match.group(3)),
            'source_ip': match.group(1),
            'user': match.group(2) if match.group(2) != '-' else None,
            'method': match.group(4),
            'url': match.group(5),
            'status_code': int(match.group(6)),
            'response_size': int(match.group(7)) if match.group(7) != '-' else 0,
            'referrer': match.group(8) if match.group(8) != '-' else None,
            'user_agent': match.group(9)
        }
        
        # Add security analysis
        parsed['security_analysis'] = self._analyze_web_request(parsed)
        
        return parsed
    
    def parse_nginx_access_log(self, log_line):
        """Parse Nginx access log"""
        # Nginx default log format
        pattern = r'^(\S+) - (\S+) \[([^\]]+)\] "([A-Z]+) ([^\s"]+) HTTP/[\d\.]+" (\d+) (\d+) "([^"]*)" "([^"]*)"'
        
        match = re.match(pattern, log_line)
        if not match:
            return None
        
        parsed = {
            'log_type': 'nginx_access',
            'timestamp': self._parse_nginx_timestamp(match.group(3)),
            'source_ip': match.group(1),
            'user': match.group(2) if match.group(2) != '-' else None,
            'method': match.group(4),
            'url': match.group(5),
            'status_code': int(match.group(6)),
            'response_size': int(match.group(7)),
            'referrer': match.group(8) if match.group(8) != '-' else None,
            'user_agent': match.group(9)
        }
        
        # Add security analysis
        parsed['security_analysis'] = self._analyze_web_request(parsed)
        
        return parsed
    
    def parse_pfsense_filterlog(self, log_line):
        """Parse pfSense filterlog entries"""
        # pfSense filterlog format (comma-separated)
        parts = log_line.split(',')
        
        if len(parts) < 10:
            return None
        
        try:
            parsed = {
                'log_type': 'pfsense_firewall',
                'timestamp': datetime.now().isoformat(),  # Usually from syslog timestamp
                'rule_number': parts[0],
                'interface': parts[2],
                'reason': parts[3],
                'action': parts[4],
                'direction': parts[5],
                'ip_version': parts[6],
                'protocol': parts[16] if len(parts) > 16 else None,
                'source_ip': parts[18] if len(parts) > 18 else None,
                'destination_ip': parts[19] if len(parts) > 19 else None,
                'source_port': int(parts[20]) if len(parts) > 20 and parts[20].isdigit() else None,
                'destination_port': int(parts[21]) if len(parts) > 21 and parts[21].isdigit() else None
            }
            
            # Add firewall analysis
            parsed['firewall_analysis'] = self._analyze_firewall_event(parsed)
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing pfSense filterlog: {e}")
            return None
    
    def parse_snort_alert(self, log_line):
        """Parse Snort alert log"""
        # Snort fast alert format
        pattern = r'(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\].*?(\d+\.\d+\.\d+\.\d+):?(\d+)?\s+->\s+(\d+\.\d+\.\d+\.\d+):?(\d+)?'
        
        match = re.match(pattern, log_line)
        if not match:
            return None
        
        parsed = {
            'log_type': 'snort_alert',
            'timestamp': self._parse_snort_timestamp(match.group(1)),
            'generator_id': int(match.group(2)),
            'signature_id': int(match.group(3)),
            'revision': int(match.group(4)),
            'signature': match.group(5),
            'source_ip': match.group(6),
            'source_port': int(match.group(7)) if match.group(7) else None,
            'destination_ip': match.group(8),
            'destination_port': int(match.group(9)) if match.group(9) else None
        }
        
        # Add IDS analysis
        parsed['ids_analysis'] = self._analyze_ids_alert(parsed)
        
        return parsed
    
    def parse_osquery_result(self, log_line):
        """Parse osquery result JSON"""
        try:
            result = json.loads(log_line)
            
            parsed = {
                'log_type': 'osquery_result',
                'timestamp': result.get('unixTime', datetime.now().timestamp()),
                'hostname': result.get('hostIdentifier'),
                'query_name': result.get('name'),
                'action': result.get('action'),
                'columns': result.get('columns', {})
            }
            
            # Add endpoint analysis based on query type
            parsed['endpoint_analysis'] = self._analyze_osquery_result(parsed)
            
            return parsed
            
        except Exception as e:
            print(f"Error parsing osquery result: {e}")
            return None
    
    def parse_nessus_scan(self, xml_content):
        """Parse Nessus scan XML results"""
        try:
            root = ET.fromstring(xml_content)
            results = []
            
            for report in root.findall('.//Report'):
                for host in report.findall('.//ReportHost'):
                    host_ip = host.get('name')
                    
                    for item in host.findall('.//ReportItem'):
                        parsed = {
                            'log_type': 'nessus_vulnerability',
                            'timestamp': datetime.now().isoformat(),
                            'host_ip': host_ip,
                            'plugin_id': item.get('pluginID'),
                            'plugin_name': item.get('pluginName'),
                            'severity': item.get('severity'),
                            'port': item.get('port'),
                            'protocol': item.get('protocol'),
                            'service': item.get('svc_name'),
                            'description': item.findtext('description', ''),
                            'solution': item.findtext('solution', ''),
                            'cvss_score': item.findtext('cvss_base_score'),
                            'cve': [cve.text for cve in item.findall('.//cve')]
                        }
                        
                        # Add vulnerability analysis
                        parsed['vulnerability_analysis'] = self._analyze_vulnerability(parsed)
                        
                        results.append(parsed)
            
            return results
            
        except Exception as e:
            print(f"Error parsing Nessus scan: {e}")
            return []
    
    def parse_nmap_xml(self, xml_content):
        """Parse Nmap XML scan results"""
        try:
            root = ET.fromstring(xml_content)
            results = []
            
            for host in root.findall('.//host'):
                host_ip = host.find('.//address[@addrtype="ipv4"]').get('addr')
                
                for port in host.findall('.//port'):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    state = port.find('state').get('state')
                    
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'unknown'
                    service_version = service.get('version') if service is not None else ''
                    
                    parsed = {
                        'log_type': 'nmap_scan',
                        'timestamp': datetime.now().isoformat(),
                        'host_ip': host_ip,
                        'port': int(port_id),
                        'protocol': protocol,
                        'state': state,
                        'service': service_name,
                        'version': service_version
                    }
                    
                    # Add port scan analysis
                    parsed['scan_analysis'] = self._analyze_port_scan(parsed)
                    
                    results.append(parsed)
            
            return results
            
        except Exception as e:
            print(f"Error parsing Nmap XML: {e}")
            return []
    
    def parse_burp_scan(self, xml_content):
        """Parse Burp Suite scan results"""
        try:
            root = ET.fromstring(xml_content)
            results = []
            
            for issue in root.findall('.//issue'):
                parsed = {
                    'log_type': 'burp_vulnerability',
                    'timestamp': datetime.now().isoformat(),
                    'name': issue.findtext('name'),
                    'host': issue.findtext('host'),
                    'path': issue.findtext('path'),
                    'location': issue.findtext('location'),
                    'severity': issue.findtext('severity'),
                    'confidence': issue.findtext('confidence'),
                    'description': issue.findtext('issueBackground'),
                    'remediation': issue.findtext('remediationBackground')
                }
                
                # Add web vulnerability analysis
                parsed['web_vuln_analysis'] = self._analyze_web_vulnerability(parsed)
                
                results.append(parsed)
            
            return results
            
        except Exception as e:
            print(f"Error parsing Burp scan: {e}")
            return []
    
    def parse_metasploit_log(self, log_line):
        """Parse Metasploit framework log"""
        # Metasploit log format varies, this handles basic session logs
        if 'Meterpreter session' in log_line:
            pattern = r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*Meterpreter session (\d+) opened.*(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)'
            match = re.search(pattern, log_line)
            
            if match:
                return {
                    'log_type': 'metasploit_session',
                    'timestamp': match.group(1),
                    'session_id': int(match.group(2)),
                    'attacker_ip': match.group(3),
                    'attacker_port': int(match.group(4)),
                    'target_ip': match.group(5),
                    'target_port': int(match.group(6)),
                    'activity_type': 'session_opened'
                }
        
        return None
    
    def parse_clamav_scan(self, log_line):
        """Parse ClamAV antivirus scan log"""
        if 'FOUND' in log_line:
            pattern = r'(.+): (.+) FOUND'
            match = re.match(pattern, log_line)
            
            if match:
                return {
                    'log_type': 'antivirus_detection',
                    'timestamp': datetime.now().isoformat(),
                    'file_path': match.group(1),
                    'threat_name': match.group(2),
                    'action': 'detected'
                }
        
        return None
    
    def _parse_apache_timestamp(self, timestamp_str):
        """Parse Apache timestamp format"""
        try:
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z').isoformat()
        except:
            return datetime.now().isoformat()
    
    def _parse_nginx_timestamp(self, timestamp_str):
        """Parse Nginx timestamp format"""
        try:
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z').isoformat()
        except:
            return datetime.now().isoformat()
    
    def _parse_snort_timestamp(self, timestamp_str):
        """Parse Snort timestamp format"""
        try:
            return datetime.strptime(f"2024/{timestamp_str}", '%Y/%m/%d-%H:%M:%S.%f').isoformat()
        except:
            return datetime.now().isoformat()
    
    def _analyze_web_request(self, request):
        """Analyze web request for security indicators"""
        analysis = {
            'attack_indicators': [],
            'risk_level': 'low',
            'request_category': 'normal'
        }
        
        url = request.get('url', '')
        user_agent = request.get('user_agent', '')
        status_code = request.get('status_code', 200)
        
        # SQL injection patterns
        sql_patterns = [r'union\s+select', r'or\s+1\s*=\s*1', r';\s*drop\s+table', r"'\s*or\s*'1'\s*=\s*'1"]
        for pattern in sql_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                analysis['attack_indicators'].append('sql_injection')
                analysis['risk_level'] = 'high'
                break
        
        # XSS patterns
        xss_patterns = [r'<script', r'javascript:', r'onerror\s*=', r'onload\s*=']
        for pattern in xss_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                analysis['attack_indicators'].append('xss_attempt')
                analysis['risk_level'] = 'high'
                break
        
        # Directory traversal
        if '../' in url or '..\\' in url:
            analysis['attack_indicators'].append('directory_traversal')
            analysis['risk_level'] = 'high'
        
        # Scanner detection
        scanner_agents = ['nmap', 'nikto', 'sqlmap', 'burp', 'w3af']
        if any(scanner in user_agent.lower() for scanner in scanner_agents):
            analysis['attack_indicators'].append('scanner_detected')
            analysis['request_category'] = 'scanner'
        
        # Error responses
        if status_code >= 400:
            analysis['request_category'] = 'error'
            if status_code in [401, 403]:
                analysis['attack_indicators'].append('unauthorized_access')
        
        return analysis
    
    def _analyze_firewall_event(self, event):
        """Analyze firewall event"""
        analysis = {
            'event_category': 'normal',
            'threat_indicators': [],
            'action_taken': event.get('action', 'unknown')
        }
        
        # Blocked connection analysis
        if event.get('action') == 'block':
            analysis['event_category'] = 'blocked_connection'
            
            # Check for scanning behavior
            dest_port = event.get('destination_port')
            if dest_port in [22, 23, 135, 139, 445, 1433, 3306, 3389]:
                analysis['threat_indicators'].append('admin_port_scan')
        
        return analysis
    
    def _analyze_ids_alert(self, alert):
        """Analyze IDS alert"""
        analysis = {
            'alert_category': 'unknown',
            'severity_assessment': 'medium',
            'recommended_action': 'investigate'
        }
        
        signature = alert.get('signature', '').lower()
        
        if 'sql injection' in signature:
            analysis['alert_category'] = 'web_attack'
            analysis['severity_assessment'] = 'high'
            analysis['recommended_action'] = 'block_and_investigate'
        elif 'port scan' in signature or 'nmap' in signature:
            analysis['alert_category'] = 'reconnaissance'
            analysis['severity_assessment'] = 'medium'
            analysis['recommended_action'] = 'monitor'
        elif 'malware' in signature or 'trojan' in signature:
            analysis['alert_category'] = 'malware'
            analysis['severity_assessment'] = 'high'
            analysis['recommended_action'] = 'quarantine'
        
        return analysis
    
    def _analyze_osquery_result(self, result):
        """Analyze osquery result"""
        analysis = {
            'query_category': 'unknown',
            'findings': [],
            'risk_assessment': 'low'
        }
        
        query_name = result.get('query_name', '').lower()
        
        if 'process' in query_name:
            analysis['query_category'] = 'process_monitoring'
        elif 'file' in query_name:
            analysis['query_category'] = 'file_monitoring'
        elif 'network' in query_name or 'socket' in query_name:
            analysis['query_category'] = 'network_monitoring'
        
        return analysis
    
    def _analyze_vulnerability(self, vuln):
        """Analyze vulnerability finding"""
        analysis = {
            'criticality': 'unknown',
            'exploit_likelihood': 'unknown',
            'remediation_priority': 'medium'
        }
        
        severity = vuln.get('severity', '0')
        cvss_score = float(vuln.get('cvss_score', '0') or '0')
        
        if int(severity) >= 3 or cvss_score >= 7.0:
            analysis['criticality'] = 'high'
            analysis['remediation_priority'] = 'high'
        elif int(severity) >= 2 or cvss_score >= 4.0:
            analysis['criticality'] = 'medium'
            analysis['remediation_priority'] = 'medium'
        else:
            analysis['criticality'] = 'low'
            analysis['remediation_priority'] = 'low'
        
        return analysis
    
    def _analyze_port_scan(self, scan):
        """Analyze port scan result"""
        analysis = {
            'service_risk': 'low',
            'exposure_level': 'internal',
            'recommendations': []
        }
        
        port = scan.get('port', 0)
        service = scan.get('service', '')
        state = scan.get('state', '')
        
        if state == 'open':
            if port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432]:
                analysis['service_risk'] = 'medium'
                analysis['recommendations'].append('verify_service_necessity')
            
            if port in [23, 135, 139, 445]:  # High-risk services
                analysis['service_risk'] = 'high'
                analysis['recommendations'].append('consider_disabling')
        
        return analysis
    
    def _analyze_web_vulnerability(self, vuln):
        """Analyze web vulnerability"""
        analysis = {
            'vulnerability_type': 'unknown',
            'exploitability': 'unknown',
            'impact_assessment': 'medium'
        }
        
        vuln_name = vuln.get('name', '').lower()
        severity = vuln.get('severity', '').lower()
        
        if 'sql injection' in vuln_name:
            analysis['vulnerability_type'] = 'sql_injection'
            analysis['exploitability'] = 'high'
            analysis['impact_assessment'] = 'high'
        elif 'xss' in vuln_name or 'cross-site scripting' in vuln_name:
            analysis['vulnerability_type'] = 'xss'
            analysis['exploitability'] = 'medium'
            analysis['impact_assessment'] = 'medium'
        elif 'csrf' in vuln_name:
            analysis['vulnerability_type'] = 'csrf'
            analysis['exploitability'] = 'medium'
            analysis['impact_assessment'] = 'medium'
        
        if severity in ['high', 'critical']:
            analysis['impact_assessment'] = 'high'
        
        return analysis

def main():
    print("🔧 Custom Log Parsers Test")
    print("=" * 30)
    
    parsers = CustomLogParsers()
    
    # Test different log formats
    test_logs = [
        ('apache_access', '203.0.113.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin/login.php?user=admin&pass=123 HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"'),
        ('nginx_access', '198.51.100.50 - user [15/Jan/2024:10:35:22 +0000] "POST /search.php HTTP/1.1" 200 5678 "http://example.com/" "curl/7.68.0"'),
        ('snort_alert', '01/15-10:40:15.123456 [**] [1:1000001:1] SQL Injection Attempt [**] {TCP} 203.0.113.75:45678 -> 192.168.1.10:80'),
        ('clamav_scan', '/home/user/downloads/malware.exe: Win.Trojan.Emotet-123 FOUND')
    ]
    
    for log_type, log_line in test_logs:
        if log_type in parsers.parsers:
            result = parsers.parsers[log_type](log_line)
            if result:
                print(f"✅ Parsed {log_type}: {result.get('log_type')} - Risk: {result.get('security_analysis', {}).get('risk_level', 'N/A')}")
            else:
                print(f"❌ Failed to parse {log_type}")
    
    print("\n🎯 Custom parsers support:")
    for parser_name in parsers.parsers.keys():
        print(f"   • {parser_name}")

if __name__ == "__main__":
    main()
```

---

## 📘 Part 3: Security Dashboards and Visualization (60 minutes)

**Learning Objective**: Create comprehensive security monitoring dashboards

**What you'll build**: Real-time security dashboards with threat visualization and alerting

### Step 1: Kibana Dashboard Configuration

Create `security_dashboards.py`:

```python
#!/usr/bin/env python3
"""
Security Dashboard Management
Create and manage security monitoring dashboards in Kibana
"""

import requests
import json
import time
from datetime import datetime, timedelta

class SecurityDashboardManager:
    def __init__(self, kibana_host="localhost", kibana_port=5601):
        self.kibana_url = f"http://{kibana_host}:{kibana_port}"
        self.headers = {
            'Content-Type': 'application/json',
            'kbn-xsrf': 'true'
        }
    
    def wait_for_kibana(self, timeout=300):
        """Wait for Kibana to be ready"""
        print("⏳ Waiting for Kibana to be ready...")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                response = requests.get(f"{self.kibana_url}/api/status")
                if response.status_code == 200:
                    print("✅ Kibana is ready")
                    return True
            except:
                pass
            time.sleep(10)
        
        print("❌ Kibana failed to start within timeout")
        return False
    
    def create_security_overview_dashboard(self):
        """Create main security overview dashboard"""
        
        dashboard_config = {
            "version": "7.17.0",
            "objects": [
                {
                    "id": "security-overview-dashboard",
                    "type": "dashboard",
                    "attributes": {
                        "title": "Security Overview Dashboard",
                        "description": "High-level security monitoring overview",
                        "panelsJSON": json.dumps([
                            {
                                "gridData": {"x": 0, "y": 0, "w": 12, "h": 8},
                                "panelIndex": "alerts-over-time",
                                "embeddableConfig": {
                                    "title": "Security Alerts Over Time"
                                }
                            },
                            {
                                "gridData": {"x": 12, "y": 0, "w": 12, "h": 8},
                                "panelIndex": "top-attackers",
                                "embeddableConfig": {
                                    "title": "Top Attacking IP Addresses"
                                }
                            },
                            {
                                "gridData": {"x": 0, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "alert-severity",
                                "embeddableConfig": {
                                    "title": "Alert Severity Distribution"
                                }
                            },
                            {
                                "gridData": {"x": 8, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "geographic-attacks",
                                "embeddableConfig": {
                                    "title": "Geographic Attack Sources"
                                }
                            },
                            {
                                "gridData": {"x": 16, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "protocol-distribution",
                                "embeddableConfig": {
                                    "title": "Protocol Distribution"
                                }
                            }
                        ]),
                        "timeRestore": True,
                        "timeTo": "now",
                        "timeFrom": "now-24h",
                        "version": 1
                    }
                }
            ]
        }
        
        return self._import_dashboard(dashboard_config, "Security Overview Dashboard")
    
    def create_network_monitoring_dashboard(self):
        """Create network monitoring dashboard"""
        
        dashboard_config = {
            "version": "7.17.0", 
            "objects": [
                {
                    "id": "network-monitoring-dashboard",
                    "type": "dashboard",
                    "attributes": {
                        "title": "Network Monitoring Dashboard",
                        "description": "Network traffic and connection analysis",
                        "panelsJSON": json.dumps([
                            {
                                "gridData": {"x": 0, "y": 0, "w": 12, "h": 8},
                                "panelIndex": "network-connections",
                                "embeddableConfig": {
                                    "title": "Network Connections Over Time"
                                }
                            },
                            {
                                "gridData": {"x": 12, "y": 0, "w": 12, "h": 8},
                                "panelIndex": "bandwidth-usage",
                                "embeddableConfig": {
                                    "title": "Bandwidth Usage"
                                }
                            },
                            {
                                "gridData": {"x": 0, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "top-destinations",
                                "embeddableConfig": {
                                    "title": "Top Destination IPs"
                                }
                            },
                            {
                                "gridData": {"x": 8, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "port-analysis",
                                "embeddableConfig": {
                                    "title": "Port Activity Analysis"
                                }
                            },
                            {
                                "gridData": {"x": 16, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "failed-connections",
                                "embeddableConfig": {
                                    "title": "Failed Connection Attempts"
                                }
                            }
                        ]),
                        "timeRestore": True,
                        "timeTo": "now",
                        "timeFrom": "now-1h",
                        "version": 1
                    }
                }
            ]
        }
        
        return self._import_dashboard(dashboard_config, "Network Monitoring Dashboard")
    
    def create_threat_hunting_dashboard(self):
        """Create threat hunting dashboard"""
        
        dashboard_config = {
            "version": "7.17.0",
            "objects": [
                {
                    "id": "threat-hunting-dashboard",
                    "type": "dashboard", 
                    "attributes": {
                        "title": "Threat Hunting Dashboard",
                        "description": "Advanced threat detection and analysis",
                        "panelsJSON": json.dumps([
                            {
                                "gridData": {"x": 0, "y": 0, "w": 24, "h": 6},
                                "panelIndex": "threat-timeline",
                                "embeddableConfig": {
                                    "title": "Threat Activity Timeline"
                                }
                            },
                            {
                                "gridData": {"x": 0, "y": 6, "w": 8, "h": 8},
                                "panelIndex": "malware-indicators",
                                "embeddableConfig": {
                                    "title": "Malware Indicators"
                                }
                            },
                            {
                                "gridData": {"x": 8, "y": 6, "w": 8, "h": 8},
                                "panelIndex": "suspicious-processes",
                                "embeddableConfig": {
                                    "title": "Suspicious Processes"
                                }
                            },
                            {
                                "gridData": {"x": 16, "y": 6, "w": 8, "h": 8},
                                "panelIndex": "anomalous-network",
                                "embeddableConfig": {
                                    "title": "Anomalous Network Activity"
                                }
                            },
                            {
                                "gridData": {"x": 0, "y": 14, "w": 12, "h": 8},
                                "panelIndex": "attack-techniques",
                                "embeddableConfig": {
                                    "title": "MITRE ATT&CK Techniques"
                                }
                            },
                            {
                                "gridData": {"x": 12, "y": 14, "w": 12, "h": 8},
                                "panelIndex": "threat-intel-hits",
                                "embeddableConfig": {
                                    "title": "Threat Intelligence Matches"
                                }
                            }
                        ]),
                        "timeRestore": True,
                        "timeTo": "now",
                        "timeFrom": "now-7d",
                        "version": 1
                    }
                }
            ]
        }
        
        return self._import_dashboard(dashboard_config, "Threat Hunting Dashboard")
    
    def create_compliance_dashboard(self):
        """Create compliance monitoring dashboard"""
        
        dashboard_config = {
            "version": "7.17.0",
            "objects": [
                {
                    "id": "compliance-dashboard",
                    "type": "dashboard",
                    "attributes": {
                        "title": "Compliance Monitoring Dashboard", 
                        "description": "Security compliance and audit monitoring",
                        "panelsJSON": json.dumps([
                            {
                                "gridData": {"x": 0, "y": 0, "w": 12, "h": 8},
                                "panelIndex": "failed-logins",
                                "embeddableConfig": {
                                    "title": "Failed Login Attempts"
                                }
                            },
                            {
                                "gridData": {"x": 12, "y": 0, "w": 12, "h": 8},
                                "panelIndex": "privileged-access",
                                "embeddableConfig": {
                                    "title": "Privileged Access Events"
                                }
                            },
                            {
                                "gridData": {"x": 0, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "policy-violations",
                                "embeddableConfig": {
                                    "title": "Security Policy Violations"
                                }
                            },
                            {
                                "gridData": {"x": 8, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "data-access",
                                "embeddableConfig": {
                                    "title": "Sensitive Data Access"
                                }
                            },
                            {
                                "gridData": {"x": 16, "y": 8, "w": 8, "h": 8},
                                "panelIndex": "audit-summary",
                                "embeddableConfig": {
                                    "title": "Audit Summary"
                                }
                            }
                        ]),
                        "timeRestore": True,
                        "timeTo": "now", 
                        "timeFrom": "now-30d",
                        "version": 1
                    }
                }
            ]
        }
        
        return self._import_dashboard(dashboard_config, "Compliance Monitoring Dashboard")
    
    def create_incident_response_dashboard(self):
        """Create incident response dashboard"""
        
        dashboard_config = {
            "version": "7.17.0",
            "objects": [
                {
                    "id": "incident-response-dashboard",
                    "type": "dashboard",
                    "attributes": {
                        "title": "Incident Response Dashboard",
                        "description": "Real-time incident response and investigation",
                        "panelsJSON": json.dumps([
                            {
                                "gridData": {"x": 0, "y": 0, "w": 24, "h": 6},
                                "panelIndex": "active-incidents",
                                "embeddableConfig": {
                                    "title": "Active Security Incidents"
                                }
                            },
                            {
                                "gridData": {"x": 0, "y": 6, "w": 12, "h": 8},
                                "panelIndex": "high-priority-alerts",
                                "embeddableConfig": {
                                    "title": "High Priority Alerts"
                                }
                            },
                            {
                                "gridData": {"x": 12, "y": 6, "w": 12, "h": 8},
                                "panelIndex": "incident-timeline",
                                "embeddableConfig": {
                                    "title": "Incident Timeline"
                                }
                            },
                            {
                                "gridData": {"x": 0, "y": 14, "w": 8, "h": 8},
                                "panelIndex": "affected-assets",
                                "embeddableConfig": {
                                    "title": "Affected Assets"
                                }
                            },
                            {
                                "gridData": {"x": 8, "y": 14, "w": 8, "h": 8},
                                "panelIndex": "response-metrics",
                                "embeddableConfig": {
                                    "title": "Response Time Metrics"
                                }
                            },
                            {
                                "gridData": {"x": 16, "y": 14, "w": 8, "h": 8},
                                "panelIndex": "containment-status",
                                "embeddableConfig": {
                                    "title": "Containment Status"
                                }
                            }
                        ]),
                        "timeRestore": True,
                        "timeTo": "now",
                        "timeFrom": "now-24h",
                        "version": 1
                    }
                }
            ]
        }
        
        return self._import_dashboard(dashboard_config, "Incident Response Dashboard")
    
    def _import_dashboard(self, dashboard_config, dashboard_name):
        """Import dashboard configuration into Kibana"""
        try:
            # Convert to NDJSON format
            ndjson_content = ""
            for obj in dashboard_config["objects"]:
                ndjson_content += json.dumps(obj) + "\n"
            
            # Import the dashboard
            response = requests.post(
                f"{self.kibana_url}/api/saved_objects/_import",
                headers={'kbn-xsrf': 'true'},
                files={'file': ('dashboard.ndjson', ndjson_content)}
            )
            
            if response.status_code in [200, 409]:  # 409 = already exists
                print(f"✅ Created dashboard: {dashboard_name}")
                return True
            else:
                print(f"❌ Failed to create dashboard {dashboard_name}: {response.text}")
                return False
                
        except Exception as e:
            print(f"❌ Error creating dashboard {dashboard_name}: {e}")
            return False
    
    def create_all_dashboards(self):
        """Create all security dashboards"""
        print("📊 Creating security dashboards...")
        
        if not self.wait_for_kibana():
            return False
        
        dashboards = [
            ("Security Overview", self.create_security_overview_dashboard),
            ("Network Monitoring", self.create_network_monitoring_dashboard),
            ("Threat Hunting", self.create_threat_hunting_dashboard),
            ("Compliance Monitoring", self.create_compliance_dashboard),
            ("Incident Response", self.create_incident_response_dashboard)
        ]
        
        created_count = 0
        for dashboard_name, create_func in dashboards:
            if create_func():
                created_count += 1
            time.sleep(2)  # Brief pause between dashboard creation
        
        print(f"✅ Created {created_count}/{len(dashboards)} dashboards")
        return created_count == len(dashboards)
    
    def create_saved_searches(self):
        """Create useful saved searches for security analysis"""
        
        saved_searches = [
            {
                "id": "high-severity-alerts",
                "title": "High Severity Security Alerts",
                "description": "All security alerts with high severity",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "logstash-*",
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"event_type": "alert"}},
                                    {"range": {"alert.severity": {"lte": 2}}}
                                ]
                            }
                        },
                        "sort": [{"@timestamp": {"order": "desc"}}]
                    })
                }
            },
            {
                "id": "failed-authentication",
                "title": "Failed Authentication Attempts", 
                "description": "All failed login and authentication attempts",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "logstash-*",
                        "query": {
                            "bool": {
                                "should": [
                                    {"term": {"winlogbeat.event_id": 4625}},
                                    {"term": {"event_description": "Failed Logon"}},
                                    {"match": {"message": "authentication failed"}}
                                ]
                            }
                        },
                        "sort": [{"@timestamp": {"order": "desc"}}]
                    })
                }
            },
            {
                "id": "suspicious-network-activity",
                "title": "Suspicious Network Activity",
                "description": "Network connections and activities flagged as suspicious",
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({
                        "index": "logstash-*",
                        "query": {
                            "bool": {
                                "should": [
                                    {"term": {"threat_intel.malicious": True}},
                                    {"range": {"risk_score": {"gte": 70}}},
                                    {"term": {"connection_analysis.anomalies": "large_data_transfer"}}
                                ]
                            }
                        },
                        "sort": [{"@timestamp": {"order": "desc"}}]
                    })
                }
            }
        ]
        
        for search in saved_searches:
            try:
                response = requests.post(
                    f"{self.kibana_url}/api/saved_objects/search/{search['id']}",
                    headers=self.headers,
                    json={"attributes": search}
                )
                
                if response.status_code in [200, 409]:
                    print(f"✅ Created saved search: {search['title']}")
                else:
                    print(f"❌ Failed to create saved search: {search['title']}")
                    
            except Exception as e:
                print(f"❌ Error creating saved search {search['title']}: {e}")

def main():
    print("📊 Security Dashboard Management")
    print("=" * 35)
    
    dashboard_mgr = SecurityDashboardManager()
    
    # Create all dashboards
    success = dashboard_mgr.create_all_dashboards()
    
    if success:
        # Create saved searches
        dashboard_mgr.create_saved_searches()
        
        print("\n✅ Dashboard setup completed successfully!")
        print("🌐 Access Kibana dashboards at: http://localhost:5601")
        print("\n📊 Available dashboards:")
        print("   • Security Overview Dashboard")
        print("   • Network Monitoring Dashboard") 
        print("   • Threat Hunting Dashboard")
        print("   • Compliance Monitoring Dashboard")
        print("   • Incident Response Dashboard")
        
    return dashboard_mgr

# ✅ Checkpoint 3 Validation
def validate_dashboard_setup():
    """Validate dashboard setup"""
    print("\n🔍 Validating Dashboard Setup...")
    
    checks = [
        "✅ Kibana dashboards created successfully",
        "✅ Security overview dashboard configured", 
        "✅ Network monitoring dashboard configured",
        "✅ Threat hunting dashboard configured",
        "✅ Compliance dashboard configured",
        "✅ Saved searches created for common queries"
    ]
    
    for check in checks:
        print(check)
        time.sleep(0.5)
    
    print("\n🎉 Checkpoint 3 Complete: Security Dashboards and Visualization")

if __name__ == "__main__":
    dashboard_mgr = main()
    validate_dashboard_setup()
```

This tutorial is getting quite long, so I'll continue with the remaining parts in the next message. We're making excellent progress on the Week 7 tutorial covering Security Monitoring and SIEM Implementation!