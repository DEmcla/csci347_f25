# Week 11 Tutorial: Advanced File System and Network Forensics

**Estimated Time**: 4-5 hours (self-paced)  
**Prerequisites**: Week 10 completed, understanding of basic forensics concepts

## 🎯 Tutorial Goals

Work through these modules at your own pace. Each builds on the previous:

1. **Part 1** (60 min): Master advanced file system artifacts and metadata analysis
2. **Part 2** (60 min): Analyze network packet captures for forensic reconstruction  
3. **Part 3** (60 min): Investigate database and email forensics techniques
4. **Part 4** (90 min): Detect anti-forensics techniques and countermeasures
5. **Part 5** (45 min): Build automated forensics analysis pipelines

### 📊 Self-Paced Progress Tracking
Check off each section as you complete it. Take breaks as needed:

- [ ] Part 1: Advanced File System Artifacts ✅ Ready for Part 2
- [ ] Part 2: Network Packet Analysis ✅ Ready for Part 3
- [ ] Part 3: Database & Email Forensics ✅ Ready for Part 4
- [ ] Part 4: Anti-Forensics Detection ✅ Ready for Part 5
- [ ] Part 5: Automated Analysis Pipelines ✅ Tutorial Complete

## 🔧 Self-Directed Setup

Set up your environment when you're ready to begin:

```bash
# Check your environment
python --version  # Should be 3.11+

# Install required packages (run when you start each part)
pip install scapy dpkt pyshark sqlite3 email-parser

# Optional: Install Wireshark for GUI analysis
# Download from: https://www.wireshark.org/

# Create your working directory
mkdir week11-advanced-forensics
cd week11-advanced-forensics
```

---

## 📘 Part 1: Advanced File System Artifacts (60 minutes)

**Self-Paced Learning Objective**: Deep dive into file system metadata and deleted file recovery

**What you'll build**: Advanced file system artifact analyzer with journal recovery

### Step 1: File System Metadata Deep Dive

Create `advanced_filesystem.py`:

```python
import os
import struct
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json

class AdvancedFileSystemAnalyzer:
    """Advanced file system artifact analysis"""
    
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.artifacts = {
            'deleted_files': [],
            'file_slack': [],
            'journal_entries': [],
            'metadata_anomalies': [],
            'timeline_gaps': []
        }
        
        print(f"🔍 Advanced FS Analyzer initialized for: {image_path}")
    
    def analyze_file_slack(self, file_path: str) -> Dict:
        """
        Analyze file slack space for hidden data
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dict: Slack space analysis results
        """
        print(f"📄 Analyzing file slack: {file_path}")
        
        if not os.path.exists(file_path):
            return {'error': 'File not found'}
        
        # Get file and cluster information
        file_size = os.path.getsize(file_path)
        
        # Assume 4KB clusters (common for modern filesystems)
        cluster_size = 4096
        clusters_used = (file_size + cluster_size - 1) // cluster_size
        allocated_space = clusters_used * cluster_size
        slack_space = allocated_space - file_size
        
        slack_analysis = {
            'file_size': file_size,
            'allocated_space': allocated_space,
            'slack_bytes': slack_space,
            'clusters_used': clusters_used,
            'cluster_size': cluster_size,
            'slack_data': None
        }
        
        # Read slack space if it exists
        if slack_space > 0:
            try:
                with open(file_path, 'rb') as f:
                    f.seek(file_size)  # Move to end of actual file data
                    remaining_cluster = cluster_size - (file_size % cluster_size)
                    if remaining_cluster < cluster_size:
                        slack_data = f.read(remaining_cluster)
                        slack_analysis['slack_data'] = slack_data
                        slack_analysis['slack_entropy'] = self._calculate_entropy(slack_data)
                        slack_analysis['contains_text'] = self._contains_readable_text(slack_data)
            except Exception as e:
                slack_analysis['read_error'] = str(e)
        
        print(f"   Slack space: {slack_space} bytes")
        if slack_space > 0 and slack_analysis.get('contains_text'):
            print("   ⚠️  Slack space contains readable text - potential data hiding")
        
        return slack_analysis
    
    def extract_deleted_file_signatures(self, image_path: str) -> List[Dict]:
        """
        Search for file signatures in unallocated space
        
        Args:
            image_path: Disk image to search
            
        Returns:
            List of discovered file signatures
        """
        print("🔍 Searching for deleted file signatures...")
        
        # Common file signatures (magic numbers)
        signatures = {
            b'\xFF\xD8\xFF': {'type': 'JPEG', 'extension': '.jpg'},
            b'\x89PNG\r\n\x1A\n': {'type': 'PNG', 'extension': '.png'},
            b'PK\x03\x04': {'type': 'ZIP/Office', 'extension': '.zip'},
            b'%PDF': {'type': 'PDF', 'extension': '.pdf'},
            b'\xD0\xCF\x11\xE0': {'type': 'MS Office', 'extension': '.doc'},
            b'SQLite format 3': {'type': 'SQLite DB', 'extension': '.db'},
            b'RIFF': {'type': 'RIFF/WAV', 'extension': '.wav'}
        }
        
        found_signatures = []
        
        try:
            with open(image_path, 'rb') as f:
                chunk_size = 1024 * 1024  # 1MB chunks
                offset = 0
                
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # Search for each signature in this chunk
                    for signature, info in signatures.items():
                        pos = 0
                        while True:
                            pos = chunk.find(signature, pos)
                            if pos == -1:
                                break
                            
                            file_offset = offset + pos
                            found_signatures.append({
                                'offset': file_offset,
                                'offset_hex': f'0x{file_offset:08X}',
                                'signature': signature.hex(),
                                'type': info['type'],
                                'extension': info['extension']
                            })
                            
                            pos += len(signature)
                    
                    offset += chunk_size
                    
                    # Progress indicator for large images
                    if offset % (10 * 1024 * 1024) == 0:  # Every 10MB
                        print(f"   Processed: {offset // (1024*1024)} MB...")
        
        except Exception as e:
            print(f"❌ Error during signature search: {e}")
            return []
        
        print(f"✅ Found {len(found_signatures)} file signatures")
        return found_signatures
    
    def analyze_mft_records(self, mft_path: str) -> List[Dict]:
        """
        Analyze NTFS Master File Table records
        
        Args:
            mft_path: Path to extracted MFT file
            
        Returns:
            List of MFT record analysis
        """
        print("🗃️  Analyzing NTFS MFT records...")
        
        if not os.path.exists(mft_path):
            print("⚠️  MFT file not found - creating simulated analysis")
            return self._create_simulated_mft_analysis()
        
        mft_records = []
        
        try:
            with open(mft_path, 'rb') as f:
                record_size = 1024  # Standard MFT record size
                record_num = 0
                
                while True:
                    record_data = f.read(record_size)
                    if len(record_data) < record_size:
                        break
                    
                    # Check for valid MFT signature
                    if record_data[:4] == b'FILE':
                        record_info = self._parse_mft_record(record_data, record_num)
                        if record_info:
                            mft_records.append(record_info)
                    
                    record_num += 1
                    
                    # Limit processing for demo
                    if record_num > 100:
                        break
        
        except Exception as e:
            print(f"❌ Error analyzing MFT: {e}")
            return self._create_simulated_mft_analysis()
        
        print(f"✅ Analyzed {len(mft_records)} MFT records")
        return mft_records
    
    def detect_timeline_anomalies(self, file_entries: List[Dict]) -> List[Dict]:
        """
        Detect timestamp anomalies that may indicate tampering
        
        Args:
            file_entries: List of file metadata entries
            
        Returns:
            List of detected anomalies
        """
        print("🕐 Detecting timeline anomalies...")
        
        anomalies = []
        
        for entry in file_entries:
            timestamps = entry.get('timestamps', {})
            
            # Extract timestamps
            created = timestamps.get('created', 0)
            modified = timestamps.get('modified', 0) 
            accessed = timestamps.get('accessed', 0)
            
            # Check for logical inconsistencies
            if created > 0 and modified > 0:
                if modified < created:
                    anomalies.append({
                        'type': 'MODIFIED_BEFORE_CREATED',
                        'file': entry.get('name', 'unknown'),
                        'created': datetime.fromtimestamp(created).isoformat(),
                        'modified': datetime.fromtimestamp(modified).isoformat(),
                        'description': 'File modified before it was created'
                    })
            
            # Check for future timestamps
            now = datetime.now().timestamp()
            for ts_type, timestamp in timestamps.items():
                if timestamp > now:
                    anomalies.append({
                        'type': 'FUTURE_TIMESTAMP',
                        'file': entry.get('name', 'unknown'),
                        'timestamp_type': ts_type,
                        'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                        'description': f'{ts_type.title()} timestamp is in the future'
                    })
            
            # Check for timestamps set to epoch (suspicious)
            epoch_times = ['1970-01-01', '1980-01-01', '1601-01-01']
            for ts_type, timestamp in timestamps.items():
                if timestamp > 0:
                    ts_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
                    if ts_str in epoch_times:
                        anomalies.append({
                            'type': 'EPOCH_TIMESTAMP',
                            'file': entry.get('name', 'unknown'),
                            'timestamp_type': ts_type,
                            'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                            'description': f'Suspicious epoch-based timestamp'
                        })
        
        print(f"⚠️  Found {len(anomalies)} timeline anomalies")
        return anomalies
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _contains_readable_text(self, data: bytes) -> bool:
        """Check if data contains readable ASCII text"""
        if not data:
            return False
        
        try:
            text = data.decode('ascii', errors='ignore')
            printable_chars = sum(1 for c in text if c.isprintable())
            return printable_chars > len(data) * 0.7  # 70% printable
        except:
            return False
    
    def _parse_mft_record(self, record_data: bytes, record_num: int) -> Optional[Dict]:
        """Parse individual MFT record (simplified)"""
        try:
            # This is a simplified parser - real MFT parsing is very complex
            signature = record_data[:4]
            if signature != b'FILE':
                return None
            
            # Extract basic information
            flags = struct.unpack('<H', record_data[22:24])[0]
            is_allocated = bool(flags & 0x01)
            is_directory = bool(flags & 0x02)
            
            return {
                'record_number': record_num,
                'signature': signature.decode('ascii', errors='ignore'),
                'allocated': is_allocated,
                'is_directory': is_directory,
                'flags': flags,
                'record_size': len(record_data)
            }
        
        except Exception:
            return None
    
    def _create_simulated_mft_analysis(self) -> List[Dict]:
        """Create simulated MFT analysis for demonstration"""
        return [
            {
                'record_number': 5,
                'signature': 'FILE',
                'allocated': True,
                'is_directory': False,
                'flags': 1,
                'filename': 'document.txt',
                'file_size': 1024,
                'created': '2024-01-15T10:30:00',
                'note': 'Simulated MFT record'
            },
            {
                'record_number': 37,
                'signature': 'FILE', 
                'allocated': False,
                'is_directory': False,
                'flags': 0,
                'filename': 'deleted_file.pdf',
                'file_size': 2048,
                'created': '2024-01-10T14:20:00',
                'note': 'Simulated deleted file record'
            }
        ]

def demo_advanced_filesystem():
    """Demonstrate advanced file system analysis"""
    print("🔬 Advanced File System Analysis Demo")
    print("="*50)
    print("Work through this at your own pace. Each demo builds on the previous.")
    
    # Initialize analyzer
    analyzer = AdvancedFileSystemAnalyzer("test_image.dd")
    
    # Demo 1: File slack analysis
    print("\n📋 Demo 1: File Slack Analysis")
    print("   This analyzes unused space at the end of file clusters")
    
    # Create a test file for slack analysis
    test_file = "slack_test.txt"
    with open(test_file, 'w') as f:
        f.write("This is test data for slack analysis.")
    
    slack_analysis = analyzer.analyze_file_slack(test_file)
    
    print(f"   File size: {slack_analysis['file_size']} bytes")
    print(f"   Allocated space: {slack_analysis['allocated_space']} bytes") 
    print(f"   Slack space: {slack_analysis['slack_bytes']} bytes")
    
    # Demo 2: Deleted file signature search
    print(f"\n📋 Demo 2: Deleted File Signature Search")
    print("   Searching for file headers in unallocated space...")
    
    # Create test image with embedded signatures
    test_image = "test_signatures.bin"
    with open(test_image, 'wb') as f:
        # Write some random data
        f.write(b'\x00' * 1000)
        # Embed a JPEG signature
        f.write(b'\xFF\xD8\xFF\xE0')
        f.write(b'\x00' * 500)
        # Embed a PDF signature
        f.write(b'%PDF-1.4')
        f.write(b'\x00' * 1000)
    
    signatures = analyzer.extract_deleted_file_signatures(test_image)
    
    for sig in signatures[:3]:  # Show first 3 results
        print(f"   Found: {sig['type']} at offset {sig['offset_hex']}")
    
    # Demo 3: MFT analysis
    print(f"\n📋 Demo 3: NTFS MFT Analysis")
    print("   Analyzing Master File Table records...")
    
    mft_records = analyzer.analyze_mft_records("nonexistent_mft")  # Will use simulated data
    
    for record in mft_records:
        status = "ALLOCATED" if record['allocated'] else "DELETED"
        print(f"   Record {record['record_number']}: {record.get('filename', 'N/A')} ({status})")
    
    # Demo 4: Timeline anomaly detection
    print(f"\n📋 Demo 4: Timeline Anomaly Detection")
    print("   Detecting suspicious timestamp patterns...")
    
    # Create sample file entries with anomalies
    sample_entries = [
        {
            'name': 'normal_file.txt',
            'timestamps': {
                'created': 1704067200,  # 2024-01-01 00:00:00
                'modified': 1704153600, # 2024-01-02 00:00:00
                'accessed': 1704240000  # 2024-01-03 00:00:00
            }
        },
        {
            'name': 'suspicious_file.doc',
            'timestamps': {
                'created': 1704153600,  # 2024-01-02 00:00:00
                'modified': 1704067200, # 2024-01-01 00:00:00 (BEFORE creation!)
                'accessed': 1704240000  # 2024-01-03 00:00:00
            }
        },
        {
            'name': 'future_file.txt',
            'timestamps': {
                'created': 2147483647,  # Future timestamp
                'modified': 2147483647,
                'accessed': 2147483647
            }
        }
    ]
    
    anomalies = analyzer.detect_timeline_anomalies(sample_entries)
    
    for anomaly in anomalies:
        print(f"   ⚠️  {anomaly['type']}: {anomaly['file']}")
        print(f"       {anomaly['description']}")
    
    # Cleanup
    os.remove(test_file)
    os.remove(test_image)
    
    print(f"\n✅ Advanced filesystem analysis complete!")
    print(f"   Take a break before moving to Part 2: Network Analysis")

if __name__ == "__main__":
    demo_advanced_filesystem()
```

### Self-Check Questions for Part 1
Before moving on, make sure you understand:
- What is file slack space and why is it forensically important?
- How do file signatures help recover deleted files?
- What timeline anomalies might indicate tampering?

**Ready for Part 2? ✅ Check the box above and continue when ready.**

---

## 📘 Part 2: Network Packet Analysis (60 minutes)

**Self-Paced Learning**: Analyze network traffic for forensic evidence

**What you'll build**: Network forensics analyzer with protocol reconstruction

### Step 2: Network Traffic Analysis

Create `network_forensics.py`:

```python
import struct
import socket
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import hashlib
import json

class NetworkForensicsAnalyzer:
    """Network packet analysis for forensic investigations"""
    
    def __init__(self):
        self.connections = {}
        self.protocols_seen = set()
        self.suspicious_patterns = []
        self.extracted_files = []
        
        print("🌐 Network Forensics Analyzer initialized")
    
    def analyze_pcap_summary(self, pcap_data: List[Dict]) -> Dict:
        """
        Analyze network capture summary statistics
        
        Args:
            pcap_data: List of packet dictionaries
            
        Returns:
            Dict: Analysis summary
        """
        print("📊 Analyzing network capture summary...")
        
        summary = {
            'total_packets': len(pcap_data),
            'protocols': {},
            'conversations': {},
            'time_span': {},
            'suspicious_indicators': [],
            'top_talkers': {}
        }
        
        if not pcap_data:
            return summary
        
        # Analyze protocols
        for packet in pcap_data:
            protocol = packet.get('protocol', 'Unknown')
            summary['protocols'][protocol] = summary['protocols'].get(protocol, 0) + 1
            self.protocols_seen.add(protocol)
        
        # Analyze conversations (simplified)
        for packet in pcap_data:
            src = packet.get('src_ip', 'unknown')
            dst = packet.get('dst_ip', 'unknown')
            
            if src != 'unknown' and dst != 'unknown':
                conv_key = tuple(sorted([src, dst]))
                if conv_key not in summary['conversations']:
                    summary['conversations'][conv_key] = {
                        'packet_count': 0,
                        'protocols': set(),
                        'ports': set()
                    }
                
                summary['conversations'][conv_key]['packet_count'] += 1
                summary['conversations'][conv_key]['protocols'].add(protocol)
                
                if 'src_port' in packet:
                    summary['conversations'][conv_key]['ports'].add(packet['src_port'])
                if 'dst_port' in packet:
                    summary['conversations'][conv_key]['ports'].add(packet['dst_port'])
        
        # Convert sets to lists for JSON serialization
        for conv_key, conv_data in summary['conversations'].items():
            conv_data['protocols'] = list(conv_data['protocols'])
            conv_data['ports'] = list(conv_data['ports'])
        
        # Analyze time span
        if pcap_data:
            timestamps = [p.get('timestamp', 0) for p in pcap_data if p.get('timestamp')]
            if timestamps:
                summary['time_span'] = {
                    'start': min(timestamps),
                    'end': max(timestamps),
                    'duration_seconds': max(timestamps) - min(timestamps)
                }
        
        print(f"   Analyzed {len(pcap_data)} packets")
        print(f"   Protocols: {list(summary['protocols'].keys())}")
        print(f"   Conversations: {len(summary['conversations'])}")
        
        return summary
    
    def detect_suspicious_network_activity(self, pcap_data: List[Dict]) -> List[Dict]:
        """
        Detect suspicious network patterns
        
        Args:
            pcap_data: Network packet data
            
        Returns:
            List of suspicious activity indicators
        """
        print("🚨 Detecting suspicious network activity...")
        
        suspicious = []
        
        # Track connection attempts
        connection_attempts = {}
        port_scans = {}
        
        for packet in pcap_data:
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            dst_port = packet.get('dst_port')
            protocol = packet.get('protocol')
            
            if not all([src_ip, dst_ip, dst_port]):
                continue
            
            # Detect port scanning
            if src_ip not in port_scans:
                port_scans[src_ip] = {'ports': set(), 'targets': set()}
            
            port_scans[src_ip]['ports'].add(dst_port)
            port_scans[src_ip]['targets'].add(dst_ip)
        
        # Analyze port scan patterns
        for src_ip, scan_data in port_scans.items():
            if len(scan_data['ports']) > 10:  # Scanned many ports
                suspicious.append({
                    'type': 'PORT_SCAN',
                    'source_ip': src_ip,
                    'ports_scanned': len(scan_data['ports']),
                    'targets': len(scan_data['targets']),
                    'description': f'Host {src_ip} scanned {len(scan_data["ports"])} ports on {len(scan_data["targets"])} targets'
                })
        
        # Detect unusual protocols
        common_protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
        for protocol in self.protocols_seen:
            if protocol not in common_protocols:
                suspicious.append({
                    'type': 'UNUSUAL_PROTOCOL',
                    'protocol': protocol,
                    'description': f'Uncommon protocol detected: {protocol}'
                })
        
        # Detect large data transfers
        transfer_volumes = {}
        for packet in pcap_data:
            src_dst = (packet.get('src_ip'), packet.get('dst_ip'))
            size = packet.get('size', 0)
            
            if src_dst[0] and src_dst[1]:
                transfer_volumes[src_dst] = transfer_volumes.get(src_dst, 0) + size
        
        for (src, dst), volume in transfer_volumes.items():
            if volume > 10 * 1024 * 1024:  # More than 10MB
                suspicious.append({
                    'type': 'LARGE_DATA_TRANSFER',
                    'source_ip': src,
                    'destination_ip': dst,
                    'volume_bytes': volume,
                    'description': f'Large data transfer: {volume:,} bytes from {src} to {dst}'
                })
        
        print(f"   Found {len(suspicious)} suspicious indicators")
        return suspicious
    
    def reconstruct_http_sessions(self, pcap_data: List[Dict]) -> List[Dict]:
        """
        Reconstruct HTTP sessions from packet data
        
        Args:
            pcap_data: Network packet data
            
        Returns:
            List of reconstructed HTTP sessions
        """
        print("🔗 Reconstructing HTTP sessions...")
        
        http_sessions = []
        
        # Group HTTP packets by connection
        connections = {}
        
        for packet in pcap_data:
            if packet.get('protocol') != 'HTTP':
                continue
            
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            src_port = packet.get('src_port')
            dst_port = packet.get('dst_port')
            
            # Create connection identifier
            conn_key = (src_ip, src_port, dst_ip, dst_port)
            
            if conn_key not in connections:
                connections[conn_key] = {
                    'packets': [],
                    'requests': [],
                    'responses': []
                }
            
            connections[conn_key]['packets'].append(packet)
            
            # Parse HTTP content (simplified)
            payload = packet.get('payload', '')
            if payload.startswith('GET ') or payload.startswith('POST '):
                connections[conn_key]['requests'].append({
                    'method': payload.split()[0],
                    'uri': payload.split()[1] if len(payload.split()) > 1 else '/',
                    'timestamp': packet.get('timestamp', 0),
                    'payload': payload
                })
            elif payload.startswith('HTTP/'):
                status_code = payload.split()[1] if len(payload.split()) > 1 else '000'
                connections[conn_key]['responses'].append({
                    'status_code': status_code,
                    'timestamp': packet.get('timestamp', 0),
                    'payload': payload
                })
        
        # Create session summaries
        for conn_key, conn_data in connections.items():
            if conn_data['requests'] or conn_data['responses']:
                session = {
                    'connection': {
                        'src_ip': conn_key[0],
                        'src_port': conn_key[1],
                        'dst_ip': conn_key[2],
                        'dst_port': conn_key[3]
                    },
                    'requests': len(conn_data['requests']),
                    'responses': len(conn_data['responses']),
                    'total_packets': len(conn_data['packets']),
                    'sample_requests': conn_data['requests'][:3],  # First 3 requests
                    'sample_responses': conn_data['responses'][:3]  # First 3 responses
                }
                http_sessions.append(session)
        
        print(f"   Reconstructed {len(http_sessions)} HTTP sessions")
        return http_sessions
    
    def extract_network_files(self, pcap_data: List[Dict]) -> List[Dict]:
        """
        Extract files transferred over network
        
        Args:
            pcap_data: Network packet data
            
        Returns:
            List of extracted file information
        """
        print("📁 Extracting network-transferred files...")
        
        extracted = []
        
        # Look for file transfer protocols
        for packet in pcap_data:
            payload = packet.get('payload', '')
            
            # Look for HTTP file downloads
            if 'Content-Disposition: attachment' in payload:
                filename_start = payload.find('filename=')
                if filename_start != -1:
                    filename_end = payload.find('\r\n', filename_start)
                    if filename_end != -1:
                        filename = payload[filename_start+9:filename_end].strip('"')
                        
                        extracted.append({
                            'protocol': 'HTTP',
                            'filename': filename,
                            'source_ip': packet.get('src_ip'),
                            'timestamp': packet.get('timestamp'),
                            'size_estimate': len(payload),
                            'extraction_method': 'HTTP Content-Disposition header'
                        })
            
            # Look for FTP transfers
            elif packet.get('dst_port') == 21 or packet.get('src_port') == 21:
                if 'STOR ' in payload or 'RETR ' in payload:
                    command_parts = payload.strip().split()
                    if len(command_parts) >= 2:
                        filename = command_parts[1]
                        
                        extracted.append({
                            'protocol': 'FTP',
                            'filename': filename,
                            'source_ip': packet.get('src_ip'),
                            'timestamp': packet.get('timestamp'),
                            'command': command_parts[0],
                            'extraction_method': 'FTP command analysis'
                        })
        
        print(f"   Found {len(extracted)} file transfers")
        return extracted
    
    def generate_network_timeline(self, pcap_data: List[Dict]) -> str:
        """Generate network activity timeline"""
        print("📅 Generating network activity timeline...")
        
        timeline_file = "network_timeline.txt"
        
        # Sort packets by timestamp
        sorted_packets = sorted(pcap_data, key=lambda p: p.get('timestamp', 0))
        
        with open(timeline_file, 'w') as f:
            f.write("NETWORK FORENSICS TIMELINE\n")
            f.write("=" * 50 + "\n\n")
            
            for packet in sorted_packets:
                timestamp = packet.get('timestamp', 0)
                if timestamp > 0:
                    dt = datetime.fromtimestamp(timestamp)
                    f.write(f"{dt.isoformat()} - ")
                else:
                    f.write("UNKNOWN_TIME - ")
                
                protocol = packet.get('protocol', 'Unknown')
                src = packet.get('src_ip', 'unknown')
                dst = packet.get('dst_ip', 'unknown')
                size = packet.get('size', 0)
                
                f.write(f"{protocol} {src} -> {dst} ({size} bytes)\n")
                
                # Add payload preview if available
                payload = packet.get('payload', '')
                if payload:
                    preview = payload[:100].replace('\n', ' ').replace('\r', '')
                    f.write(f"    Data: {preview}...\n")
                
                f.write("\n")
        
        print(f"✅ Timeline saved to: {timeline_file}")
        return timeline_file

def create_sample_pcap_data() -> List[Dict]:
    """Create sample network data for demonstration"""
    return [
        {
            'timestamp': 1704067200,  # 2024-01-01 00:00:00
            'protocol': 'HTTP',
            'src_ip': '192.168.1.100',
            'dst_ip': '203.0.113.1',
            'src_port': 54321,
            'dst_port': 80,
            'size': 512,
            'payload': 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'
        },
        {
            'timestamp': 1704067201,
            'protocol': 'HTTP',
            'src_ip': '203.0.113.1', 
            'dst_ip': '192.168.1.100',
            'src_port': 80,
            'dst_port': 54321,
            'size': 2048,
            'payload': 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>...</html>'
        },
        {
            'timestamp': 1704067210,
            'protocol': 'FTP',
            'src_ip': '192.168.1.100',
            'dst_ip': '203.0.113.2', 
            'src_port': 54322,
            'dst_port': 21,
            'size': 64,
            'payload': 'STOR secret_document.pdf\r\n'
        },
        {
            'timestamp': 1704067220,
            'protocol': 'TCP',
            'src_ip': '192.168.1.100',
            'dst_ip': '203.0.113.3',
            'src_port': 54323,
            'dst_port': 22,
            'size': 128,
            'payload': 'SSH connection attempt'
        },
        # Add scanning activity
        {
            'timestamp': 1704067230,
            'protocol': 'TCP',
            'src_ip': '192.168.1.200',
            'dst_ip': '192.168.1.100',
            'src_port': 54400,
            'dst_port': 80,
            'size': 64,
            'payload': 'SYN'
        },
        {
            'timestamp': 1704067231,
            'protocol': 'TCP',
            'src_ip': '192.168.1.200',
            'dst_ip': '192.168.1.100',
            'src_port': 54401,
            'dst_port': 443,
            'size': 64,
            'payload': 'SYN'
        },
        {
            'timestamp': 1704067232,
            'protocol': 'TCP',
            'src_ip': '192.168.1.200',
            'dst_ip': '192.168.1.100',
            'src_port': 54402,
            'dst_port': 22,
            'size': 64,
            'payload': 'SYN'
        }
    ]

def demo_network_forensics():
    """Demonstrate network forensics analysis - work at your own pace"""
    print("🌐 Network Forensics Analysis Demo")
    print("="*50)
    print("Analyze this step by step - no rush!")
    
    # Initialize analyzer
    analyzer = NetworkForensicsAnalyzer()
    
    # Create sample network data
    print("\n📋 Creating sample network capture data...")
    pcap_data = create_sample_pcap_data()
    print(f"   Sample contains {len(pcap_data)} packets")
    
    # Demo 1: Traffic summary analysis
    print(f"\n📋 Demo 1: Network Traffic Summary")
    
    summary = analyzer.analyze_pcap_summary(pcap_data)
    
    print(f"   Protocol distribution:")
    for protocol, count in summary['protocols'].items():
        percentage = (count / summary['total_packets']) * 100
        print(f"     {protocol}: {count} packets ({percentage:.1f}%)")
    
    print(f"   Active conversations: {len(summary['conversations'])}")
    
    # Demo 2: Suspicious activity detection
    print(f"\n📋 Demo 2: Suspicious Activity Detection")
    
    suspicious = analyzer.detect_suspicious_network_activity(pcap_data)
    
    if suspicious:
        for activity in suspicious:
            print(f"   🚨 {activity['type']}: {activity['description']}")
    else:
        print("   No suspicious activity detected in sample data")
    
    # Demo 3: HTTP session reconstruction
    print(f"\n📋 Demo 3: HTTP Session Reconstruction")
    
    http_sessions = analyzer.reconstruct_http_sessions(pcap_data)
    
    for session in http_sessions:
        conn = session['connection']
        print(f"   Session: {conn['src_ip']}:{conn['src_port']} -> {conn['dst_ip']}:{conn['dst_port']}")
        print(f"     Requests: {session['requests']}, Responses: {session['responses']}")
        
        if session['sample_requests']:
            req = session['sample_requests'][0]
            print(f"     Sample request: {req['method']} {req['uri']}")
    
    # Demo 4: File extraction
    print(f"\n📋 Demo 4: Network File Extraction")
    
    extracted_files = analyzer.extract_network_files(pcap_data)
    
    if extracted_files:
        for file_info in extracted_files:
            print(f"   📁 {file_info['protocol']}: {file_info['filename']}")
            print(f"       From: {file_info['source_ip']}")
    else:
        print("   No file transfers detected in sample data")
    
    # Demo 5: Timeline generation
    print(f"\n📋 Demo 5: Network Timeline Generation")
    
    timeline_file = analyzer.generate_network_timeline(pcap_data)
    
    # Show preview
    with open(timeline_file, 'r') as f:
        lines = f.readlines()
        print(f"   Timeline preview (first 10 lines):")
        for line in lines[:10]:
            print(f"     {line.rstrip()}")
    
    print(f"\n✅ Network forensics analysis complete!")
    print(f"   Ready for Part 3: Database & Email Forensics")
    
    # Cleanup
    os.remove(timeline_file)

if __name__ == "__main__":
    demo_network_forensics()
```

### Self-Check Questions for Part 2
Before continuing, ensure you understand:
- How do you detect port scanning in network traffic?
- What information can be extracted from HTTP sessions?
- How would you identify data exfiltration attempts?

**Ready for Part 3? ✅ Check the box above when ready to proceed.**

---

## 📘 Part 3: Database & Email Forensics (60 minutes)

**Self-Paced Learning**: Analyze structured data and email systems

**What you'll build**: Database and email forensics analyzer

### Step 3: Database and Email Analysis

Create `database_email_forensics.py`:

```python
import sqlite3
import json
import email
from email.header import decode_header
from datetime import datetime
from typing import Dict, List, Optional
import hashlib
import re

class DatabaseForensicsAnalyzer:
    """SQLite database forensic analysis"""
    
    def __init__(self):
        self.analysis_results = {
            'tables': [],
            'deleted_records': [],
            'metadata': {},
            'suspicious_patterns': []
        }
        
        print("🗃️  Database Forensics Analyzer initialized")
    
    def analyze_sqlite_database(self, db_path: str) -> Dict:
        """
        Comprehensive SQLite database analysis
        
        Args:
            db_path: Path to SQLite database
            
        Returns:
            Dict: Analysis results
        """
        print(f"📊 Analyzing SQLite database: {db_path}")
        
        try:
            # Connect to database
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row  # Enable column access by name
            cursor = conn.cursor()
            
            # Get database schema
            cursor.execute("SELECT name, type, sql FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            analysis = {
                'database_path': db_path,
                'tables': [],
                'total_records': 0,
                'analysis_timestamp': datetime.now().isoformat()
            }
            
            # Analyze each table
            for table in tables:
                table_name = table['name']
                table_sql = table['sql']
                
                print(f"   Analyzing table: {table_name}")
                
                # Get record count
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                record_count = cursor.fetchone()[0]
                
                # Get sample data
                cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
                sample_records = [dict(row) for row in cursor.fetchall()]
                
                # Get column information
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                table_info = {
                    'name': table_name,
                    'record_count': record_count,
                    'columns': [dict(col) for col in columns],
                    'create_sql': table_sql,
                    'sample_records': sample_records
                }
                
                analysis['tables'].append(table_info)
                analysis['total_records'] += record_count
            
            # Look for deleted records (simplified WAL analysis)
            analysis['wal_analysis'] = self._analyze_wal_file(db_path)
            
            # Detect suspicious patterns
            analysis['suspicious_patterns'] = self._detect_db_anomalies(analysis)
            
            conn.close()
            
            print(f"   Database contains {len(analysis['tables'])} tables with {analysis['total_records']} total records")
            
            return analysis
            
        except Exception as e:
            print(f"❌ Error analyzing database: {e}")
            return {'error': str(e), 'database_path': db_path}
    
    def extract_browser_artifacts(self, profile_path: str) -> Dict:
        """
        Extract browser history and other artifacts
        
        Args:
            profile_path: Path to browser profile directory
            
        Returns:
            Dict: Browser artifacts
        """
        print(f"🌐 Extracting browser artifacts from: {profile_path}")
        
        artifacts = {
            'history': [],
            'downloads': [],
            'cookies': [],
            'cache_analysis': {}
        }
        
        # Common browser database files
        db_files = {
            'history': 'History',
            'cookies': 'Cookies',
            'downloads': 'History'  # Downloads are often in History DB
        }
        
        for artifact_type, db_filename in db_files.items():
            db_path = f"{profile_path}/{db_filename}"
            
            try:
                if artifact_type == 'history':
                    artifacts['history'] = self._extract_browser_history(db_path)
                elif artifact_type == 'cookies':
                    artifacts['cookies'] = self._extract_browser_cookies(db_path)
                elif artifact_type == 'downloads':
                    artifacts['downloads'] = self._extract_browser_downloads(db_path)
                    
            except Exception as e:
                print(f"   ⚠️  Could not extract {artifact_type}: {e}")
                artifacts[artifact_type] = []
        
        return artifacts
    
    def _analyze_wal_file(self, db_path: str) -> Dict:
        """Analyze SQLite WAL file for deleted records"""
        wal_path = db_path + '-wal'
        
        wal_analysis = {
            'wal_exists': False,
            'wal_size': 0,
            'potential_deleted_records': 0
        }
        
        try:
            if os.path.exists(wal_path):
                wal_analysis['wal_exists'] = True
                wal_analysis['wal_size'] = os.path.getsize(wal_path)
                
                # Simple heuristic: larger WAL files may contain more deleted data
                wal_analysis['potential_deleted_records'] = wal_analysis['wal_size'] // 1024  # Rough estimate
                
                print(f"   Found WAL file: {wal_analysis['wal_size']} bytes")
            
        except Exception as e:
            print(f"   WAL analysis error: {e}")
        
        return wal_analysis
    
    def _detect_db_anomalies(self, analysis: Dict) -> List[Dict]:
        """Detect suspicious patterns in database"""
        anomalies = []
        
        for table in analysis.get('tables', []):
            table_name = table['name']
            
            # Check for tables with suspicious names
            suspicious_names = ['temp', 'cache', 'log', 'audit', 'deleted']
            if any(name in table_name.lower() for name in suspicious_names):
                anomalies.append({
                    'type': 'SUSPICIOUS_TABLE_NAME',
                    'table': table_name,
                    'description': f'Table name may indicate temporary or hidden data: {table_name}'
                })
            
            # Check for empty tables (potential evidence removal)
            if table['record_count'] == 0:
                anomalies.append({
                    'type': 'EMPTY_TABLE',
                    'table': table_name,
                    'description': f'Table {table_name} is empty - potential data removal'
                })
            
            # Check for tables with only recent data (potential cleanup)
            sample_records = table.get('sample_records', [])
            if sample_records:
                # Look for timestamp columns
                timestamp_columns = [col['name'] for col in table['columns'] 
                                   if 'time' in col['name'].lower() or 'date' in col['name'].lower()]
                
                if timestamp_columns:
                    anomalies.append({
                        'type': 'TIMESTAMP_ANALYSIS',
                        'table': table_name,
                        'timestamp_columns': timestamp_columns,
                        'description': f'Table {table_name} contains timestamp data for temporal analysis'
                    })
        
        return anomalies
    
    def _extract_browser_history(self, db_path: str) -> List[Dict]:
        """Extract browser history from database"""
        if not os.path.exists(db_path):
            return []
        
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Chrome/Chromium history query
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls 
                ORDER BY last_visit_time DESC 
                LIMIT 100
            """)
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'url': row['url'],
                    'title': row['title'],
                    'visit_count': row['visit_count'],
                    'last_visit': row['last_visit_time']
                })
            
            conn.close()
            return history
            
        except Exception as e:
            print(f"   Browser history extraction error: {e}")
            return []
    
    def _extract_browser_cookies(self, db_path: str) -> List[Dict]:
        """Extract browser cookies"""
        # Simplified cookie extraction
        return [{'note': 'Cookie extraction would require decryption in real scenario'}]
    
    def _extract_browser_downloads(self, db_path: str) -> List[Dict]:
        """Extract browser download history"""
        # Simplified download extraction
        return [{'note': 'Download history extraction from History database'}]

class EmailForensicsAnalyzer:
    """Email forensic analysis"""
    
    def __init__(self):
        self.email_stats = {
            'total_emails': 0,
            'unique_senders': set(),
            'unique_recipients': set(),
            'suspicious_emails': []
        }
        
        print("📧 Email Forensics Analyzer initialized")
    
    def analyze_email_file(self, email_file: str) -> Dict:
        """
        Analyze individual email file
        
        Args:
            email_file: Path to email file (.eml format)
            
        Returns:
            Dict: Email analysis results
        """
        print(f"📨 Analyzing email file: {email_file}")
        
        try:
            with open(email_file, 'rb') as f:
                email_content = f.read()
            
            # Parse email
            msg = email.message_from_bytes(email_content)
            
            # Extract basic headers
            analysis = {
                'file_path': email_file,
                'message_id': msg.get('Message-ID', 'Unknown'),
                'from': self._decode_header(msg.get('From', '')),
                'to': self._decode_header(msg.get('To', '')),
                'cc': self._decode_header(msg.get('Cc', '')),
                'bcc': self._decode_header(msg.get('Bcc', '')),
                'subject': self._decode_header(msg.get('Subject', '')),
                'date': msg.get('Date', ''),
                'received_headers': [],
                'attachments': [],
                'body_text': '',
                'body_html': '',
                'suspicious_indicators': []
            }
            
            # Extract Received headers for tracking
            for header in msg.get_all('Received', []):
                analysis['received_headers'].append(header)
            
            # Extract body content
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    
                    if content_type == 'text/plain':
                        body = part.get_payload(decode=True)
                        if body:
                            analysis['body_text'] = body.decode('utf-8', errors='ignore')
                    
                    elif content_type == 'text/html':
                        body = part.get_payload(decode=True)
                        if body:
                            analysis['body_html'] = body.decode('utf-8', errors='ignore')
                    
                    elif part.get_filename():
                        # Attachment found
                        attachment = {
                            'filename': part.get_filename(),
                            'content_type': content_type,
                            'size': len(part.get_payload(decode=True) or b'')
                        }
                        analysis['attachments'].append(attachment)
            else:
                # Single part message
                body = msg.get_payload(decode=True)
                if body:
                    analysis['body_text'] = body.decode('utf-8', errors='ignore')
            
            # Analyze for suspicious indicators
            analysis['suspicious_indicators'] = self._detect_email_anomalies(analysis)
            
            return analysis
            
        except Exception as e:
            print(f"❌ Error analyzing email: {e}")
            return {'error': str(e), 'file_path': email_file}
    
    def analyze_email_headers(self, email_analysis: Dict) -> Dict:
        """
        Detailed email header analysis
        
        Args:
            email_analysis: Results from analyze_email_file
            
        Returns:
            Dict: Header analysis
        """
        print("📋 Analyzing email headers for forensic indicators...")
        
        header_analysis = {
            'routing_analysis': [],
            'authentication_results': {},
            'timestamp_analysis': {},
            'suspicious_headers': []
        }
        
        # Analyze Received headers for routing path
        received_headers = email_analysis.get('received_headers', [])
        
        for i, received in enumerate(received_headers):
            # Extract IP addresses from Received headers
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, received)
            
            routing_step = {
                'step': i + 1,
                'header': received[:100] + '...' if len(received) > 100 else received,
                'ip_addresses': ips
            }
            header_analysis['routing_analysis'].append(routing_step)
        
        # Check for authentication headers
        subject = email_analysis.get('subject', '')
        sender = email_analysis.get('from', '')
        
        # Look for potential phishing indicators
        phishing_keywords = ['urgent', 'verify', 'suspend', 'click here', 'immediate action']
        phishing_score = sum(1 for keyword in phishing_keywords if keyword.lower() in subject.lower())
        
        if phishing_score > 0:
            header_analysis['suspicious_headers'].append({
                'type': 'POTENTIAL_PHISHING',
                'score': phishing_score,
                'keywords_found': [kw for kw in phishing_keywords if kw.lower() in subject.lower()],
                'description': f'Subject contains {phishing_score} phishing-related keywords'
            })
        
        return header_analysis
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header value"""
        if not header_value:
            return ''
        
        try:
            decoded_parts = decode_header(header_value)
            decoded_string = ''
            
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_string += part.decode(encoding, errors='ignore')
                    else:
                        decoded_string += part.decode('utf-8', errors='ignore')
                else:
                    decoded_string += part
            
            return decoded_string
            
        except Exception:
            return header_value
    
    def _detect_email_anomalies(self, analysis: Dict) -> List[Dict]:
        """Detect suspicious patterns in email"""
        anomalies = []
        
        subject = analysis.get('subject', '')
        sender = analysis.get('from', '')
        body_text = analysis.get('body_text', '')
        
        # Check for suspicious attachments
        attachments = analysis.get('attachments', [])
        for attachment in attachments:
            filename = attachment['filename'].lower()
            
            # Check for executable attachments
            executable_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com']
            if any(filename.endswith(ext) for ext in executable_extensions):
                anomalies.append({
                    'type': 'EXECUTABLE_ATTACHMENT',
                    'filename': attachment['filename'],
                    'description': f'Potentially dangerous executable attachment: {attachment["filename"]}'
                })
            
            # Check for double extensions (e.g., document.pdf.exe)
            if filename.count('.') > 1:
                anomalies.append({
                    'type': 'DOUBLE_EXTENSION',
                    'filename': attachment['filename'],
                    'description': f'File with multiple extensions (potential disguise): {attachment["filename"]}'
                })
        
        # Check for URL shorteners in body
        url_shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']
        for shortener in url_shorteners:
            if shortener in body_text.lower():
                anomalies.append({
                    'type': 'URL_SHORTENER',
                    'shortener': shortener,
                    'description': f'Email contains shortened URL from {shortener}'
                })
        
        return anomalies

def create_sample_email_file() -> str:
    """Create sample email for demonstration"""
    email_content = """From: john.doe@example.com
To: jane.smith@company.com
Subject: Urgent: Verify Your Account
Date: Mon, 1 Jan 2024 10:00:00 +0000
Message-ID: <sample123@example.com>

Dear User,

Your account requires immediate verification. Please click the link below:

http://bit.ly/verify-account-urgent

Failure to verify within 24 hours will result in account suspension.

Best regards,
Security Team
"""
    
    email_file = "sample_email.eml"
    with open(email_file, 'w') as f:
        f.write(email_content)
    
    return email_file

def demo_database_email_forensics():
    """Demonstrate database and email forensics - self-paced learning"""
    print("🗃️  Database & Email Forensics Demo")
    print("="*50)
    print("Take your time with each section - practice is key!")
    
    # Demo 1: Database forensics
    print(f"\n📋 Demo 1: SQLite Database Analysis")
    
    db_analyzer = DatabaseForensicsAnalyzer()
    
    # Create sample database
    sample_db = "sample_forensics.db"
    conn = sqlite3.connect(sample_db)
    cursor = conn.cursor()
    
    # Create sample tables
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            email TEXT,
            last_login TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER,
            recipient_id INTEGER,
            message TEXT,
            sent_time TIMESTAMP,
            deleted INTEGER DEFAULT 0
        )
    ''')
    
    # Insert sample data
    cursor.execute("INSERT INTO users VALUES (1, 'alice', 'alice@example.com', '2024-01-01 10:00:00')")
    cursor.execute("INSERT INTO users VALUES (2, 'bob', 'bob@example.com', '2024-01-01 11:00:00')")
    
    cursor.execute("INSERT INTO messages VALUES (1, 1, 2, 'Hello Bob!', '2024-01-01 10:30:00', 0)")
    cursor.execute("INSERT INTO messages VALUES (2, 2, 1, 'Hi Alice!', '2024-01-01 10:31:00', 1)")
    
    conn.commit()
    conn.close()
    
    # Analyze the database
    db_analysis = db_analyzer.analyze_sqlite_database(sample_db)
    
    print(f"   Database contains {len(db_analysis['tables'])} tables:")
    for table in db_analysis['tables']:
        print(f"     • {table['name']}: {table['record_count']} records")
        
        # Show suspicious patterns if any
        if 'suspicious_patterns' in db_analysis:
            for pattern in db_analysis['suspicious_patterns']:
                if pattern['table'] == table['name']:
                    print(f"       ⚠️  {pattern['description']}")
    
    # Demo 2: Email forensics
    print(f"\n📋 Demo 2: Email Forensic Analysis")
    
    email_analyzer = EmailForensicsAnalyzer()
    
    # Create and analyze sample email
    sample_email = create_sample_email_file()
    
    email_analysis = email_analyzer.analyze_email_file(sample_email)
    
    print(f"   Email Analysis Results:")
    print(f"     From: {email_analysis['from']}")
    print(f"     Subject: {email_analysis['subject']}")
    print(f"     Attachments: {len(email_analysis['attachments'])}")
    
    # Show suspicious indicators
    suspicious = email_analysis.get('suspicious_indicators', [])
    if suspicious:
        print(f"     Suspicious indicators found:")
        for indicator in suspicious:
            print(f"       🚨 {indicator['type']}: {indicator['description']}")
    
    # Demo 3: Email header analysis
    print(f"\n📋 Demo 3: Email Header Analysis")
    
    header_analysis = email_analyzer.analyze_email_headers(email_analysis)
    
    print(f"   Header Analysis:")
    print(f"     Routing steps: {len(header_analysis['routing_analysis'])}")
    
    for step in header_analysis['routing_analysis'][:2]:  # Show first 2 steps
        print(f"       Step {step['step']}: IPs found: {step['ip_addresses']}")
    
    # Show suspicious headers
    suspicious_headers = header_analysis.get('suspicious_headers', [])
    if suspicious_headers:
        for header in suspicious_headers:
            print(f"       🚨 {header['type']}: {header['description']}")
    
    print(f"\n✅ Database & Email forensics analysis complete!")
    print(f"   Move on to Part 4 when you're ready: Anti-Forensics Detection")
    
    # Cleanup
    os.remove(sample_db)
    os.remove(sample_email)

if __name__ == "__main__":
    demo_database_email_forensics()
```

### Self-Check Questions for Part 3
Take time to understand:
- How do you extract artifacts from SQLite databases?
- What email headers are most important for forensic analysis?
- How can you detect phishing attempts in email content?

**Ready for Part 4? ✅ Check the box when you're confident with the material.**

---

## ✅ Tutorial Completion Checklist

Work through these at your own pace. Check each as you master the concept:

- [ ] I can perform advanced file system artifact analysis
- [ ] I understand network traffic analysis for forensic purposes
- [ ] I can extract evidence from databases and email systems
- [ ] I can detect anti-forensics techniques and countermeasures
- [ ] I can build automated forensics analysis workflows
- [ ] I understand multi-source evidence correlation

## 🚀 Ready for the Assignment?

Take your time! When you feel confident with all the concepts, review the assignment requirements. The assignment combines everything you've learned into a complete incident reconstruction.

**Next step**: Review [assignment.md](assignment.md) when ready.

## 💡 Key Concepts Learned (Self-Review)

Review each concept - make sure you understand it before moving forward:

1. **Advanced file system analysis** - slack space, deleted files, metadata anomalies
2. **Network packet forensics** - traffic analysis, session reconstruction, suspicious activity detection  
3. **Database forensics** - SQLite analysis, browser artifacts, WAL file examination
4. **Email forensics** - header analysis, phishing detection, attachment analysis
5. **Anti-forensics detection** - timestamp manipulation, data hiding techniques
6. **Automated analysis** - building forensics pipelines and workflows

---

**Questions or stuck on something?** That's normal! Check the troubleshooting section or ask in Canvas discussions. Learning forensics takes time and practice.