# Week 13 Tutorial: Mobile Device and Cloud Forensics

**Estimated Time**: 3-4 hours (broken into 4 modules)  
**Prerequisites**: Understanding of mobile OS architecture, basic forensics concepts

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Module 1** (45 min): Analyzed Android device artifacts and databases
2. **Module 2** (60 min): Investigated iOS backups and application data
3. **Module 3** (45 min): Examined cloud storage and synchronization
4. **Module 4** (60 min): Built cross-platform mobile forensics toolkit

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Module 1: Android Device Forensics ✅ Checkpoint 1
- [ ] Module 2: iOS Device Analysis ✅ Checkpoint 2  
- [ ] Module 3: Cloud Storage Investigation ✅ Checkpoint 3
- [ ] Module 4: Mobile Forensics Toolkit ✅ Checkpoint 4

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Install required packages
pip install sqlite3 plistlib biplist cryptography pyaes

# Create working directory
mkdir week13-work
cd week13-work
```

---

## 📘 Module 1: Android Device Forensics (45 minutes)

**Learning Objective**: Extract and analyze Android device artifacts

**What you'll build**: Android artifact analyzer for apps, databases, and system data

### Step 1: Android Artifact Analysis

Create a new file `android_forensics.py`:

```python
import sqlite3
import json
import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import base64

@dataclass
class AndroidApp:
    """Represents an Android application"""
    package_name: str
    app_name: str
    version: str
    install_date: str
    permissions: List[str]
    data_dir: str
    
@dataclass
class Message:
    """Represents a text message"""
    thread_id: int
    address: str
    date: datetime
    message_type: str  # sent/received
    body: str
    read: bool

@dataclass
class Contact:
    """Represents a contact"""
    contact_id: int
    display_name: str
    phone_numbers: List[str]
    emails: List[str]
    last_contacted: Optional[datetime]

class AndroidForensics:
    """Android device forensics analyzer"""
    
    def __init__(self, device_path: str = None):
        self.device_path = device_path
        self.apps: List[AndroidApp] = []
        self.messages: List[Message] = []
        self.contacts: List[Contact] = []
        self.call_log = []
        self.wifi_networks = []
        self.browser_history = []
    
    def analyze_sms_database(self, sms_db_path: str = None) -> List[Message]:
        """Analyze SMS/MMS database"""
        # Simulated SMS analysis (in production, parse actual mmssms.db)
        sample_messages = [
            Message(
                thread_id=1,
                address="+1234567890",
                date=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                message_type="received",
                body="Hey, are you coming to the meeting?",
                read=True
            ),
            Message(
                thread_id=1,
                address="+1234567890",
                date=datetime(2024, 1, 15, 10, 35, 0, tzinfo=timezone.utc),
                message_type="sent",
                body="Yes, I'll be there in 10 minutes",
                read=True
            ),
            Message(
                thread_id=2,
                address="+9876543210",
                date=datetime(2024, 1, 16, 14, 20, 0, tzinfo=timezone.utc),
                message_type="received",
                body="Your package has been delivered",
                read=False
            ),
            Message(
                thread_id=3,
                address="+5555555555",
                date=datetime(2024, 1, 17, 9, 15, 0, tzinfo=timezone.utc),
                message_type="received",
                body="URGENT: Your account needs verification. Click here: http://phishing-site.com",
                read=False
            )
        ]
        
        self.messages = sample_messages
        
        # Analyze for suspicious content
        suspicious_keywords = ["urgent", "verify", "click here", "suspended", "prize"]
        suspicious_messages = []
        
        for msg in self.messages:
            if any(keyword in msg.body.lower() for keyword in suspicious_keywords):
                suspicious_messages.append({
                    "from": msg.address,
                    "date": msg.date.isoformat(),
                    "content": msg.body,
                    "threat": "Potential phishing/scam"
                })
        
        return self.messages
    
    def analyze_contacts_database(self) -> List[Contact]:
        """Analyze contacts database"""
        # Simulated contacts analysis
        sample_contacts = [
            Contact(
                contact_id=1,
                display_name="John Doe",
                phone_numbers=["+1234567890", "+1234567891"],
                emails=["john.doe@email.com"],
                last_contacted=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
            ),
            Contact(
                contact_id=2,
                display_name="Jane Smith",
                phone_numbers=["+9876543210"],
                emails=["jane.smith@email.com", "jsmith@work.com"],
                last_contacted=datetime(2024, 1, 14, 15, 45, 0, tzinfo=timezone.utc)
            ),
            Contact(
                contact_id=3,
                display_name="Unknown Caller",
                phone_numbers=["+5555555555"],
                emails=[],
                last_contacted=datetime(2024, 1, 17, 9, 15, 0, tzinfo=timezone.utc)
            )
        ]
        
        self.contacts = sample_contacts
        return self.contacts
    
    def analyze_call_log(self) -> List[Dict]:
        """Analyze call log database"""
        # Simulated call log analysis
        call_log = [
            {
                "number": "+1234567890",
                "name": "John Doe",
                "date": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc).isoformat(),
                "duration": 180,  # seconds
                "type": "incoming",
                "country": "US"
            },
            {
                "number": "+9876543210",
                "name": "Jane Smith",
                "date": datetime(2024, 1, 14, 15, 45, 0, tzinfo=timezone.utc).isoformat(),
                "duration": 420,
                "type": "outgoing",
                "country": "US"
            },
            {
                "number": "+5555555555",
                "name": "Unknown",
                "date": datetime(2024, 1, 17, 9, 15, 0, tzinfo=timezone.utc).isoformat(),
                "duration": 5,
                "type": "missed",
                "country": "Unknown"
            }
        ]
        
        self.call_log = call_log
        
        # Analyze patterns
        patterns = {
            "total_calls": len(call_log),
            "incoming": len([c for c in call_log if c["type"] == "incoming"]),
            "outgoing": len([c for c in call_log if c["type"] == "outgoing"]),
            "missed": len([c for c in call_log if c["type"] == "missed"]),
            "average_duration": sum(c["duration"] for c in call_log) / len(call_log) if call_log else 0,
            "international_calls": len([c for c in call_log if c["country"] not in ["US", "Unknown"]])
        }
        
        return call_log
    
    def analyze_installed_apps(self) -> List[AndroidApp]:
        """Analyze installed applications"""
        # Simulated app analysis
        sample_apps = [
            AndroidApp(
                package_name="com.whatsapp",
                app_name="WhatsApp",
                version="2.24.1.5",
                install_date="2023-06-15",
                permissions=["CAMERA", "CONTACTS", "STORAGE", "MICROPHONE"],
                data_dir="/data/data/com.whatsapp"
            ),
            AndroidApp(
                package_name="com.facebook.katana",
                app_name="Facebook",
                version="450.0.0.35.70",
                install_date="2023-07-20",
                permissions=["LOCATION", "CAMERA", "CONTACTS", "STORAGE"],
                data_dir="/data/data/com.facebook.katana"
            ),
            AndroidApp(
                package_name="com.suspicious.app",
                app_name="FreeVPN",
                version="1.0.0",
                install_date="2024-01-10",
                permissions=["INTERNET", "ACCESS_NETWORK_STATE", "READ_PHONE_STATE", "READ_SMS"],
                data_dir="/data/data/com.suspicious.app"
            ),
            AndroidApp(
                package_name="com.banking.app",
                app_name="MyBank",
                version="5.2.1",
                install_date="2023-05-01",
                permissions=["INTERNET", "FINGERPRINT", "CAMERA"],
                data_dir="/data/data/com.banking.app"
            )
        ]
        
        self.apps = sample_apps
        
        # Check for suspicious apps
        suspicious_apps = []
        dangerous_permissions = ["READ_SMS", "SEND_SMS", "READ_PHONE_STATE", "RECORD_AUDIO"]
        
        for app in self.apps:
            risk_score = 0
            risks = []
            
            # Check permissions
            for perm in dangerous_permissions:
                if perm in app.permissions:
                    risk_score += 1
                    risks.append(f"Has {perm} permission")
            
            # Check for known suspicious packages
            if "vpn" in app.app_name.lower() or "free" in app.app_name.lower():
                risk_score += 1
                risks.append("Potentially unwanted app")
            
            if risk_score > 0:
                suspicious_apps.append({
                    "app": app.app_name,
                    "package": app.package_name,
                    "risk_score": risk_score,
                    "risks": risks
                })
        
        return self.apps
    
    def analyze_wifi_networks(self) -> List[Dict]:
        """Analyze WiFi connection history"""
        # Simulated WiFi analysis
        wifi_networks = [
            {
                "ssid": "HomeNetwork",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "security": "WPA2",
                "last_connected": "2024-01-15T08:00:00Z",
                "frequency": 2437,
                "signal_strength": -45
            },
            {
                "ssid": "CoffeeShop_WiFi", 
                "bssid": "11:22:33:44:55:66",
                "security": "Open",
                "last_connected": "2024-01-12T14:30:00Z",
                "frequency": 2412,
                "signal_strength": -67
            },
            {
                "ssid": "FreeWiFi_Suspicious",
                "bssid": "99:88:77:66:55:44", 
                "security": "Open",
                "last_connected": "2024-01-10T11:15:00Z",
                "frequency": 2462,
                "signal_strength": -89
            }
        ]
        
        self.wifi_networks = wifi_networks
        
        # Check for suspicious networks
        suspicious_networks = []
        for network in wifi_networks:
            if network["security"] == "Open":
                suspicious_networks.append({
                    "ssid": network["ssid"],
                    "risk": "Open network - potential security risk",
                    "last_connected": network["last_connected"]
                })
        
        return wifi_networks
    
    def analyze_location_data(self) -> List[Dict]:
        """Analyze location history"""
        # Simulated location analysis
        locations = [
            {
                "timestamp": "2024-01-15T08:00:00Z",
                "latitude": 37.7749,
                "longitude": -122.4194,
                "accuracy": 10,
                "activity": "Home",
                "address": "San Francisco, CA"
            },
            {
                "timestamp": "2024-01-15T09:30:00Z", 
                "latitude": 37.7849,
                "longitude": -122.4094,
                "accuracy": 15,
                "activity": "Work",
                "address": "Office Building, San Francisco"
            },
            {
                "timestamp": "2024-01-12T14:30:00Z",
                "latitude": 37.7949,
                "longitude": -122.3994, 
                "accuracy": 20,
                "activity": "Coffee",
                "address": "Coffee Shop, Market St"
            }
        ]
        
        # Analyze patterns
        frequent_locations = {}
        for loc in locations:
            key = f"{loc['latitude']:.3f},{loc['longitude']:.3f}"
            frequent_locations[key] = frequent_locations.get(key, 0) + 1
        
        return locations

# Demo the Android forensics
if __name__ == "__main__":
    print("📱 ANDROID FORENSICS ANALYZER")
    print("="*60)
    
    forensics = AndroidForensics("android_device")
    
    # Analyze SMS
    print("\n📱 Analyzing SMS Messages...")
    messages = forensics.analyze_sms_database()
    print(f"Found {len(messages)} messages")
    
    # Show suspicious messages
    suspicious_count = len([m for m in messages if "urgent" in m.body.lower() or "verify" in m.body.lower()])
    if suspicious_count > 0:
        print(f"⚠️ Found {suspicious_count} potentially suspicious messages")
    
    # Analyze contacts
    print("\n📞 Analyzing Contacts...")
    contacts = forensics.analyze_contacts_database()
    print(f"Found {len(contacts)} contacts")
    
    # Analyze calls
    print("\n📞 Analyzing Call Log...")
    calls = forensics.analyze_call_log()
    print(f"Found {len(calls)} call records")
    
    # Show call statistics
    incoming = len([c for c in calls if c["type"] == "incoming"])
    outgoing = len([c for c in calls if c["type"] == "outgoing"])
    print(f"  Incoming: {incoming}, Outgoing: {outgoing}")
    
    # Analyze apps
    print("\n📲 Analyzing Installed Apps...")
    apps = forensics.analyze_installed_apps()
    print(f"Found {len(apps)} installed apps")
    
    # Analyze WiFi
    print("\n📶 Analyzing WiFi Networks...")
    wifi = forensics.analyze_wifi_networks()
    print(f"Found {len(wifi)} WiFi networks")
    
    open_networks = [n for n in wifi if n["security"] == "Open"]
    if open_networks:
        print(f"⚠️ {len(open_networks)} open networks detected")
```

### ✅ Checkpoint 1 Complete!
You can now analyze Android devices. Ready for Module 2?

---

## 📘 Module 2: iOS Device Analysis (60 minutes)

**Learning Objective**: Investigate iOS backups and application data

**What you'll build**: iOS forensics analyzer for backups and plist files

### Step 1: iOS Backup Analysis

Create `ios_forensics.py`:

```python
import plistlib
import sqlite3
import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib
import biplist

@dataclass
class iOSApp:
    """Represents an iOS application"""
    bundle_id: str
    name: str
    version: str
    install_date: datetime
    data_size: int

@dataclass  
class iOSMessage:
    """Represents an iOS message"""
    message_id: int
    chat_id: int
    text: str
    sender: str
    timestamp: datetime
    is_from_me: bool
    service: str  # iMessage or SMS

class iOSForensics:
    """iOS device forensics analyzer"""
    
    def __init__(self, backup_path: str):
        self.backup_path = backup_path
        self.apps: List[iOSApp] = []
        self.messages: List[iOSMessage] = []
        self.contacts = []
        self.photos = []
        
    def analyze_info_plist(self) -> Dict:
        """Analyze iTunes backup Info.plist"""
        # Simulated Info.plist analysis
        info_data = {
            "Device Name": "John's iPhone",
            "Display Name": "iPhone 15 Pro",
            "GUID": "ABCD1234-5678-90EF-GHIJ-KLMNOPQRSTUV",
            "ICCID": "89014103211118510720",
            "IMEI": "351234567890123",
            "Last Backup Date": datetime(2024, 1, 15, 20, 30, 0),
            "Phone Number": "+1234567890",
            "Product Name": "iPhone15,2",
            "Product Type": "iPhone15,2",
            "Product Version": "17.2.1",
            "Serial Number": "ABC123DEF456",
            "Target Identifier": "12345678-1234567890ABCDEF",
            "Target Type": "Device",
            "iTunes Version": "12.12.10.1",
            "Unique Identifier": "12345678-1234567890ABCDEF"
        }
        
        return info_data
    
    def analyze_messages_db(self) -> List[iOSMessage]:
        """Analyze SMS.db for iMessages and SMS"""
        # Simulated message analysis
        sample_messages = [
            iOSMessage(
                message_id=1,
                chat_id=1,
                text="Hey, how's it going?",
                sender="+1234567890",
                timestamp=datetime(2024, 1, 15, 10, 30, 0),
                is_from_me=False,
                service="iMessage"
            ),
            iOSMessage(
                message_id=2,
                chat_id=1, 
                text="Good! Just finished work",
                sender="+1234567890",
                timestamp=datetime(2024, 1, 15, 10, 35, 0),
                is_from_me=True,
                service="iMessage"
            ),
            iOSMessage(
                message_id=3,
                chat_id=2,
                text="URGENT: Your account has been suspended. Click here to verify: http://phishing-link.com",
                sender="+5555555555",
                timestamp=datetime(2024, 1, 16, 14, 20, 0),
                is_from_me=False,
                service="SMS"
            ),
            iOSMessage(
                message_id=4,
                chat_id=3,
                text="Meeting moved to 3 PM",
                sender="boss@company.com",
                timestamp=datetime(2024, 1, 17, 9, 15, 0),
                is_from_me=False,
                service="iMessage"
            )
        ]
        
        self.messages = sample_messages
        
        # Analyze for threats
        suspicious_messages = []
        threat_indicators = ["urgent", "suspended", "verify", "click here", "act now", "prize"]
        
        for msg in self.messages:
            if any(indicator in msg.text.lower() for indicator in threat_indicators):
                suspicious_messages.append({
                    "message_id": msg.message_id,
                    "sender": msg.sender,
                    "text": msg.text,
                    "service": msg.service,
                    "timestamp": msg.timestamp.isoformat(),
                    "threat_type": "Potential phishing/scam"
                })
        
        return self.messages
    
    def analyze_call_history(self) -> List[Dict]:
        """Analyze call_history.db"""
        # Simulated call history
        call_history = [
            {
                "rowid": 1,
                "address": "+1234567890",
                "date": datetime(2024, 1, 15, 10, 30, 0),
                "duration": 180,
                "flags": 5,  # Outgoing call
                "id": 1,
                "name": "John Doe",
                "country_code": "us"
            },
            {
                "rowid": 2,
                "address": "+9876543210",
                "date": datetime(2024, 1, 14, 15, 45, 0),
                "duration": 420,
                "flags": 4,  # Incoming call
                "id": 2, 
                "name": "Jane Smith",
                "country_code": "us"
            },
            {
                "rowid": 3,
                "address": "+5555555555",
                "date": datetime(2024, 1, 17, 9, 15, 0),
                "duration": 0,
                "flags": 1,  # Missed call
                "id": 3,
                "name": "Unknown",
                "country_code": "unknown"
            }
        ]
        
        # Analyze patterns
        total_duration = sum(call['duration'] for call in call_history)
        call_types = {
            "outgoing": len([c for c in call_history if c['flags'] == 5]),
            "incoming": len([c for c in call_history if c['flags'] == 4]),
            "missed": len([c for c in call_history if c['flags'] == 1])
        }
        
        return call_history
    
    def analyze_installed_apps(self) -> List[iOSApp]:
        """Analyze installed applications"""
        # Simulated app analysis
        sample_apps = [
            iOSApp(
                bundle_id="com.apple.mobilemail",
                name="Mail",
                version="17.2.1",
                install_date=datetime(2024, 1, 1, 0, 0, 0),
                data_size=52428800  # 50 MB
            ),
            iOSApp(
                bundle_id="com.whatsapp.WhatsApp",
                name="WhatsApp Messenger", 
                version="24.1.78",
                install_date=datetime(2023, 6, 15, 12, 30, 0),
                data_size=314572800  # 300 MB
            ),
            iOSApp(
                bundle_id="com.suspicious.vpn",
                name="Free VPN Master",
                version="1.0.5",
                install_date=datetime(2024, 1, 10, 16, 45, 0),
                data_size=10485760  # 10 MB
            ),
            iOSApp(
                bundle_id="com.bankofamerica.mobile",
                name="Bank of America Mobile Banking",
                version="27.4.1",
                install_date=datetime(2023, 5, 1, 10, 0, 0),
                data_size=157286400  # 150 MB
            )
        ]
        
        self.apps = sample_apps
        
        # Check for suspicious apps
        suspicious_apps = []
        suspicious_keywords = ["vpn", "free", "proxy", "hack", "crack"]
        
        for app in self.apps:
            risk_score = 0
            risks = []
            
            # Check app name
            for keyword in suspicious_keywords:
                if keyword in app.name.lower():
                    risk_score += 1
                    risks.append(f"Contains suspicious keyword: {keyword}")
            
            # Check recent installation
            days_since_install = (datetime.now() - app.install_date).days
            if days_since_install < 7:
                risk_score += 0.5
                risks.append("Recently installed")
            
            if risk_score > 0:
                suspicious_apps.append({
                    "app": app.name,
                    "bundle_id": app.bundle_id,
                    "risk_score": risk_score,
                    "risks": risks
                })
        
        return self.apps
    
    def analyze_safari_history(self) -> List[Dict]:
        """Analyze Safari browsing history"""
        # Simulated Safari history
        browsing_history = [
            {
                "id": 1,
                "url": "https://www.apple.com",
                "title": "Apple",
                "visit_time": datetime(2024, 1, 15, 9, 30, 0),
                "visit_count": 5
            },
            {
                "id": 2,
                "url": "https://www.facebook.com",
                "title": "Facebook",
                "visit_time": datetime(2024, 1, 15, 14, 20, 0),
                "visit_count": 25
            },
            {
                "id": 3,
                "url": "http://suspicious-site.com/malware",
                "title": "Free Software Download",
                "visit_time": datetime(2024, 1, 16, 11, 15, 0),
                "visit_count": 1
            },
            {
                "id": 4,
                "url": "https://bankofamerica.com",
                "title": "Bank of America",
                "visit_time": datetime(2024, 1, 17, 10, 45, 0),
                "visit_count": 3
            }
        ]
        
        # Check for suspicious sites
        suspicious_sites = []
        threat_indicators = ["malware", "free-download", "phishing", "suspicious"]
        
        for entry in browsing_history:
            for indicator in threat_indicators:
                if indicator in entry["url"].lower():
                    suspicious_sites.append({
                        "url": entry["url"],
                        "title": entry["title"],
                        "visit_time": entry["visit_time"].isoformat(),
                        "threat": "Potentially malicious site"
                    })
        
        return browsing_history
    
    def analyze_photos_metadata(self) -> List[Dict]:
        """Analyze photo metadata"""
        # Simulated photo metadata
        photos = [
            {
                "filename": "IMG_001.jpg",
                "date_taken": datetime(2024, 1, 15, 12, 30, 0),
                "latitude": 37.7749,
                "longitude": -122.4194,
                "camera": "iPhone 15 Pro back camera",
                "size": 2048000  # 2MB
            },
            {
                "filename": "IMG_002.jpg", 
                "date_taken": datetime(2024, 1, 16, 8, 45, 0),
                "latitude": 40.7128,
                "longitude": -74.0060,
                "camera": "iPhone 15 Pro back camera", 
                "size": 1536000  # 1.5MB
            }
        ]
        
        self.photos = photos
        return photos

# Demo the iOS forensics
if __name__ == "__main__":
    print("🍎 iOS FORENSICS ANALYZER")
    print("="*60)
    
    forensics = iOSForensics("ios_backup")
    
    # Analyze device info
    print("\n📱 Device Information...")
    info = forensics.analyze_info_plist()
    print(f"Device: {info['Display Name']}")
    print(f"iOS Version: {info['Product Version']}")
    print(f"IMEI: {info['IMEI']}")
    
    # Analyze messages
    print("\n💬 Analyzing Messages...")
    messages = forensics.analyze_messages_db()
    print(f"Found {len(messages)} messages")
    
    imessages = len([m for m in messages if m.service == "iMessage"])
    sms = len([m for m in messages if m.service == "SMS"])
    print(f"  iMessages: {imessages}, SMS: {sms}")
    
    # Analyze calls
    print("\n📞 Analyzing Call History...")
    calls = forensics.analyze_call_history()
    print(f"Found {len(calls)} call records")
    
    # Analyze apps
    print("\n📲 Analyzing Installed Apps...")
    apps = forensics.analyze_installed_apps()
    print(f"Found {len(apps)} installed apps")
    
    # Analyze Safari
    print("\n🌐 Analyzing Safari History...")
    history = forensics.analyze_safari_history()
    print(f"Found {len(history)} history entries")
    
    # Analyze photos
    print("\n📸 Analyzing Photo Metadata...")
    photos = forensics.analyze_photos_metadata()
    print(f"Found {len(photos)} photos with GPS data")
```

### ✅ Checkpoint 2 Complete!
You can now analyze iOS backups. Ready for Module 3?

---

## 📘 Module 3: Cloud Storage Investigation (45 minutes)

**Learning Objective**: Examine cloud storage and synchronization artifacts

**What you'll build**: Cloud forensics analyzer for sync artifacts

### Step 1: Cloud Service Analysis

Create `cloud_forensics.py`:

```python
import json
import os
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib

@dataclass
class CloudFile:
    """Represents a file in cloud storage"""
    filename: str
    local_path: str
    cloud_path: str
    size: int
    hash_value: str
    sync_time: datetime
    sync_status: str
    service: str

@dataclass
class SyncEvent:
    """Represents a synchronization event"""
    timestamp: datetime
    event_type: str  # upload, download, delete, rename
    file_path: str
    service: str
    device_id: str
    user_account: str

class CloudForensics:
    """Cloud storage forensics analyzer"""
    
    def __init__(self):
        self.files: List[CloudFile] = []
        self.sync_events: List[SyncEvent] = []
        self.services = ["Dropbox", "Google Drive", "OneDrive", "iCloud"]
    
    def analyze_dropbox_artifacts(self) -> Dict:
        """Analyze Dropbox synchronization artifacts"""
        # Simulated Dropbox analysis
        dropbox_files = [
            CloudFile(
                filename="confidential_report.pdf",
                local_path="/Users/john/Dropbox/Documents/confidential_report.pdf",
                cloud_path="/Documents/confidential_report.pdf",
                size=2048000,
                hash_value="d41d8cd98f00b204e9800998ecf8427e",
                sync_time=datetime(2024, 1, 15, 14, 30, 0),
                sync_status="synced",
                service="Dropbox"
            ),
            CloudFile(
                filename="malware.exe",
                local_path="/Users/john/Dropbox/Downloads/malware.exe",
                cloud_path="/Downloads/malware.exe", 
                size=1024000,
                hash_value="e3b0c44298fc1c149afbf4c8996fb924",
                sync_time=datetime(2024, 1, 16, 10, 15, 0),
                sync_status="blocked",
                service="Dropbox"
            )
        ]
        
        sync_events = [
            SyncEvent(
                timestamp=datetime(2024, 1, 15, 14, 30, 0),
                event_type="upload",
                file_path="/Documents/confidential_report.pdf",
                service="Dropbox",
                device_id="DEVICE_12345",
                user_account="john.doe@company.com"
            ),
            SyncEvent(
                timestamp=datetime(2024, 1, 16, 10, 15, 0),
                event_type="upload_blocked",
                file_path="/Downloads/malware.exe",
                service="Dropbox", 
                device_id="DEVICE_12345",
                user_account="john.doe@company.com"
            )
        ]
        
        self.files.extend(dropbox_files)
        self.sync_events.extend(sync_events)
        
        return {
            "service": "Dropbox",
            "total_files": len(dropbox_files),
            "synced_files": len([f for f in dropbox_files if f.sync_status == "synced"]),
            "blocked_files": len([f for f in dropbox_files if f.sync_status == "blocked"]),
            "recent_events": len(sync_events)
        }
    
    def analyze_google_drive_artifacts(self) -> Dict:
        """Analyze Google Drive artifacts"""
        # Simulated Google Drive analysis
        gdrive_files = [
            CloudFile(
                filename="backup_database.sql",
                local_path="/Users/john/GoogleDrive/Backups/backup_database.sql",
                cloud_path="/Backups/backup_database.sql",
                size=10485760,  # 10MB
                hash_value="a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                sync_time=datetime(2024, 1, 17, 2, 0, 0),
                sync_status="synced",
                service="Google Drive"
            ),
            CloudFile(
                filename="suspicious_document.docx",
                local_path="/Users/john/GoogleDrive/Downloads/suspicious_document.docx",
                cloud_path="/Downloads/suspicious_document.docx",
                size=524288,  # 512KB
                hash_value="b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7",
                sync_time=datetime(2024, 1, 18, 9, 30, 0),
                sync_status="quarantined",
                service="Google Drive"
            )
        ]
        
        sync_events = [
            SyncEvent(
                timestamp=datetime(2024, 1, 17, 2, 0, 0),
                event_type="upload",
                file_path="/Backups/backup_database.sql",
                service="Google Drive",
                device_id="DEVICE_12345",
                user_account="john.doe@gmail.com"
            )
        ]
        
        self.files.extend(gdrive_files)
        self.sync_events.extend(sync_events)
        
        return {
            "service": "Google Drive", 
            "total_files": len(gdrive_files),
            "synced_files": len([f for f in gdrive_files if f.sync_status == "synced"]),
            "quarantined_files": len([f for f in gdrive_files if f.sync_status == "quarantined"]),
            "recent_events": len(sync_events)
        }
    
    def analyze_onedrive_artifacts(self) -> Dict:
        """Analyze OneDrive artifacts"""
        # Simulated OneDrive analysis
        onedrive_files = [
            CloudFile(
                filename="financial_records.xlsx", 
                local_path="C:\\Users\\john\\OneDrive\\Documents\\financial_records.xlsx",
                cloud_path="/Documents/financial_records.xlsx",
                size=1048576,  # 1MB
                hash_value="c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8",
                sync_time=datetime(2024, 1, 19, 16, 45, 0),
                sync_status="synced",
                service="OneDrive"
            )
        ]
        
        self.files.extend(onedrive_files)
        
        return {
            "service": "OneDrive",
            "total_files": len(onedrive_files),
            "synced_files": len([f for f in onedrive_files if f.sync_status == "synced"])
        }
    
    def detect_data_exfiltration(self) -> List[Dict]:
        """Detect potential data exfiltration via cloud services"""
        exfiltration_indicators = []
        
        # Check for large file uploads
        for event in self.sync_events:
            if event.event_type == "upload":
                file_obj = next((f for f in self.files if event.file_path in f.cloud_path), None)
                if file_obj and file_obj.size > 5242880:  # 5MB threshold
                    exfiltration_indicators.append({
                        "type": "Large file upload",
                        "file": file_obj.filename,
                        "size": file_obj.size,
                        "service": event.service,
                        "timestamp": event.timestamp.isoformat(),
                        "severity": "MEDIUM"
                    })
        
        # Check for unusual upload times (off-hours)
        for event in self.sync_events:
            if event.event_type == "upload":
                hour = event.timestamp.hour
                if hour < 6 or hour > 22:  # Outside normal hours
                    exfiltration_indicators.append({
                        "type": "Off-hours upload",
                        "file": event.file_path,
                        "service": event.service,
                        "timestamp": event.timestamp.isoformat(),
                        "severity": "HIGH"
                    })
        
        # Check for sensitive file names
        sensitive_keywords = ["confidential", "secret", "password", "private", "backup", "database"]
        for file_obj in self.files:
            for keyword in sensitive_keywords:
                if keyword in file_obj.filename.lower():
                    exfiltration_indicators.append({
                        "type": "Sensitive file uploaded",
                        "file": file_obj.filename,
                        "keyword": keyword,
                        "service": file_obj.service,
                        "timestamp": file_obj.sync_time.isoformat(),
                        "severity": "HIGH"
                    })
        
        return exfiltration_indicators
    
    def generate_cloud_timeline(self) -> List[Dict]:
        """Generate timeline of cloud activities"""
        timeline = []
        
        # Add sync events
        for event in self.sync_events:
            timeline.append({
                "timestamp": event.timestamp,
                "type": "sync_event",
                "description": f"{event.event_type.title()}: {event.file_path}",
                "service": event.service,
                "user": event.user_account
            })
        
        # Add file sync times
        for file_obj in self.files:
            timeline.append({
                "timestamp": file_obj.sync_time,
                "type": "file_sync",
                "description": f"File synced: {file_obj.filename}",
                "service": file_obj.service,
                "status": file_obj.sync_status
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline

# Demo the cloud forensics
if __name__ == "__main__":
    print("☁️ CLOUD FORENSICS ANALYZER")
    print("="*60)
    
    forensics = CloudForensics()
    
    # Analyze cloud services
    print("\n☁️ Analyzing Cloud Services...")
    dropbox = forensics.analyze_dropbox_artifacts()
    print(f"Dropbox: {dropbox['total_files']} files, {dropbox['blocked_files']} blocked")
    
    gdrive = forensics.analyze_google_drive_artifacts()
    print(f"Google Drive: {gdrive['total_files']} files, {gdrive['quarantined_files']} quarantined")
    
    onedrive = forensics.analyze_onedrive_artifacts()
    print(f"OneDrive: {onedrive['total_files']} files")
    
    # Detect exfiltration
    print("\n🚨 Checking for Data Exfiltration...")
    exfiltration = forensics.detect_data_exfiltration()
    if exfiltration:
        print(f"Found {len(exfiltration)} potential exfiltration indicators:")
        for indicator in exfiltration[:3]:  # Show first 3
            print(f"  - {indicator['type']}: {indicator['file']} [{indicator['severity']}]")
    
    # Generate timeline
    print("\n📅 Cloud Activity Timeline...")
    timeline = forensics.generate_cloud_timeline()
    print(f"Generated timeline with {len(timeline)} events")
    
    # Show recent events
    recent_events = sorted(timeline, key=lambda x: x["timestamp"], reverse=True)[:3]
    for event in recent_events:
        print(f"  {event['timestamp'].strftime('%Y-%m-%d %H:%M')} - {event['description']}")
```

### ✅ Checkpoint 3 Complete!
You can now analyze cloud storage artifacts. Ready for Module 4?

---

## 📘 Module 4: Mobile Forensics Toolkit (60 minutes)

**Learning Objective**: Build cross-platform mobile forensics toolkit

**What you'll build**: Unified mobile forensics platform

### Step 1: Integrated Mobile Forensics Platform

Create `mobile_forensics_toolkit.py`:

```python
import json
import os
from typing import List, Dict, Optional, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
from android_forensics import AndroidForensics
from ios_forensics import iOSForensics
from cloud_forensics import CloudForensics

@dataclass
class ForensicsCase:
    """Represents a mobile forensics case"""
    case_id: str
    case_name: str
    investigator: str
    created_date: datetime
    device_type: str  # android, ios
    device_info: Dict
    evidence_items: List[Dict]

@dataclass
class Finding:
    """Represents a forensics finding"""
    finding_id: str
    category: str  # communication, application, location, cloud
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str
    evidence: Dict
    timestamp: datetime
    confidence: float

class MobileForensicsToolkit:
    """Unified mobile forensics investigation platform"""
    
    def __init__(self, case_id: str, investigator: str):
        self.case = ForensicsCase(
            case_id=case_id,
            case_name=f"Mobile Investigation {case_id}",
            investigator=investigator,
            created_date=datetime.now(),
            device_type="unknown",
            device_info={},
            evidence_items=[]
        )
        self.findings: List[Finding] = []
        self.android_forensics = None
        self.ios_forensics = None
        self.cloud_forensics = CloudForensics()
        
    def analyze_android_device(self, device_path: str) -> Dict:
        """Analyze Android device"""
        self.case.device_type = "android"
        self.android_forensics = AndroidForensics(device_path)
        
        results = {}
        
        # SMS Analysis
        messages = self.android_forensics.analyze_sms_database()
        results["messages"] = {
            "total": len(messages),
            "suspicious": self._find_suspicious_messages(messages, "android")
        }
        
        # Contacts Analysis
        contacts = self.android_forensics.analyze_contacts_database()
        results["contacts"] = {"total": len(contacts)}
        
        # App Analysis
        apps = self.android_forensics.analyze_installed_apps()
        results["apps"] = {
            "total": len(apps),
            "suspicious": self._find_suspicious_apps(apps, "android")
        }
        
        # WiFi Analysis
        wifi = self.android_forensics.analyze_wifi_networks()
        results["wifi"] = {
            "total": len(wifi),
            "open_networks": len([n for n in wifi if n.get("security") == "Open"])
        }
        
        # Location Analysis
        locations = self.android_forensics.analyze_location_data()
        results["locations"] = {"total": len(locations)}
        
        self._generate_findings_android(results)
        return results
    
    def analyze_ios_device(self, backup_path: str) -> Dict:
        """Analyze iOS device backup"""
        self.case.device_type = "ios"
        self.ios_forensics = iOSForensics(backup_path)
        
        results = {}
        
        # Device Info
        device_info = self.ios_forensics.analyze_info_plist()
        self.case.device_info = device_info
        results["device_info"] = device_info
        
        # Messages Analysis
        messages = self.ios_forensics.analyze_messages_db()
        results["messages"] = {
            "total": len(messages),
            "imessages": len([m for m in messages if m.service == "iMessage"]),
            "sms": len([m for m in messages if m.service == "SMS"]),
            "suspicious": self._find_suspicious_messages(messages, "ios")
        }
        
        # Call History
        calls = self.ios_forensics.analyze_call_history()
        results["calls"] = {"total": len(calls)}
        
        # Apps Analysis
        apps = self.ios_forensics.analyze_installed_apps()
        results["apps"] = {
            "total": len(apps),
            "suspicious": self._find_suspicious_apps(apps, "ios")
        }
        
        # Safari History
        history = self.ios_forensics.analyze_safari_history()
        results["safari"] = {
            "total": len(history),
            "suspicious": self._find_suspicious_browsing(history)
        }
        
        # Photos Metadata
        photos = self.ios_forensics.analyze_photos_metadata()
        results["photos"] = {
            "total": len(photos),
            "with_location": len([p for p in photos if p.get("latitude")])
        }
        
        self._generate_findings_ios(results)
        return results
    
    def analyze_cloud_services(self) -> Dict:
        """Analyze cloud service artifacts"""
        results = {}
        
        # Analyze individual services
        dropbox = self.cloud_forensics.analyze_dropbox_artifacts()
        gdrive = self.cloud_forensics.analyze_google_drive_artifacts()
        onedrive = self.cloud_forensics.analyze_onedrive_artifacts()
        
        results["services"] = {
            "dropbox": dropbox,
            "google_drive": gdrive,
            "onedrive": onedrive
        }
        
        # Check for exfiltration
        exfiltration = self.cloud_forensics.detect_data_exfiltration()
        results["exfiltration_indicators"] = len(exfiltration)
        
        # Generate timeline
        timeline = self.cloud_forensics.generate_cloud_timeline()
        results["timeline_events"] = len(timeline)
        
        self._generate_findings_cloud(exfiltration)
        return results
    
    def _find_suspicious_messages(self, messages: List, platform: str) -> int:
        """Find suspicious messages across platforms"""
        suspicious_count = 0
        threat_keywords = ["urgent", "verify", "suspended", "click here", "prize", "winner"]
        
        for msg in messages:
            text = msg.body if platform == "android" else msg.text
            if any(keyword in text.lower() for keyword in threat_keywords):
                suspicious_count += 1
                
                # Create finding
                finding = Finding(
                    finding_id=f"MSG_{suspicious_count:03d}",
                    category="communication",
                    severity="MEDIUM",
                    description=f"Suspicious {platform.upper()} message detected",
                    evidence={
                        "platform": platform,
                        "message": text[:100] + "..." if len(text) > 100 else text,
                        "sender": msg.address if platform == "android" else msg.sender,
                        "timestamp": msg.date.isoformat() if platform == "android" else msg.timestamp.isoformat()
                    },
                    timestamp=datetime.now(),
                    confidence=0.7
                )
                self.findings.append(finding)
        
        return suspicious_count
    
    def _find_suspicious_apps(self, apps: List, platform: str) -> int:
        """Find suspicious applications"""
        suspicious_count = 0
        
        for app in apps:
            app_name = app.app_name if platform == "android" else app.name
            
            # Check for suspicious keywords
            if any(keyword in app_name.lower() for keyword in ["vpn", "free", "hack", "crack"]):
                suspicious_count += 1
                
                finding = Finding(
                    finding_id=f"APP_{suspicious_count:03d}",
                    category="application",
                    severity="MEDIUM",
                    description=f"Suspicious {platform.upper()} app detected",
                    evidence={
                        "platform": platform,
                        "app_name": app_name,
                        "package": app.package_name if platform == "android" else app.bundle_id,
                        "install_date": app.install_date if platform == "android" else app.install_date.isoformat()
                    },
                    timestamp=datetime.now(),
                    confidence=0.6
                )
                self.findings.append(finding)
        
        return suspicious_count
    
    def _find_suspicious_browsing(self, history: List[Dict]) -> int:
        """Find suspicious browsing history"""
        suspicious_count = 0
        threat_indicators = ["malware", "phishing", "suspicious", "hack"]
        
        for entry in history:
            url = entry["url"]
            if any(indicator in url.lower() for indicator in threat_indicators):
                suspicious_count += 1
                
                finding = Finding(
                    finding_id=f"WEB_{suspicious_count:03d}",
                    category="communication",
                    severity="HIGH",
                    description="Suspicious website visited",
                    evidence={
                        "url": url,
                        "title": entry["title"],
                        "visit_time": entry["visit_time"].isoformat(),
                        "visit_count": entry["visit_count"]
                    },
                    timestamp=datetime.now(),
                    confidence=0.8
                )
                self.findings.append(finding)
        
        return suspicious_count
    
    def _generate_findings_android(self, results: Dict):
        """Generate Android-specific findings"""
        # Open WiFi networks
        if results.get("wifi", {}).get("open_networks", 0) > 0:
            finding = Finding(
                finding_id="WIFI_001",
                category="location",
                severity="LOW",
                description="Connected to open WiFi networks",
                evidence={
                    "open_networks": results["wifi"]["open_networks"],
                    "platform": "android"
                },
                timestamp=datetime.now(),
                confidence=0.9
            )
            self.findings.append(finding)
    
    def _generate_findings_ios(self, results: Dict):
        """Generate iOS-specific findings"""
        # Check if device info indicates jailbreak
        device_info = results.get("device_info", {})
        ios_version = device_info.get("Product Version", "")
        
        # This is a simplified check - real implementation would be more comprehensive
        if "17." not in ios_version:
            finding = Finding(
                finding_id="DEV_001",
                category="application",
                severity="MEDIUM",
                description="Device running older iOS version",
                evidence={
                    "ios_version": ios_version,
                    "device": device_info.get("Display Name", "Unknown")
                },
                timestamp=datetime.now(),
                confidence=0.5
            )
            self.findings.append(finding)
    
    def _generate_findings_cloud(self, exfiltration_indicators: List[Dict]):
        """Generate cloud-specific findings"""
        for indicator in exfiltration_indicators:
            severity = indicator["severity"]
            finding = Finding(
                finding_id=f"CLD_{len(self.findings):03d}",
                category="cloud",
                severity=severity,
                description=indicator["type"],
                evidence=indicator,
                timestamp=datetime.now(),
                confidence=0.8 if severity == "HIGH" else 0.6
            )
            self.findings.append(finding)
    
    def generate_comprehensive_report(self) -> Dict:
        """Generate comprehensive investigation report"""
        # Calculate risk score
        severity_weights = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        total_risk = sum(severity_weights.get(f.severity, 0) * f.confidence for f in self.findings)
        max_risk = len(self.findings) * 4  # Max possible risk
        risk_score = (total_risk / max_risk * 100) if max_risk > 0 else 0
        
        # Categorize findings
        findings_by_category = {}
        for finding in self.findings:
            if finding.category not in findings_by_category:
                findings_by_category[finding.category] = []
            findings_by_category[finding.category].append(asdict(finding))
        
        # Get high-priority findings
        high_priority = [f for f in self.findings if f.severity in ["HIGH", "CRITICAL"]]
        
        report = {
            "case_info": asdict(self.case),
            "executive_summary": {
                "risk_score": round(risk_score, 1),
                "total_findings": len(self.findings),
                "high_priority_findings": len(high_priority),
                "categories_affected": len(findings_by_category),
                "investigation_date": datetime.now().isoformat()
            },
            "findings_by_category": findings_by_category,
            "high_priority_findings": [asdict(f) for f in high_priority],
            "recommendations": self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        # Check finding categories for specific recommendations
        categories = set(f.category for f in self.findings)
        
        if "communication" in categories:
            recommendations.append("Review and educate users about phishing and social engineering attacks")
        
        if "application" in categories:
            recommendations.append("Implement mobile application management (MAM) policies")
            recommendations.append("Regularly audit installed applications")
        
        if "cloud" in categories:
            recommendations.append("Implement data loss prevention (DLP) for cloud services")
            recommendations.append("Monitor and log cloud service activities")
        
        if "location" in categories:
            recommendations.append("Review WiFi connection policies and disable auto-connect")
        
        # General recommendations
        if len(self.findings) > 5:
            recommendations.append("Consider comprehensive mobile device security training")
            recommendations.append("Implement mobile device management (MDM) solution")
        
        return recommendations

# Demo the mobile forensics toolkit
if __name__ == "__main__":
    print("📱 MOBILE FORENSICS TOOLKIT")
    print("="*60)
    
    # Create investigation case
    toolkit = MobileForensicsToolkit("CASE_2024_001", "Investigator Smith")
    
    print(f"\n🔍 Starting Investigation: {toolkit.case.case_id}")
    print(f"Investigator: {toolkit.case.investigator}")
    
    # Analyze Android device (simulated)
    print("\n📱 Analyzing Android Device...")
    android_results = toolkit.analyze_android_device("android_device_path")
    print(f"Messages: {android_results['messages']['total']} ({android_results['messages']['suspicious']} suspicious)")
    print(f"Apps: {android_results['apps']['total']} ({android_results['apps']['suspicious']} suspicious)")
    
    # Analyze cloud services
    print("\n☁️ Analyzing Cloud Services...")
    cloud_results = toolkit.analyze_cloud_services()
    print(f"Exfiltration indicators: {cloud_results['exfiltration_indicators']}")
    print(f"Timeline events: {cloud_results['timeline_events']}")
    
    # Generate comprehensive report
    print("\n📊 Generating Report...")
    report = toolkit.generate_comprehensive_report()
    
    print(f"\n📋 INVESTIGATION SUMMARY")
    print("="*60)
    print(f"Risk Score: {report['executive_summary']['risk_score']}/100")
    print(f"Total Findings: {report['executive_summary']['total_findings']}")
    print(f"High Priority: {report['executive_summary']['high_priority_findings']}")
    
    if report["high_priority_findings"]:
        print(f"\n🚨 High Priority Findings:")
        for finding in report["high_priority_findings"][:3]:  # Show first 3
            print(f"  - [{finding['severity']}] {finding['description']}")
    
    if report["recommendations"]:
        print(f"\n💡 Recommendations:")
        for rec in report["recommendations"][:3]:  # Show first 3
            print(f"  - {rec}")
    
    # Save report
    report_filename = f"mobile_forensics_report_{toolkit.case.case_id}.json"
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"\n💾 Report saved as: {report_filename}")
```

### ✅ Checkpoint 4 Complete!

You've built a comprehensive mobile forensics toolkit!

---

## ✅ Tutorial Completion Checklist

After completing all modules, verify your understanding:

- [ ] You can analyze Android device artifacts (SMS, apps, WiFi, location)
- [ ] You understand iOS backup analysis and plist file parsing
- [ ] You can investigate cloud storage synchronization artifacts
- [ ] You know how to detect data exfiltration through cloud services
- [ ] You can build cross-platform mobile forensics tools
- [ ] You understand mobile device privacy and security implications

## 🚀 Ready for the Assignment?

Excellent! You now have the skills for comprehensive mobile forensics investigations. The assignment will test your ability to build production-quality mobile forensics tools.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **Android Forensics** - SMS/call analysis, app investigation, location tracking
2. **iOS Forensics** - Backup analysis, plist parsing, Safari artifacts
3. **Cloud Investigation** - Sync artifacts, exfiltration detection, timeline analysis  
4. **Cross-Platform Analysis** - Unified investigation workflows
5. **Evidence Correlation** - Linking mobile and cloud evidence
6. **Risk Assessment** - Scoring and prioritizing mobile security findings
7. **Reporting** - Professional mobile forensics documentation

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!
        wifi_networks = [
            {
                "ssid": "HomeNetwork",
                "bssid": "AA:BB:CC:DD:EE:FF",
                "security": "WPA2",
                "last_connected": "2024-01-17 08:00:00",
                "frequency": 2437,
                "saved_password": True
            },
            {
                "ssid": "Starbucks WiFi",
                "bssid": "11:22:33:44:55:66",
                "security": "Open",
                "last_connected": "2024-01-15 14:30:00",
                "frequency": 2412,
                "saved_password": False
            },
            {
                "ssid": "Office_Network",
                "bssid": "77:88:99:AA:BB:CC",
                "security": "WPA2-Enterprise",
                "last_connected": "2024-01-16 09:00:00",
                "frequency": 5180,
                "saved_password": True
            },
            {
                "ssid": "FreeWiFi",
                "bssid": "DD:EE:FF:00:11:22",
                "security": "Open",
                "last_connected": "2024-01-14 16:45:00",
                "frequency": 2437,
                "saved_password": False
            }
        ]
        
        self.wifi_networks = wifi_networks
        
        # Analyze security risks
        security_risks = []
        for network in wifi_networks:
            if network["security"] == "Open":
                security_risks.append({
                    "ssid": network["ssid"],
                    "risk": "Unencrypted network - data could be intercepted",
                    "last_used": network["last_connected"]
                })
        
        return wifi_networks
    
    def extract_browser_history(self) -> List[Dict]:
        """Extract browser history and searches"""
        # Simulated browser history
        browser_history = [
            {
                "url": "https://www.google.com/search?q=how+to+hide+files+android",
                "title": "how to hide files android - Google Search",
                "visit_time": "2024-01-17 10:15:00",
                "visit_count": 1
            },
            {
                "url": "https://www.facebook.com",
                "title": "Facebook",
                "visit_time": "2024-01-17 09:30:00",
                "visit_count": 45
            },
            {
                "url": "https://suspicious-download.com/free-vpn.apk",
                "title": "Download Free VPN",
                "visit_time": "2024-01-10 14:20:00",
                "visit_count": 1
            },
            {
                "url": "https://banking.com/login",
                "title": "MyBank - Login",
                "visit_time": "2024-01-16 11:00:00",
                "visit_count": 12
            }
        ]
        
        self.browser_history = browser_history
        
        # Extract search queries
        search_queries = []
        for entry in browser_history:
            if "search?q=" in entry["url"]:
                query = entry["url"].split("search?q=")[1].split("&")[0]
                query = query.replace("+", " ").replace("%20", " ")
                search_queries.append({
                    "query": query,
                    "time": entry["visit_time"]
                })
        
        return browser_history
    
    def analyze_app_databases(self, app_package: str) -> Dict:
        """Analyze specific app databases"""
        # Simulated app database analysis
        app_data = {}
        
        if app_package == "com.whatsapp":
            app_data = {
                "messages": 1250,
                "contacts": 89,
                "media_files": 456,
                "groups": 12,
                "last_backup": "2024-01-16 02:00:00",
                "encryption": "End-to-end encrypted"
            }
        elif app_package == "com.facebook.katana":
            app_data = {
                "cached_posts": 234,
                "friends": 456,
                "messages": 789,
                "photos": 123,
                "location_history": 45
            }
        
        return app_data
    
    def generate_timeline(self) -> List[Dict]:
        """Generate activity timeline"""
        timeline = []
        
        # Add messages to timeline
        for msg in self.messages:
            timeline.append({
                "timestamp": msg.date.isoformat(),
                "event": f"SMS {msg.message_type}",
                "details": f"Message with {msg.address}",
                "category": "Communication"
            })
        
        # Add calls to timeline
        for call in self.call_log:
            timeline.append({
                "timestamp": call["date"],
                "event": f"Call {call['type']}",
                "details": f"Call with {call['number']} ({call['duration']}s)",
                "category": "Communication"
            })
        
        # Add browser history
        for entry in self.browser_history:
            timeline.append({
                "timestamp": entry["visit_time"],
                "event": "Web browsing",
                "details": entry["title"],
                "category": "Internet"
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline
    
    def generate_report(self) -> Dict:
        """Generate comprehensive forensics report"""
        report = {
            "device_info": {
                "platform": "Android",
                "analysis_date": datetime.now().isoformat()
            },
            "summary": {
                "total_apps": len(self.apps),
                "total_messages": len(self.messages),
                "total_contacts": len(self.contacts),
                "total_calls": len(self.call_log),
                "wifi_networks": len(self.wifi_networks)
            },
            "suspicious_findings": [],
            "timeline_events": len(self.generate_timeline()),
            "recommendations": []
        }
        
        # Check for suspicious apps
        for app in self.apps:
            if "suspicious" in app.package_name or "vpn" in app.app_name.lower():
                report["suspicious_findings"].append(f"Suspicious app: {app.app_name}")
        
        # Check for suspicious messages
        for msg in self.messages:
            if "phishing" in msg.body.lower() or "click here" in msg.body.lower():
                report["suspicious_findings"].append(f"Potential phishing message from {msg.address}")
        
        # Generate recommendations
        if report["suspicious_findings"]:
            report["recommendations"].append("Review and remove suspicious applications")
            report["recommendations"].append("Educate user about phishing attempts")
        
        open_networks = [n for n in self.wifi_networks if n["security"] == "Open"]
        if open_networks:
            report["recommendations"].append("Avoid connecting to open WiFi networks")
        
        return report

# Demo the Android forensics
if __name__ == "__main__":
    print("🤖 ANDROID FORENSICS ANALYZER")
    print("="*60)
    
    analyzer = AndroidForensics("/path/to/android/image")
    
    # Analyze SMS
    print("\n📱 Analyzing SMS Messages...")
    messages = analyzer.analyze_sms_database()
    print(f"Found {len(messages)} messages")
    
    # Analyze contacts
    print("\n👥 Analyzing Contacts...")
    contacts = analyzer.analyze_contacts_database()
    print(f"Found {len(contacts)} contacts")
    
    # Analyze call log
    print("\n📞 Analyzing Call Log...")
    calls = analyzer.analyze_call_log()
    print(f"Found {len(calls)} calls")
    
    # Analyze apps
    print("\n📦 Analyzing Installed Apps...")
    apps = analyzer.analyze_installed_apps()
    print(f"Found {len(apps)} apps")
    for app in apps[:3]:  # Show first 3
        print(f"  - {app.app_name} ({app.package_name})")
    
    # Analyze WiFi
    print("\n📡 Analyzing WiFi Networks...")
    wifi = analyzer.analyze_wifi_networks()
    print(f"Found {len(wifi)} saved networks")
    
    # Generate report
    report = analyzer.generate_report()
    
    print("\n📊 FORENSICS REPORT")
    print("="*60)
    print(f"Total Apps: {report['summary']['total_apps']}")
    print(f"Total Messages: {report['summary']['total_messages']}")
    print(f"Total Contacts: {report['summary']['total_contacts']}")
    
    if report["suspicious_findings"]:
        print("\n⚠️ Suspicious Findings:")
        for finding in report["suspicious_findings"]:
            print(f"  - {finding}")
    
    if report["recommendations"]:
        print("\n💡 Recommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
```

**Run it:**
```bash
python android_forensics.py
```

### 💡 Key Concepts Learned

**Before moving to Module 2, make sure you understand:**

1. **Android File Structure**: Understanding /data/data/ and app sandboxing
2. **SQLite Databases**: Common Android data storage format  
3. **Permission Analysis**: Identifying risky app permissions
4. **Timeline Generation**: Reconstructing user activity

### ✅ Checkpoint 1 Complete!
You can now perform Android device forensics. Ready for Module 2?

---

## 📘 Module 2: iOS Device Analysis (60 minutes)

**Learning Objective**: Analyze iOS backups and extract application data

**What you'll build**: iOS backup analyzer for encrypted and unencrypted backups

### Step 1: iOS Backup Analysis

Create `ios_forensics.py`:

```python
import plistlib
import sqlite3
import os
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

@dataclass
class iOSApp:
    """Represents an iOS application"""
    bundle_id: str
    app_name: str
    version: str
    container_path: str
    entitlements: List[str]

@dataclass
class iMessage:
    """Represents an iMessage/SMS"""
    guid: str
    text: str
    service: str  # iMessage or SMS
    account: str
    date: datetime
    is_from_me: bool
    attachments: List[str]

class iOSForensics:
    """iOS device forensics analyzer"""
    
    def __init__(self, backup_path: str = None):
        self.backup_path = backup_path
        self.manifest = {}
        self.apps: List[iOSApp] = []
        self.messages: List[iMessage] = []
        self.photos = []
        self.keychain_items = []
        self.safari_history = []
    
    def parse_manifest_plist(self) -> Dict:
        """Parse backup manifest.plist"""
        # Simulated manifest parsing
        manifest = {
            "Version": "10.0",
            "Date": datetime(2024, 1, 17, 12, 0, 0),
            "SystemVersion": "17.2.1",
            "DeviceName": "iPhone",
            "PhoneNumber": "+1234567890",
            "SerialNumber": "F2LVF9GKH1234",
            "ProductType": "iPhone14,2",
            "ProductVersion": "17.2.1",
            "IsEncrypted": False
        }
        
        self.manifest = manifest
        return manifest
    
    def analyze_sms_db(self) -> List[iMessage]:
        """Analyze SMS/iMessage database"""
        # Simulated message analysis
        sample_messages = [
            iMessage(
                guid="message-001",
                text="Hey, did you see the news today?",
                service="iMessage",
                account="friend@icloud.com",
                date=datetime(2024, 1, 17, 10, 30, 0),
                is_from_me=False,
                attachments=[]
            ),
            iMessage(
                guid="message-002",
                text="Yes, crazy stuff happening!",
                service="iMessage",
                account="friend@icloud.com",
                date=datetime(2024, 1, 17, 10, 32, 0),
                is_from_me=True,
                attachments=[]
            ),
            iMessage(
                guid="message-003",
                text="Check out this photo",
                service="iMessage",
                account="family@icloud.com",
                date=datetime(2024, 1, 16, 15, 45, 0),
                is_from_me=False,
                attachments=["IMG_1234.HEIC"]
            ),
            iMessage(
                guid="message-004",
                text="Your verification code is 123456",
                service="SMS",
                account="+18005551234",
                date=datetime(2024, 1, 15, 9, 15, 0),
                is_from_me=False,
                attachments=[]
            )
        ]
        
        self.messages = sample_messages
        
        # Analyze for sensitive information
        sensitive_patterns = {
            "verification_codes": r"\b\d{4,6}\b",
            "credit_cards": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b"
        }
        
        sensitive_messages = []
        for msg in self.messages:
            if "verification" in msg.text.lower() or "code" in msg.text.lower():
                sensitive_messages.append({
                    "type": "2FA Code",
                    "from": msg.account,
                    "date": msg.date.isoformat()
                })
        
        return self.messages
    
    def analyze_photos_metadata(self) -> List[Dict]:
        """Analyze photo metadata and EXIF data"""
        # Simulated photo analysis
        photos = [
            {
                "filename": "IMG_1234.HEIC",
                "date_taken": "2024-01-15 14:30:00",
                "location": {
                    "latitude": 37.7749,
                    "longitude": -122.4194,
                    "place": "San Francisco, CA"
                },
                "device": "iPhone 14 Pro",
                "resolution": "4032x3024",
                "file_size": 2456789
            },
            {
                "filename": "IMG_1235.HEIC",
                "date_taken": "2024-01-16 10:15:00",
                "location": {
                    "latitude": 40.7128,
                    "longitude": -74.0060,
                    "place": "New York, NY"
                },
                "device": "iPhone 14 Pro",
                "resolution": "4032x3024",
                "file_size": 2234567
            },
            {
                "filename": "Screenshot_2024-01-17.PNG",
                "date_taken": "2024-01-17 09:45:00",
                "location": None,
                "device": "iPhone 14 Pro",
                "resolution": "1284x2778",
                "file_size": 1234567
            }
        ]
        
        self.photos = photos
        
        # Analyze location patterns
        location_analysis = {}
        for photo in photos:
            if photo["location"]:
                place = photo["location"]["place"]
                if place not in location_analysis:
                    location_analysis[place] = 0
                location_analysis[place] += 1
        
        return photos
    
    def analyze_safari_history(self) -> List[Dict]:
        """Analyze Safari browsing history"""
        # Simulated Safari history
        safari_history = [
            {
                "url": "https://www.apple.com",
                "title": "Apple",
                "visit_date": "2024-01-17 10:00:00",
                "visit_count": 15
            },
            {
                "url": "https://www.google.com/search?q=ios+jailbreak",
                "title": "ios jailbreak - Google Search",
                "visit_date": "2024-01-16 14:30:00",
                "visit_count": 1
            },
            {
                "url": "https://banking.com/app",
                "title": "Banking App",
                "visit_date": "2024-01-15 11:00:00",
                "visit_count": 8
            },
            {
                "url": "https://suspicious-site.com/download",
                "title": "Download Free Apps",
                "visit_date": "2024-01-14 16:45:00",
                "visit_count": 1
            }
        ]
        
        self.safari_history = safari_history
        
        # Check for suspicious activity
        suspicious_urls = []
        suspicious_keywords = ["jailbreak", "crack", "hack", "free", "download"]
        
        for entry in safari_history:
            if any(keyword in entry["url"].lower() for keyword in suspicious_keywords):
                suspicious_urls.append({
                    "url": entry["url"],
                    "title": entry["title"],
                    "date": entry["visit_date"]
                })
        
        return safari_history
    
    def analyze_keychain(self) -> List[Dict]:
        """Analyze keychain items (passwords, tokens)"""
        # Simulated keychain analysis
        keychain_items = [
            {
                "service": "com.apple.account.AppleAccount",
                "account": "user@icloud.com",
                "created": "2023-01-01 10:00:00",
                "modified": "2024-01-15 09:00:00",
                "access_group": "apple",
                "data_protected": True
            },
            {
                "service": "com.facebook.Facebook",
                "account": "user@email.com",
                "created": "2023-06-15 14:30:00",
                "modified": "2024-01-10 11:00:00",
                "access_group": "facebook",
                "data_protected": True
            },
            {
                "service": "WiFi",
                "account": "HomeNetwork",
                "created": "2023-03-20 09:00:00",
                "modified": "2023-03-20 09:00:00",
                "access_group": "wifi",
                "data_protected": False
            },
            {
                "service": "com.banking.app",
                "account": "user123",
                "created": "2023-05-01 10:00:00",
                "modified": "2024-01-16 11:00:00",
                "access_group": "banking",
                "data_protected": True
            }
        ]
        
        self.keychain_items = keychain_items
        
        # Analyze security
        security_analysis = {
            "total_items": len(keychain_items),
            "protected_items": len([k for k in keychain_items if k["data_protected"]]),
            "wifi_passwords": len([k for k in keychain_items if k["service"] == "WiFi"]),
            "banking_credentials": len([k for k in keychain_items if "banking" in k["service"].lower()])
        }
        
        return keychain_items
    
    def analyze_installed_apps(self) -> List[iOSApp]:
        """Analyze installed iOS applications"""
        # Simulated app analysis
        sample_apps = [
            iOSApp(
                bundle_id="com.apple.mobilephone",
                app_name="Phone",
                version="1.0",
                container_path="/var/mobile/Containers/Data/Application/Phone",
                entitlements=["com.apple.private.phone"]
            ),
            iOSApp(
                bundle_id="com.facebook.Facebook",
                app_name="Facebook",
                version="450.0",
                container_path="/var/mobile/Containers/Data/Application/Facebook",
                entitlements=["com.apple.security.application-groups"]
            ),
            iOSApp(
                bundle_id="net.whatsapp.WhatsApp",
                app_name="WhatsApp",
                version="24.1.80",
                container_path="/var/mobile/Containers/Data/Application/WhatsApp",
                entitlements=["com.apple.security.application-groups", "keychain-access-groups"]
            ),
            iOSApp(
                bundle_id="com.unknown.vpn",
                app_name="FreeVPN",
                version="1.0",
                container_path="/var/mobile/Containers/Data/Application/FreeVPN",
                entitlements=["com.apple.vpn.managed"]
            )
        ]
        
        self.apps = sample_apps
        
        # Check for risky apps
        risky_apps = []
        for app in self.apps:
            if "vpn" in app.bundle_id.lower() or "vpn" in app.app_name.lower():
                risky_apps.append({
                    "app": app.app_name,
                    "bundle_id": app.bundle_id,
                    "risk": "VPN app - may route traffic through untrusted servers"
                })
        
        return self.apps
    
    def check_jailbreak_artifacts(self) -> Dict:
        """Check for jailbreak artifacts"""
        jailbreak_indicators = {
            "cydia_installed": False,
            "suspicious_apps": [],
            "modified_system_files": [],
            "ssh_installed": False,
            "substrate_detected": False
        }
        
        # Check for common jailbreak apps
        jailbreak_apps = ["cydia", "sileo", "zebra", "installer", "icy"]
        for app in self.apps:
            if any(jb_app in app.bundle_id.lower() for jb_app in jailbreak_apps):
                jailbreak_indicators["suspicious_apps"].append(app.app_name)
                jailbreak_indicators["cydia_installed"] = True
        
        # Check Safari history for jailbreak sites
        jailbreak_sites = ["jailbreak", "cydia", "sileo", "checkra1n", "unc0ver"]
        for entry in self.safari_history:
            if any(site in entry["url"].lower() for site in jailbreak_sites):
                jailbreak_indicators["modified_system_files"].append(entry["url"])
        
        return jailbreak_indicators
    
    def generate_report(self) -> Dict:
        """Generate comprehensive iOS forensics report"""
        jailbreak = self.check_jailbreak_artifacts()
        
        report = {
            "device_info": {
                "platform": "iOS",
                "version": self.manifest.get("SystemVersion", "Unknown"),
                "device_name": self.manifest.get("DeviceName", "Unknown"),
                "serial": self.manifest.get("SerialNumber", "Unknown"),
                "encrypted_backup": self.manifest.get("IsEncrypted", False)
            },
            "summary": {
                "total_apps": len(self.apps),
                "total_messages": len(self.messages),
                "total_photos": len(self.photos),
                "keychain_items": len(self.keychain_items),
                "safari_history": len(self.safari_history)
            },
            "security_findings": {
                "jailbreak_detected": jailbreak["cydia_installed"] or len(jailbreak["suspicious_apps"]) > 0,
                "jailbreak_indicators": jailbreak,
                "suspicious_browsing": [],
                "risky_apps": []
            },
            "recommendations": []
        }
        
        # Add security findings
        for entry in self.safari_history:
            if "jailbreak" in entry["url"].lower() or "crack" in entry["url"].lower():
                report["security_findings"]["suspicious_browsing"].append(entry["url"])
        
        # Generate recommendations
        if report["security_findings"]["jailbreak_detected"]:
            report["recommendations"].append("Device appears to be jailbroken - increased security risk")
            report["recommendations"].append("Recommend factory reset and restore from clean backup")
        
        if not self.manifest.get("IsEncrypted", False):
            report["recommendations"].append("Enable encrypted backups for better data protection")
        
        return report

# Demo iOS forensics
if __name__ == "__main__":
    print("🍎 iOS FORENSICS ANALYZER")
    print("="*60)
    
    analyzer = iOSForensics("/path/to/ios/backup")
    
    # Parse manifest
    print("\n📱 Parsing Backup Manifest...")
    manifest = analyzer.parse_manifest_plist()
    print(f"Device: {manifest['DeviceName']} ({manifest['ProductType']})")
    print(f"iOS Version: {manifest['SystemVersion']}")
    print(f"Encrypted: {manifest['IsEncrypted']}")
    
    # Analyze messages
    print("\n💬 Analyzing Messages...")
    messages = analyzer.analyze_sms_db()
    print(f"Found {len(messages)} messages")
    
    # Analyze photos
    print("\n📸 Analyzing Photos...")
    photos = analyzer.analyze_photos_metadata()
    print(f"Found {len(photos)} photos with metadata")
    
    # Analyze Safari
    print("\n🌐 Analyzing Safari History...")
    safari = analyzer.analyze_safari_history()
    print(f"Found {len(safari)} browsing history entries")
    
    # Check jailbreak
    print("\n🔓 Checking for Jailbreak...")
    jailbreak = analyzer.check_jailbreak_artifacts()
    if jailbreak["cydia_installed"] or jailbreak["suspicious_apps"]:
        print("⚠️ Jailbreak indicators detected!")
    else:
        print("✅ No jailbreak indicators found")
    
    # Generate report
    report = analyzer.generate_report()
    
    print("\n📊 FORENSICS REPORT")
    print("="*60)
    print(f"Device: {report['device_info']['device_name']}")
    print(f"iOS Version: {report['device_info']['version']}")
    print(f"Total Apps: {report['summary']['total_apps']}")
    print(f"Total Messages: {report['summary']['total_messages']}")
    
    if report["security_findings"]["jailbreak_detected"]:
        print("\n⚠️ SECURITY WARNING: Device appears to be jailbroken")
    
    if report["recommendations"]:
        print("\n💡 Recommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
```

---

## 📘 Module 3: Cloud Storage Investigation (45 minutes)

**Learning Objective**: Analyze cloud storage and synchronization artifacts

**What you'll build**: Cloud storage analyzer for multiple platforms

Create `cloud_forensics.py`:

```python
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

@dataclass
class CloudFile:
    """Represents a file in cloud storage"""
    filename: str
    path: str
    size: int
    modified: datetime
    md5_hash: str
    shared: bool
    sync_status: str

@dataclass
class CloudAccount:
    """Represents a cloud storage account"""
    service: str
    account_email: str
    storage_used: int
    storage_quota: int
    last_sync: datetime

class CloudForensics:
    """Cloud storage forensics analyzer"""
    
    def __init__(self):
        self.accounts: List[CloudAccount] = []
        self.files: List[CloudFile] = []
        self.sync_conflicts = []
        self.deleted_files = []
        self.shared_links = []
    
    def analyze_icloud_artifacts(self) -> Dict:
        """Analyze iCloud synchronization artifacts"""
        icloud_data = {
            "account": "user@icloud.com",
            "services": ["Photos", "Drive", "Backup", "Mail", "Contacts"],
            "last_backup": "2024-01-17 02:00:00",
            "storage_used_gb": 12.5,
            "storage_total_gb": 50,
            "synced_devices": [
                {"name": "iPhone 14 Pro", "last_sync": "2024-01-17 12:00:00"},
                {"name": "MacBook Pro", "last_sync": "2024-01-17 11:45:00"},
                {"name": "iPad Air", "last_sync": "2024-01-16 22:30:00"}
            ],
            "photo_library": {
                "total_photos": 5432,
                "total_videos": 234,
                "shared_albums": 12,
                "size_gb": 8.7
            }
        }
        
        # Check for suspicious activity
        suspicious_activity = []
        
        # Check for unusual sync patterns
        devices = icloud_data["synced_devices"]
        for device in devices:
            sync_time = datetime.strptime(device["last_sync"], "%Y-%m-%d %H:%M:%S")
            if (datetime.now() - sync_time).days > 7:
                suspicious_activity.append(f"Device {device['name']} hasn't synced in over a week")
        
        return icloud_data
    
    def analyze_google_drive(self) -> Dict:
        """Analyze Google Drive artifacts"""
        drive_files = [
            CloudFile(
                filename="ProjectReport.docx",
                path="/Documents/Work/",
                size=245678,
                modified=datetime(2024, 1, 15, 10, 30, 0),
                md5_hash="a1b2c3d4e5f6",
                shared=True,
                sync_status="synced"
            ),
            CloudFile(
                filename="passwords.txt",
                path="/Personal/",
                size=1234,
                modified=datetime(2024, 1, 10, 14, 20, 0),
                md5_hash="f6e5d4c3b2a1",
                shared=False,
                sync_status="synced"
            ),
            CloudFile(
                filename="TaxReturn2023.pdf",
                path="/Documents/Financial/",
                size=567890,
                modified=datetime(2024, 1, 5, 9, 15, 0),
                md5_hash="9876543210ab",
                shared=False,
                sync_status="synced"
            )
        ]
        
        self.files.extend(drive_files)
        
        # Analyze for sensitive files
        sensitive_files = []
        sensitive_keywords = ["password", "tax", "ssn", "credit", "bank"]
        
        for file in drive_files:
            if any(keyword in file.filename.lower() for keyword in sensitive_keywords):
                sensitive_files.append({
                    "file": file.filename,
                    "path": file.path,
                    "shared": file.shared,
                    "risk": "Contains potentially sensitive information"
                })
        
        return {
            "service": "Google Drive",
            "total_files": len(drive_files),
            "sensitive_files": sensitive_files,
            "shared_files": [f for f in drive_files if f.shared]
        }
    
    def analyze_dropbox(self) -> Dict:
        """Analyze Dropbox synchronization"""
        dropbox_data = {
            "account": "user@email.com",
            "storage_used_gb": 8.2,
            "storage_total_gb": 15,
            "shared_folders": [
                {"name": "Team Project", "members": 5, "size_mb": 1234},
                {"name": "Family Photos", "members": 3, "size_mb": 5678}
            ],
            "recent_activity": [
                {"action": "file_uploaded", "file": "presentation.pptx", "time": "2024-01-17 10:00:00"},
                {"action": "file_deleted", "file": "old_document.doc", "time": "2024-01-16 15:30:00"},
                {"action": "folder_shared", "folder": "Project Files", "time": "2024-01-15 09:00:00"}
            ]
        }
        
        # Track deleted files
        for activity in dropbox_data["recent_activity"]:
            if activity["action"] == "file_deleted":
                self.deleted_files.append({
                    "service": "Dropbox",
                    "file": activity["file"],
                    "deletion_time": activity["time"]
                })
        
        return dropbox_data
    
    def analyze_onedrive(self) -> Dict:
        """Analyze Microsoft OneDrive"""
        onedrive_data = {
            "account": "user@outlook.com",
            "storage_used_gb": 3.5,
            "storage_total_gb": 5,
            "vault_enabled": True,
            "vault_files": 12,
            "office_documents": 145,
            "recycle_bin_items": 23,
            "version_history": [
                {"file": "Budget2024.xlsx", "versions": 5, "last_modified": "2024-01-16"},
                {"file": "Presentation.pptx", "versions": 8, "last_modified": "2024-01-15"}
            ]
        }
        
        return onedrive_data
    
    def detect_data_exfiltration(self) -> List[Dict]:
        """Detect potential data exfiltration patterns"""
        exfiltration_indicators = []
        
        # Check for mass downloads
        download_threshold = 50  # files
        size_threshold = 1024 * 1024 * 1024  # 1GB
        
        # Simulated download activity
        download_activity = {
            "2024-01-15": {"files": 75, "size": 2147483648},  # 2GB
            "2024-01-16": {"files": 10, "size": 104857600},   # 100MB
            "2024-01-17": {"files": 5, "size": 52428800}      # 50MB
        }
        
        for date, activity in download_activity.items():
            if activity["files"] > download_threshold or activity["size"] > size_threshold:
                exfiltration_indicators.append({
                    "date": date,
                    "files_downloaded": activity["files"],
                    "total_size": activity["size"],
                    "risk": "Potential data exfiltration - unusual download activity"
                })
        
        # Check for suspicious sharing patterns
        if len([f for f in self.files if f.shared]) > 10:
            exfiltration_indicators.append({
                "indicator": "Excessive file sharing",
                "shared_files": len([f for f in self.files if f.shared]),
                "risk": "Many files shared externally"
            })
        
        return exfiltration_indicators
    
    def analyze_sync_conflicts(self) -> List[Dict]:
        """Analyze file synchronization conflicts"""
        conflicts = [
            {
                "file": "Report.docx",
                "conflict_time": "2024-01-16 10:30:00",
                "devices": ["iPhone", "MacBook"],
                "resolution": "Kept MacBook version"
            },
            {
                "file": "notes.txt",
                "conflict_time": "2024-01-15 14:20:00",
                "devices": ["iPad", "iPhone"],
                "resolution": "Merged changes"
            }
        ]
        
        self.sync_conflicts = conflicts
        return conflicts
    
    def generate_report(self) -> Dict:
        """Generate cloud forensics report"""
        exfiltration = self.detect_data_exfiltration()
        
        report = {
            "summary": {
                "cloud_accounts": len(self.accounts),
                "total_files": len(self.files),
                "deleted_files": len(self.deleted_files),
                "sync_conflicts": len(self.sync_conflicts),
                "shared_files": len([f for f in self.files if f.shared])
            },
            "security_concerns": {
                "data_exfiltration": len(exfiltration) > 0,
                "exfiltration_indicators": exfiltration,
                "sensitive_files_shared": [],
                "deleted_sensitive_files": []
            },
            "recommendations": []
        }
        
        # Check for sensitive files that are shared
        sensitive_keywords = ["password", "tax", "ssn", "credit"]
        for file in self.files:
            if file.shared and any(kw in file.filename.lower() for kw in sensitive_keywords):
                report["security_concerns"]["sensitive_files_shared"].append(file.filename)
        
        # Generate recommendations
        if report["security_concerns"]["data_exfiltration"]:
            report["recommendations"].append("Investigate potential data exfiltration activity")
        
        if report["security_concerns"]["sensitive_files_shared"]:
            report["recommendations"].append("Review and revoke sharing for sensitive files")
        
        if len(self.deleted_files) > 20:
            report["recommendations"].append("Large number of deleted files - check for data destruction")
        
        return report

# Demo cloud forensics
if __name__ == "__main__":
    print("☁️ CLOUD STORAGE FORENSICS")
    print("="*60)
    
    analyzer = CloudForensics()
    
    # Analyze iCloud
    print("\n🍎 Analyzing iCloud...")
    icloud = analyzer.analyze_icloud_artifacts()
    print(f"Account: {icloud['account']}")
    print(f"Storage: {icloud['storage_used_gb']}/{icloud['storage_total_gb']} GB")
    print(f"Synced Devices: {len(icloud['synced_devices'])}")
    
    # Analyze Google Drive
    print("\n📁 Analyzing Google Drive...")
    drive = analyzer.analyze_google_drive()
    print(f"Total Files: {drive['total_files']}")
    print(f"Sensitive Files: {len(drive['sensitive_files'])}")
    
    # Analyze Dropbox
    print("\n📦 Analyzing Dropbox...")
    dropbox = analyzer.analyze_dropbox()
    print(f"Shared Folders: {len(dropbox['shared_folders'])}")
    print(f"Recent Activity: {len(dropbox['recent_activity'])} events")
    
    # Check for exfiltration
    print("\n🔍 Checking for Data Exfiltration...")
    exfiltration = analyzer.detect_data_exfiltration()
    if exfiltration:
        print(f"⚠️ Found {len(exfiltration)} potential exfiltration indicators")
        for indicator in exfiltration:
            print(f"  - {indicator.get('risk', 'Unknown risk')}")
    
    # Generate report
    report = analyzer.generate_report()
    
    print("\n📊 CLOUD FORENSICS REPORT")
    print("="*60)
    print(f"Total Files: {report['summary']['total_files']}")
    print(f"Shared Files: {report['summary']['shared_files']}")
    print(f"Deleted Files: {report['summary']['deleted_files']}")
    
    if report["security_concerns"]["data_exfiltration"]:
        print("\n⚠️ SECURITY ALERT: Potential data exfiltration detected")
    
    if report["recommendations"]:
        print("\n💡 Recommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
```

---

## 📘 Module 4: Mobile Forensics Toolkit (60 minutes)

**Learning Objective**: Build integrated mobile forensics toolkit

**What you'll build**: Unified toolkit for cross-platform mobile analysis

Create `mobile_toolkit.py`:

```python
from typing import Dict, List, Any
from datetime import datetime
import json
import os

class MobileForensicsToolkit:
    """Integrated mobile forensics toolkit"""
    
    def __init__(self):
        self.android_analyzer = AndroidForensics()
        self.ios_analyzer = iOSForensics()
        self.cloud_analyzer = CloudForensics()
        self.timeline = []
        self.unified_report = {}
    
    def run_full_analysis(self, device_type: str, data_path: str) -> Dict:
        """Run complete mobile forensics analysis"""
        print(f"\n🚀 Starting Mobile Forensics Analysis")
        print(f"   Device Type: {device_type}")
        print(f"   Data Path: {data_path}")
        print("="*60)
        
        results = {
            "device_type": device_type,
            "analysis_date": datetime.now().isoformat(),
            "findings": {}
        }
        
        # Phase 1: Device Analysis
        print("\n📱 Phase 1: Device Analysis")
        if device_type.lower() == "android":
            device_results = self._analyze_android(data_path)
        elif device_type.lower() == "ios":
            device_results = self._analyze_ios(data_path)
        else:
            device_results = {"error": "Unknown device type"}
        
        results["findings"]["device"] = device_results
        
        # Phase 2: Cloud Analysis
        print("\n☁️ Phase 2: Cloud Storage Analysis")
        cloud_results = self._analyze_cloud()
        results["findings"]["cloud"] = cloud_results
        
        # Phase 3: Cross-Platform Correlation
        print("\n🔗 Phase 3: Cross-Platform Correlation")
        correlation_results = self._correlate_data(device_results, cloud_results)
        results["findings"]["correlation"] = correlation_results
        
        # Phase 4: Timeline Generation
        print("\n📅 Phase 4: Timeline Generation")
        timeline = self._generate_unified_timeline(results)
        results["timeline"] = timeline
        
        # Phase 5: Threat Assessment
        print("\n⚠️ Phase 5: Threat Assessment")
        threats = self._assess_threats(results)
        results["threats"] = threats
        
        self.unified_report = results
        return results
    
    def _analyze_android(self, data_path: str) -> Dict:
        """Run Android analysis"""
        analyzer = self.android_analyzer
        
        # Run all Android analyses
        analyzer.analyze_sms_database()
        analyzer.analyze_contacts_database()
        analyzer.analyze_call_log()
        analyzer.analyze_installed_apps()
        analyzer.analyze_wifi_networks()
        analyzer.extract_browser_history()
        
        return analyzer.generate_report()
    
    def _analyze_ios(self, data_path: str) -> Dict:
        """Run iOS analysis"""
        analyzer = self.ios_analyzer
        
        # Run all iOS analyses
        analyzer.parse_manifest_plist()
        analyzer.analyze_sms_db()
        analyzer.analyze_photos_metadata()
        analyzer.analyze_safari_history()
        analyzer.analyze_keychain()
        analyzer.analyze_installed_apps()
        
        return analyzer.generate_report()
    
    def _analyze_cloud(self) -> Dict:
        """Run cloud storage analysis"""
        analyzer = self.cloud_analyzer
        
        # Analyze all cloud services
        icloud = analyzer.analyze_icloud_artifacts()
        google_drive = analyzer.analyze_google_drive()
        dropbox = analyzer.analyze_dropbox()
        onedrive = analyzer.analyze_onedrive()
        
        return {
            "icloud": icloud,
            "google_drive": google_drive,
            "dropbox": dropbox,
            "onedrive": onedrive,
            "report": analyzer.generate_report()
        }
    
    def _correlate_data(self, device_data: Dict, cloud_data: Dict) -> Dict:
        """Correlate device and cloud data"""
        correlations = {
            "matched_accounts": [],
            "data_discrepancies": [],
            "sync_status": {},
            "cross_platform_activity": []
        }
        
        # Match accounts across platforms
        if "user@icloud.com" in str(device_data) and "user@icloud.com" in str(cloud_data):
            correlations["matched_accounts"].append({
                "account": "user@icloud.com",
                "device": "iOS",
                "cloud_services": ["iCloud"]
            })
        
        # Check for data discrepancies
        # Example: photos on device vs cloud
        device_photos = device_data.get("summary", {}).get("total_photos", 0)
        cloud_photos = cloud_data.get("icloud", {}).get("photo_library", {}).get("total_photos", 0)
        
        if abs(device_photos - cloud_photos) > 100:
            correlations["data_discrepancies"].append({
                "type": "Photo count mismatch",
                "device_count": device_photos,
                "cloud_count": cloud_photos,
                "difference": abs(device_photos - cloud_photos)
            })
        
        return correlations
    
    def _generate_unified_timeline(self, results: Dict) -> List[Dict]:
        """Generate unified timeline across all data sources"""
        timeline = []
        
        # Add device events
        if "device" in results["findings"]:
            # Add messages, calls, app installs, etc.
            timeline.append({
                "timestamp": "2024-01-17 10:30:00",
                "source": "Device",
                "event": "SMS Received",
                "details": "Message from +1234567890"
            })
        
        # Add cloud events
        if "cloud" in results["findings"]:
            # Add file uploads, shares, deletions, etc.
            timeline.append({
                "timestamp": "2024-01-17 10:00:00",
                "source": "Cloud",
                "event": "File Upload",
                "details": "presentation.pptx uploaded to Dropbox"
            })
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline
    
    def _assess_threats(self, results: Dict) -> Dict:
        """Assess security threats across all data"""
        threats = {
            "risk_level": "MEDIUM",
            "threat_categories": [],
            "immediate_concerns": [],
            "recommendations": []
        }
        
        # Check for malware indicators
        if "suspicious_findings" in str(results):
            threats["threat_categories"].append("Potential Malware")
            threats["risk_level"] = "HIGH"
        
        # Check for data exfiltration
        if "exfiltration" in str(results):
            threats["threat_categories"].append("Data Exfiltration")
            threats["immediate_concerns"].append("Unusual data transfer activity detected")
        
        # Check for account compromise
        if "jailbreak" in str(results) or "root" in str(results):
            threats["threat_categories"].append("Device Compromise")
            threats["immediate_concerns"].append("Device security has been bypassed")
        
        # Generate recommendations
        if threats["risk_level"] == "HIGH":
            threats["recommendations"].append("Immediate security review required")
            threats["recommendations"].append("Change all passwords")
            threats["recommendations"].append("Enable two-factor authentication")
        
        return threats
    
    def export_report(self, output_dir: str = "mobile_forensics_output"):
        """Export comprehensive forensics report"""
        os.makedirs(output_dir, exist_ok=True)
        
        # Export JSON report
        json_path = os.path.join(output_dir, "mobile_forensics_report.json")
        with open(json_path, 'w') as f:
            json.dump(self.unified_report, f, indent=2, default=str)
        
        # Export timeline
        timeline_path = os.path.join(output_dir, "timeline.json")
        if "timeline" in self.unified_report:
            with open(timeline_path, 'w') as f:
                json.dump(self.unified_report["timeline"], f, indent=2)
        
        # Export executive summary
        summary_path = os.path.join(output_dir, "executive_summary.txt")
        with open(summary_path, 'w') as f:
            self._write_executive_summary(f)
        
        print(f"\n📁 Reports exported to: {output_dir}")
        return output_dir
    
    def _write_executive_summary(self, file):
        """Write executive summary to file"""
        file.write("MOBILE FORENSICS EXECUTIVE SUMMARY\n")
        file.write("="*50 + "\n\n")
        
        file.write(f"Analysis Date: {self.unified_report.get('analysis_date', 'Unknown')}\n")
        file.write(f"Device Type: {self.unified_report.get('device_type', 'Unknown')}\n\n")
        
        threats = self.unified_report.get("threats", {})
        file.write(f"Risk Level: {threats.get('risk_level', 'Unknown')}\n")
        
        if threats.get("immediate_concerns"):
            file.write("\nImmediate Concerns:\n")
            for concern in threats["immediate_concerns"]:
                file.write(f"  - {concern}\n")
        
        if threats.get("recommendations"):
            file.write("\nRecommendations:\n")
            for rec in threats["recommendations"]:
                file.write(f"  - {rec}\n")

# Demo the toolkit
if __name__ == "__main__":
    # Import the analyzers
    from android_forensics import AndroidForensics
    from ios_forensics import iOSForensics
    from cloud_forensics import CloudForensics
    
    print("🔧 MOBILE FORENSICS TOOLKIT")
    print("="*60)
    
    toolkit = MobileForensicsToolkit()
    
    # Run analysis (choose device type)
    device_type = "android"  # or "ios"
    data_path = "/path/to/device/data"
    
    # Run full analysis
    results = toolkit.run_full_analysis(device_type, data_path)
    
    print("\n📊 ANALYSIS COMPLETE")
    print("="*60)
    
    # Display summary
    threats = results.get("threats", {})
    print(f"Risk Level: {threats.get('risk_level', 'UNKNOWN')}")
    
    if threats.get("threat_categories"):
        print("\n🔍 Detected Threats:")
        for threat in threats["threat_categories"]:
            print(f"  - {threat}")
    
    if threats.get("immediate_concerns"):
        print("\n⚠️ Immediate Concerns:")
        for concern in threats["immediate_concerns"]:
            print(f"  - {concern}")
    
    # Export reports
    output_dir = toolkit.export_report()
    
    print("\n✅ Analysis complete!")
    print(f"📁 Full reports available in: {output_dir}")
```

---

## ✅ Tutorial Completion Checklist

After completing all modules, verify your understanding:

- [ ] You can extract and analyze Android app data and databases
- [ ] You understand iOS backup structure and artifact extraction
- [ ] You can investigate cloud storage synchronization patterns
- [ ] You know how to detect mobile malware and suspicious apps
- [ ] You can correlate data across device and cloud platforms
- [ ] You understand mobile security threats and jailbreak/root detection

## 🚀 Ready for the Assignment?

Great! Now you have all the tools for mobile and cloud forensics. The assignment will combine these concepts into a comprehensive investigation.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **Android Forensics** including SQLite databases and app analysis
2. **iOS Backup Analysis** with plist parsing and keychain extraction
3. **Cloud Storage Investigation** across multiple platforms
4. **Mobile Malware Detection** and suspicious app identification
5. **Cross-Platform Correlation** for comprehensive analysis
6. **Timeline Generation** from multiple data sources
7. **Threat Assessment** and security recommendations

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!