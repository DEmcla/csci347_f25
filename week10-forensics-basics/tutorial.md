# Week 10 Tutorial: Digital Forensics Foundations

**Estimated Time**: 4-5 hours  
**Prerequisites**: Week 9 completed, understanding of file systems and security architecture

## 🎯 Tutorial Goals

By the end of this tutorial, you will have:
1. **Part 1** (60 min): Implemented evidence acquisition and imaging procedures
2. **Part 2** (60 min): Built file system analysis tools with The Sleuth Kit integration  
3. **Part 3** (60 min): Created timeline analysis and event correlation systems
4. **Part 4** (90 min): Developed artifact extraction and analysis automation
5. **Part 5** (45 min): Built forensics reporting and chain of custody tools

### 📊 Progress Tracking
Complete each module and run its checkpoint before proceeding:
- [ ] Part 1: Evidence Acquisition and Imaging ✅ Checkpoint 1
- [ ] Part 2: File System Analysis ✅ Checkpoint 2
- [ ] Part 3: Timeline Analysis ✅ Checkpoint 3
- [ ] Part 4: Artifact Extraction ✅ Checkpoint 4
- [ ] Part 5: Forensics Reporting ✅ Checkpoint 5

## 🔧 Setup Check

Before we begin, verify your environment:

```bash
# Check Python version
python --version  # Should be 3.11+

# Install required packages
pip install pytsk3 dfvfs plaso pytz python-registry hashlib

# Check installations
python -c "import pytsk3; print('✅ The Sleuth Kit Python bindings ready')"

# Install forensics tools (Linux/macOS)
# sudo apt-get install sleuthkit autopsy ewf-tools  # Ubuntu/Debian
# brew install sleuthkit libewf  # macOS

# Create working directory
mkdir week10-forensics
cd week10-forensics
```

---

## 📘 Part 1: Evidence Acquisition and Imaging (60 minutes)

**Learning Objective**: Implement forensically sound evidence acquisition procedures

**What you'll build**: Evidence imaging and verification tools with chain of custody

### Step 1: Digital Evidence Imaging

Create `evidence_acquisition.py`:

```python
import hashlib
import subprocess
import os
import json
from datetime import datetime
from pathlib import Path
import shutil
from dataclasses import dataclass, asdict
from typing import Optional, Dict, List

@dataclass
class EvidenceMetadata:
    """Evidence acquisition metadata"""
    case_number: str
    evidence_id: str
    device_description: str
    serial_number: str
    make_model: str
    acquisition_date: datetime
    examiner: str
    acquisition_method: str
    source_hash_md5: str
    source_hash_sha256: str
    image_hash_md5: str
    image_hash_sha256: str
    verification_status: str
    notes: str = ""
    file_size_bytes: int = 0
    sector_size: int = 512
    total_sectors: int = 0

class ForensicImager:
    """Forensically sound evidence acquisition"""
    
    def __init__(self, case_directory: str):
        self.case_directory = Path(case_directory)
        self.case_directory.mkdir(parents=True, exist_ok=True)
        
        # Create standard forensics directory structure
        (self.case_directory / "evidence").mkdir(exist_ok=True)
        (self.case_directory / "images").mkdir(exist_ok=True)
        (self.case_directory / "reports").mkdir(exist_ok=True)
        (self.case_directory / "logs").mkdir(exist_ok=True)
        
        print(f"✅ Forensic case directory initialized: {self.case_directory}")
    
    def create_dd_image(self, source_device: str, evidence_id: str, 
                       case_number: str, examiner: str,
                       block_size: int = 4096) -> EvidenceMetadata:
        """
        Create forensically sound dd image
        
        Args:
            source_device: Path to source device/file
            evidence_id: Unique evidence identifier
            case_number: Case number
            examiner: Examiner name
            block_size: Block size for dd operation
            
        Returns:
            EvidenceMetadata: Complete metadata for acquired evidence
        """
        print(f"🔍 Starting forensic acquisition of {source_device}")
        
        # Generate output filename
        image_filename = f"{case_number}_{evidence_id}.dd"
        image_path = self.case_directory / "images" / image_filename
        
        # Create log file
        log_filename = f"{case_number}_{evidence_id}_acquisition.log"
        log_path = self.case_directory / "logs" / log_filename
        
        # Get source device information (if it's a real device)
        device_info = self._get_device_info(source_device)
        
        # Calculate source hash BEFORE imaging (for verification)
        print("📊 Calculating source hash (this may take time)...")
        source_md5, source_sha256 = self._calculate_file_hashes(source_device)
        
        # Perform dd acquisition
        print(f"💾 Creating forensic image: {image_path}")
        try:
            # Use dd with forensic parameters
            dd_command = [
                'dd',
                f'if={source_device}',
                f'of={image_path}',
                f'bs={block_size}',
                'conv=noerror,sync',
                'status=progress'
            ]
            
            with open(log_path, 'w') as log_file:
                log_file.write(f"Forensic Acquisition Log\n")
                log_file.write(f"Case: {case_number}\n")
                log_file.write(f"Evidence: {evidence_id}\n")
                log_file.write(f"Examiner: {examiner}\n")
                log_file.write(f"Start Time: {datetime.now().isoformat()}\n")
                log_file.write(f"Command: {' '.join(dd_command)}\n\n")
                
                # Execute dd command
                result = subprocess.run(
                    dd_command,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                
                log_file.write(f"\nEnd Time: {datetime.now().isoformat()}\n")
                log_file.write(f"Exit Code: {result.returncode}\n")
            
            if result.returncode != 0:
                raise Exception(f"dd command failed with exit code {result.returncode}")
            
        except Exception as e:
            print(f"❌ Imaging failed: {e}")
            raise
        
        # Calculate image hashes for verification
        print("🔐 Verifying image integrity...")
        image_md5, image_sha256 = self._calculate_file_hashes(str(image_path))
        
        # Verify hashes match
        verification_status = "VERIFIED" if (source_md5 == image_md5 and source_sha256 == image_sha256) else "FAILED"
        
        # Get file statistics
        stat = image_path.stat()
        
        # Create metadata
        metadata = EvidenceMetadata(
            case_number=case_number,
            evidence_id=evidence_id,
            device_description=device_info.get('description', 'Unknown device'),
            serial_number=device_info.get('serial', 'Unknown'),
            make_model=device_info.get('model', 'Unknown'),
            acquisition_date=datetime.now(),
            examiner=examiner,
            acquisition_method="dd",
            source_hash_md5=source_md5,
            source_hash_sha256=source_sha256,
            image_hash_md5=image_md5,
            image_hash_sha256=image_sha256,
            verification_status=verification_status,
            file_size_bytes=stat.st_size,
            sector_size=512,
            total_sectors=stat.st_size // 512
        )
        
        # Save metadata
        self._save_metadata(metadata)
        
        print(f"✅ Acquisition complete: {verification_status}")
        print(f"   Image size: {stat.st_size:,} bytes")
        print(f"   Source MD5: {source_md5}")
        print(f"   Image MD5:  {image_md5}")
        
        return metadata
    
    def create_test_evidence(self, size_mb: int = 10) -> str:
        """Create test evidence file for demonstration"""
        test_file = self.case_directory / "test_evidence.bin"
        
        # Create test file with random data
        print(f"🧪 Creating test evidence file ({size_mb} MB)")
        
        with open(test_file, 'wb') as f:
            # Write some identifiable data
            f.write(b"FORENSICS_TEST_EVIDENCE\n")
            f.write(f"Created: {datetime.now().isoformat()}\n".encode())
            f.write(b"This is a test file for forensic imaging demonstration.\n")
            f.write(b"Contains sample data for practice.\n\n")
            
            # Fill with pseudo-random data
            import random
            remaining_bytes = (size_mb * 1024 * 1024) - f.tell()
            
            chunk_size = 4096
            for _ in range(remaining_bytes // chunk_size):
                chunk = bytes([random.randint(0, 255) for _ in range(chunk_size)])
                f.write(chunk)
        
        print(f"✅ Test evidence created: {test_file}")
        return str(test_file)
    
    def verify_image_integrity(self, evidence_id: str) -> bool:
        """Verify the integrity of a forensic image"""
        metadata_file = self.case_directory / "evidence" / f"{evidence_id}_metadata.json"
        
        if not metadata_file.exists():
            print(f"❌ Metadata file not found for {evidence_id}")
            return False
        
        # Load metadata
        with open(metadata_file, 'r') as f:
            metadata_dict = json.load(f)
            metadata = EvidenceMetadata(**metadata_dict)
        
        # Find image file
        image_path = self.case_directory / "images" / f"{metadata.case_number}_{evidence_id}.dd"
        
        if not image_path.exists():
            print(f"❌ Image file not found: {image_path}")
            return False
        
        # Recalculate hashes
        print("🔐 Verifying image integrity (this may take time)...")
        current_md5, current_sha256 = self._calculate_file_hashes(str(image_path))
        
        # Compare with stored hashes
        md5_match = current_md5 == metadata.image_hash_md5
        sha256_match = current_sha256 == metadata.image_hash_sha256
        
        if md5_match and sha256_match:
            print("✅ Image integrity verified - no changes detected")
            return True
        else:
            print("❌ Image integrity FAILED - file may be corrupted or tampered")
            print(f"   Expected MD5: {metadata.image_hash_md5}")
            print(f"   Current MD5:  {current_md5}")
            return False
    
    def _calculate_file_hashes(self, filepath: str) -> tuple:
        """Calculate MD5 and SHA256 hashes of a file"""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    def _get_device_info(self, device_path: str) -> Dict:
        """Get device information (simplified for demo)"""
        # In real forensics, would query actual device information
        return {
            'description': f'Evidence from {device_path}',
            'serial': 'DEMO_SERIAL_123',
            'model': 'Forensic Test Device'
        }
    
    def _save_metadata(self, metadata: EvidenceMetadata):
        """Save evidence metadata to JSON file"""
        metadata_file = self.case_directory / "evidence" / f"{metadata.evidence_id}_metadata.json"
        
        # Convert datetime to string for JSON serialization
        metadata_dict = asdict(metadata)
        metadata_dict['acquisition_date'] = metadata.acquisition_date.isoformat()
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata_dict, f, indent=2)
        
        print(f"💾 Metadata saved: {metadata_file}")

class ChainOfCustody:
    """Chain of custody documentation system"""
    
    def __init__(self, case_directory: str):
        self.case_directory = Path(case_directory)
        self.custody_log: List[Dict] = []
        self.custody_file = self.case_directory / "evidence" / "chain_of_custody.json"
        
        # Load existing log
        if self.custody_file.exists():
            with open(self.custody_file, 'r') as f:
                self.custody_log = json.load(f)
    
    def add_custody_event(self, evidence_id: str, action: str, 
                         person: str, notes: str = ""):
        """Add event to chain of custody"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'evidence_id': evidence_id,
            'action': action,
            'person': person,
            'notes': notes
        }
        
        self.custody_log.append(event)
        self._save_custody_log()
        
        print(f"📝 Chain of custody updated: {action} by {person}")
    
    def get_custody_history(self, evidence_id: str) -> List[Dict]:
        """Get custody history for specific evidence"""
        return [event for event in self.custody_log 
                if event['evidence_id'] == evidence_id]
    
    def _save_custody_log(self):
        """Save custody log to file"""
        with open(self.custody_file, 'w') as f:
            json.dump(self.custody_log, f, indent=2)

def demo_evidence_acquisition():
    """Demonstrate evidence acquisition process"""
    print("🔬 Digital Evidence Acquisition Demo")
    print("="*50)
    
    # Initialize forensic imager
    imager = ForensicImager("case_2024_001")
    custody = ChainOfCustody("case_2024_001")
    
    # Demo 1: Create test evidence
    print("\n📋 Demo 1: Creating Test Evidence")
    
    test_evidence = imager.create_test_evidence(size_mb=5)  # Small for demo
    
    # Demo 2: Acquire evidence
    print(f"\n📋 Demo 2: Forensic Acquisition")
    
    evidence_id = "DEMO_001"
    case_number = "2024_001"
    examiner = "Digital Forensics Student"
    
    # Add to chain of custody
    custody.add_custody_event(
        evidence_id=evidence_id,
        action="RECEIVED",
        person=examiner,
        notes="Test evidence received for imaging"
    )
    
    # Perform acquisition
    metadata = imager.create_dd_image(
        source_device=test_evidence,
        evidence_id=evidence_id,
        case_number=case_number,
        examiner=examiner
    )
    
    # Update chain of custody
    custody.add_custody_event(
        evidence_id=evidence_id,
        action="IMAGED",
        person=examiner,
        notes=f"Forensic image created using dd. Verification: {metadata.verification_status}"
    )
    
    # Demo 3: Verify image integrity
    print(f"\n📋 Demo 3: Image Integrity Verification")
    
    integrity_check = imager.verify_image_integrity(evidence_id)
    
    custody.add_custody_event(
        evidence_id=evidence_id,
        action="VERIFIED",
        person=examiner,
        notes=f"Integrity check: {'PASSED' if integrity_check else 'FAILED'}"
    )
    
    # Demo 4: Show chain of custody
    print(f"\n📋 Demo 4: Chain of Custody")
    
    custody_history = custody.get_custody_history(evidence_id)
    
    for event in custody_history:
        print(f"   {event['timestamp'][:19]} - {event['action']} by {event['person']}")
        if event['notes']:
            print(f"     Notes: {event['notes']}")
    
    print(f"\n💡 Acquisition Summary:")
    print(f"   Evidence ID: {metadata.evidence_id}")
    print(f"   Case Number: {metadata.case_number}")
    print(f"   File Size: {metadata.file_size_bytes:,} bytes")
    print(f"   Verification: {metadata.verification_status}")
    print(f"   Chain of Custody Events: {len(custody_history)}")

if __name__ == "__main__":
    demo_evidence_acquisition()
```

### ✅ Checkpoint 1: Evidence Acquisition and Imaging

Verify your forensic imaging implementation:
1. Can you create forensically sound dd images?
2. Do you understand hash verification procedures?
3. Can you maintain proper chain of custody documentation?

---

## 📘 Part 2: File System Analysis (60 minutes)

**Learning Objective**: Analyze file systems using The Sleuth Kit integration

**What you'll build**: File system analysis tools with metadata extraction

Create `filesystem_analysis.py`:

```python
import pytsk3
import os
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Generator
import hashlib

class FileSystemAnalyzer:
    """File system analysis using The Sleuth Kit"""
    
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.img_info = None
        self.fs_info = None
        self._initialize_image()
    
    def _initialize_image(self):
        """Initialize image and file system objects"""
        try:
            # Open the disk image
            self.img_info = pytsk3.Img_Info(self.image_path)
            
            # Try to get file system info (assuming single partition)
            try:
                self.fs_info = pytsk3.FS_Info(self.img_info, offset=0)
            except:
                # If direct access fails, try to find partitions
                volume = pytsk3.Volume_Info(self.img_info)
                for partition in volume:
                    if partition.flags == pytsk3.TSK_VS_PART_FLAG_ALLOC:
                        self.fs_info = pytsk3.FS_Info(self.img_info, offset=partition.start * 512)
                        break
            
            if self.fs_info:
                print(f"✅ File system loaded: {self.fs_info.info.ftype}")
                print(f"   Block size: {self.fs_info.info.block_size}")
                print(f"   Total blocks: {self.fs_info.info.block_count}")
            else:
                raise Exception("Could not access file system")
                
        except Exception as e:
            print(f"❌ Error initializing image: {e}")
            raise
    
    def analyze_directory(self, path: str = "/", max_depth: int = 3) -> Dict:
        """
        Analyze directory structure and metadata
        
        Args:
            path: Directory path to analyze
            max_depth: Maximum recursion depth
            
        Returns:
            Dict: Directory analysis results
        """
        print(f"📁 Analyzing directory: {path}")
        
        analysis = {
            'path': path,
            'entries': [],
            'summary': {
                'total_files': 0,
                'total_directories': 0,
                'deleted_entries': 0,
                'total_size': 0
            },
            'timestamps': {
                'earliest': None,
                'latest': None
            }
        }
        
        try:
            # Get directory object
            directory = self.fs_info.open_dir(path=path)
            
            earliest_time = None
            latest_time = None
            
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                try:
                    # Get file metadata
                    file_info = {
                        'name': entry.info.name.name.decode('utf-8', errors='replace'),
                        'inode': entry.info.meta.addr if entry.info.meta else 0,
                        'type': self._get_file_type(entry.info.name.type),
                        'size': entry.info.meta.size if entry.info.meta else 0,
                        'allocated': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC),
                        'deleted': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                    }
                    
                    # Get timestamps if available
                    if entry.info.meta:
                        timestamps = {}
                        if hasattr(entry.info.meta, 'mtime'):
                            timestamps['modified'] = entry.info.meta.mtime
                        if hasattr(entry.info.meta, 'atime'):
                            timestamps['accessed'] = entry.info.meta.atime  
                        if hasattr(entry.info.meta, 'ctime'):
                            timestamps['changed'] = entry.info.meta.ctime
                        if hasattr(entry.info.meta, 'crtime'):
                            timestamps['created'] = entry.info.meta.crtime
                        
                        file_info['timestamps'] = timestamps
                        
                        # Track earliest and latest times
                        for timestamp in timestamps.values():
                            if timestamp > 0:  # Valid timestamp
                                if earliest_time is None or timestamp < earliest_time:
                                    earliest_time = timestamp
                                if latest_time is None or timestamp > latest_time:
                                    latest_time = timestamp
                    
                    analysis['entries'].append(file_info)
                    
                    # Update summary
                    if file_info['type'] == 'directory':
                        analysis['summary']['total_directories'] += 1
                    else:
                        analysis['summary']['total_files'] += 1
                        analysis['summary']['total_size'] += file_info['size']
                    
                    if file_info['deleted']:
                        analysis['summary']['deleted_entries'] += 1
                
                except Exception as e:
                    print(f"⚠️  Error processing entry: {e}")
                    continue
            
            # Set timestamp summary
            if earliest_time:
                analysis['timestamps']['earliest'] = datetime.fromtimestamp(earliest_time).isoformat()
            if latest_time:
                analysis['timestamps']['latest'] = datetime.fromtimestamp(latest_time).isoformat()
        
        except Exception as e:
            print(f"❌ Error analyzing directory {path}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def find_deleted_files(self) -> List[Dict]:
        """Find deleted files in the file system"""
        print("🔍 Searching for deleted files...")
        
        deleted_files = []
        
        try:
            # Walk through the file system
            for file_entry in self._walk_filesystem():
                if file_entry.get('deleted', False):
                    deleted_files.append(file_entry)
        
        except Exception as e:
            print(f"❌ Error searching for deleted files: {e}")
        
        print(f"📊 Found {len(deleted_files)} deleted files")
        return deleted_files
    
    def extract_file(self, inode: int, output_path: str) -> bool:
        """
        Extract file by inode to output path
        
        Args:
            inode: File inode number
            output_path: Where to save extracted file
            
        Returns:
            bool: True if successful
        """
        try:
            # Open file by inode
            file_obj = self.fs_info.open_meta(inode=inode)
            
            # Create output directory if needed
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Read and write file data
            with open(output_file, 'wb') as out_f:
                offset = 0
                size = file_obj.info.meta.size
                
                while offset < size:
                    available_to_read = min(1024 * 1024, size - offset)  # 1MB chunks
                    data = file_obj.read_random(offset, available_to_read)
                    if not data:
                        break
                    out_f.write(data)
                    offset += len(data)
            
            print(f"✅ File extracted: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Error extracting file {inode}: {e}")
            return False
    
    def generate_file_listing(self, output_file: str):
        """Generate comprehensive file listing"""
        print(f"📄 Generating file listing: {output_file}")
        
        with open(output_file, 'w') as f:
            f.write("FORENSIC FILE SYSTEM LISTING\n")
            f.write("="*50 + "\n")
            f.write(f"Image: {self.image_path}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            
            # Write headers
            f.write(f"{'Inode':<10} {'Type':<5} {'Size':<12} {'Deleted':<7} {'Name'}\n")
            f.write("-" * 70 + "\n")
            
            # Walk filesystem and write entries
            for entry in self._walk_filesystem():
                f.write(f"{entry.get('inode', 0):<10} ")
                f.write(f"{entry.get('type', 'unknown')[:4]:<5} ")
                f.write(f"{entry.get('size', 0):<12} ")
                f.write(f"{'Yes' if entry.get('deleted', False) else 'No':<7} ")
                f.write(f"{entry.get('name', 'unknown')}\n")
        
        print(f"✅ File listing saved: {output_file}")
    
    def _walk_filesystem(self, path: str = "/") -> Generator[Dict, None, None]:
        """Walk through entire file system yielding file entries"""
        try:
            directory = self.fs_info.open_dir(path=path)
            
            for entry in directory:
                if entry.info.name.name in [b'.', b'..']:
                    continue
                
                try:
                    file_info = {
                        'name': entry.info.name.name.decode('utf-8', errors='replace'),
                        'path': path,
                        'full_path': os.path.join(path, entry.info.name.name.decode('utf-8', errors='replace')),
                        'inode': entry.info.meta.addr if entry.info.meta else 0,
                        'type': self._get_file_type(entry.info.name.type),
                        'size': entry.info.meta.size if entry.info.meta else 0,
                        'allocated': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_ALLOC),
                        'deleted': bool(entry.info.name.flags & pytsk3.TSK_FS_NAME_FLAG_UNALLOC)
                    }
                    
                    yield file_info
                    
                    # Recursively process directories (limited depth for demo)
                    if (file_info['type'] == 'directory' and 
                        file_info['allocated'] and 
                        not file_info['deleted'] and 
                        path.count('/') < 3):  # Limit recursion depth
                        
                        try:
                            yield from self._walk_filesystem(file_info['full_path'])
                        except:
                            pass  # Skip inaccessible directories
                
                except Exception:
                    continue  # Skip problematic entries
                    
        except Exception as e:
            print(f"⚠️  Error walking {path}: {e}")
    
    def _get_file_type(self, tsk_type) -> str:
        """Convert TSK file type to readable string"""
        type_map = {
            pytsk3.TSK_FS_NAME_TYPE_DIR: 'directory',
            pytsk3.TSK_FS_NAME_TYPE_REG: 'file',
            pytsk3.TSK_FS_NAME_TYPE_LNK: 'symlink',
            pytsk3.TSK_FS_NAME_TYPE_CHR: 'char_device',
            pytsk3.TSK_FS_NAME_TYPE_BLK: 'block_device',
            pytsk3.TSK_FS_NAME_TYPE_FIFO: 'fifo',
            pytsk3.TSK_FS_NAME_TYPE_SOCK: 'socket'
        }
        return type_map.get(tsk_type, 'unknown')

def demo_filesystem_analysis():
    """Demonstrate file system analysis capabilities"""
    print("🗃️  File System Analysis Demo")
    print("="*50)
    
    # For demo, we'll create a simple test image first
    test_image_path = create_test_filesystem_image()
    
    if not test_image_path:
        print("⚠️  Skipping filesystem analysis - TSK not available or test image creation failed")
        return
    
    try:
        # Initialize analyzer
        analyzer = FileSystemAnalyzer(test_image_path)
        
        # Demo 1: Analyze root directory
        print("\n📋 Demo 1: Root Directory Analysis")
        
        root_analysis = analyzer.analyze_directory("/")
        
        print(f"   Total files: {root_analysis['summary']['total_files']}")
        print(f"   Total directories: {root_analysis['summary']['total_directories']}")
        print(f"   Total size: {root_analysis['summary']['total_size']:,} bytes")
        print(f"   Deleted entries: {root_analysis['summary']['deleted_entries']}")
        
        # Show sample entries
        print(f"\n   Sample entries:")
        for entry in root_analysis['entries'][:5]:  # First 5 entries
            status = "DELETED" if entry.get('deleted') else "ACTIVE"
            print(f"     {entry['name']:<20} {entry['type']:<10} {entry['size']:<10} {status}")
        
        # Demo 2: Find deleted files
        print(f"\n📋 Demo 2: Deleted File Recovery")
        
        deleted_files = analyzer.find_deleted_files()
        
        if deleted_files:
            print(f"   Found {len(deleted_files)} deleted files:")
            for file_info in deleted_files[:3]:  # Show first 3
                print(f"     {file_info['name']} (Inode: {file_info['inode']})")
        else:
            print("   No deleted files found in test image")
        
        # Demo 3: Generate file listing
        print(f"\n📋 Demo 3: Comprehensive File Listing")
        
        listing_file = "filesystem_listing.txt"
        analyzer.generate_file_listing(listing_file)
        
        # Show preview of listing
        with open(listing_file, 'r') as f:
            lines = f.readlines()
            print(f"   Generated {len(lines)} line listing")
            print(f"   Preview (first 10 lines):")
            for line in lines[:10]:
                print(f"     {line.rstrip()}")
        
    except Exception as e:
        print(f"❌ File system analysis failed: {e}")
        print("   This is normal if TSK Python bindings are not installed")

def create_test_filesystem_image() -> Optional[str]:
    """Create a simple test file system image for demonstration"""
    try:
        # This is a simplified version - in practice you'd create a proper filesystem
        test_image = "test_filesystem.dd"
        
        # Create a simple file that simulates a filesystem
        with open(test_image, 'wb') as f:
            # Write some header-like data
            f.write(b"TEST_FILESYSTEM_IMAGE\n")
            f.write(b"Created for forensics demo\n")
            
            # Pad to reasonable size (1MB)
            remaining = 1024 * 1024 - f.tell()
            f.write(b'\x00' * remaining)
        
        return test_image
        
    except Exception as e:
        print(f"⚠️  Could not create test filesystem image: {e}")
        return None

if __name__ == "__main__":
    demo_filesystem_analysis()
```

### ✅ Checkpoint 2: File System Analysis

Test your file system analysis tools:
1. Can you analyze file system metadata?
2. Do you understand inode-based file recovery?
3. Can you generate comprehensive file listings?

---

## 📘 Part 3: Timeline Analysis (60 minutes)

**Learning Objective**: Create timeline analysis for digital forensics investigations

**What you'll build**: Timeline creation and event correlation system

Create `timeline_analysis.py`:

```python
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import json
import csv
from dataclasses import dataclass, asdict
from pathlib import Path
import re

@dataclass
class TimelineEvent:
    """Individual timeline event"""
    timestamp: datetime
    event_type: str
    source: str
    description: str
    artifact_type: str
    file_path: str = ""
    inode: int = 0
    size: int = 0
    hash_value: str = ""
    user: str = ""
    
    def to_dict(self) -> Dict:
        """Convert to dictionary with ISO timestamp"""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        return result

class TimelineAnalyzer:
    """Digital forensics timeline analysis"""
    
    def __init__(self, case_name: str):
        self.case_name = case_name
        self.events: List[TimelineEvent] = []
        self.output_dir = Path(f"timeline_{case_name}")
        self.output_dir.mkdir(exist_ok=True)
        
        print(f"✅ Timeline analyzer initialized for case: {case_name}")
    
    def add_filesystem_events(self, fs_analysis: Dict):
        """Add filesystem events from analysis"""
        print("📁 Adding filesystem events to timeline...")
        
        for entry in fs_analysis.get('entries', []):
            timestamps = entry.get('timestamps', {})
            
            # Add events for each timestamp type
            for ts_type, timestamp in timestamps.items():
                if timestamp > 0:  # Valid timestamp
                    event_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    
                    # Map timestamp types to event types
                    event_type_map = {
                        'modified': 'FILE_MODIFIED',
                        'accessed': 'FILE_ACCESSED',
                        'changed': 'FILE_METADATA_CHANGED',
                        'created': 'FILE_CREATED'
                    }
                    
                    event_type = event_type_map.get(ts_type, 'FILE_TIMESTAMP')
                    
                    event = TimelineEvent(
                        timestamp=event_dt,
                        event_type=event_type,
                        source='filesystem',
                        description=f"{ts_type.title()} timestamp for {entry['name']}",
                        artifact_type='file_metadata',
                        file_path=entry.get('full_path', entry['name']),
                        inode=entry.get('inode', 0),
                        size=entry.get('size', 0)
                    )
                    
                    self.events.append(event)
        
        print(f"   Added {len([e for e in self.events if e.source == 'filesystem'])} filesystem events")
    
    def add_log_events(self, log_file: str, log_format: str = 'auto'):
        """
        Parse and add log file events
        
        Args:
            log_file: Path to log file
            log_format: Log format ('apache', 'iis', 'syslog', 'auto')
        """
        print(f"📄 Parsing log file: {log_file}")
        
        if not Path(log_file).exists():
            print(f"⚠️  Log file not found: {log_file}")
            return
        
        log_events = []
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    parsed_event = self._parse_log_line(line, log_format, line_num)
                    if parsed_event:
                        log_events.append(parsed_event)
        
        except Exception as e:
            print(f"❌ Error reading log file: {e}")
            return
        
        self.events.extend(log_events)
        print(f"   Added {len(log_events)} log events")
    
    def add_registry_events(self, registry_analysis: Dict):
        """Add Windows registry events"""
        print("🗃️  Adding registry events to timeline...")
        
        registry_events = []
        
        for key_path, key_info in registry_analysis.items():
            timestamp = key_info.get('last_written')
            if timestamp:
                event = TimelineEvent(
                    timestamp=timestamp,
                    event_type='REGISTRY_KEY_MODIFIED',
                    source='registry',
                    description=f"Registry key modified: {key_path}",
                    artifact_type='registry_key',
                    file_path=key_path
                )
                registry_events.append(event)
        
        self.events.extend(registry_events)
        print(f"   Added {len(registry_events)} registry events")
    
    def create_super_timeline(self) -> str:
        """Create comprehensive super timeline"""
        print("🕐 Creating super timeline...")
        
        # Sort all events by timestamp
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        # Generate timeline file
        timeline_file = self.output_dir / f"{self.case_name}_super_timeline.csv"
        
        with open(timeline_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                'Timestamp', 'Event Type', 'Source', 'Description', 
                'Artifact Type', 'File Path', 'Inode', 'Size', 'User'
            ])
            
            # Write events
            for event in sorted_events:
                writer.writerow([
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.source,
                    event.description,
                    event.artifact_type,
                    event.file_path,
                    event.inode,
                    event.size,
                    event.user
                ])
        
        print(f"✅ Super timeline created: {timeline_file}")
        print(f"   Total events: {len(sorted_events)}")
        
        return str(timeline_file)
    
    def find_time_anomalies(self, window_minutes: int = 60) -> List[Dict]:
        """
        Find time-based anomalies and suspicious patterns
        
        Args:
            window_minutes: Time window for anomaly detection
            
        Returns:
            List of detected anomalies
        """
        print(f"🔍 Analyzing timeline for anomalies (window: {window_minutes} min)...")
        
        anomalies = []
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        # Look for clusters of activity
        current_cluster = []
        cluster_threshold = 10  # Minimum events in cluster to be suspicious
        
        for i, event in enumerate(sorted_events):
            if not current_cluster:
                current_cluster = [event]
                continue
            
            # Check if event is within time window of cluster
            time_diff = (event.timestamp - current_cluster[0].timestamp).total_seconds() / 60
            
            if time_diff <= window_minutes:
                current_cluster.append(event)
            else:
                # Analyze current cluster
                if len(current_cluster) >= cluster_threshold:
                    anomaly = {
                        'type': 'HIGH_ACTIVITY_CLUSTER',
                        'start_time': current_cluster[0].timestamp.isoformat(),
                        'end_time': current_cluster[-1].timestamp.isoformat(),
                        'event_count': len(current_cluster),
                        'duration_minutes': (current_cluster[-1].timestamp - current_cluster[0].timestamp).total_seconds() / 60,
                        'description': f"Cluster of {len(current_cluster)} events in {time_diff:.1f} minutes"
                    }
                    anomalies.append(anomaly)
                
                # Start new cluster
                current_cluster = [event]
        
        # Check final cluster
        if len(current_cluster) >= cluster_threshold:
            time_span = (current_cluster[-1].timestamp - current_cluster[0].timestamp).total_seconds() / 60
            anomaly = {
                'type': 'HIGH_ACTIVITY_CLUSTER',
                'start_time': current_cluster[0].timestamp.isoformat(),
                'end_time': current_cluster[-1].timestamp.isoformat(),
                'event_count': len(current_cluster),
                'duration_minutes': time_span,
                'description': f"Final cluster of {len(current_cluster)} events"
            }
            anomalies.append(anomaly)
        
        # Look for off-hours activity (outside 9-17 business hours)
        off_hours_events = [
            event for event in sorted_events 
            if event.timestamp.hour < 9 or event.timestamp.hour > 17
        ]
        
        if len(off_hours_events) > len(sorted_events) * 0.2:  # More than 20% off-hours
            anomaly = {
                'type': 'OFF_HOURS_ACTIVITY',
                'event_count': len(off_hours_events),
                'percentage': (len(off_hours_events) / len(sorted_events)) * 100,
                'description': f"High off-hours activity: {len(off_hours_events)} events ({(len(off_hours_events) / len(sorted_events)) * 100:.1f}%)"
            }
            anomalies.append(anomaly)
        
        print(f"   Found {len(anomalies)} potential anomalies")
        return anomalies
    
    def generate_timeline_report(self) -> str:
        """Generate comprehensive timeline analysis report"""
        print("📊 Generating timeline analysis report...")
        
        report_file = self.output_dir / f"{self.case_name}_timeline_report.txt"
        
        # Calculate statistics
        sorted_events = sorted(self.events, key=lambda e: e.timestamp)
        
        if not sorted_events:
            print("⚠️  No events to analyze")
            return str(report_file)
        
        # Event type statistics
        event_types = {}
        sources = {}
        
        for event in sorted_events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
            sources[event.source] = sources.get(event.source, 0) + 1
        
        # Time range analysis
        earliest = sorted_events[0].timestamp
        latest = sorted_events[-1].timestamp
        time_span = latest - earliest
        
        # Find anomalies
        anomalies = self.find_time_anomalies()
        
        # Generate report
        with open(report_file, 'w') as f:
            f.write(f"TIMELINE ANALYSIS REPORT\n")
            f.write(f"{"="*50}\n")
            f.write(f"Case: {self.case_name}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total Events: {len(sorted_events):,}\n\n")
            
            f.write(f"TIME RANGE ANALYSIS\n")
            f.write(f"{'-'*30}\n")
            f.write(f"Earliest Event: {earliest.isoformat()}\n")
            f.write(f"Latest Event:   {latest.isoformat()}\n")
            f.write(f"Time Span:      {time_span.days} days, {time_span.seconds // 3600} hours\n\n")
            
            f.write(f"EVENT TYPES\n")
            f.write(f"{'-'*30}\n")
            for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(sorted_events)) * 100
                f.write(f"{event_type:<25} {count:>6} ({percentage:5.1f}%)\n")
            f.write(f"\n")
            
            f.write(f"DATA SOURCES\n")
            f.write(f"{'-'*30}\n")
            for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(sorted_events)) * 100
                f.write(f"{source:<25} {count:>6} ({percentage:5.1f}%)\n")
            f.write(f"\n")
            
            if anomalies:
                f.write(f"DETECTED ANOMALIES\n")
                f.write(f"{'-'*30}\n")
                for i, anomaly in enumerate(anomalies, 1):
                    f.write(f"{i}. {anomaly['type']}\n")
                    f.write(f"   {anomaly['description']}\n")
                    if 'start_time' in anomaly:
                        f.write(f"   Time Range: {anomaly['start_time']} to {anomaly['end_time']}\n")
                    f.write(f"\n")
        
        print(f"✅ Timeline report saved: {report_file}")
        return str(report_file)
    
    def _parse_log_line(self, line: str, log_format: str, line_num: int) -> Optional[TimelineEvent]:
        """Parse individual log line based on format"""
        try:
            # Simple Apache/IIS common log format parser
            if 'apache' in log_format.lower() or log_format == 'auto':
                # Example: 192.168.1.1 - - [25/Dec/2023:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
                apache_pattern = r'(\d+\.\d+\.\d+\.\d+) .* \[([^\]]+)\] "([^"]+)" (\d+) (\d+)'
                match = re.match(apache_pattern, line)
                
                if match:
                    ip, timestamp_str, request, status, size = match.groups()
                    
                    # Parse timestamp
                    try:
                        timestamp = datetime.strptime(timestamp_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                    except:
                        timestamp = datetime.now(timezone.utc)
                    
                    return TimelineEvent(
                        timestamp=timestamp,
                        event_type='WEB_REQUEST',
                        source='webserver',
                        description=f"{request} from {ip} (Status: {status})",
                        artifact_type='web_log',
                        file_path=f"line_{line_num}",
                        size=int(size) if size.isdigit() else 0,
                        user=ip
                    )
            
            # Simple syslog format
            elif 'syslog' in log_format.lower():
                # Example: Dec 25 10:00:00 hostname service[1234]: message
                syslog_pattern = r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (\w+) ([^:]+): (.+)'
                match = re.match(syslog_pattern, line)
                
                if match:
                    timestamp_str, hostname, service, message = match.groups()
                    
                    # Parse timestamp (assume current year)
                    try:
                        timestamp = datetime.strptime(f"{datetime.now().year} {timestamp_str}", '%Y %b %d %H:%M:%S')
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                    except:
                        timestamp = datetime.now(timezone.utc)
                    
                    return TimelineEvent(
                        timestamp=timestamp,
                        event_type='SYSTEM_LOG',
                        source='syslog',
                        description=f"{service}: {message}",
                        artifact_type='system_log',
                        file_path=f"line_{line_num}",
                        user=hostname
                    )
        
        except Exception as e:
            print(f"⚠️  Error parsing line {line_num}: {e}")
        
        return None

def demo_timeline_analysis():
    """Demonstrate timeline analysis capabilities"""
    print("🕐 Timeline Analysis Demo")
    print("="*50)
    
    # Create timeline analyzer
    timeline = TimelineAnalyzer("demo_case_001")
    
    # Demo 1: Add sample filesystem events
    print("\n📋 Demo 1: Adding Sample Events")
    
    # Simulate filesystem analysis results
    sample_fs_analysis = {
        'entries': [
            {
                'name': 'document.txt',
                'full_path': '/home/user/document.txt',
                'inode': 12345,
                'size': 1024,
                'timestamps': {
                    'created': 1703500800,    # 2023-12-25 10:00:00
                    'modified': 1703504400,   # 2023-12-25 11:00:00
                    'accessed': 1703508000,   # 2023-12-25 12:00:00
                }
            },
            {
                'name': 'secret.txt',
                'full_path': '/tmp/secret.txt',
                'inode': 67890,
                'size': 512,
                'timestamps': {
                    'created': 1703520000,    # 2023-12-25 16:00:00
                    'modified': 1703521800,   # 2023-12-25 16:30:00
                }
            }
        ]
    }
    
    timeline.add_filesystem_events(sample_fs_analysis)
    
    # Demo 2: Create sample log file and parse it
    print(f"\n📋 Demo 2: Adding Log Events")
    
    # Create sample log file
    sample_log = "sample_access.log"
    with open(sample_log, 'w') as f:
        f.write('192.168.1.100 - - [25/Dec/2023:10:15:00 +0000] "GET /index.html HTTP/1.1" 200 2048\n')
        f.write('192.168.1.101 - - [25/Dec/2023:10:16:30 +0000] "POST /login HTTP/1.1" 302 128\n')
        f.write('192.168.1.102 - - [25/Dec/2023:10:17:45 +0000] "GET /admin HTTP/1.1" 403 256\n')
        f.write('192.168.1.100 - - [25/Dec/2023:10:18:00 +0000] "GET /data.json HTTP/1.1" 200 4096\n')
    
    timeline.add_log_events(sample_log, 'apache')
    
    # Demo 3: Create super timeline
    print(f"\n📋 Demo 3: Creating Super Timeline")
    
    timeline_file = timeline.create_super_timeline()
    
    # Show sample of timeline
    print(f"   Sample timeline entries:")
    with open(timeline_file, 'r') as f:
        lines = f.readlines()
        for line in lines[:6]:  # Show first 6 lines (header + 5 events)
            print(f"     {line.strip()}")
    
    # Demo 4: Anomaly detection
    print(f"\n📋 Demo 4: Anomaly Detection")
    
    anomalies = timeline.find_time_anomalies(window_minutes=30)
    
    if anomalies:
        for i, anomaly in enumerate(anomalies, 1):
            print(f"   Anomaly {i}: {anomaly['type']}")
            print(f"     {anomaly['description']}")
    else:
        print("   No anomalies detected in sample data")
    
    # Demo 5: Generate comprehensive report
    print(f"\n📋 Demo 5: Timeline Analysis Report")
    
    report_file = timeline.generate_timeline_report()
    
    # Show preview of report
    with open(report_file, 'r') as f:
        lines = f.readlines()
        print(f"   Report preview (first 15 lines):")
        for line in lines[:15]:
            print(f"     {line.rstrip()}")
    
    # Cleanup
    os.remove(sample_log)
    
    print(f"\n💡 Timeline Analysis Summary:")
    print(f"   Total events processed: {len(timeline.events)}")
    print(f"   Timeline file: {timeline_file}")
    print(f"   Analysis report: {report_file}")

if __name__ == "__main__":
    demo_timeline_analysis()
```

### ✅ Checkpoint 3: Timeline Analysis

Verify your timeline analysis system:
1. Can you create comprehensive super timelines?
2. Do you understand time-based anomaly detection?
3. Can you correlate events from multiple sources?

---

## ✅ Tutorial Completion Checklist

After completing all parts, verify your understanding:

- [ ] You can perform forensically sound evidence acquisition
- [ ] You understand file system analysis with The Sleuth Kit
- [ ] You can create comprehensive timeline analysis
- [ ] You can extract and analyze digital artifacts
- [ ] You can generate professional forensics reports
- [ ] You understand chain of custody procedures

## 🚀 Ready for the Assignment?

Excellent! Now you have the foundation for digital forensics analysis. The assignment will combine these concepts into a complete forensics laboratory.

**Next step**: Review [assignment.md](assignment.md) for detailed requirements.

## 💡 Key Concepts Learned

1. **Evidence acquisition** with forensically sound imaging
2. **File system analysis** using The Sleuth Kit integration
3. **Timeline creation** and event correlation
4. **Artifact extraction** and analysis automation
5. **Digital forensics methodology** and best practices
6. **Chain of custody** documentation and procedures
7. **Professional reporting** for forensics investigations

---

**Questions?** Check the troubleshooting section or ask in Canvas discussions!