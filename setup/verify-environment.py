#!/usr/bin/env python3
"""
CSCI 347 Environment Verification Script

This script checks that your development environment is properly configured
for the Network Security and Digital Forensics course.
"""

import sys
import subprocess
import importlib
import platform
import os
from pathlib import Path

def print_header():
    """Print the verification header"""
    print("=" * 50)
    print("CSCI 347 Environment Verification")
    print("Network Security and Digital Forensics")
    print("=" * 50)

def check_python_version():
    """Check Python version meets requirements"""
    print("\n🐍 Python Environment")
    print("-" * 20)
    
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major == 3 and version.minor >= 11:
        print("✅ Python version meets requirements (3.11+)")
        return True
    else:
        print("❌ Python 3.11 or higher required")
        print("   Install Python 3.11+ and try again")
        return False

def check_virtual_environment():
    """Check if running in virtual environment"""
    in_venv = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )
    
    if in_venv:
        print("✅ Virtual environment is active")
        print(f"   Virtual env path: {sys.prefix}")
        return True
    else:
        print("⚠️  Not in virtual environment")
        print("   Recommended: Create and activate a virtual environment")
        return False

def check_required_packages():
    """Check if required Python packages are installed"""
    print("\n📦 Required Packages")
    print("-" * 20)
    
    required_packages = {
        'cryptography': 'Cryptographic operations',
        'requests': 'HTTP client library',
        'pandas': 'Data analysis',
        'scapy': 'Network packet manipulation',
        'volatility3': 'Memory forensics (optional)',
        'yara': 'Pattern matching (optional)'
    }
    
    installed = []
    missing = []
    optional_missing = []
    
    for package, description in required_packages.items():
        try:
            importlib.import_module(package.replace('-', '_'))
            print(f"✅ {package:<15} - {description}")
            installed.append(package)
        except ImportError:
            if package in ['volatility3', 'yara']:
                print(f"⚠️  {package:<15} - {description} (optional)")
                optional_missing.append(package)
            else:
                print(f"❌ {package:<15} - {description}")
                missing.append(package)
    
    if missing:
        print(f"\n❌ Missing required packages: {', '.join(missing)}")
        print("   Install with: pip install " + " ".join(missing))
        return False
    else:
        print(f"\n✅ All required packages installed ({len(installed)}/{len(required_packages)})")
        if optional_missing:
            print(f"   Optional packages to install: {', '.join(optional_missing)}")
        return True

def check_git():
    """Check Git installation and configuration"""
    print("\n🔧 Git Configuration")
    print("-" * 20)
    
    try:
        # Check if git is installed
        result = subprocess.run(['git', '--version'], 
                               capture_output=True, text=True, check=True)
        print(f"✅ Git installed: {result.stdout.strip()}")
        
        # Check git configuration
        try:
            name = subprocess.run(['git', 'config', 'user.name'], 
                                 capture_output=True, text=True, check=True)
            email = subprocess.run(['git', 'config', 'user.email'], 
                                  capture_output=True, text=True, check=True)
            
            if name.stdout.strip() and email.stdout.strip():
                git_name = name.stdout.strip()
                git_email = email.stdout.strip()
                print(f"✅ Git user configured: {git_name} <{git_email}>")
                
                # Check if course identifier is present  
                if "CSCI347_f25" in git_name:
                    print("✅ Course identifier found in git name")
                    print("   This indicates work directory git config is properly set")
                else:
                    print("ℹ️  Global git config detected (not work directory)")
                    print("   Make sure your work directory has course identifier:")
                    print("   cd CSCI347_f25_YourName && git config user.name 'FirstName LastName - CSCI347_f25'")
                    print("   Example: git config user.name 'Jane Smith - CSCI347_f25'")
                
                return True
            else:
                print("⚠️  Git user not configured")
                print("   Configure with course identifier:")
                print("   git config user.name 'FirstName LastName - CSCI347_f25'")
                print("   git config user.email 'your.email@university.edu'")
                return False
                
        except subprocess.CalledProcessError:
            print("⚠️  Git user not configured")
            return False
            
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Git not installed or not in PATH")
        print("   Install Git from: https://git-scm.com/downloads")
        return False

def check_virtualbox():
    """Check VirtualBox installation"""
    print("\n📦 VirtualBox")
    print("-" * 20)
    
    # Common VirtualBox executable locations
    vbox_commands = ['VBoxManage', 'vboxmanage', '/usr/bin/VBoxManage']
    
    for cmd in vbox_commands:
        try:
            result = subprocess.run([cmd, '--version'], 
                                   capture_output=True, text=True, check=True)
            version = result.stdout.strip()
            print(f"✅ VirtualBox installed: {version}")
            
            # Check if we can list VMs (basic functionality test)
            try:
                subprocess.run([cmd, 'list', 'vms'], 
                              capture_output=True, text=True, check=True)
                print("✅ VirtualBox working properly")
                return True
            except subprocess.CalledProcessError:
                print("⚠️  VirtualBox installed but may have issues")
                return False
                
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
    
    print("❌ VirtualBox not found")
    print("   Install from: https://www.virtualbox.org/wiki/Downloads")
    return False

def check_network():
    """Check network connectivity"""
    print("\n🌐 Network Connectivity")
    print("-" * 20)
    
    try:
        import urllib.request
        
        # Test connectivity to key resources
        test_urls = [
            ('GitHub', 'https://github.com'),
            ('NIST', 'https://csrc.nist.gov'),
            ('Python Packages', 'https://pypi.org')
        ]
        
        for name, url in test_urls:
            try:
                urllib.request.urlopen(url, timeout=5)
                print(f"✅ {name} reachable")
            except Exception:
                print(f"⚠️  {name} not reachable")
                
        return True
        
    except ImportError:
        print("❌ Cannot test network connectivity")
        return False

def check_file_system():
    """Check file system permissions and space"""
    print("\n💾 File System")
    print("-" * 20)
    
    # Check current directory is writable
    try:
        test_file = Path('test_write_permissions.tmp')
        test_file.write_text('test')
        test_file.unlink()
        print("✅ Current directory writable")
        write_ok = True
    except Exception as e:
        print(f"❌ Cannot write to current directory: {e}")
        write_ok = False
    
    # Check available disk space
    try:
        if platform.system() == 'Windows':
            import shutil
            total, used, free = shutil.disk_usage('.')
        else:
            statvfs = os.statvfs('.')
            free = statvfs.f_bavail * statvfs.f_frsize
            total = statvfs.f_blocks * statvfs.f_frsize
        
        free_gb = free / (1024**3)
        total_gb = total / (1024**3)
        
        print(f"📊 Available space: {free_gb:.1f} GB / {total_gb:.1f} GB")
        
        if free_gb >= 100:
            print("✅ Sufficient disk space (100+ GB available)")
            space_ok = True
        else:
            print("⚠️  Limited disk space (recommend 100+ GB)")
            space_ok = False
            
    except Exception:
        print("⚠️  Cannot check disk space")
        space_ok = True
    
    return write_ok and space_ok

def check_course_structure():
    """Check if course files are properly organized"""
    print("\n📁 Course Structure")
    print("-" * 20)
    
    expected_dirs = [
        'setup',
        'resources', 
        'week01-crypto-basics',
        'projects'
    ]
    
    missing_dirs = []
    for dir_name in expected_dirs:
        if Path(dir_name).exists():
            print(f"✅ {dir_name}/ directory found")
        else:
            print(f"⚠️  {dir_name}/ directory missing")
            missing_dirs.append(dir_name)
    
    if missing_dirs:
        print(f"\n⚠️  Some course directories missing: {missing_dirs}")
        print("   Make sure you're in the course root directory")
        return False
    else:
        print("\n✅ Course structure looks good")
        return True

def main():
    """Main verification function"""
    print_header()
    
    checks = [
        ('Python Version', check_python_version),
        ('Virtual Environment', check_virtual_environment), 
        ('Required Packages', check_required_packages),
        ('Git Configuration', check_git),
        ('VirtualBox', check_virtualbox),
        ('Network Connectivity', check_network),
        ('File System', check_file_system),
        ('Course Structure', check_course_structure)
    ]
    
    results = []
    for name, check_func in checks:
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            print(f"❌ Error checking {name}: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 50)
    print("VERIFICATION SUMMARY")
    print("=" * 50)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL" 
        print(f"{name:<20} {status}")
    
    print(f"\nOverall: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 Environment setup complete!")
        print("   You're ready to start Week 1.")
        print("\n📚 Next steps:")
        print("   1. Read week01-crypto-basics/README.md")
        print("   2. Complete the tutorial")
        print("   3. Submit your first assignment")
        return True
    else:
        print("\n⚠️  Some issues found. Please fix them before starting the course.")
        print("\n🔧 Common fixes:")
        print("   - Install missing packages: pip install -r requirements.txt")
        print("   - Configure Git: git config --global user.name 'Your Name'")
        print("   - Install VirtualBox from official website")
        print("   - Make sure you're in the course root directory")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)