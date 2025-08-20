# Environment Setup for CSCI 347

**⏱️ Time needed: 15-20 minutes**

**📋 Need the quick version?** → [Setup checklist](../quick-reference/setup-checklist.md) (2 minutes)

## 🖥️ System Requirements Check

Before starting, verify your system meets the minimum requirements:

### Hardware Requirements
- **RAM**: 8GB minimum (16GB strongly recommended)
- **Storage**: 100GB free space (200GB recommended)
- **Processor**: Dual-core with virtualization support
- **Network**: Reliable broadband internet connection

### Check Virtualization Support

**Windows:**
```cmd
systeminfo | findstr Hyper-V
```

**macOS:**
```bash
sysctl -a | grep machdep.cpu.features | grep VMX
```

**Linux:**
```bash
egrep -c '(vmx|svm)' /proc/cpuinfo
```

If you see output, virtualization is supported. If not, enable it in your BIOS/UEFI settings.

## 📱 Operating System Setup

### Windows 10/11 Setup

1. **Enable WSL2 (Windows Subsystem for Linux)**
   ```powershell
   # Run as Administrator
   wsl --install -d Ubuntu-22.04
   ```

2. **Install Windows Terminal** (from Microsoft Store)

3. **Install Git for Windows**
   - Download from: https://git-scm.com/download/win

4. **Install Python 3.11+**
   - Download from: https://www.python.org/downloads/
   - ⚠️ Check "Add Python to PATH" during installation

### macOS Setup

1. **Install Homebrew** (package manager)
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install required tools**
   ```bash
   brew install python@3.11 git
   ```

3. **Install Xcode Command Line Tools**
   ```bash
   xcode-select --install
   ```

### Linux (Ubuntu/Debian) Setup

1. **Update package lists**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install required packages**
   ```bash
   sudo apt install -y python3.11 python3.11-pip python3.11-venv git build-essential
   ```

### Linux (CentOS/RHEL/Fedora) Setup

1. **Update packages**
   ```bash
   # CentOS/RHEL
   sudo yum update -y
   # Fedora
   sudo dnf update -y
   ```

2. **Install Python and Git**
   ```bash
   # CentOS/RHEL
   sudo yum install -y python311 python311-pip git
   # Fedora
   sudo dnf install -y python3.11 python3-pip git
   ```

## 🐍 Python Environment Setup

### 1. Verify Python Installation

```bash
python3 --version
# Should show Python 3.11.x or higher
```

If you see an older version or get an error:
- **Windows**: Use `python` instead of `python3`
- **macOS**: Install Python 3.11 with Homebrew
- **Linux**: Install python3.11 package

### 2. Create Virtual Environment

```bash
# Navigate to course directory
cd csci347-fall2025

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
```

You should see `(venv)` in your command prompt.

### 3. Install Python Packages

```bash
# Upgrade pip first
pip install --upgrade pip

# Install core packages
pip install cryptography pyOpenSSL volatility3 scapy pandas requests

# Install additional forensics packages
pip install python-registry python-magic yara-python

# Install development tools
pip install pytest black flake8
```

### 4. Create Requirements File

```bash
pip freeze > requirements.txt
```

This creates a file you can use to recreate your environment:
```bash
pip install -r requirements.txt
```

## 💻 Virtualization Setup

Virtualization provides isolated environments for security testing and forensics analysis.

### For Intel/AMD Macs and PCs: VirtualBox

**VirtualBox** is the recommended free option:

1. **Download**: https://www.virtualbox.org/wiki/Downloads
2. **Install**: Follow the installer for your operating system
3. ⚠️ Reboot after installation
4. **Enable virtualization** in BIOS/UEFI if needed

### For Apple M1/M2/M3 Macs: UTM

⚠️ **Important**: VirtualBox does not work on Apple Silicon (M1/M2/M3) Macs.

**UTM** is the recommended free alternative:

1. **Download UTM**: https://mac.getutm.app/
2. **Install** from Mac App Store or download directly
3. **Alternative**: VMware Fusion for Mac (free for personal use)

### Required Virtual Machines

Create a folder for your VMs and set up:

1. **Kali Linux** (Security testing)
   - **For VirtualBox**: Download pre-built VM from https://www.kali.org/get-kali/#kali-virtual-machines
   - **For UTM**: Download ARM64 version from Kali Linux downloads

2. **Ubuntu Server** (Network services and forensics)
   - **For VirtualBox**: Download Ubuntu Server 22.04 LTS ISO
   - **For UTM**: Use ARM64 server image for better performance

3. **Windows 10/11** (Forensics practice - optional)
   - **For VirtualBox**: Use Microsoft evaluation VMs
   - **For UTM**: Use Windows 11 ARM insider preview (requires Microsoft account)

### Alternative: Docker Containers

For lightweight isolation, many exercises can use Docker:

```bash
# Install Docker Desktop
# Download from: https://www.docker.com/products/docker-desktop/

# Test installation
docker --version

# Pull useful security containers
docker pull kalilinux/kali-rolling
docker pull ubuntu:22.04
```

### Cloud Alternative (All Platforms)

If local virtualization isn't working:

1. **AWS EC2 Free Tier**: Launch Linux instances for exercises
2. **Google Cloud**: $300 free credit for new accounts  
3. **Azure**: Free tier with Linux VMs
4. **DigitalOcean**: $200 credit for students via GitHub Education Pack

## 🔧 Course-Specific Tools

### Professional Git Workflow Setup

This course uses **industry-standard Pull Request workflow** to develop real collaborative development skills while maintaining academic integrity.

#### Step 1: Fork the Course Repository

```bash
# 1. Go to GitHub: https://github.com/[instructor]/CSCI347_f25
# 2. Click "Fork" button (creates your own copy of the repository)
# 3. Your fork will be at: https://github.com/YourUsername/CSCI347_f25
```

#### Step 2: Clone YOUR Fork (Not the Original)

```bash
# Clone YOUR fork to your local machine
git clone https://github.com/YourUsername/CSCI347_f25.git
cd CSCI347_f25

# Configure git with course identifier for assignment submissions
git config user.name "John Smith - CSCI347_f25"
git config user.email "jsmith@university.edu"

# Add the original course repo as "upstream" to get updates
git remote add upstream https://github.com/[instructor]/CSCI347_f25.git

# Verify remotes
git remote -v
# Should show:
# origin    https://github.com/YourUsername/CSCI347_f25.git (your fork)
# upstream  https://github.com/[instructor]/CSCI347_f25.git (course repo)
```

#### Step 3: Create Your Assignment Directory Structure

```bash
# Create your personal assignment directories
mkdir -p assignments/CSCI347_f25_John_Smith/{week01,week02,week03,week04,week05,week06,week07}
mkdir -p assignments/CSCI347_f25_John_Smith/{week08,week09,week10,week11,week12,week13,week14}

# Initial commit
git add assignments/
git commit -m "Set up assignment directory structure for John Smith"
git push origin main
```

**Why this professional approach**:
- ✅ **Real collaborative workflow** - Fork, branch, pull request process used in industry
- ✅ **Professional code review** - Instructor feedback via pull request comments
- ✅ **Academic integrity maintained** - Staggered releases, timestamped submissions
- ✅ **Portfolio building** - Students build GitHub portfolio with real PR experience
- ✅ **FERPA compliant** - Grades in Canvas, but professional collaboration via GitHub

### SSH Key Setup (for GitHub)

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "your.email@example.com"

# Add to SSH agent
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

# Display public key to add to GitHub
cat ~/.ssh/id_ed25519.pub
```

Add this key to your GitHub account: Settings → SSH and GPG keys → New SSH key

### Professional Assignment Workflow

#### Getting Course Updates (New Materials/Announcements)

```bash
# Sync with instructor's updates
cd CSCI347_f25
git fetch upstream
git merge upstream/main
git push origin main  # Update your fork
```

#### Working on Assignments (Professional Branch Workflow)

```bash
# 1. Create a feature branch for each assignment
git checkout -b week01-crypto-assignment

# 2. Work in your assignment directory
cd assignments/CSCI347_f25_John_Smith/week01

# 3. Create your solution files
# password_vault.py, README.md, tests, etc.

# 4. Commit your work with meaningful messages
git add .
git commit -m "Implement basic password vault with Fernet encryption"

git add password_vault.py
git commit -m "Add input validation and error handling"

git add tests/
git commit -m "Add comprehensive unit tests for password operations"

# 5. Push your feature branch
git push origin week01-crypto-assignment
```

#### Submitting via Pull Request (Professional Code Review)

```bash
# After pushing your branch, go to GitHub:
# 1. Navigate to YOUR fork on GitHub
# 2. Click "Compare & pull request" button
# 3. Fill out the PR template:

Title: "Week 1: Password Vault Implementation - John Smith"
Description: 
"- Implemented secure password storage using PBKDF2 key derivation
 - Added Fernet encryption for password protection  
 - Included comprehensive CLI interface with add/get/update/delete
 - Added unit tests with 90% coverage
 - Follows all security requirements from assignment"

# 4. Click "Create pull request"
```

#### Responding to Instructor Feedback

```bash
# When instructor adds PR comments:
# 1. Read feedback carefully
# 2. Make requested changes in your local branch
git checkout week01-crypto-assignment

# Edit files based on feedback
git add .
git commit -m "Fix key derivation issue per instructor feedback"
git push origin week01-crypto-assignment

# 3. Reply to PR comments explaining your changes
# 4. Request re-review when ready
```

## ✅ Environment Verification

Run the verification script to ensure everything is working:

```bash
# From the course materials directory
cd CSCI347_f25_materials
python setup/verify-environment.py
```

This script checks:
- ✅ Python version and packages
- ✅ VirtualBox installation
- ✅ Git configuration
- ✅ Network connectivity
- ✅ File permissions

### Expected Output

```
CSCI 347 Environment Check
==========================
✅ Python 3.11.5 found
✅ Virtual environment active
✅ All required packages installed
✅ VirtualBox 7.0.x installed
✅ Git configured properly
✅ Internet connectivity good
✅ File system writable

🎉 Environment setup complete!
You're ready to start Week 1.
```

## 🚨 Troubleshooting

### Common Issues

**Python not found:**
- **Windows**: Use `python` instead of `python3`
- **Path issues**: Reinstall Python and check "Add to PATH"

**Permission denied errors:**
```bash
# macOS/Linux: Don't use sudo with pip in virtual environments
# Instead, recreate the virtual environment:
deactivate
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**VirtualBox won't start VMs:**
- Enable virtualization in BIOS
- Disable Windows Hyper-V: `dism.exe /Online /Disable-Feature:Microsoft-Hyper-V`

**Git clone fails:**
```bash
# Use HTTPS instead of SSH initially:
git clone https://github.com/[instructor]/csci347-fall2025.git
```

**Package installation fails:**
```bash
# Update pip and try again:
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### Getting Help

1. **Check**: [resources/troubleshooting.md](../resources/troubleshooting.md)
2. **Search**: GitHub Issues in the course repository
3. **Ask**: Create a new GitHub Issue with:
   - Your operating system
   - Error messages (full text)
   - Steps you tried
   - Output of `python --version` and `pip list`

## 📚 Next Steps

Once your environment is set up:

1. **Read**: The complete [resources/reading-list.md](../resources/reading-list.md)
2. **Start**: [week01-crypto-basics/README.md](../week01-crypto-basics/README.md)
3. **Join**: Canvas course for announcements and discussions

## 🔐 Security Notes

### Safe Practices
- **Isolate**: Always run security tools in VMs
- **Update**: Keep your system and tools updated
- **Backup**: Regularly backup your work
- **Legal**: Only test on systems you own or have permission to test

### VM Network Settings
- **NAT**: Default, safe for most exercises
- **Host-only**: For inter-VM communication
- **Bridged**: Only when specifically required
- **⚠️ Never**: Run malware on your host system

## 📖 Additional Resources

### Learning Resources
- **Python**: https://docs.python.org/3/tutorial/
- **Git**: https://git-scm.com/book
- **VirtualBox**: https://www.virtualbox.org/manual/
- **Linux**: https://linuxjourney.com/

### Community
- **Discord**: Course Discord server (link in Canvas)
- **Reddit**: r/AskNetsec, r/digitalforensics
- **Twitter**: Follow #InfoSec hashtag

---

**Questions?** Create an issue in the course repository or ask in Canvas discussions.

**Ready to learn?** Head to [Week 1: Cryptography Basics](../week01-crypto-basics/README.md)!