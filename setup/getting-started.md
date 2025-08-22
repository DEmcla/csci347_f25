# Course Environment Setup

**Time needed: 15-20 minutes**

**Need the quick version?** See [Setup Checklist](../quick-reference/setup-checklist.md) (2 minutes)

## System Requirements

**Minimum requirements:**
- 8GB RAM (16GB recommended)
- 100GB free disk space 
- Python 3.11 or higher
- Git
- VirtualBox (or UTM for Apple Silicon Macs)

## Step 1: Install Python & Git

### Windows
1. **Python**: Download from [python.org](https://python.org) - **Check "Add Python to PATH"**
2. **Git**: Download from [git-scm.com](https://git-scm.com)

### macOS  
```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Git
brew install python@3.11 git
```

### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install -y python3.11 python3.11-pip python3.11-venv git
```

## Step 2: Set Up Course Repository

```bash
# 1. Fork the course repository on GitHub
# Go to: https://github.com/DEmcla/csci347_f25 and click "Fork"

# 2. Clone YOUR fork (replace YourUsername)
git clone https://github.com/YourUsername/csci347_f25.git
cd csci347_f25

# 3. Configure Git for the course
git config user.name "Your Name - CSCI347_f25"
git config user.email "your.email@example.com"

# 4. Add the original repo to get updates
git remote add upstream https://github.com/DEmcla/csci347_f25.git
```

## Step 3: Create Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install required packages
pip install --upgrade pip
pip install cryptography pyOpenSSL volatility3 scapy requests pytest
```

## Step 4: Install VirtualBox

**For Intel/AMD processors:**
- Download [VirtualBox](https://virtualbox.org) and install

**For Apple Silicon (M1/M2/M3) Macs:**
- Download [UTM](https://mac.getutm.app/) instead (VirtualBox won't work)

## Step 5: Verify Setup

```bash
python setup/verify-environment.py
```

**Expected output:**
```
✅ Python 3.11+ found
✅ Virtual environment active  
✅ Required packages installed
✅ Git configured
✅ Ready to start!
```

## Create Your Assignment Folder

```bash
# Create your personal assignment directory (use your actual name)
mkdir -p assignments/CSCI347_f25_FirstName_LastName/week01

# Commit the structure
git add assignments/
git commit -m "Set up assignment directory structure"
git push origin main
```

## Troubleshooting

**Python not found?**
- Windows: Try `python` instead of `python3`
- Make sure Python was added to PATH during installation

**Permission errors?**
- Don't use `sudo` with pip in virtual environments
- Recreate the virtual environment if needed

**Need help?**
- Check [troubleshooting guide](../resources/troubleshooting.md)
- Post questions in Canvas discussions
- Create GitHub issue for technical problems

## Next Steps

1. **Verify everything works**: Run the verification script
2. **Start learning**: Go to [Week 1](../week01-crypto-basics/README.md)
3. **Join discussions**: Canvas for questions and announcements

---

**Ready to learn?** Head to [Week 1: Cryptography Basics](../week01-crypto-basics/README.md)!