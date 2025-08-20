# Quick Setup Checklist

**⏱️ Time needed: 15 minutes**

## ✅ Pre-Setup Check
```bash
python --version  # Should be 3.11+
git --version     # Should be 2.0+
```

## ✅ Environment Setup (5 min)
```bash
# 1. Create virtual environment
python -m venv venv

# 2. Activate it
source venv/bin/activate  # Mac/Linux
# OR
venv\Scripts\activate     # Windows

# 3. Install crypto library
pip install cryptography
```

## ✅ Git Configuration (2 min)
```bash
git config user.name "FirstName LastName - CSCI347_f25"
git config user.email "your.email@university.edu"
```

## ✅ Repository Setup (5 min)
```bash
# Fork course repo on GitHub, then:
git clone https://github.com/YourUsername/CSCI347_f25.git
cd CSCI347_f25
git remote add upstream https://github.com/instructor/CSCI347_f25.git
```

## ✅ Verification (3 min)
```bash
python setup/verify-environment.py
```

**✅ Success**: You should see "Environment ready for CSCI 347"

---

**❌ Problems?** See [full troubleshooting guide](../resources/troubleshooting.md)