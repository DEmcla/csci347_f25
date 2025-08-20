# CSCI 347 Troubleshooting Guide

Common issues and solutions for Network Security and Digital Forensics course.

## 🆘 For Struggling Students: Quick Help

### "I'm Completely Overwhelmed"
1. **Don't try to understand everything** - Focus on making the code run first
2. **Use the template files** - Don't start from scratch
3. **Read just one tutorial module at a time** - Don't try to absorb everything at once
4. **Ask for help after 15 minutes of being stuck** - Don't suffer in silence
5. **Schedule office hours** - Get personal 1-on-1 help

### "I Don't Know Where to Start"
1. **Start with the tutorial** - Run the provided examples first
2. **Copy-paste and modify** - Start with working code, then make small changes
3. **Focus on the template TODO comments** - They tell you exactly what to do
4. **Test each small piece** - Don't write lots of code without testing

### "Nothing Makes Sense"
1. **That's normal** - Security concepts are complex
2. **Focus on "what" before "why"** - Get it working before understanding how
3. **Use print() statements liberally** - See what your code is actually doing
4. **Ask specific questions** - "Why does line 15 give an error?" not "I don't understand anything"

## 🐍 Python Environment Issues

### ImportError: No module named 'cryptography'
```bash
# Solution 1: Install in virtual environment
pip install cryptography

# Solution 2: Upgrade pip first
pip install --upgrade pip
pip install cryptography

# Solution 3: Use system package manager (Linux)
sudo apt-get install python3-cryptography
```

### Virtual Environment Not Activating
```bash
# Windows
venv\Scripts\activate

# macOS/Linux  
source venv/bin/activate

# If activation script missing, recreate environment
rm -rf venv
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
```

### Python Version Issues
```bash
# Check Python version
python --version

# If wrong version, use specific version
python3.11 -m venv venv
# or
py -3.11 -m venv venv  # Windows with Python launcher
```

## 🔐 Cryptography Library Issues

### "Microsoft Visual C++ 14.0 is required" (Windows)
1. Install Microsoft C++ Build Tools
2. Or install Visual Studio Community Edition
3. Or use pre-compiled wheels: `pip install --only-binary=cryptography cryptography`

### macOS Compilation Errors
```bash
# Install development tools
xcode-select --install

# Install using Homebrew
brew install openssl libffi
pip install --upgrade pip setuptools wheel
pip install cryptography
```

### Linux Compilation Errors
```bash
# Ubuntu/Debian
sudo apt-get install build-essential libssl-dev libffi-dev python3-dev

# CentOS/RHEL
sudo yum install gcc openssl-devel libffi-devel python3-devel

# Fedora
sudo dnf install gcc openssl-devel libffi-devel python3-devel
```

## 🖥️ VirtualBox Issues

### Virtualization Not Available
1. **Enable in BIOS**: Reboot and enable VT-x/AMD-V in BIOS/UEFI
2. **Windows Hyper-V Conflict**: Disable Hyper-V in Windows Features
3. **Check Support**: Run `systeminfo` (Windows) or check `/proc/cpuinfo` (Linux)

### VM Performance Issues
- **Increase RAM**: Allocate at least 2GB to VMs
- **Enable Hardware Acceleration**: VT-x/AMD-V in VM settings
- **Disable Visual Effects**: In guest OS for better performance
- **Use Bridged Networking**: Only when needed, NAT is faster

### VM Won't Start
```bash
# Check VirtualBox service (Windows)
net start vboxdrv

# Check kernel modules (Linux)
sudo /sbin/vboxconfig
sudo modprobe vboxdrv
```

## 🔧 Git and GitHub Issues

### Authentication Failed
```bash
# Use personal access token instead of password
git config --global credential.helper store

# Or use SSH keys
ssh-keygen -t ed25519 -C "your.email@example.com"
# Add public key to GitHub account
```

### Repository Clone Issues
```bash
# Use HTTPS instead of SSH if SSH fails
git clone https://github.com/user/repo.git

# Check firewall/proxy settings
git config --global http.proxy http://proxy.company.com:8080
```

### Large File Issues
```bash
# For large forensics images, use Git LFS
git lfs install
git lfs track "*.img"
git add .gitattributes
```

## 📱 Network and Connectivity

### Package Installation Timeouts
```bash
# Use different index URL
pip install --index-url https://pypi.python.org/simple/ package_name

# Increase timeout
pip install --timeout 1000 package_name

# Use proxy if behind firewall
pip install --proxy user:password@proxy.company.com:8080 package_name
```

### Firewall Blocking Connections
- **Windows**: Add Python and VirtualBox to Windows Firewall exceptions
- **Corporate Networks**: Work with IT to allow required connections
- **VPN Issues**: Some VPNs block virtualization or specific ports

## 🔬 Course-Specific Issues

### Week 1: Cryptography Problems

**"Fernet key must be 32 url-safe base64-encoded bytes"**
```python
# Correct key generation
key = Fernet.generate_key()
# Don't manually create keys unless you know what you're doing
```

**Key derivation issues**
```python
# Ensure consistent salt usage
salt = os.urandom(16)  # Generate once, reuse for verification
# Don't generate new salt each time for same password
```

### Week 2: Hashing Issues

**Hash mismatch on different systems**
```python
# Always use binary mode for files
with open(filename, 'rb') as f:  # Note 'rb' not 'r'
    data = f.read()
```

**HMAC verification failures**
```python
# Use hmac.compare_digest() to prevent timing attacks
return hmac.compare_digest(expected_mac, computed_mac)
# Don't use == for MAC comparison
```

### Week 3: Certificate Issues

**Certificate validation errors**
- Check system time (certificates have validity periods)
- Verify certificate chain is complete
- Ensure correct certificate extensions

**TLS connection failures**
- Check hostname matches certificate CN/SAN
- Verify certificate chain up to trusted root
- Check for proxy/firewall interference

### Weeks 10-14: Forensics Issues

**Large file handling**
```python
# Read files in chunks for large forensic images
def hash_large_file(filepath):
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):  # 8KB chunks
            hasher.update(chunk)
    return hasher.hexdigest()
```

**Memory issues with Volatility**
- Increase system RAM if possible
- Use 64-bit Python for large memory dumps
- Close other applications during analysis

## 🎯 Assignment-Specific Help

### Code Not Working After Tutorial
1. **Check file paths**: Use absolute paths or verify current directory
2. **Virtual environment**: Ensure it's activated
3. **Package versions**: Some packages may have breaking changes
4. **Copy-paste errors**: Retype critical sections instead of copying

### GitHub Repository Issues
- **Files not appearing**: Check .gitignore isn't excluding them
- **Large files**: Use Git LFS for files >100MB
- **Private vs public**: Ensure repository visibility is correct
- **README not displaying**: Check markdown syntax

### Canvas Submission Problems
- **File size limits**: Canvas may limit file uploads
- **Format issues**: Ensure files are in accepted formats
- **Late submissions**: Check deadline and late policy
- **Multiple attempts**: Some assignments allow resubmission

## 💡 General Debugging Tips

### Systematic Debugging
1. **Read error messages carefully** - they usually tell you what's wrong
2. **Check the basics** - Python version, virtual environment, file paths
3. **Isolate the problem** - Test smaller parts of your code
4. **Search online** - Stack Overflow often has solutions
5. **Ask for help** - Use Canvas discussions or office hours

### Code Debugging
```python
# Add debug prints to understand program flow
print(f"DEBUG: variable_name = {variable_name}")

# Use Python debugger for complex issues
import pdb; pdb.set_trace()

# Check types and values
print(f"Type: {type(variable)}, Value: {variable}")
```

### Environment Debugging
```bash
# Check Python environment
which python
python --version
pip list

# Check Git configuration  
git config --list

# Verify course-specific git config
git config user.name    # Should include "CSCI347_f25"
git config user.email   # Should be your university email

# Check network connectivity
ping google.com
curl -I https://pypi.org
```

## 🆘 Getting Help

### Course Support Channels
1. **Canvas Discussions**: Post questions for peer and instructor help
2. **Office Hours**: Regular virtual or in-person assistance
3. **GitHub Issues**: Report problems with course materials
4. **Email**: For private or urgent issues

### External Resources
- **Stack Overflow**: Programming questions and solutions
- **Python Documentation**: Official Python and package documentation
- **Cryptography Documentation**: https://cryptography.io/
- **VirtualBox Manual**: https://www.virtualbox.org/manual/

### Professional Development
- **Security Communities**: Reddit r/netsec, r/cybersecurity
- **Industry Forums**: SANS Community, InfoSec Twitter
- **Local Meetups**: Cybersecurity and Python user groups
- **Conferences**: DEF CON, BSides, local security conferences

