# Quick Troubleshooting (Top 10 Issues)

## 🐍 Python Issues

**"No module named cryptography"**
```bash
pip install cryptography
```

**"Python command not found"**
```bash
python3 --version  # Try python3 instead
```

**Virtual environment not working**
```bash
deactivate
rm -rf venv
python -m venv venv
source venv/bin/activate
```

## 🔐 Crypto Issues

**"Fernet key must be 32 url-safe base64-encoded bytes"**
```python
# Use Fernet.generate_key(), don't create manually
key = Fernet.generate_key()
```

**Decryption fails**
- Check you're using the same key
- Verify file wasn't corrupted
- Make sure you're using binary mode: `open(file, 'rb')`

## 📁 Git Issues

**"Authentication failed"**
- Use personal access token, not password
- Check GitHub account settings

**"Repository not found"**
- Make sure you forked the repository first
- Use your GitHub username in clone URL

## ⚡ Quick Fixes

**Stuck for >15 minutes?**
1. Post error message in Canvas discussions
2. Schedule office hours
3. Try the [full troubleshooting guide](../resources/troubleshooting.md)

**Code not working after tutorial?**
1. Check you're in virtual environment: `which python`
2. Verify file paths are correct
3. Add print statements to debug

**Assignment seems overwhelming?**
1. Focus on making basic code work first
2. Use the template file as starting point
3. Don't try to understand everything at once