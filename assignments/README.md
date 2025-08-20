# Assignment Submissions

## 📁 Directory Structure

Students create their assignment folder using this format:
```
assignments/
└── CSCI347_f25_FirstName_LastName/
    ├── week01/
    │   ├── password_vault.py
    │   ├── README.md
    │   ├── tests/
    │   └── examples/
    ├── week02/
    ├── week03/
    └── ...
```

## 🔄 Submission Workflow

### 1. Create Your Directory
```bash
cd assignments
mkdir CSCI347_f25_Jane_Smith  # Use your actual name
cd CSCI347_f25_Jane_Smith
```

### 2. Work on Assignments
```bash
# For each week, create a directory
mkdir week01
cd week01

# Work on your assignment files
# - Main implementation file
# - README with usage instructions
# - Test files
# - Example usage
```

### 3. Submit via Pull Request
```bash
# Create feature branch for the week
git checkout -b week01-crypto-assignment

# Add your work
git add assignments/CSCI347_f25_Your_Name/week01/
git commit -m "Complete Week 1 password vault assignment"

# Push and create PR
git push origin week01-crypto-assignment
```

## 📋 Required Files

Each week's assignment should include:
- **Main implementation** (e.g., `password_vault.py`)
- **README.md** with usage instructions and design decisions
- **tests/** directory with test files
- **examples/** directory with usage examples

## ⚠️ Important Notes

- Use your **actual name** in the directory: `CSCI347_f25_Jane_Smith`
- Ensure git is configured with: `git config user.name "Jane Smith - CSCI347_f25"`
- Submit each week's assignment via separate Pull Request
- Include the course identifier `CSCI347_f25` in your directory name

---

**Need help?** Check the [Git commands reference](../quick-reference/git-commands.md)