# Essential Git Commands for CSCI 347

## Assignment Workflow

### Start New Assignment
```bash
# Update your fork
git checkout main
git pull upstream main
git push origin main

# Create feature branch
git checkout -b week01-crypto-assignment
```

### Work on Assignment
```bash
# Check status
git status

# Add changes
git add filename.py
# OR add all changes
git add .

# Commit with message
git commit -m "Implement password vault encryption"
```

### Submit Assignment
```bash
# Push branch to your fork
git push origin week01-crypto-assignment

# Then create Pull Request on GitHub
```

## Common Commands

| Command | Purpose |
|---------|---------|
| `git status` | See what changed |
| `git add .` | Stage all changes |
| `git commit -m "message"` | Save changes |
| `git push` | Upload to GitHub |
| `git pull` | Download updates |

## Troubleshooting

**Merge conflicts?**
```bash
git status  # See conflicted files
# Edit files to resolve conflicts
git add .
git commit -m "Resolve merge conflicts"
```

**Need to undo?**
```bash
git checkout -- filename  # Undo file changes
git reset HEAD~1          # Undo last commit
```

---

**More help**: [Full Git guide](../setup/getting-started.md)