# GIT SECRETS Scanner 🔍
Advanced secret detection tool for GitHub repositories and local filesystems

## Features
- 100+ secret patterns detection
- Interactive CLI interface
- GitHub Action integration
- Pre-commit hook
- False positive reduction

## Quick Start
```bash
git clone https://github.com/MrDark0x7/git-secrets-scanner
cd git-secrets-scanner
pip install -r requirements.txt

# Scan repository
python src/scanner.py --repo owner/repo

# Scan local files
python src/scanner.py --path ./src

#Ethical Use
⚠️ Always get proper authorization before scanning repositories. Never exploit found secrets.
