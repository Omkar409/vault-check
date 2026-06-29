# vault-check

Password security analyzer using Shannon entropy, NIST compliance checks, and GPU brute-force estimation. Detects keyboard walks, leetspeak, breach dictionaries, and sequential patterns with actionable hardening tips for enterprise credential policies.

**Works on: Windows, macOS, Linux (Ubuntu, Kali, Debian, etc.)**

---

## 🚀 Quick Start (For Beginners)

Choose your operating system and follow the steps:

### 🪟 Windows

#### Step 1: Install Python

1. Go to [python.org/downloads](https://python.org/downloads)
2. Click **Download Python** (latest version)
3. Run the installer
4. **IMPORTANT**: Check "Add Python to PATH" at the bottom
5. Click **Install Now**

Verify installation:
```cmd
python --version
```

#### Step 2: Download the Tool

**Option A: Using Git**
```cmd
# Install Git from https://git-scm.com/download/win
# Then open Command Prompt or PowerShell and run:

git clone https://github.com/Omkar409/vault-check.git
cd vault-check
```

**Option B: Manual Download (No Git)**
1. Go to: https://github.com/Omkar409/vault-check
2. Click green **Code** button → **Download ZIP**
3. Extract the ZIP to your Desktop
4. Open Command Prompt in the extracted folder

#### Step 3: Run the Tool

```cmd
# Interactive mode
python password_checker\password_checker.py

# Or analyze a password directly
python password_checker\password_checker.py "YourPassword123!"

# Generate a secure password
python password_checker\password_checker.py -g 16
```

---

### 🍎 macOS

#### Step 1: Install Python

```bash
# Check if Python is installed
python3 --version

# If not installed, install via Homebrew:
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python3
```

#### Step 2: Download the Tool

```bash
# Install git if needed
brew install git

# Clone the repository
git clone https://github.com/Omkar409/vault-check.git
cd vault-check
```

Or manually download the ZIP from GitHub and extract it.

#### Step 3: Run the Tool

```bash
# Make executable
chmod +x password_checker/password_checker.py

# Interactive mode
python3 password_checker/password_checker.py

# Or analyze a password directly
python3 password_checker/password_checker.py "YourPassword123!"

# Generate a secure password
python3 password_checker/password_checker.py -g 16
```

---

### 🐧 Linux (Ubuntu, Kali, Debian, etc.)

#### Step 1: Install Python

```bash
# Check if Python is installed
python3 --version

# If not installed:
sudo apt update
sudo apt install python3 python3-pip -y
```

#### Step 2: Download the Tool

```bash
# Install git if needed
sudo apt install git -y

# Clone the repository
git clone https://github.com/Omkar409/vault-check.git
cd vault-check
```

Or manually download the ZIP from GitHub and extract it.

#### Step 3: Run the Tool

```bash
# Make executable
chmod +x password_checker/password_checker.py

# Interactive mode
python3 password_checker/password_checker.py

# Or analyze a password directly
python3 password_checker/password_checker.py "YourPassword123!"

# Generate a secure password
python3 password_checker/password_checker.py -g 16
```

---

## 📋 What You'll See

When you run the tool, you'll get a colorful output like this:

```
╔══════════════════════════════════════════════════════════════╗
║           PASSWORD STRENGTH ANALYZER v2.0                    ║
║              Cross-Platform Security Tool                  ║
╚══════════════════════════════════════════════════════════════╝

┌─ Analysis Results ─────────────────────────────────────┐
│ Password:     Pa*******!
│ Length:       12 characters
│ Strength:     MODERATE (65/100)
│ Meter:        [█████████████░░░░░░░]
│ Entropy:      45.2 bits
│ Crack Time:   2.3 centuries
├─ Character Composition ────────────────────────────────┤
│ [OK] Lowercase    Present
│ [OK] Uppercase    Present
│ [OK] Digits       Present
│ [OK] Special      Present
├─ Security Warnings ────────────────────────────────────┤
│ [OK] No common patterns detected
└────────────────────────────────────────────────────────┘

Recommendations:
  -> Use at least 16 characters for maximum security
  -> Excellent password! Consider using a password manager.
```

---

## 📖 How to Use (Interactive Mode Commands)

Once the tool is running, you can type these commands:

| Command | What It Does | Example |
|---------|-----------|---------|
| `analyze <password>` | Check password strength | `analyze MyP@ssw0rd` |
| `generate <length>` | Create secure password | `generate 20` |
| `quit` or `exit` | Close the tool | `quit` |

---

## 🎓 Understanding the Results

### Strength Meter

| Color | Score | Meaning | Action Needed |
|-------|-------|---------|---------------|
| 🔴 Red | 0-25 | VERY WEAK | Change immediately! |
| 🟡 Yellow | 26-50 | WEAK | Add more complexity |
| 🟠 Orange | 51-75 | MODERATE | Good, but can be better |
| 🟢 Green | 76-100 | STRONG | Excellent password |

### What is Entropy?

**Entropy** measures how random your password is. Higher = better:

- **< 30 bits**: Very weak (cracked in seconds)
- **30-50 bits**: Weak (cracked in hours/days)
- **50-80 bits**: Moderate (cracked in years)
- **> 80 bits**: Strong (cracked in centuries)

### What is Crack Time?

This estimates how long a hacker with a powerful GPU would take to crack your password using brute force.

---

## 🛠️ Advanced Setup (Optional)

### Create Virtual Environment (Recommended for Developers)

**Windows:**
```cmd
cd vault-check
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```bash
cd vault-check
python3 -m venv venv
source venv/bin/activate
```

**Deactivate when done:**
```bash
deactivate
```

---

## 🐛 Troubleshooting

### Windows: `python is not recognized`

**Fix:** Reinstall Python and check "Add Python to PATH" during installation.

### macOS/Linux: `python3: command not found`

**Fix:**
```bash
# macOS
brew install python3

# Linux (Ubuntu/Debian/Kali)
sudo apt update
sudo apt install python3 -y
```

### `Permission denied` (macOS/Linux)

**Fix:**
```bash
chmod +x password_checker/password_checker.py
```

### Colors look weird or don't show

**Fix:** The tool auto-detects color support. If colors don't work, the tool still functions normally — just without colors.

For Windows, install colorama for better color support:
```bash
pip install colorama
```

### `ModuleNotFoundError: No module named 'getpass'`

**Fix:** This is a built-in module, so this error shouldn't occur. If it does, your Python installation may be corrupted. Reinstall Python.

---

## 🗺️ Project Roadmap

| Tool | Purpose | Status |
|------|---------|--------|
| ✅ Password Checker | Strength analysis | **Ready** |
| ⏳ Network Recon | Port scanning | Planned |
| ⏳ Log Analyzer | Parse & analyze logs | Planned |
| ⏳ File Encryption | Encrypt/decrypt files | Planned |
| ⏳ System Info | Hardware monitoring | Planned |

---

## 🤝 Contributing

Found a bug or want to add a feature?

1. Fork the repository
2. Create a new branch: `git checkout -b feature-name`
3. Make your changes
4. Push and create a Pull Request

---

## 📄 License

This project is open source and available under the **MIT License**.

---

## 🙋 Need Help?

- **Open an Issue**: https://github.com/Omkar409/vault-check/issues
- **Star this repo** if you found it useful! ⭐

**Happy Hacking! 🛡️**
