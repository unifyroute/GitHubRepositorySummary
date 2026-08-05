# GitHub Repository Summary Commands Reference 📋

This document lists all the useful commands for running, configuring, and serving this project.

---

## 1. Repository Scanner (`github_scan.py`) 🔍

### A) Standard Scan
Scan using a plain `keys.csv` and output results to a directory:
```powershell
python github_scan.py --input keys.csv --output-dir output
```

### B) Scan with Custom Parameters
Set a custom HTTP request timeout and a pause delay between account scans:
```powershell
python github_scan.py --input keys.csv --output-dir output --timeout 45 --pause 0.2
```

### C) Show Command Help
View all available CLI flags and their descriptions:
```powershell
python github_scan.py --help
```

---

## 2. Key Encryption & Security 🔐

### A) Encrypt Plain `keys.csv`
Encrypt your credentials so they are not stored in plaintext:
```powershell
python github_scan.py --input keys.csv --encrypt-input --encrypt-key "your-secret-string"
```

### B) Encrypt to Custom Output Path
```powershell
python github_scan.py --input keys.csv --encrypt-input --encrypt-key "your-secret-string" --encrypted-output secure\my-keys.enc
```

### C) Scan with Encrypted Key File
Perform a scan by providing the decryption key:
```powershell
python github_scan.py --input keys.enc --decrypt-key "your-secret-string" --output-dir output
```

### D) Export Decrypted Credentials
Export an encrypted key file back to plain CSV:
```powershell
python github_scan.py --input keys.enc --decrypt-key "your-secret-string" --export-decrypted key.decrypted.csv
```

---

## 3. Dashboard Generator (`generate_dashboard.py`) 📊

### A) Generate HTML Dashboard (Plain Text Keys)
Create the dashboard index and detailed repository HTML subpages:
```powershell
python generate_dashboard.py --input keys.csv --output-dir output
```

### B) Generate HTML Dashboard (Encrypted Keys)
Create the dashboard by decrypting your credentials:
```powershell
python generate_dashboard.py --input keys.enc --decrypt-key "your-secret-string"
```

---

## 4. Web Server (`server.py`) 🚀

### A) Start Web Server (Auto-detect Directory)
Serves the generated dashboard. It will automatically detect directories like `20260806` or `output` to find `GitHubDashBoard.html`:
```powershell
python server.py
```

### B) Start Web Server on a Custom Port and Directory
```powershell
python server.py --port 8080 --dir 20260806
```
