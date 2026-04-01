# GitHub Repository Scanner 🚀

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)
![GitHub API](https://img.shields.io/badge/GitHub%20API-v3-black.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

Scan all your GitHub repositories at once and generate a clean summary for each project in one run. 📦

This script reads account credentials from `key.csv`, calls the GitHub API for each account's owned repositories, and produces documentation-ready output files.

## Why This Project? ✨

- Scan multiple accounts in one command
- Capture technologies used in each repo
- Extract README-based project summaries
- Generate JSON, CSV, and Markdown reports
- Support encrypted key files for safer token handling

## Secure Key File (Encrypt/Decrypt) 🔐

You can encrypt your key file using a user-defined string so tokens are not stored in plain text.

- If the input file is encrypted, scanning requires `--decrypt-key`.
- If `--decrypt-key` is missing or incorrect, the script exits with an error.
- You can export a decrypted file when needed.

### 1) Encrypt plain `key.csv` 🧩

```powershell
python github_scan.py --input key.csv --encrypt-input --encrypt-key "your-secret-string"
```

Default encrypted output: `key.csv.enc`

Custom encrypted output path:

```powershell
python github_scan.py --input key.csv --encrypt-input --encrypt-key "your-secret-string" --encrypted-output secure\my-keys.enc
```

### 2) Scan using encrypted key file 🛡️

```powershell
python github_scan.py --input keys.enc --decrypt-key "your-secret-string" --output-dir output
```

### 3) Export decrypted file (optional) 📤

```powershell
python github_scan.py --input keys.enc --decrypt-key "your-secret-string" --export-decrypted key.decrypted.csv
```

## Create Personal Access Tokens (Classic)

Create one token per GitHub account and grant only `repo` scope.

1. Sign in to GitHub for the account you want to scan.
2. Open `Settings`.
3. Go to `Developer settings`.
4. Go to `Personal access tokens`.
5. Select `Tokens (classic)`.
6. Click `Generate new token` and then `Generate new token (classic)`.
7. Set a note and expiration as needed.
8. Under scopes, select only `repo`.
9. Click `Generate token` and copy it immediately.
10. Add it to `key.csv` as `username,token`.

Repeat for each account you want to include in the scan.

## Quick Examples 🧪

### A) Standard scan using plain `key.csv`

```powershell
python github_scan.py --input key.csv --output-dir output
```

### B) Scan with custom timeout and pause

```powershell
python github_scan.py --input key.csv --output-dir output --timeout 45 --pause 0.2
```

### C) Encrypt first, then scan with decrypt key

```powershell
python github_scan.py --input key.csv --encrypt-input --encrypt-key "your-secret-string"
python github_scan.py --input key.csv.enc --decrypt-key "your-secret-string" --output-dir output
```

### D) Export decrypted file only

```powershell
python github_scan.py --input key.csv.enc --decrypt-key "your-secret-string" --export-decrypted key.decrypted.csv
```

### E) Custom encrypted output path

```powershell
python github_scan.py --input key.csv --encrypt-input --encrypt-key "your-secret-string" --encrypted-output secure\my-keys.enc
```

### F) Show command help

```powershell
python github_scan.py --help
```

## Input Format 📝

`key.csv` must contain one account per line:

```csv
username,github_personal_access_token
```

Example:

```csv
octocat,ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
my-org-bot,ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

## What It Generates 📊

Running the scanner creates files under `output/`:

- `output/repositories.json`: full structured repository data
- `output/repositories.csv`: flattened repository list for spreadsheets
- `output/repository-report.md`: human-readable inventory report with technologies and README summaries
- `output/project-summaries.md`: compact summary table (`owner`, `repo`, `technologies`, `tags`, `summary`, `url`)

Each repository now includes:

- `language`: GitHub primary language
- `languages`: all detected repository languages (from GitHub language stats)
- `technologies`: inferred technology stack from language stats and README keywords
- `tags`: hashtag-style labels derived from technologies (example: `#python #django #react`)
- `readme_summary`: short summary extracted from the repository README

## Run ▶️

```powershell
python github_scan.py --input key.csv --output-dir output
```

Optional arguments:

- `--timeout 30` request timeout in seconds (default: 30)
- `--pause 0.0` delay in seconds between account scans (default: 0.0)
- `--decrypt-key "..."` decrypt key for encrypted input file
- `--encrypt-input` encrypt the input key file and exit
- `--encrypt-key "..."` user-defined key for encryption
- `--encrypted-output path` custom output path for encrypted file
- `--export-decrypted path` export decrypted key file and exit

## Notes 📌

- Tokens are used only for API requests and are never written to output files.
- The script continues scanning other accounts if one token fails.
- Ensure each token has permissions to read repositories for its account.

## Labels / Badges 🏷️

- `License: MIT`
- `Python 3.10+`
- `GitHub API v3`
- `Status: Active`

## License 📄

This project is licensed under the **MIT License**. See `LICENSE` for details.
