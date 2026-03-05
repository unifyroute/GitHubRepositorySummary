# GitHub Repository Scanner

This project can scan all your GitHub repositories at once and generate a summary for each repository in one run.

It reads account credentials from `key.csv`, queries the GitHub API for each account's owned repositories, and generates documentation artifacts.

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

## Input Format

`key.csv` must contain one account per line:

```csv
username,github_personal_access_token
```

Example:

```csv
octocat,ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
my-org-bot,ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

## What It Generates

Running the scanner creates files under `output/`:

- `output/repositories.json`: full structured repository data
- `output/repositories.csv`: flattened repository list for spreadsheets
- `output/repository-report.md`: human-readable inventory report with technologies and README summaries
- `output/project-summaries.md`: compact summary table (`owner`, `repo`, `technologies`, `tags`, `summary`, `url`)

Each repository now includes:

- `language`: GitHub primary language
- `languages`: all detected repository languages (from GitHub language stats)
- `technologies`: inferred technology stack from language stats and README keywords
- `tags`: hashtag-style tags derived from technologies (example: `#python #django #react`)
- `readme_summary`: short summary extracted from the repository README

## Run

```powershell
python github_scan.py --input key.csv --output-dir output
```

Optional arguments:

- `--timeout 30` request timeout in seconds (default: 30)
- `--pause 0.0` delay in seconds between account scans (default: 0.0)

## Notes

- Tokens are used only for API requests and are never written to output files.
- The script continues scanning other accounts if one token fails.
- Ensure each token has permissions to read repositories for its account.
