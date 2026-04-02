from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

API_BASE = "https://api.github.com"
ENC_MAGIC = "GITHUB_SCAN_ENC_V1"
PBKDF2_ITERATIONS = 200_000
CONFIG_FILE = "scan_config.ini"

# Valid affiliation tokens accepted by the GitHub API.
_VALID_AFFILIATIONS = {"owner", "collaborator", "organization_member"}


def load_config(config_path: str = CONFIG_FILE) -> configparser.ConfigParser:
    """Load scan_config.ini, returning a ConfigParser with built-in defaults."""
    cfg = configparser.ConfigParser(
        defaults={
            "affiliation": "owner",
            "timeout": "30",
            "pause": "0.0",
            "output_dir": "output",
            "input": "key.csv",
            "max_commits_per_repo": "1000",
        }
    )
    # Ensure the [scan] section always exists even if the file is missing.
    cfg.read_dict({"scan": {}})
    cfg.read(config_path, encoding="utf-8")
    return cfg


def validate_affiliation(raw: str) -> str:
    """Validate and normalise the affiliation string from config or CLI."""
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    invalid = [t for t in tokens if t not in _VALID_AFFILIATIONS]
    if invalid:
        raise ValueError(
            f"Invalid affiliation value(s): {invalid}. "
            f"Allowed values: {sorted(_VALID_AFFILIATIONS)}"
        )
    if not tokens:
        raise ValueError("affiliation must not be empty.")
    return ",".join(tokens)


@dataclass
class AccountResult:
    csv_owner: str
    authenticated_login: str | None
    repo_count: int
    commits: list[dict[str, Any]]
    warnings: list[str]
    error: str | None


class GitHubApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def xor_with_keystream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    # Deterministic stream for symmetric encrypt/decrypt from key+nonce.
    out = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        block = hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        block_len = min(len(block), len(data) - offset)
        for index in range(block_len):
            out[offset + index] = data[offset + index] ^ block[index]
        offset += block_len
        counter += 1
    return bytes(out)


def derive_keys(passphrase: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    if not passphrase:
        raise ValueError("Encryption key must not be empty.")

    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        iterations,
        dklen=64,
    )
    return key_material[:32], key_material[32:]


def build_mac(mac_key: bytes, salt: bytes, nonce: bytes, iterations: int, ciphertext: bytes) -> str:
    payload = (
        ENC_MAGIC.encode("ascii")
        + b"\n"
        + salt
        + nonce
        + iterations.to_bytes(8, "big")
        + ciphertext
    )
    return hmac.new(mac_key, payload, hashlib.sha256).hexdigest()


def encrypt_text(plaintext: str, passphrase: str) -> bytes:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    enc_key, mac_key = derive_keys(passphrase, salt, PBKDF2_ITERATIONS)

    ciphertext = xor_with_keystream(plaintext.encode("utf-8"), enc_key, nonce)
    mac = build_mac(mac_key, salt, nonce, PBKDF2_ITERATIONS, ciphertext)

    envelope = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "iterations": PBKDF2_ITERATIONS,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "mac": mac,
    }
    return (ENC_MAGIC + "\n" + json.dumps(envelope, separators=(",", ":"))).encode("utf-8")


def decrypt_text(blob: bytes, passphrase: str) -> str:
    try:
        prefix, payload = blob.split(b"\n", 1)
    except ValueError as exc:
        raise ValueError("Encrypted file format is invalid.") from exc

    if prefix.decode("utf-8", errors="replace") != ENC_MAGIC:
        raise ValueError("Input file is not in supported encrypted format.")

    try:
        envelope = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Encrypted file payload is not valid JSON.") from exc

    try:
        salt = base64.b64decode(str(envelope["salt"]))
        nonce = base64.b64decode(str(envelope["nonce"]))
        ciphertext = base64.b64decode(str(envelope["ciphertext"]))
        iterations = int(envelope["iterations"])
        provided_mac = str(envelope["mac"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("Encrypted file is missing required fields.") from exc

    enc_key, mac_key = derive_keys(passphrase, salt, iterations)
    expected_mac = build_mac(mac_key, salt, nonce, iterations, ciphertext)
    if not hmac.compare_digest(expected_mac, provided_mac):
        raise ValueError("Failed to decrypt key file: wrong decrypt key or corrupted file.")

    plaintext = xor_with_keystream(ciphertext, enc_key, nonce)
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Decrypted key file is not valid UTF-8 text.") from exc


def is_encrypted_blob(blob: bytes) -> bool:
    return blob.startswith((ENC_MAGIC + "\n").encode("ascii"))


def load_credentials_from_text(csv_text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with io.StringIO(csv_text) as handle:
        reader = csv.reader(handle)
        for index, row in enumerate(reader, start=1):
            if not row:
                continue
            if row[0].strip().startswith("#"):
                continue
            if len(row) < 2:
                raise ValueError(f"Invalid row {index}: expected 'username,token'.")

            owner = row[0].strip()
            token = row[1].strip()
            if not owner or not token:
                raise ValueError(f"Invalid row {index}: username or token is empty.")
            rows.append((owner, token))

    if not rows:
        raise ValueError("No credentials found in input CSV.")
    return rows


def load_credentials(csv_path: Path, decrypt_key: str | None) -> list[tuple[str, str]]:
    raw = csv_path.read_bytes()
    if is_encrypted_blob(raw):
        if not decrypt_key:
            raise ValueError("Input key file is encrypted. Provide --decrypt-key to continue.")
        csv_text = decrypt_text(raw, decrypt_key)
    else:
        csv_text = raw.decode("utf-8-sig")

    return load_credentials_from_text(csv_text)


def github_get_json(url: str, token: str, timeout: int, accept: str = "application/vnd.github+json") -> Any:
    req = request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "User-Agent": "github-commits-scan-script",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )

    try:
        with request.urlopen(req, timeout=timeout) as response:
            payload = response.read().decode("utf-8")
            return json.loads(payload)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        message = body
        try:
            parsed = json.loads(body)
            message = parsed.get("message", body)
        except json.JSONDecodeError:
            pass
        raise GitHubApiError(f"HTTP {exc.code}: {message}", status_code=exc.code) from exc
    except error.URLError as exc:
        raise GitHubApiError(f"Network error: {exc.reason}") from exc


def get_authenticated_login(token: str, timeout: int) -> str:
    profile = github_get_json(f"{API_BASE}/user", token, timeout)
    login = profile.get("login") if isinstance(profile, dict) else None
    if not login:
        raise GitHubApiError("Unable to determine authenticated user login.")
    return str(login)


def fetch_owned_repos(token: str, timeout: int, affiliation: str = "owner") -> list[dict[str, Any]]:
    repos: list[dict[str, Any]] = []
    page = 1

    while True:
        params = parse.urlencode(
            {
                "per_page": 100,
                "page": page,
                "visibility": "all",
                "affiliation": affiliation,
                "sort": "full_name",
                "direction": "asc",
            }
        )
        url = f"{API_BASE}/user/repos?{params}"
        page_data = github_get_json(url, token, timeout)

        if not isinstance(page_data, list):
            raise GitHubApiError("Unexpected API response while reading repositories.")
        if not page_data:
            break

        repos.extend(page_data)
        page += 1

    return repos


def fetch_repo_commits(full_name: str, token: str, timeout: int, max_commits: int = 1000) -> list[dict[str, Any]]:
    commits: list[dict[str, Any]] = []
    page = 1
    endpoint_repo = parse.quote(full_name, safe="/")
    
    while len(commits) < max_commits:
        params = parse.urlencode({
            "per_page": 100,
            "page": page,
        })
        url = f"{API_BASE}/repos/{endpoint_repo}/commits?{params}"
        try:
            page_data = github_get_json(url, token, timeout)
            if not isinstance(page_data, list):
                break
            if not page_data:
                break
                
            commits.extend(page_data)
            if len(page_data) < 100:
                break
            page += 1
        except GitHubApiError as exc:
            if exc.status_code == 409: # Empty repo (Git Repository is empty)
                return []
            if exc.status_code == 404:
                return []
            raise
            
    return commits[:max_commits]


def md_cell(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").strip()
    if not text:
        return "-"
    return text.replace("|", "\\|")


def run_commits_scan(
    input_path: Path,
    output_dir: Path,
    timeout: int,
    pause_seconds: float,
    decrypt_key: str | None,
    affiliation: str = "owner",
    max_commits_per_repo: int = 1000,
) -> int:
    credentials = load_credentials(input_path, decrypt_key)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "commits-report.md"
    
    report_lines: list[str] = [
        "# GitHub Commits Report",
        "",
        f"Generated at (UTC): `{utc_now_iso()}`",
        f"Input file: `{input_path}`",
        "",
    ]
    
    seen_repos: set[str] = set()
    total_commits_documented = 0
    total_repos_processed = 0

    for index, (csv_owner, token) in enumerate(credentials, start=1):
        print(f"[{index}/{len(credentials)}] Scanning account '{csv_owner}'...")
        
        try:
            auth_login = get_authenticated_login(token, timeout)
            repos = fetch_owned_repos(token, timeout, affiliation=affiliation)
            
            for repo in repos:
                full_name = repo["full_name"]
                if full_name in seen_repos:
                    continue
                
                seen_repos.add(full_name)
                total_repos_processed += 1
                
                print(f"  [{total_repos_processed}] Fetching commits for {full_name}...")
                report_lines.extend([
                    f"## Repository: {full_name}",
                    "",
                    "| Date | Author | SHA | Message |",
                    "| --- | --- | --- | --- |"
                ])
                
                try:
                    repo_commits = fetch_repo_commits(full_name, token, timeout, max_commits_per_repo)
                    if not repo_commits:
                        report_lines.append("| - | - | - | *No commits found or empty repository* |")
                    
                    for c in repo_commits:
                        commit_info = c.get("commit", {})
                        author_info = commit_info.get("author", {})
                        
                        date = md_cell(author_info.get("date", ""))
                        author = md_cell(author_info.get("name", ""))
                        sha = md_cell(c.get("sha", "")[:7])
                        message = md_cell(commit_info.get("message", ""))
                        
                        report_lines.append(f"| {date} | {author} | `{sha}` | {message} |")
                        total_commits_documented += 1
                except GitHubApiError as repo_exc:
                    print(f"    Warning: Failed to fetch commits for {full_name}: {repo_exc}")
                    report_lines.append(f"| - | - | - | *Error fetching commits: {repo_exc}* |")
                
                report_lines.append("")
                    
        except (GitHubApiError, ValueError) as exc:
            print(f"  Failed to scan account '{csv_owner}': {exc}")
            report_lines.extend([
                f"## Error: Account {csv_owner}",
                "",
                f"Failed to scan account: {exc}",
                ""
            ])

        if pause_seconds > 0 and index < len(credentials):
            time.sleep(pause_seconds)

    report_lines.extend([
        "---",
        "## Summary",
        "",
        f"- **Total Repositories**: {total_repos_processed}",
        f"- **Total Commits**: {total_commits_documented}",
    ])

    output_file.write_text("\n".join(report_lines), encoding="utf-8")

    print(f"\nCompleted.")
    print(f"Total repositories processed: {total_repos_processed}")
    print(f"Total commits documented: {total_commits_documented}")
    print(f"Output report: {output_file}")
    
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for all commits and generate a single CSV report."
    )
    parser.add_argument(
        "--config",
        default=CONFIG_FILE,
        help=f"Path to INI config file (default: {CONFIG_FILE}).",
    )
    parser.add_argument("--input", default=None, help="Path to input CSV containing username,token rows.")
    parser.add_argument("--output-dir", default=None, help="Directory for generated output files.")
    parser.add_argument("--timeout", type=int, default=None, help="HTTP timeout in seconds.")
    parser.add_argument("--pause", type=float, default=None, help="Delay in seconds between scanning each account.")
    parser.add_argument(
        "--affiliation",
        default=None,
        help="Comma-separated GitHub repo affiliation scope (owner, collaborator, organization_member).",
    )
    parser.add_argument(
        "--max-commits",
        type=int,
        default=None,
        help="Maximum commits to fetch per repository (default: 1000).",
    )
    parser.add_argument("--decrypt-key", default=None, help="Decrypt key for encrypted key file input.")
    
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)
    section = "scan"

    resolved_input = args.input or cfg.get(section, "input")
    resolved_output_dir = args.output_dir or cfg.get(section, "output_dir")
    resolved_timeout = args.timeout if args.timeout is not None else cfg.getint(section, "timeout")
    resolved_pause = args.pause if args.pause is not None else cfg.getfloat(section, "pause")
    raw_affiliation = args.affiliation or cfg.get(section, "affiliation")
    resolved_max_commits = args.max_commits if args.max_commits is not None else cfg.getint(section, "max_commits_per_repo", fallback=1000)

    input_path = Path(resolved_input)
    output_dir = Path(resolved_output_dir)

    try:
        affiliation = validate_affiliation(raw_affiliation)
        
        if not input_path.exists():
            print(f"Error: Input file not found: {input_path}", file=sys.stderr)
            return 2

        print(f"Scan Commits | config={args.config} | affiliation={affiliation} | timeout={resolved_timeout}s | max_commits_per_repo={resolved_max_commits}")
        
        return run_commits_scan(
            input_path=input_path,
            output_dir=output_dir,
            timeout=resolved_timeout,
            pause_seconds=resolved_pause,
            decrypt_key=args.decrypt_key,
            affiliation=affiliation,
            max_commits_per_repo=resolved_max_commits,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)
