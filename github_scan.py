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
TECH_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("django", "Django"),
    ("fastapi", "FastAPI"),
    ("flask", "Flask"),
    ("react", "React"),
    ("next.js", "Next.js"),
    ("nextjs", "Next.js"),
    ("angular", "Angular"),
    ("vue", "Vue"),
    ("node", "Node.js"),
    ("express", "Express"),
    ("postgres", "PostgreSQL"),
    ("mysql", "MySQL"),
    ("mongodb", "MongoDB"),
    ("redis", "Redis"),
    ("clickhouse", "ClickHouse"),
    ("tailwind", "Tailwind CSS"),
    ("docker", "Docker"),
    ("kubernetes", "Kubernetes"),
    ("aws", "AWS"),
    ("azure", "Azure"),
    ("gcp", "GCP"),
)


@dataclass
class AccountResult:
    csv_owner: str
    authenticated_login: str | None
    repo_count: int
    personal_repo_count: int
    org_repo_count: int
    repos: list[dict[str, Any]]
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


def encrypt_credentials_file(input_path: Path, output_path: Path, encrypt_key: str) -> None:
    if not input_path.exists():
        raise ValueError(f"Input file not found: {input_path}")

    raw = input_path.read_bytes()
    if is_encrypted_blob(raw):
        raise ValueError("Input file is already encrypted.")

    plaintext = raw.decode("utf-8-sig")
    encrypted = encrypt_text(plaintext, encrypt_key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encrypted)


def export_decrypted_file(input_path: Path, output_path: Path, decrypt_key: str) -> None:
    if not input_path.exists():
        raise ValueError(f"Input file not found: {input_path}")

    raw = input_path.read_bytes()
    if not is_encrypted_blob(raw):
        raise ValueError("Input file is not encrypted.")

    plaintext = decrypt_text(raw, decrypt_key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(plaintext, encoding="utf-8")


def github_get_json(url: str, token: str, timeout: int, accept: str = "application/vnd.github+json") -> Any:
    req = request.Request(
        url,
        headers={
            "Accept": accept,
            "Authorization": f"Bearer {token}",
            "User-Agent": "github-scan-script",
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


def fetch_repo_languages(repo: dict[str, Any], token: str, timeout: int) -> dict[str, int]:
    languages_url = str(repo.get("languages_url") or "")
    if not languages_url:
        return {}

    payload = github_get_json(languages_url, token, timeout)
    if not isinstance(payload, dict):
        return {}

    results: dict[str, int] = {}
    for language, score in payload.items():
        if isinstance(language, str):
            try:
                results[language] = int(score)
            except (TypeError, ValueError):
                continue
    return results


def fetch_repo_readme_text(full_name: str, token: str, timeout: int) -> str | None:
    endpoint_repo = parse.quote(full_name, safe="/")
    url = f"{API_BASE}/repos/{endpoint_repo}/readme"

    try:
        payload = github_get_json(url, token, timeout)
    except GitHubApiError as exc:
        if exc.status_code == 404:
            return None
        raise

    if not isinstance(payload, dict):
        return None

    if str(payload.get("encoding") or "") != "base64":
        return None

    encoded = payload.get("content")
    if not isinstance(encoded, str) or not encoded.strip():
        return None

    try:
        decoded = base64.b64decode(encoded, validate=False).decode("utf-8", errors="replace")
    except (ValueError, TypeError):
        return None
    return decoded


def summarize_readme(readme_text: str | None) -> str:
    if not readme_text:
        return ""

    lines = readme_text.replace("\r", "").split("\n")
    in_code_block = False
    paragraphs: list[str] = []
    current: list[str] = []

    for raw_line in lines:
        stripped = raw_line.strip()

        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_code_block = not in_code_block
            continue

        if in_code_block:
            continue

        if not stripped:
            if current:
                paragraphs.append(" ".join(current).strip())
                current = []
            continue

        if stripped.startswith("#"):
            continue
        if stripped.startswith("![") or stripped.startswith("[!["):
            continue
        if re.fullmatch(r"[-|: ]{3,}", stripped):
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            continue

        cleaned = re.sub(r"!\[[^\]]*\]\([^)]+\)", " ", stripped)
        cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
        cleaned = re.sub(r"<[^>]+>", " ", cleaned)
        cleaned = cleaned.strip("-*`> ")
        cleaned = re.sub(r"\s+", " ", cleaned).strip()

        if cleaned:
            current.append(cleaned)

    if current:
        paragraphs.append(" ".join(current).strip())

    if not paragraphs:
        return ""

    first = next((p for p in paragraphs if len(p) >= 25), paragraphs[0])
    sentences = re.split(r"(?<=[.!?])\s+", first)
    summary = " ".join([s for s in sentences if s][:2]).strip() or first
    if len(summary) > 260:
        summary = summary[:257].rsplit(" ", 1)[0] + "..."
    return summary


def detect_technologies(
    primary_language: str,
    languages_by_bytes: dict[str, int],
    readme_text: str | None,
) -> list[str]:
    technologies: list[str] = []

    sorted_languages = [key for key, _ in sorted(languages_by_bytes.items(), key=lambda item: item[1], reverse=True)]
    for language in sorted_languages:
        if language and language not in technologies:
            technologies.append(language)

    if primary_language and primary_language not in technologies:
        technologies.insert(0, primary_language)

    lower_readme = (readme_text or "").lower()
    for keyword, technology in TECH_KEYWORDS:
        if keyword in lower_readme and technology not in technologies:
            technologies.append(technology)

    return technologies[:10]


def to_tag_label(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    if not normalized:
        return ""
    return f"#{normalized}"


def build_tags(technologies: list[str]) -> list[str]:
    tags: list[str] = []
    for technology in technologies:
        if not technology:
            continue
        tag = to_tag_label(technology)
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def get_authenticated_login(token: str, timeout: int) -> str:
    profile = github_get_json(f"{API_BASE}/user", token, timeout)
    login = profile.get("login") if isinstance(profile, dict) else None
    if not login:
        raise GitHubApiError("Unable to determine authenticated user login.")
    return str(login)


def fetch_owned_repos(token: str, timeout: int, affiliation: str = "owner") -> list[dict[str, Any]]:
    """Fetch repositories for the authenticated user.

    Args:
        token:       GitHub personal access token.
        timeout:     HTTP request timeout in seconds.
        affiliation: Comma-separated GitHub affiliation scope.
                     Supported values: owner, collaborator, organization_member.
                     Defaults to 'owner' (personal repos only).
    """
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


def sanitize_repo(
    repo: dict[str, Any],
    csv_owner: str,
    authenticated_login: str | None,
    languages_by_bytes: dict[str, int],
    technologies: list[str],
    readme_summary: str,
) -> dict[str, Any]:
    owner_obj = repo.get("owner") if isinstance(repo.get("owner"), dict) else {}
    tags = build_tags(technologies)
    repo_owner_login = str(owner_obj.get("login") or "")
    # Detect if this is an org / forked repo (owner != the authenticated user scanning it).
    is_org_repo = bool(authenticated_login and repo_owner_login and
                       repo_owner_login.lower() != authenticated_login.lower())
    return {
        "csv_owner": csv_owner,
        "authenticated_login": authenticated_login,
        "repo_name": repo.get("name"),
        "full_name": repo.get("full_name"),
        "owner_login": repo_owner_login,
        "org_repo": is_org_repo,
        # members is a list that will be merged during deduplication
        "members": [authenticated_login] if authenticated_login else ([csv_owner] if csv_owner else []),
        "private": bool(repo.get("private", False)),
        "html_url": repo.get("html_url"),
        "description": repo.get("description") or "",
        "language": repo.get("language") or "",
        "languages": [key for key, _ in sorted(languages_by_bytes.items(), key=lambda item: item[1], reverse=True)],
        "technologies": technologies,
        "tags": tags,
        "topics": repo.get("topics") or [],
        "readme_summary": readme_summary,
        "default_branch": repo.get("default_branch") or "",
        "stargazers_count": int(repo.get("stargazers_count", 0) or 0),
        "forks_count": int(repo.get("forks_count", 0) or 0),
        "updated_at": repo.get("updated_at") or "",
    }


def md_cell(value: Any) -> str:
    text = str(value if value is not None else "").replace("\n", " ").strip()
    if not text:
        return "-"
    return text.replace("|", "\\|")


def deduplicate_repos(all_repos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge duplicate repos (same full_name) that appear across multiple accounts.

    Org repos are often accessible by several members.  This function collapses
    them into a single canonical entry and records every member that had access
    in the 'members' list.  The first occurrence wins for all data fields.
    """
    seen: dict[str, dict[str, Any]] = {}  # full_name -> merged entry
    ordered_keys: list[str] = []          # preserve insertion order

    for repo in all_repos:
        full_name = str(repo.get("full_name") or "")
        if not full_name:
            # No full_name — cannot deduplicate, keep as-is.
            ordered_keys.append(f"__no_full_name_{id(repo)}")
            seen[ordered_keys[-1]] = repo
            continue

        if full_name not in seen:
            seen[full_name] = dict(repo)  # clone so we don't mutate originals
            seen[full_name]["members"] = list(repo.get("members") or [])
            ordered_keys.append(full_name)
        else:
            # Merge: add any new members not already listed.
            existing_members: list[str] = seen[full_name]["members"]
            for member in (repo.get("members") or []):
                if member and member not in existing_members:
                    existing_members.append(member)

    return [seen[k] for k in ordered_keys]


def write_project_summaries(all_repos: list[dict[str, Any]], output_dir: Path, scanned_users: set[str] | None = None) -> None:
    """Write the cross-account project-summaries.md.

    Uses the deduplicated repo list so org repos appear only once.
    Categorizes into Org and User sections.
    """
    summary_lines: list[str] = [
        "# Project Summaries",
        "",
        f"Generated at (UTC): `{utc_now_iso()}`",
        "",
    ]

    if scanned_users is None:
        scanned_users = set()

    org_repos = [r for r in all_repos if (r.get("owner_login") or "").lower() not in scanned_users]
    user_repos = [r for r in all_repos if (r.get("owner_login") or "").lower() in scanned_users]

    def add_table(repos: list[dict[str, Any]], title: str):
        if not repos:
            return
        summary_lines.extend([f"## {title}", ""])
        summary_lines.extend(
            [
                "| Owner | Repository | Members | Technologies | Tags | Description | Summary | Topics |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        sorted_repos = sorted(
            repos,
            key=lambda row: (
                str(row.get("owner_login") or row.get("authenticated_login") or row.get("csv_owner") or "").lower(),
                str(row.get("repo_name") or "").lower(),
            ),
        )
        for repo in sorted_repos:
            owner = md_cell(repo.get("owner_login") or repo.get("authenticated_login") or repo.get("csv_owner") or "")
            repo_name = md_cell(repo.get("repo_name", ""))
            members_list = repo.get("members") or []
            members = md_cell(", ".join([str(m) for m in members_list if m]))
            technologies = md_cell(", ".join([str(item) for item in repo.get("technologies", []) if item]) or "")
            tags = md_cell(" ".join([str(item) for item in repo.get("tags", []) if item]) or "")
            description = md_cell(repo.get("description", ""))
            summary = md_cell(repo.get("readme_summary", ""))
            topics = md_cell(", ".join([str(t) for t in repo.get("topics", []) if t]) or "")
            summary_lines.append(f"| {owner} | {repo_name} | {members} | {technologies} | {tags} | {description} | {summary} | {topics} |")
        summary_lines.append("")

    add_table(org_repos, "Org Repos")
    add_table(user_repos, "User Repos")

    summary_path = output_dir / "project-summaries.md"
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")





def write_outputs(results: list[AccountResult], output_dir: Path, input_path: Path, deduplicate: bool = True) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # Raw flat list — every account's repos including org-repo duplicates.
    all_repos_raw: list[dict[str, Any]] = []
    for result in results:
        all_repos_raw.extend(result.repos)

    # Deduplicated list used for cross-account outputs.
    all_repos = deduplicate_repos(all_repos_raw) if deduplicate else all_repos_raw
    org_repo_count = sum(1 for r in all_repos if r.get("org_repo"))
    dup_removed = len(all_repos_raw) - len(all_repos)

    json_payload = {
        "generated_at_utc": utc_now_iso(),
        "input_file": str(input_path),
        "deduplication": {
            "enabled": deduplicate,
            "raw_repo_count": len(all_repos_raw),
            "unique_repo_count": len(all_repos),
            "duplicates_removed": dup_removed,
            "org_repos": org_repo_count,
        },
        "accounts": [
            {
                "csv_owner": item.csv_owner,
                "authenticated_login": item.authenticated_login,
                "repo_count": item.repo_count,
                "personal_repo_count": item.personal_repo_count,
                "org_repo_count": item.org_repo_count,
                "warnings": item.warnings,
                "error": item.error,
            }
            for item in results
        ],
        "repositories": all_repos,
    }

    json_path = output_dir / "repositories.json"
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    csv_path = output_dir / "repositories.csv"
    headers = [
        "repo_name",
        "full_name",
        "owner_login",
        "org_repo",
        "members",
        "private",
        "html_url",
        "description",
        "language",
        "languages",
        "technologies",
        "tags",
        "readme_summary",
        "default_branch",
        "stargazers_count",
        "forks_count",
        "updated_at",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in all_repos:
            csv_row = dict(row)
            csv_row["members"] = ", ".join([str(m) for m in row.get("members", []) if m])
            csv_row["languages"] = "; ".join([str(item) for item in row.get("languages", []) if item])
            csv_row["technologies"] = "; ".join([str(item) for item in row.get("technologies", []) if item])
            csv_row["tags"] = "; ".join([str(item) for item in row.get("tags", []) if item])
            writer.writerow(csv_row)

    report_lines: list[str] = [
        "# GitHub Repository Inventory",
        "",
        f"Generated at (UTC): `{utc_now_iso()}`",
        f"Input file: `{input_path}`",
        "",
        "## Account Summary",
        "",
        "| Owner | Login | Personal | Org | Total | Status |",
        "| --- | --- | ---: | ---: | ---: | --- |",
    ]

    for account in results:
        status = "OK"
        if account.error:
            status = f"ERROR: {account.error}"
        elif account.warnings:
            status = "WARNING: " + "; ".join(account.warnings)

        report_lines.append(
            f"| {account.csv_owner} | {account.authenticated_login or '-'} | "
            f"{account.personal_repo_count} | {account.org_repo_count} | {account.repo_count} | {status} |"
        )

    # Scanned users identification for robust categorization
    scanned_users = {a.authenticated_login.lower() for a in results if a.authenticated_login}
    user_repos_all = [r for r in all_repos if (r.get("owner_login") or "").lower() in scanned_users]
    org_repos_all = [r for r in all_repos if (r.get("owner_login") or "").lower() not in scanned_users]

    # --- User Repos Section ---
    report_lines.extend(["", "## User Repos", ""])
    if deduplicate:
        report_lines.append("> **Deduplication Info**: Org repositories shared with these accounts are listed in the Organization sections below.")
    
    # Track which user repos we've already listed (in case of overlaps, though usually user repos are unique to one account)
    listed_user_repos: set[str] = set()

    for account in results:
        if not account.authenticated_login:
            continue
        
        login_lower = account.authenticated_login.lower()
        # Find repos owned by this specific user
        owner_repos = [r for r in user_repos_all if (r.get("owner_login") or "").lower() == login_lower]
        
        if owner_repos:
            owner_repos_sorted = sorted(owner_repos, key=lambda r: str(r.get("repo_name") or "").lower())
            report_lines.extend(["", f"### User: {account.authenticated_login}", ""])
            report_lines.extend(
                [
                    "| Name | Owner | Visibility | Primary Language | Technologies | Description | README Summary | Updated At |",
                    "| --- | --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            for r in owner_repos_sorted:
                name = md_cell(r.get("repo_name", ""))
                owner = md_cell(r.get("owner_login") or "")
                visibility = "Private" if r.get("private") else "Public"
                lang = md_cell(r.get("language") or "")
                tech = md_cell(", ".join([str(item) for item in r.get("technologies", []) if item]))
                desc = md_cell(r.get("description") or "")
                summary = md_cell(r.get("readme_summary") or "")
                updated = md_cell(r.get("updated_at") or "")
                report_lines.append(f"| {name} | {owner} | {visibility} | {lang} | {tech} | {desc} | {summary} | {updated} |")
                listed_user_repos.add(str(r.get("full_name") or ""))

    # --- Organization Summary Section ---
    report_lines.extend(["", "## Organization Summary", ""])
    
    if org_repos_all:
        report_lines.extend(
            [
                "| Organization | Rep Count | Members |",
                "| --- | ---: | --- |",
            ]
        )
        # Group by organization
        by_org: dict[str, dict[str, Any]] = {}
        for r in org_repos_all:
            org = str(r.get("owner_login") or "").lower()
            if org not in by_org:
                by_org[org] = {"count": 0, "members": set()}
            by_org[org]["count"] += 1
            for m in (r.get("members") or []):
                if m:
                    by_org[org]["members"].add(str(m))

        sorted_orgs = sorted(by_org.keys())
        for org in sorted_orgs:
            count = by_org[org]["count"]
            members = md_cell(", ".join(sorted(by_org[org]["members"])))
            report_lines.append(f"| {org} | {count} | {members} |")
        report_lines.append("")

        # --- Org Repo Details Section ---
        report_lines.extend(["## Org Repo Details", ""])
        
        if deduplicate:
            report_lines.append(f"> **Deduplication Info**: Found {len(all_repos_raw)} results across all accounts. "
                              f"The tables below show unique repositories found.")
        
        # Group org repos for detailed display
        org_repo_groups: dict[str, list[dict[str, Any]]] = {}
        for r in org_repos_all:
            org = str(r.get("owner_login") or "").lower()
            if org not in org_repo_groups:
                org_repo_groups[org] = []
            org_repo_groups[org].append(r)
        
        for org in sorted_orgs:
            repos_in_org = sorted(org_repo_groups[org], key=lambda r: str(r.get("repo_name") or "").lower())
            report_lines.extend(["", f"### Organization: {org}", ""])
            report_lines.extend(
                [
                    "| Name | Members | Visibility | Primary Language | Technologies | Description | README Summary | Updated At |",
                    "| --- | --- | --- | --- | --- | --- | --- | --- |",
                ]
            )
            for r in repos_in_org:
                name = md_cell(r.get("repo_name", ""))
                members_list = r.get("members") or []
                members = md_cell(", ".join([str(m) for m in members_list if m]))
                visibility = "Private" if r.get("private") else "Public"
                lang = md_cell(r.get("language") or "")
                tech = md_cell(", ".join([str(item) for item in r.get("technologies", []) if item]))
                desc = md_cell(r.get("description") or "")
                summary = md_cell(r.get("readme_summary") or "")
                updated = md_cell(r.get("updated_at") or "")
                report_lines.append(f"| {name} | {members} | {visibility} | {lang} | {tech} | {desc} | {summary} | {updated} |")
            report_lines.append("")

    report_path = output_dir / "repository-report.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    write_project_summaries(all_repos, output_dir, scanned_users=scanned_users)

    if deduplicate and dup_removed > 0:
        print(f"  Deduplication: {len(all_repos_raw)} raw entries -> {len(all_repos)} unique repos ({dup_removed} duplicates removed).")


def run_scan(
    input_path: Path,
    output_dir: Path,
    timeout: int,
    pause_seconds: float,
    decrypt_key: str | None,
    affiliation: str = "owner",
    deduplicate: bool = True,
) -> int:
    credentials = load_credentials(input_path, decrypt_key)
    results: list[AccountResult] = []

    for index, (csv_owner, token) in enumerate(credentials, start=1):
        print(f"[{index}/{len(credentials)}] Scanning account '{csv_owner}'...")

        warnings: list[str] = []
        auth_login: str | None = None
        account_repos: list[dict[str, Any]] = []
        account_error: str | None = None

        try:
            auth_login = get_authenticated_login(token, timeout)
            if auth_login.lower() != csv_owner.lower():
                warnings.append(f"CSV owner '{csv_owner}' differs from authenticated login '{auth_login}'.")

            raw_repos = fetch_owned_repos(token, timeout, affiliation=affiliation)
            enrich_failures = 0
            for repo in raw_repos:
                languages_by_bytes: dict[str, int] = {}
                readme_text: str | None = None

                try:
                    languages_by_bytes = fetch_repo_languages(repo, token, timeout)
                except GitHubApiError:
                    enrich_failures += 1

                full_name = str(repo.get("full_name") or "")
                if full_name:
                    try:
                        readme_text = fetch_repo_readme_text(full_name, token, timeout)
                    except GitHubApiError:
                        enrich_failures += 1

                technologies = detect_technologies(str(repo.get("language") or ""), languages_by_bytes, readme_text)
                readme_summary = summarize_readme(readme_text)

                account_repos.append(
                    sanitize_repo(
                        repo=repo,
                        csv_owner=csv_owner,
                        authenticated_login=auth_login,
                        languages_by_bytes=languages_by_bytes,
                        technologies=technologies,
                        readme_summary=readme_summary,
                    )
                )

            if enrich_failures:
                warnings.append(
                    f"Technology/README enrichment requests failed for {enrich_failures} API call(s); partial data shown."
                )
            print(f"  Retrieved {len(account_repos)} repositories.")
        except (GitHubApiError, ValueError) as exc:
            account_error = str(exc)
            print(f"  Failed: {account_error}")

        personal_count = sum(1 for r in account_repos if not r.get("org_repo"))
        org_count = sum(1 for r in account_repos if r.get("org_repo"))

        results.append(
            AccountResult(
                csv_owner=csv_owner,
                authenticated_login=auth_login,
                repo_count=len(account_repos),
                personal_repo_count=personal_count,
                org_repo_count=org_count,
                repos=account_repos,
                warnings=warnings,
                error=account_error,
            )
        )

        if pause_seconds > 0 and index < len(credentials):
            time.sleep(pause_seconds)

    write_outputs(results, output_dir, input_path, deduplicate=deduplicate)

    total_repos = sum(item.repo_count for item in results)
    total_personal = sum(item.personal_repo_count for item in results)
    total_org = sum(item.org_repo_count for item in results)
    failed_accounts = sum(1 for item in results if item.error)
    print(f"Completed. Accounts: {len(results)}, Repositories: {total_repos} (Personal: {total_personal}, Org: {total_org}), Failures: {failed_accounts}")
    print(f"Output directory: {output_dir}")

    return 0 if failed_accounts == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Scan GitHub repositories for accounts listed in a CSV file and "
            "generate documentation outputs. "
            f"Default values are read from '{CONFIG_FILE}' when present; "
            "CLI flags always take precedence."
        )
    )
    parser.add_argument(
        "--config",
        default=CONFIG_FILE,
        help=f"Path to INI config file (default: {CONFIG_FILE}).",
    )
    parser.add_argument("--input", default=None, help="Path to input CSV containing username,token rows.")
    parser.add_argument("--output-dir", default=None, help="Directory for generated output files.")
    parser.add_argument("--timeout", type=int, default=None, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--pause",
        type=float,
        default=None,
        help="Delay in seconds between scanning each account.",
    )
    parser.add_argument(
        "--affiliation",
        default=None,
        help=(
            "Comma-separated GitHub repo affiliation scope. "
            "Allowed values: owner, collaborator, organization_member. "
            "Example: --affiliation owner,organization_member"
        ),
    )
    parser.add_argument(
        "--no-deduplicate",
        action="store_true",
        default=False,
        help=(
            "Disable cross-account deduplication of org repos. "
            "By default, repos shared across multiple accounts (e.g. org repos) "
            "appear once in CSV/JSON/project-summaries with all members listed. "
            "Use this flag to revert to the raw per-account output."
        ),
    )
    parser.add_argument("--decrypt-key", default=None, help="Decrypt key for encrypted key file input.")
    parser.add_argument("--encrypt-key", default=None, help="User-defined key used to encrypt key file.")
    parser.add_argument(
        "--encrypt-input",
        action="store_true",
        help="Encrypt --input file and exit without scanning.",
    )
    parser.add_argument(
        "--encrypted-output",
        default=None,
        help="Output path for encrypted key file (default: <input>.enc).",
    )
    parser.add_argument(
        "--export-decrypted",
        default=None,
        help="Write decrypted key file to this path and exit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # ------------------------------------------------------------------
    # Load config file, then let explicit CLI flags override each value.
    # ------------------------------------------------------------------
    cfg = load_config(args.config)
    section = "scan"

    resolved_input = args.input or cfg.get(section, "input")
    resolved_output_dir = args.output_dir or cfg.get(section, "output_dir")
    resolved_timeout = args.timeout if args.timeout is not None else cfg.getint(section, "timeout")
    resolved_pause = args.pause if args.pause is not None else cfg.getfloat(section, "pause")
    raw_affiliation = args.affiliation or cfg.get(section, "affiliation")
    resolved_deduplicate = cfg.getboolean(section, "deduplicate") if not args.no_deduplicate else False

    input_path = Path(resolved_input)
    output_dir = Path(resolved_output_dir)

    try:
        affiliation = validate_affiliation(raw_affiliation)

        if args.encrypt_input:
            if not args.encrypt_key:
                raise ValueError("--encrypt-input requires --encrypt-key.")
            encrypted_output = Path(args.encrypted_output) if args.encrypted_output else Path(str(input_path) + ".enc")
            encrypt_credentials_file(input_path, encrypted_output, args.encrypt_key)
            print(f"Encrypted key file written to: {encrypted_output}")
            return 0

        if args.export_decrypted:
            if not args.decrypt_key:
                raise ValueError("--export-decrypted requires --decrypt-key.")
            export_decrypted_file(input_path, Path(args.export_decrypted), args.decrypt_key)
            print(f"Decrypted key file written to: {args.export_decrypted}")
            return 0

        if not input_path.exists():
            print(f"Input file not found: {input_path}", file=sys.stderr)
            return 2

        print(f"Config: {args.config} | affiliation={affiliation} | timeout={resolved_timeout}s | pause={resolved_pause}s | deduplicate={resolved_deduplicate}")

        return run_scan(
            input_path=input_path,
            output_dir=output_dir,
            timeout=resolved_timeout,
            pause_seconds=resolved_pause,
            decrypt_key=args.decrypt_key,
            affiliation=affiliation,
            deduplicate=resolved_deduplicate,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
