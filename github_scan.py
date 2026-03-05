from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import error, parse, request

API_BASE = "https://api.github.com"
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
    repos: list[dict[str, Any]]
    warnings: list[str]
    error: str | None


class GitHubApiError(RuntimeError):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_credentials(csv_path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
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


def fetch_owned_repos(token: str, timeout: int) -> list[dict[str, Any]]:
    repos: list[dict[str, Any]] = []
    page = 1

    while True:
        params = parse.urlencode(
            {
                "per_page": 100,
                "page": page,
                "visibility": "all",
                "affiliation": "owner",
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
    return {
        "csv_owner": csv_owner,
        "authenticated_login": authenticated_login,
        "repo_name": repo.get("name"),
        "full_name": repo.get("full_name"),
        "owner_login": owner_obj.get("login"),
        "private": bool(repo.get("private", False)),
        "html_url": repo.get("html_url"),
        "description": repo.get("description") or "",
        "language": repo.get("language") or "",
        "languages": [key for key, _ in sorted(languages_by_bytes.items(), key=lambda item: item[1], reverse=True)],
        "technologies": technologies,
        "tags": tags,
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


def write_project_summaries(all_repos: list[dict[str, Any]], output_dir: Path) -> None:
    summary_lines: list[str] = [
        "# Project Summaries",
        "",
        f"Generated at (UTC): `{utc_now_iso()}`",
        "",
        "| Owner | Repository | Technologies | Tags | Summary | URL |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    sorted_repos = sorted(
        all_repos,
        key=lambda row: (
            str(row.get("authenticated_login") or row.get("csv_owner") or "").lower(),
            str(row.get("repo_name") or "").lower(),
        ),
    )

    for repo in sorted_repos:
        owner = md_cell(repo.get("authenticated_login") or repo.get("csv_owner") or "")
        repo_name = md_cell(repo.get("repo_name", ""))
        technologies = md_cell(", ".join([str(item) for item in repo.get("technologies", []) if item]) or "")
        tags = md_cell(" ".join([str(item) for item in repo.get("tags", []) if item]) or "")
        summary = md_cell(repo.get("readme_summary", ""))
        url = md_cell(repo.get("html_url", ""))
        summary_lines.append(f"| {owner} | {repo_name} | {technologies} | {tags} | {summary} | {url} |")

    summary_path = output_dir / "project-summaries.md"
    summary_path.write_text("\n".join(summary_lines), encoding="utf-8")


def to_markdown_table_rows(repos: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for repo in repos:
        visibility = "Private" if repo["private"] else "Public"
        name = md_cell(repo.get("repo_name", ""))
        language = md_cell(repo.get("language", ""))
        technologies = md_cell(", ".join([str(item) for item in repo.get("technologies", []) if item]) or "")
        tags = md_cell(" ".join([str(item) for item in repo.get("tags", []) if item]) or "")
        summary = md_cell(repo.get("readme_summary", ""))
        stars = str(repo.get("stargazers_count", 0))
        forks = str(repo.get("forks_count", 0))
        updated = md_cell(repo.get("updated_at", ""))
        url = md_cell(repo.get("html_url", ""))
        lines.append(
            f"| {name} | {visibility} | {language} | {technologies} | {tags} | {summary} | {stars} | {forks} | {updated} | {url} |"
        )
    return lines


def write_outputs(results: list[AccountResult], output_dir: Path, input_path: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    all_repos: list[dict[str, Any]] = []
    for result in results:
        all_repos.extend(result.repos)

    json_payload = {
        "generated_at_utc": utc_now_iso(),
        "input_file": str(input_path),
        "accounts": [
            {
                "csv_owner": item.csv_owner,
                "authenticated_login": item.authenticated_login,
                "repo_count": item.repo_count,
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
        "csv_owner",
        "authenticated_login",
        "repo_name",
        "full_name",
        "owner_login",
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
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        for row in all_repos:
            csv_row = dict(row)
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
        "| CSV Owner | Authenticated Login | Repositories | Status |",
        "| --- | --- | ---: | --- |",
    ]

    for account in results:
        status = "OK"
        if account.error:
            status = f"ERROR: {account.error}"
        elif account.warnings:
            status = "WARNING: " + "; ".join(account.warnings)

        report_lines.append(
            f"| {account.csv_owner} | {account.authenticated_login or '-'} | {account.repo_count} | {status} |"
        )

    report_lines.extend(["", "## Repositories By Account", ""])

    for account in results:
        title = account.authenticated_login or account.csv_owner
        report_lines.append(f"### {title}")
        report_lines.append("")

        if account.error:
            report_lines.append(f"Scan failed: `{account.error}`")
            report_lines.append("")
            continue

        if not account.repos:
            report_lines.append("No repositories found.")
            report_lines.append("")
            continue

        report_lines.extend(
            [
                "| Name | Visibility | Primary Language | Technologies | Tags | README Summary | Stars | Forks | Updated At | URL |",
                "| --- | --- | --- | --- | --- | --- | ---: | ---: | --- | --- |",
            ]
        )
        report_lines.extend(to_markdown_table_rows(account.repos))
        report_lines.append("")

    report_path = output_dir / "repository-report.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    write_project_summaries(all_repos, output_dir)


def run_scan(input_path: Path, output_dir: Path, timeout: int, pause_seconds: float) -> int:
    credentials = load_credentials(input_path)
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

            raw_repos = fetch_owned_repos(token, timeout)
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

        results.append(
            AccountResult(
                csv_owner=csv_owner,
                authenticated_login=auth_login,
                repo_count=len(account_repos),
                repos=account_repos,
                warnings=warnings,
                error=account_error,
            )
        )

        if pause_seconds > 0 and index < len(credentials):
            time.sleep(pause_seconds)

    write_outputs(results, output_dir, input_path)

    total_repos = sum(item.repo_count for item in results)
    failed_accounts = sum(1 for item in results if item.error)
    print(f"Completed. Accounts: {len(results)}, Repositories: {total_repos}, Failures: {failed_accounts}")
    print(f"Output directory: {output_dir}")

    return 0 if failed_accounts == 0 else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for accounts listed in a CSV file and generate documentation outputs."
    )
    parser.add_argument("--input", default="key.csv", help="Path to input CSV containing username,token rows.")
    parser.add_argument("--output-dir", default="output", help="Directory for generated output files.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout in seconds.")
    parser.add_argument(
        "--pause",
        type=float,
        default=0.0,
        help="Delay in seconds between scanning each account.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    if not input_path.exists():
        print(f"Input file not found: {input_path}", file=sys.stderr)
        return 2

    try:
        return run_scan(
            input_path=input_path,
            output_dir=output_dir,
            timeout=args.timeout,
            pause_seconds=args.pause,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
