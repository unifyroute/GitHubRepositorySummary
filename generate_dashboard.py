import argparse
import base64
import configparser
import csv
import hashlib
import hmac
import html
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

_VALID_AFFILIATIONS = {"owner", "collaborator", "organization_member"}

def load_config(config_path: str = CONFIG_FILE) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser(
        defaults={
            "affiliation": "owner",
            "timeout": "30",
            "pause": "0.0",
            "output_dir": "output",
            "input": "key.csv",
        }
    )
    cfg.read_dict({"scan": {}})
    cfg.read(config_path, encoding="utf-8")
    return cfg

def xor_with_keystream(data: bytes, key: bytes, nonce: bytes) -> bytes:
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


def github_get_json(url: str, token: str, timeout: int) -> Any:
    req = request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "github-dashboard-gen",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}") from exc

def fetch_readme_html(full_name: str, token: str, timeout: int, output_dir: Path) -> str:
    url = f"{API_BASE}/repos/{full_name}/readme"
    req = request.Request(
        url,
        headers={
            "Accept": "application/vnd.github.html",
            "Authorization": f"Bearer {token}",
            "User-Agent": "github-dashboard-gen",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with request.urlopen(req, timeout=timeout) as res:
            html_content = res.read().decode("utf-8")
            
            # Download images inside the README
            images_dir = output_dir / "repos" / "images"
            images_dir.mkdir(exist_ok=True, parents=True)
            
            def replacer(match):
                full_img_tag = match.group(0)
                src_url = match.group(1)
                if not src_url.startswith("http"):
                    return full_img_tag
                
                try:
                    name_part = src_url.split("/")[-1].split("?")[0]
                    clean_name = "".join(c for c in name_part if c.isalnum() or c in ".-_")
                    filename = hashlib.md5(src_url.encode()).hexdigest()[:8] + "_" + clean_name[-30:]
                    if "." not in filename:
                        filename += ".png"
                        
                    local_path = images_dir / filename
                    if not local_path.exists():
                        img_req = request.Request(src_url, headers={"User-Agent": "github-dashboard-gen"})
                        with request.urlopen(img_req, timeout=timeout) as img_res:
                            local_path.write_bytes(img_res.read())
                    
                    new_tag = full_img_tag.replace(f'="{src_url}"', f'="images/{filename}"')
                    new_tag = new_tag.replace(f"='{src_url}'", f"='images/{filename}'")
                    return new_tag
                except Exception as e:
                    print(f"  Warning: Failed to download image {src_url}: {e}")
                    return full_img_tag
            
            return re.sub(r'<img[^>]+src=["\']([^"\']+)["\'][^>]*>', replacer, html_content)
    except error.HTTPError:
        return "<i>No README found for this repository.</i>"

def fetch_commits(full_name: str, token: str, timeout: int, max_commits: int = 100) -> list[dict]:
    commits = []
    page = 1
    endpoint = parse.quote(full_name, safe="/")
    while len(commits) < max_commits:
        url = f"{API_BASE}/repos/{endpoint}/commits?per_page=100&page={page}"
        try:
            data = github_get_json(url, token, timeout)
            if not isinstance(data, list) or not data:
                break
            commits.extend(data)
            if len(data) < 100:
                break
            page += 1
        except RuntimeError:
            break
    return commits[:max_commits]

def generate_dashboard(credentials: list[tuple[str, str]], output_dir: Path, timeout: int):
    output_dir.mkdir(parents=True, exist_ok=True)
    repos_dir = output_dir / "repos"
    repos_dir.mkdir(exist_ok=True)
    
    all_repos = []
    
    for owner, token in credentials:
        print(f"Fetching repos for account {owner}...")
        url = f"{API_BASE}/user/repos?per_page=100&visibility=all&affiliation=owner,organization_member"
        try:
            page_data = github_get_json(url, token, timeout)
            all_repos.extend([(r, token) for r in page_data if isinstance(r, dict)])
        except Exception as e:
            print(f"Error fetching for {owner}: {e}")
            
    seen = set()
    unique_repos = []
    for r, token in all_repos:
        if r["full_name"] not in seen:
            seen.add(r["full_name"])
            unique_repos.append((r, token))
            
    # Group repositories by Organization / Login User
    repos_by_owner = {}
    for r, token in unique_repos:
        owner_login = r["owner"]["login"]
        if owner_login not in repos_by_owner:
            repos_by_owner[owner_login] = []
        repos_by_owner[owner_login].append((r, token))
        
    dashboard_content_html = ""
    
    for owner_login in sorted(repos_by_owner.keys()):
        dashboard_content_html += f'<h2 class="org-heading">{owner_login}</h2>\n<div class="grid">\n'
        
        # Sort projects within org
        sorted_repos = sorted(repos_by_owner[owner_login], key=lambda x: str(x[0].get("name", "")).lower())
        for r, token in sorted_repos:
            full_name = r["full_name"]
            print(f"Processing {full_name}...")
            
            desc = html.escape(str(r.get("description") or "No description provided."))
            updated_at = r.get("updated_at", "").replace("T", " ").replace("Z", "")
            
            url_readme_json = f"{API_BASE}/repos/{full_name}/readme"
            readme_summary = "No README info."
            try:
                readme_data = github_get_json(url_readme_json, token, timeout)
                encoded = readme_data.get("content")
                if encoded:
                    decoded = base64.b64decode(encoded).decode("utf-8", "ignore")
                    first_lines = " ".join([line.strip() for line in decoded.split("\n") if line.strip() and not line.startswith("#") and not line.startswith("[")])
                    
                    # Remove all HTML tags to prevent unclosed tags breaking the card layout
                    clean_text = re.sub(r'<[^>]+>', ' ', first_lines)
                    clean_text = re.sub(r'\s+', ' ', clean_text).strip()
                    
                    readme_summary = html.escape((clean_text[:150] + "...") if len(clean_text) > 150 else clean_text)
                    if not readme_summary:
                       readme_summary = "No descriptive text found in README."
            except:
                pass
                
            repo_filename = full_name.replace("/", "_") + ".html"
            
            card_html = f'''
            <a href="repos/{repo_filename}" class="card">
                <h2>{r["name"]}</h2>
                <div class="org-name">{r["owner"]["login"]}</div>
                <p>{desc}</p>
                <div class="readme-summary"><strong>Summary:</strong> {readme_summary}</div>
                <div class="metadata">
                    <span>Updated: {updated_at}</span>
                    <span>⭐ {r.get("stargazers_count", 0)}</span>
                </div>
            </a>
            '''
            dashboard_content_html += card_html
            
            readme_html = fetch_readme_html(full_name, token, timeout, output_dir)
            commits = fetch_commits(full_name, token, timeout)
            
            commits_html = ""
            for c in commits:
                cmsg = c.get("commit", {}).get("message", "")
                cauthor = c.get("commit", {}).get("author", {}).get("name", "")
                cdate = c.get("commit", {}).get("author", {}).get("date", "").replace("T", " ").replace("Z", "")
                csha = c.get("sha", "")[:7]
                commits_html += f'<div class="commit-item"><strong>{csha}</strong> &mdash; <em>{cauthor}</em> on {cdate}<br/>{cmsg}</div>'
                
            if not commits_html:
                commits_html = "<p>No commits found.</p>"
                
            repo_page = f'''<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{full_name} - Details</title>
<style>
:root {{
  --bg: #0f172a; --surface: rgba(30, 41, 59, 0.7); --text: #f8fafc; --text-muted: #94a3b8; --border: rgba(255,255,255,0.1);
}}
body {{ font-family: 'Inter', system-ui, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.6; }}
.container {{ max-width: 1000px; margin: 0 auto; }}
.header-box {{ background: rgba(30, 41, 59, 0.7); padding: 2rem; border-radius: 1rem; margin-bottom: 2rem; border: 1px solid rgba(255,255,255,0.1); backdrop-filter: blur(10px); }}
.header-box h1 {{ margin-top: 0; background: linear-gradient(to right, #60a5fa, #a78bfa); -webkit-background-clip: text; color: transparent; }}
.stat {{ display: inline-block; background: rgba(255,255,255,0.1); padding: 0.5rem 1rem; border-radius: 99px; margin-right: 1rem; margin-top: 1rem; font-size: 0.9rem; }}
.readme-box {{ background: white; color: #1e293b; padding: 2rem; border-radius: 1rem; margin-bottom: 2rem; overflow-x: auto; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
.readme-box img {{ max-width: 100%; height: auto; }}
h2 {{ color: #60a5fa; }}
.commits-list {{ display: flex; flex-direction: column; gap: 1rem; }}
.commit-item {{ background: rgba(30, 41, 59, 0.7); padding: 1rem; border-radius: 0.5rem; border: 1px solid rgba(255,255,255,0.1); font-family: monospace; font-size: 0.9rem; }}
.commit-item strong {{ color: #a78bfa; }}
a.back {{ color: #60a5fa; text-decoration: none; display: inline-block; margin-bottom: 1rem; font-weight: bold; }}
a.back:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
    <a href="../GitHubDashBoard.html" class="back">&larr; Back to Dashboard</a>
    <div class="header-box">
        <h1>{full_name}</h1>
        <p>{desc}</p>
        <div>
            <span class="stat">🕒 Last Updated: {updated_at}</span>
            <span class="stat">📝 Commits: {len(commits)}</span>
        </div>
    </div>
    <h2>Readme</h2>
    <div class="readme-box">
        {readme_html}
    </div>
    <h2>Commits</h2>
    <div class="commits-list">
        {commits_html}
    </div>
</div>
</body>
</html>
'''
            (repos_dir / repo_filename).write_text(repo_page, encoding="utf-8")
        
        # Close the grid div for the organization heading
        dashboard_content_html += "</div>\n"
        
    dashboard_html = f'''<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>GitHub Repositories Dashboard</title>
<style>
:root {{ --bg: #0f172a; --surface: rgba(30, 41, 59, 0.7); --primary: #3b82f6; --text: #f8fafc; --text-muted: #94a3b8; --border: rgba(255, 255, 255, 0.1); }}
body {{ font-family: 'Inter', system-ui, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 2rem; line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; }}
h1 {{ font-size: 2.5rem; font-weight: 800; background: linear-gradient(to right, #60a5fa, #a78bfa); -webkit-background-clip: text; color: transparent; text-align: center; margin-bottom: 2rem; }}
.search-container {{ text-align: center; margin-bottom: 2.5rem; }}
.search-input {{ width: 100%; max-width: 600px; padding: 1rem 1.5rem; border-radius: 99px; border: 1px solid rgba(255, 255, 255, 0.2); background: rgba(30, 41, 59, 0.8); color: #f8fafc; font-size: 1.1rem; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }}
.search-input:focus {{ border-color: #3b82f6; box-shadow: 0 0 10px rgba(59, 130, 246, 0.5); }}
h2.org-heading {{ font-size: 2rem; color: #e2e8f0; border-bottom: 2px solid rgba(255,255,255,0.1); padding-bottom: 0.5rem; margin-top: 3rem; margin-bottom: 1.5rem; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 1.5rem; }}
.card {{ background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 1rem; padding: 1.5rem; backdrop-filter: blur(10px); transition: transform 0.2s, box-shadow 0.2s, background 0.2s; cursor: pointer; text-decoration: none; color: inherit; display: flex; flex-direction: column; }}
.card:hover {{ transform: translateY(-4px); box-shadow: 0 10px 20px rgba(0,0,0,0.5); background: rgba(59, 130, 246, 0.1); border-color: #3b82f6; }}
.card h2 {{ margin: 0 0 0.25rem; font-size: 1.25rem; font-weight: 600; color: #60a5fa; }}
.org-name {{ font-size: 0.8rem; color: #a78bfa; margin-bottom: 0.75rem; font-weight: bold; text-transform: uppercase; letter-spacing: 0.05em; }}
.card p {{ margin: 0 0 1rem; color: #94a3b8; font-size: 0.9rem; flex-grow: 1; }}
.readme-summary {{ font-size: 0.85rem; background: rgba(0,0,0,0.2); padding: 0.75rem; border-radius: 0.5rem; margin-bottom: 1rem; color: #cbd5e1; font-style: italic; }}
.metadata {{ display: flex; justify-content: space-between; font-size: 0.8rem; color: #94a3b8; border-top: 1px solid rgba(255, 255, 255, 0.1); padding-top: 0.75rem; }}
</style>
</head>
<body>
<div class="container">
    <h1>GitHub Repositories Dashboard</h1>
    <div class="search-container">
        <input type="text" id="searchInput" class="search-input" placeholder="Search projects (e.g., python node)...">
    </div>
    <div id="contentWrapper">
        {dashboard_content_html}
    </div>
</div>
<script>
document.getElementById('searchInput').addEventListener('input', function(e) {{
    const query = e.target.value.toLowerCase();
    const keywords = query.split(/\\s+/).filter(k => k.length > 0);
    
    const headings = document.querySelectorAll('.org-heading');
    
    headings.forEach(heading => {{
        const grid = heading.nextElementSibling;
        if (!grid || !grid.classList.contains('grid')) return;
        
        let visibleCount = 0;
        const cards = grid.querySelectorAll('.card');
        
        cards.forEach(card => {{
            const text = card.innerText.toLowerCase();
            const matches = keywords.every(kw => text.includes(kw));
            if (matches || keywords.length === 0) {{
                card.style.display = 'flex';
                visibleCount++;
            }} else {{
                card.style.display = 'none';
            }}
        }});
        
        if (visibleCount === 0) {{
            heading.style.display = 'none';
            grid.style.display = 'none';
        }} else {{
            heading.style.display = 'block';
            grid.style.display = 'grid';
        }}
    }});
}});
</script>
</body>
</html>
'''
    (output_dir / "GitHubDashBoard.html").write_text(dashboard_html, encoding="utf-8")
    print(f"\nDashboard successfully generated at: {output_dir / 'GitHubDashBoard.html'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate GitHub Repositories HTML Dashboard")
    parser.add_argument("--config", default=CONFIG_FILE)
    parser.add_argument("--input", default=None, help="Path to input CSV containing username,token rows.")
    parser.add_argument("--output-dir", default=None, help="Directory for generated output files.")
    parser.add_argument("--decrypt-key", default=None, help="Decrypt key for encrypted key file input.")
    args = parser.parse_args()
    
    cfg = load_config(args.config)
    resolved_input = args.input or cfg.get("scan", "input")
    resolved_output = args.output_dir or cfg.get("scan", "output_dir")
    
    try:
        creds = load_credentials(Path(resolved_input), args.decrypt_key)
        generate_dashboard(creds, Path(resolved_output), 30)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)
