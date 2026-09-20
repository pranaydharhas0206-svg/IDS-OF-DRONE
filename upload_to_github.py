#!/usr/bin/env python3
"""
Direct GitHub Uploader for Drone IDS Project
-------------------------------------------
Uploads the project files to a GitHub repository using only the standard library
(Python 3.10+ with urllib). Works even without git installed on your machine!

Requirements:
    - A GitHub Personal Access Token (classic or fine-grained) with 'repo' scope.
    - Get one at: https://github.com/settings/tokens

Usage:
    python upload_to_github.py --repo drone-intrusion-detection-system --token <YOUR_GITHUB_TOKEN>
    # OR interactively:
    python upload_to_github.py
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path


FILES_TO_UPLOAD = [
    "stage1_drone_ids.py",
    "README.md",
    "requirements.txt",
    ".gitignore",
    ".github/workflows/test.yml",
]


def github_request(
    url: str,
    token: str,
    method: str = "GET",
    data: dict | None = None,
) -> dict:
    headers = {
        "Authorization": f"Bearer {token.strip()}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "Drone-IDS-Uploader",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = resp.read().decode("utf-8")
            return json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as err:
        err_msg = err.read().decode("utf-8")
        try:
            parsed = json.loads(err_msg)
            message = parsed.get("message", err_msg)
        except Exception:
            message = err_msg
        raise RuntimeError(f"GitHub API Error {err.code}: {message}")


def get_authenticated_user(token: str) -> str:
    user_info = github_request("https://api.github.com/user", token)
    return user_info["login"]


def ensure_repository(user: str, repo_name: str, token: str, private: bool = False) -> str:
    try:
        repo_info = github_request(f"https://api.github.com/repos/{user}/{repo_name}", token)
        print(f"[*] Found existing repository: {repo_info['html_url']}")
        return repo_info["html_url"]
    except RuntimeError:
        print(f"[*] Creating repository '{repo_name}' on GitHub...")
        payload = {
            "name": repo_name,
            "description": "PUSHPAK Grand Challenge 2026 - Drone Intrusion Detection System (Stage 1 PoC)",
            "private": private,
            "auto_init": False,
        }
        try:
            repo_info = github_request("https://api.github.com/user/repos", token, method="POST", data=payload)
            print(f"[+] Successfully created: {repo_info['html_url']}")
            return repo_info["html_url"]
        except RuntimeError as e:
            if "403" in str(e) or "Resource not accessible" in str(e):
                print(f"\n[!] Notice: Fine-grained tokens cannot create new repositories via the API.")
                print(f"    Please create an empty repository on GitHub first:")
                print(f"    1. Open: https://github.com/new")
                print(f"    2. Set Repository name: {repo_name}")
                print(f"    3. Click 'Create repository'")
                print(f"    4. Re-run: python upload_to_github.py\n")
                sys.exit(1)
            raise


def get_file_sha(user: str, repo_name: str, file_path: str, token: str) -> str | None:
    try:
        info = github_request(f"https://api.github.com/repos/{user}/{repo_name}/contents/{file_path}", token)
        return info.get("sha")
    except RuntimeError:
        return None


def upload_file(user: str, repo_name: str, file_path: str, local_file: Path, token: str) -> None:
    content_b64 = base64.b64encode(local_file.read_bytes()).decode("utf-8")
    existing_sha = get_file_sha(user, repo_name, file_path, token)

    payload = {
        "message": f"Add/Update {file_path}",
        "content": content_b64,
    }
    if existing_sha:
        payload["sha"] = existing_sha

    url = f"https://api.github.com/repos/{user}/{repo_name}/contents/{file_path}"
    github_request(url, token, method="PUT", data=payload)
    print(f"  [✓] Uploaded {file_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload Drone IDS to GitHub")
    parser.add_argument("token_pos", nargs="?", help="GitHub Personal Access Token (optional positional)")
    parser.add_argument("--repo", default="drone-intrusion-detection-system", help="GitHub repo name")
    parser.add_argument("--token", help="GitHub Personal Access Token")
    parser.add_argument("--private", action="store_true", help="Make repository private")
    args = parser.parse_args()

    # Try loading from CLI arguments or .env in current folder / user home
    token = args.token or args.token_pos or os.getenv("GITHUB_TOKEN")
    if not token:
        for env_path in [Path(".env"), Path.home() / ".env"]:
            if env_path.exists():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    if line.startswith("GITHUB_TOKEN="):
                        token = line.split("=", 1)[1].strip().strip('"').strip("'")
                        if token:
                            break
            if token:
                break

    if not token:
        print("\n=== GitHub Authentication Required ===")
        print("Please enter your GitHub Personal Access Token (PAT).")
        print("To generate one: Go to https://github.com/settings/tokens -> Generate new token (classic) -> Select 'repo' scope.")
        token = getpass.getpass("GitHub Token: ").strip()

    if not token:
        print("Error: No token provided.")
        return 1

    try:
        user = get_authenticated_user(token)
        print(f"[+] Authenticated as GitHub user: @{user}")
    except Exception as e:
        print(f"[-] Authentication failed: {e}")
        return 1

    repo_url = ensure_repository(user, args.repo, token, private=args.private)

    project_root = Path(__file__).resolve().parent
    if (project_root / "drone-ids").is_dir() and not (project_root / "stage1_drone_ids.py").is_file():
        project_root = project_root / "drone-ids"
    elif not (project_root / "stage1_drone_ids.py").is_file():
        fallback = Path.home() / ".gemini" / "antigravity" / "scratch" / "drone-ids"
        if fallback.is_dir():
            project_root = fallback

    print(f"\n[*] Uploading files from {project_root}...")

    for rel_path in FILES_TO_UPLOAD:
        local_path = project_root / rel_path
        if local_path.is_file():
            # Use forward slashes for GitHub API path
            api_path = rel_path.replace("\\", "/")
            upload_file(user, args.repo, api_path, local_path, token)
        else:
            print(f"  [!] Warning: {rel_path} not found locally, skipping.")

    print("\n" + "=" * 60)
    print("SUCCESS! Your Drone IDS repository is live on GitHub at:")
    print(f"👉 {repo_url}")
    print("=" * 60 + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
