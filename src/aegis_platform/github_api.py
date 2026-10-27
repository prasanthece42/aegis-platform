"""Explicit-token GitHub CLI adapter for trusted workflow/operator processes.

No ambient CLI identity is accepted. App/source code is never executed by this adapter.
"""

import base64
import os
import re
import subprocess
from urllib.parse import quote, urlencode

from aegis_platform.canonical import canonical, strict_json
from aegis_platform.release import validate_repository


class GitHubAPI:
    def __init__(self, token: str, repository: str):
        if not token:
            raise ValueError("An explicit repository-scoped token is required")
        self.token, self.repository = token, validate_repository(repository)

    def call(self, method, path, payload=None, *, raw=False):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("API path must be relative")
        env = {**os.environ, "GH_TOKEN": self.token, "GH_HOST": "github.com"}
        command = ["gh", "api", path, "--method", method, "-H", "X-GitHub-Api-Version: 2026-03-10"]
        if raw:
            command += ["-H", "Accept: application/octet-stream"]
        if payload is not None:
            command += ["--input", "-"]
        result = subprocess.run(
            command,
            input=canonical(payload) if payload is not None else None,
            capture_output=True,
            env=env,
            timeout=90,
        )
        if result.returncode:
            # Never include provider output, request bodies or credential-bearing URLs.
            status = re.search(rb"HTTP ([0-9]{3})", result.stderr)
            detail = " HTTP " + status[1].decode() if status else ""
            raise ValueError(f"GitHub API {method} {path.split('?')[0]} failed{detail}")
        if len(result.stdout) > (65536 if raw else 8 * 1024 * 1024):
            raise ValueError("GitHub metadata exceeds bounded response budget")
        return result.stdout if raw else strict_json(result.stdout) if result.stdout else None

    def repo(self, method, path, payload=None, **kwargs):
        endpoint = f"/repos/{self.repository}"
        if path:
            endpoint += "/" + path.lstrip("/")
        return self.call(method, endpoint, payload, **kwargs)

    def pages(self, path, **params):
        items = []
        for page in range(1, 11):
            part = self.repo(
                "GET", path + "?" + urlencode({**params, "per_page": 100, "page": page})
            )
            if not isinstance(part, list):
                raise ValueError("Expected a bounded GitHub collection")
            items.extend(part)
            if len(part) < 100:
                match = re.fullmatch(r"commits/([0-9a-f]{40})/statuses", path)
                if match:
                    from aegis_platform.delivery import normalize_statuses

                    return normalize_statuses(items, self.repository, match[1])
                return items
        raise ValueError("GitHub discovery page budget exceeded")

    def file(self, path, ref):
        from aegis_platform.catalog import checked_path

        checked_path(path)
        result = self.repo(
            "GET", "contents/" + quote(path, safe="/") + "?" + urlencode({"ref": ref})
        )
        if (
            not isinstance(result, dict)
            or result.get("type") != "file"
            or result.get("encoding") != "base64"
            or result.get("size", 65537) > 65536
        ):
            raise ValueError("Expected a regular GitHub file within 64 KiB")
        return base64.b64decode(result["content"])

    def commit_files(self, branch, parent, files, message):
        """Create a new deterministic ref or advance it by non-force compare-and-swap."""
        if not re.fullmatch(r"aegis-requests/req-[0-9a-f]{64}", branch):
            raise ValueError("Only deterministic request branches may be created")
        tree = self.repo(
            "POST",
            "git/trees",
            {
                "base_tree": self.repo("GET", "git/commits/" + parent)["tree"]["sha"],
                "tree": [
                    {"path": path, "mode": "100644", "type": "blob", "content": content.decode()}
                    for path, content in files.items()
                ],
            },
        )["sha"]
        commit = self.repo(
            "POST",
            "git/commits",
            {
                "message": message,
                "tree": tree,
                "parents": [parent],
            },
        )["sha"]
        self.repo("POST", "git/refs", {"ref": "refs/heads/" + branch, "sha": commit})
        return commit
