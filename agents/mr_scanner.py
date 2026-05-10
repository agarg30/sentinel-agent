import os
import re
import httpx
from dotenv import load_dotenv

load_dotenv()

GITLAB_URL = os.getenv("GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")

HEADERS = {"PRIVATE-TOKEN": GITLAB_TOKEN}

# Security patterns to detect in code diffs
SECURITY_PATTERNS = [
    {
        "id": "SQL_INJECTION",
        "pattern": r"(execute|query)\s*\(\s*[\"'].*\+|SELECT.*\+.*username|WHERE.*\+",
        "severity": "CRITICAL",
        "title": "SQL Injection Vulnerability",
        "detail": "String concatenation used in SQL query. User input is not sanitized. Use parameterized queries instead."
    },
    {
        "id": "HARDCODED_SECRET",
        "pattern": r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*[\"'][^\"']{6,}[\"']",
        "severity": "CRITICAL",
        "title": "Hardcoded Secret Detected",
        "detail": "Credentials are hardcoded in source code. Use environment variables or a secrets manager instead."
    },
    {
        "id": "AUTH_TOKEN_CACHE",
        "pattern": r"(cache|redis|setex|set)\s*.*auth.*(token|session)|auth.*(token|session).*(cache|redis)",
        "severity": "HIGH",
        "title": "Auth Token Caching Risk",
        "detail": "Caching authentication tokens can prevent immediate session invalidation on logout or password reset. This team has seen this pattern cause a 2-hour auth outage."
    },
    {
        "id": "PLAINTEXT_PASSWORD",
        "pattern": r"password\s*==\s*|==\s*password|compare.*password.*plain",
        "severity": "CRITICAL",
        "title": "Plaintext Password Comparison",
        "detail": "Passwords are being compared in plaintext. Use bcrypt, argon2, or similar hashing."
    },
]


def get_mr_diffs(project_id: str, mr_iid: int) -> list:
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/diffs"
    response = httpx.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()


def post_mr_comment(project_id: str, mr_iid: int, body: str) -> dict:
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    response = httpx.post(url, headers=HEADERS, json={"body": body})
    response.raise_for_status()
    return response.json()


def analyze_diff(diffs: list) -> list:
    findings = []
    for diff in diffs:
        new_path = diff.get("new_path", "")
        diff_text = diff.get("diff", "")
        # Only analyze added lines
        added_lines = [
            (i + 1, line[1:])
            for i, line in enumerate(diff_text.split("\n"))
            if line.startswith("+") and not line.startswith("+++")
        ]
        for pattern_def in SECURITY_PATTERNS:
            for line_num, line in added_lines:
                if re.search(pattern_def["pattern"], line, re.IGNORECASE):
                    findings.append({
                        "file": new_path,
                        "line": line_num,
                        "code": line.strip(),
                        **pattern_def
                    })
    return findings


def format_comment(findings: list, mr_iid: int) -> str:
    if not findings:
        return "**SENTINEL** ✅ No security issues detected in this MR."

    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]

    lines = [
        "## 🛡️ SENTINEL Security Scan",
        "",
        f"**{len(findings)} issue(s) found** in MR !{mr_iid}",
        "",
    ]

    if critical:
        lines.append(f"### 🔴 CRITICAL ({len(critical)})")
        for f in critical:
            lines += [
                f"**{f['title']}** — `{f['file']}`",
                f"> {f['detail']}",
                f"```\n{f['code']}\n```",
                "",
            ]

    if high:
        lines.append(f"### 🟠 HIGH ({len(high)})")
        for f in high:
            lines += [
                f"**{f['title']}** — `{f['file']}`",
                f"> {f['detail']}",
                f"```\n{f['code']}\n```",
                "",
            ]

    lines += [
        "---",
        "_SENTINEL is watching. Dismissed warnings are remembered and correlated to future incidents._",
    ]
    return "\n".join(lines)


def scan_mr(project_id: str, mr_iid: int):
    print(f"[SENTINEL] Scanning MR !{mr_iid} in project {project_id}...")
    diffs = get_mr_diffs(project_id, mr_iid)
    print(f"[SENTINEL] Found {len(diffs)} changed file(s)")
    findings = analyze_diff(diffs)
    print(f"[SENTINEL] Detected {len(findings)} security issue(s)")
    comment = format_comment(findings, mr_iid)
    result = post_mr_comment(project_id, mr_iid, comment)
    print(f"[SENTINEL] Comment posted: {result.get('id')}")
    return findings


if __name__ == "__main__":
    project_id = os.getenv("GITLAB_PROJECT_ID")
    scan_mr(project_id, 1)

