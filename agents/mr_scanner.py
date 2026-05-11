import os
import re
import json
import logging
import httpx
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

GITLAB_URL = os.getenv("GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")
GCP_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT")
GCP_LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

# Gemini client — loaded lazily so the agent works even without GCP credentials
_gemini_client = None

def _get_gemini_client():
    global _gemini_client
    if _gemini_client is not None:
        return _gemini_client
    try:
        from google import genai
        # Vertex AI via Application Default Credentials (uses $100 GCP credits)
        _gemini_client = genai.Client(
            vertexai=True,
            project=GCP_PROJECT,
            location=GCP_LOCATION,
        )
        return _gemini_client
    except Exception as e:
        log.warning(f"[SENTINEL] Gemini unavailable ({e}) — falling back to pattern matching")
        return None

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


def analyze_with_gemini(diffs: list) -> list:
    """Use Gemini to find security issues in the diff. Returns findings list or None on failure."""
    client = _get_gemini_client()
    if not client:
        return None

    # Build a compact diff summary for the prompt
    diff_text = ""
    for d in diffs:
        added = "\n".join(
            line[1:] for line in d.get("diff", "").split("\n")
            if line.startswith("+") and not line.startswith("+++")
        )
        if added.strip():
            diff_text += f"\n### File: {d.get('new_path', 'unknown')}\n{added}\n"

    if not diff_text.strip():
        return []

    prompt = f"""You are a security code reviewer. Analyze the following code diff (added lines only) for security vulnerabilities.

{diff_text}

Return a JSON array of findings. Each finding must have:
- "id": short uppercase identifier (e.g. SQL_INJECTION)
- "severity": "CRITICAL" or "HIGH" or "MEDIUM"
- "title": short human-readable title
- "detail": one sentence explaining the risk and how to fix it
- "file": filename where found
- "code": the vulnerable line of code

Return ONLY valid JSON array. If no issues found, return [].
"""

    try:
        from google.genai import types
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.1,
            ),
        )
        # Extract text safely — some model versions return via candidates
        raw = None
        if response.text:
            raw = response.text.strip()
        elif response.candidates:
            raw = response.candidates[0].content.parts[0].text.strip()

        if not raw:
            log.warning("[SENTINEL] Gemini returned empty response — falling back to pattern matching")
            return None

        # Strip markdown code fences if model wrapped the JSON
        if raw.startswith("```"):
            raw = "\n".join(
                line for line in raw.splitlines()
                if not line.strip().startswith("```")
            ).strip()

        findings = json.loads(raw)
        # Normalize: ensure each finding has a "line" field
        for f in findings:
            f.setdefault("line", 0)
        log.info(f"[SENTINEL] Gemini found {len(findings)} issue(s)")
        return findings
    except Exception as e:
        log.warning(f"[SENTINEL] Gemini analysis failed ({e}) — falling back to pattern matching")
        return None


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

    # Try Gemini first for richer analysis
    findings = analyze_with_gemini(diffs)
    if findings is not None:
        print(f"[SENTINEL] Gemini analysis complete — {len(findings)} issue(s) found")
    else:
        findings = analyze_diff(diffs)
        print(f"[SENTINEL] Pattern analysis complete — {len(findings)} issue(s) found")

    comment = format_comment(findings, mr_iid)
    result = post_mr_comment(project_id, mr_iid, comment)
    print(f"[SENTINEL] Comment posted: {result.get('id')}")
    return findings


if __name__ == "__main__":
    project_id = os.getenv("GITLAB_PROJECT_ID")
    scan_mr(project_id, 1)

