"""
SENTINEL — Incident Responder Agent
------------------------------------
Triggered when a GitLab pipeline fails.
Flow:
  1. Fetch failed job logs from the pipeline
  2. Search the project for past SENTINEL security warnings on related MRs
  3. Correlate the failure to dismissed warnings
  4. Create a GitLab incident issue linking the warning to the outage
"""

import os
import re
import httpx
from dotenv import load_dotenv

load_dotenv()

GITLAB_URL = os.getenv("GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")
PROJECT_ID = os.getenv("GITLAB_PROJECT_ID", "82068580")
PROJECT_PATH = os.getenv("GITLAB_PROJECT_PATH", "contactaarti1986/sentinel-demo-app")

HEADERS = {"PRIVATE-TOKEN": GITLAB_TOKEN}


# ---------------------------------------------------------------------------
# Step 1 — Get failed job logs
# ---------------------------------------------------------------------------

def get_failed_pipeline_jobs(project_id: str, pipeline_id: int) -> list[dict]:
    """Return all failed jobs for a pipeline, each with their log excerpt."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs"
    r = httpx.get(url, headers=HEADERS, params={"scope": "failed"}, timeout=30)
    r.raise_for_status()
    jobs = r.json()

    enriched = []
    for job in jobs:
        log = get_job_log(project_id, job["id"])
        enriched.append({
            "id": job["id"],
            "name": job["name"],
            "stage": job["stage"],
            "log": log,
        })
    return enriched


def get_job_log(project_id: str, job_id: int) -> str:
    """Fetch the trace/log of a specific job (last 3000 chars)."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/jobs/{job_id}/trace"
    r = httpx.get(url, headers=HEADERS, timeout=30)
    if r.status_code == 200:
        return r.text[-3000:]  # tail — most relevant part
    return "(log unavailable)"


# ---------------------------------------------------------------------------
# Step 2 — Search for past SENTINEL warnings in MR notes
# ---------------------------------------------------------------------------

def find_sentinel_warnings(project_id: str) -> list[dict]:
    """Search all open and merged MRs for notes containing SENTINEL warnings."""
    warnings = []
    for state in ("opened", "merged"):
        url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests"
        r = httpx.get(url, headers=HEADERS, params={"state": state, "per_page": 20}, timeout=30)
        if r.status_code != 200:
            continue
        for mr in r.json():
            notes = get_mr_sentinel_notes(project_id, mr["iid"])
            for note in notes:
                warnings.append({
                    "mr_iid": mr["iid"],
                    "mr_title": mr["title"],
                    "mr_url": mr["web_url"],
                    "mr_state": state,
                    "note_id": note["id"],
                    "note_body": note["body"],
                    "created_at": note["created_at"],
                })
    return warnings


def get_mr_sentinel_notes(project_id: str, mr_iid: int) -> list[dict]:
    """Return notes on an MR that were posted by SENTINEL."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    r = httpx.get(url, headers=HEADERS, timeout=30)
    if r.status_code != 200:
        return []
    return [n for n in r.json() if "SENTINEL" in n.get("body", "")]


# ---------------------------------------------------------------------------
# Step 3 — Correlate failure to warnings
# ---------------------------------------------------------------------------

# Keywords in job logs that map to SENTINEL warning IDs
CORRELATION_RULES = [
    {
        "warning_id": "AUTH_TOKEN_CACHE",
        "log_keywords": ["stale auth token", "stale token", "token", "cache", "session", "password change"],
        "note_keywords": ["AUTH_TOKEN_CACHE", "token cach", "auth cach", "session"],
    },
    {
        "warning_id": "SQL_INJECTION",
        "log_keywords": ["sql", "injection", "query", "database error", "syntax error"],
        "note_keywords": ["SQL_INJECTION", "sql inject", "parameterized"],
    },
    {
        "warning_id": "HARDCODED_SECRET",
        "log_keywords": ["credential", "password", "secret", "unauthorized", "authentication failed"],
        "note_keywords": ["HARDCODED_SECRET", "hardcoded", "credential"],
    },
]


def correlate(failed_jobs: list[dict], warnings: list[dict]) -> list[dict]:
    """Match failed job log keywords to SENTINEL warning note keywords."""
    matches = []
    for job in failed_jobs:
        log_lower = job["log"].lower()
        for rule in CORRELATION_RULES:
            log_hit = any(kw in log_lower for kw in rule["log_keywords"])
            if not log_hit:
                continue
            for w in warnings:
                note_lower = w["note_body"].lower()
                note_hit = any(kw.lower() in note_lower for kw in rule["note_keywords"])
                if note_hit:
                    matches.append({
                        "job": job,
                        "warning": w,
                        "warning_id": rule["warning_id"],
                    })
    return matches


# ---------------------------------------------------------------------------
# Step 4 — Create a GitLab incident issue
# ---------------------------------------------------------------------------

def create_incident_issue(project_id: str, pipeline_id: int, matches: list[dict], failed_jobs: list[dict]) -> dict:
    """Open a GitLab issue that documents the incident and links to the dismissed warning."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/issues"

    if matches:
        primary = matches[0]
        warning = primary["warning"]
        job = primary["job"]
        warning_id = primary["warning_id"]

        title = f"[SENTINEL INCIDENT] Pipeline #{pipeline_id} failure linked to dismissed warning ({warning_id})"

        body = f"""## 🚨 SENTINEL Incident Report

**Pipeline:** #{pipeline_id}  
**Failed Job:** `{job['name']}` (Stage: `{job['stage']}`)  
**Correlated Warning:** `{warning_id}` — flagged in [MR !{warning['mr_iid']}]({warning['mr_url']})  
**Warning Status at Merge:** {warning['mr_state'].upper()}  

---

### What Happened

SENTINEL previously flagged a **{warning_id}** issue in [MR !{warning['mr_iid']}: {warning['mr_title']}]({warning['mr_url']}).

That warning was **not resolved before merge**. The same vulnerability has now caused a CI/CD pipeline failure.

---

### Original SENTINEL Warning (from MR !{warning['mr_iid']})

> {warning['note_body'][:600]}...

---

### Failed Job Log (tail)

```
{job['log'][-1500:]}
```

---

### Recommended Actions

1. **Immediate:** Revert or patch the code introduced in MR !{warning['mr_iid']}
2. **Short-term:** Enforce SENTINEL warnings as merge blockers for CRITICAL/HIGH severity
3. **Process:** Require security sign-off before dismissing SENTINEL warnings

---

*This incident was automatically correlated by SENTINEL — Security & Incident Response Agent.*  
*Powered by Gemini + Google Cloud Agent Builder + GitLab MCP*
"""
    else:
        # No correlation found — still create a generic incident issue
        job_summary = "\n".join(
            f"- `{j['name']}` ({j['stage']}): {j['log'][-300:]}" for j in failed_jobs
        )
        title = f"[SENTINEL INCIDENT] Pipeline #{pipeline_id} failed — no prior warning correlated"
        body = f"""## 🚨 SENTINEL Incident Report

**Pipeline:** #{pipeline_id}  
No direct correlation found between this failure and past SENTINEL warnings.

### Failed Jobs
{job_summary}

---
*Auto-generated by SENTINEL*
"""

    payload = {
        "title": title,
        "description": body,
        "labels": "incident,sentinel,security",
    }
    r = httpx.post(url, headers=HEADERS, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def respond_to_incident(project_id: str, pipeline_id: int):
    print(f"[SENTINEL] Responding to pipeline #{pipeline_id} failure in project {project_id}...")

    print("[SENTINEL] Fetching failed job logs...")
    failed_jobs = get_failed_pipeline_jobs(project_id, pipeline_id)
    if not failed_jobs:
        print("[SENTINEL] No failed jobs found — pipeline may still be running.")
        return
    print(f"[SENTINEL] Found {len(failed_jobs)} failed job(s)")

    print("[SENTINEL] Searching for past security warnings...")
    warnings = find_sentinel_warnings(project_id)
    print(f"[SENTINEL] Found {len(warnings)} past SENTINEL warning(s)")

    print("[SENTINEL] Correlating failure to warnings...")
    matches = correlate(failed_jobs, warnings)
    if matches:
        print(f"[SENTINEL] Correlated {len(matches)} match(es) — warning WAS dismissed before this failure")
    else:
        print("[SENTINEL] No direct correlation found")

    print("[SENTINEL] Creating incident issue...")
    issue = create_incident_issue(project_id, pipeline_id, matches, failed_jobs)
    print(f"[SENTINEL] Incident issue created: {issue['web_url']}")
    return issue


# ---------------------------------------------------------------------------
# Local test entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    # Accept pipeline ID as arg or prompt
    if len(sys.argv) > 1:
        pipeline_id = int(sys.argv[1])
    else:
        pipeline_id = int(input("Enter the failed pipeline ID to analyze: "))

    respond_to_incident(PROJECT_ID, pipeline_id)

