"""
Send simulated GitLab webhook payloads to the local SENTINEL server.
Run this AFTER starting:  uvicorn webhook.receiver:app --port 8000

Usage:
  python scripts/test_webhook.py mr       # simulates MR !2 being opened
  python scripts/test_webhook.py pipeline # simulates pipeline #2513848023 failing
"""

import sys
import httpx

BASE = "http://localhost:8000"

# ---------------------------------------------------------------------------
# Simulated GitLab payloads (match real GitLab schema)
# ---------------------------------------------------------------------------

MR_OPEN_PAYLOAD = {
    "object_kind": "merge_request",
    "project": {
        "id": 82068580,
        "name": "sentinel-demo-app",
        "web_url": "https://gitlab.com/contactaarti1986/sentinel-demo-app",
    },
    "object_attributes": {
        "iid": 1,
        "title": "Add Redis caching for auth tokens",
        "action": "open",
        "url": "https://gitlab.com/contactaarti1986/sentinel-demo-app/-/merge_requests/1",
        "source_branch": "feature/redis-auth-cache",
        "target_branch": "main",
    },
    "user": {"name": "Aarti Tayal", "username": "contactaarti1986"},
}

PIPELINE_FAIL_PAYLOAD = {
    "object_kind": "pipeline",
    "project": {
        "id": 82068580,
        "name": "sentinel-demo-app",
        "web_url": "https://gitlab.com/contactaarti1986/sentinel-demo-app",
    },
    "object_attributes": {
        "id": 2513848023,
        "status": "failed",
        "ref": "main",
        "sha": "abc123",
    },
}


def send(event_type: str, payload: dict):
    headers = {
        "X-Gitlab-Event": event_type,
        "Content-Type": "application/json",
    }
    print(f"\n[TEST] Sending '{event_type}' to {BASE}/webhook/gitlab ...")
    r = httpx.post(f"{BASE}/webhook/gitlab", json=payload, headers=headers, timeout=10)
    print(f"[TEST] Response: {r.status_code} — {r.json()}")
    print("[TEST] Check the uvicorn terminal for SENTINEL agent output.\n")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"

    if mode in ("mr", "both"):
        send("Merge Request Hook", MR_OPEN_PAYLOAD)

    if mode in ("pipeline", "both"):
        send("Pipeline Hook", PIPELINE_FAIL_PAYLOAD)
