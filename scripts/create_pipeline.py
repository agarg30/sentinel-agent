"""Creates a .gitlab-ci.yml in the demo project that fails — simulating a production
incident caused by the auth bug SENTINEL warned about in MR !1."""

import os
import httpx
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITLAB_TOKEN")
PROJECT_ID = os.getenv("GITLAB_PROJECT_ID", "82068580")
HEADERS = {"PRIVATE-TOKEN": TOKEN}

CI_CONTENT = """\
stages:
  - test

test_auth_tokens:
  stage: test
  image: python:3.11-slim
  script:
    - |
      python - <<'PYEOF'
      import sys

      print("[CI] Running auth token validation tests...")
      print("[CI] Test: stale token rejected after password change")

      # Simulates checking whether the auth cache is invalidated on password change.
      # This is the exact bug SENTINEL flagged in MR !1 (AUTH_TOKEN_CACHE warning).
      # The warning was dismissed — now it's a production incident.
      cached_token_still_valid = True  # bug: cache not invalidated

      if cached_token_still_valid:
          print("[CI] FAIL: Stale auth token accepted after password change!")
          print("[CI] User accounts can be accessed with revoked tokens.")
          print("[CI] SENTINEL warned about this in MR !1. Warning was dismissed.")
          sys.exit(1)

      print("[CI] PASS")
      sys.exit(0)
      PYEOF
  allow_failure: false
"""

url = f"https://gitlab.com/api/v4/projects/{PROJECT_ID}/repository/files/.gitlab-ci.yml"
payload = {
    "branch": "main",
    "content": CI_CONTENT,
    "commit_message": "ci: add auth token test (will fail due to caching bug)",
}

r = httpx.post(url, headers=HEADERS, json=payload, timeout=30)
if r.status_code == 201:
    print(f"[OK] .gitlab-ci.yml created — pipeline will trigger automatically")
    print(f"     Visit: https://gitlab.com/contactaarti1986/sentinel-demo-app/-/pipelines")
else:
    print(f"[ERR] {r.status_code}: {r.text[:400]}")
