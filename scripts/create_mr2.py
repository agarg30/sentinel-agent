"""
Creates a new branch + vulnerable file + MR on sentinel-demo-app.
This will trigger the GitLab webhook → SENTINEL on Cloud Run → Gemini analysis.
"""

import os, httpx, base64
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("GITLAB_TOKEN")
PROJECT_ID = os.getenv("GITLAB_PROJECT_ID", "82068580")
HEADERS = {"PRIVATE-TOKEN": TOKEN}
BASE = "https://gitlab.com/api/v4"


def api(method, path, **kwargs):
    r = httpx.request(method, f"{BASE}{path}", headers=HEADERS, timeout=15, **kwargs)
    r.raise_for_status()
    return r.json()


# 1. Create branch off main
print("[1] Creating branch feature/payment-api ...")
api("POST", f"/projects/{PROJECT_ID}/repository/branches", json={
    "branch": "feature/payment-api",
    "ref": "main",
})

# 2. Add a file with multiple security issues for Gemini to find
code = """\
import requests
import sqlite3

# Payment processing service
STRIPE_SECRET_KEY = "sk_live_DEMO_PLACEHOLDER_NOT_A_REAL_KEY"  # noqa: hardcoded for demo purposes
DB_PASSWORD = "prod_db_pass_2024!"
ADMIN_TOKEN = "demo-admin-jwt-token-placeholder"

def get_payment_history(user_id):
    conn = sqlite3.connect("payments.db")
    cursor = conn.cursor()
    # Build query with user input directly
    query = "SELECT * FROM payments WHERE user_id = " + user_id
    cursor.execute(query)
    return cursor.fetchall()

def charge_customer(amount, card_token):
    # Call Stripe API with hardcoded key
    response = requests.post(
        "https://api.stripe.com/v1/charges",
        auth=(STRIPE_SECRET_KEY, ""),
        data={"amount": amount, "source": card_token, "currency": "usd"},
    )
    return response.json()

def verify_admin(password):
    # Plaintext password comparison
    if password == DB_PASSWORD:
        return True
    return False
"""

print("[2] Committing payment_service.py with vulnerabilities ...")
api("POST", f"/projects/{PROJECT_ID}/repository/files/payment_service.py", json={
    "branch": "feature/payment-api",
    "content": code,
    "commit_message": "feat: add payment processing service",
})

# 3. Open MR — this fires the webhook to SENTINEL
print("[3] Opening MR !2 ...")
mr = api("POST", f"/projects/{PROJECT_ID}/merge_requests", json={
    "source_branch": "feature/payment-api",
    "target_branch": "main",
    "title": "Add payment processing service",
    "description": "Adds Stripe integration for processing customer payments.",
})

print(f"\n[OK] MR created: {mr['web_url']}")
print("[OK] Webhook fired → SENTINEL on Cloud Run is now scanning with Gemini...")
print("[OK] Check the MR in ~10 seconds for a SENTINEL comment.")
