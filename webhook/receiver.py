import logging
import os
import hmac
import hashlib
from fastapi import FastAPI, Request, BackgroundTasks, HTTPException
from dotenv import load_dotenv
from agents.mr_scanner import scan_mr
from agents.incident_responder import respond_to_incident

load_dotenv()

logging.basicConfig(level=logging.INFO, format="[SENTINEL] %(message)s")
log = logging.getLogger(__name__)

WEBHOOK_SECRET = os.getenv("GITLAB_WEBHOOK_SECRET", "")  # optional — set in GitLab webhook config

app = FastAPI(title="SENTINEL Webhook Receiver")


def _verify_secret(request: Request):
    """Validate X-Gitlab-Token header if a webhook secret is configured."""
    if not WEBHOOK_SECRET:
        return  # secret not configured — skip (dev mode)
    token = request.headers.get("X-Gitlab-Token", "")
    if not hmac.compare_digest(token, WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid webhook token")


@app.get("/health")
def health():
    return {"status": "SENTINEL is running", "version": "1.0.0"}


@app.post("/webhook/gitlab")
async def gitlab_webhook(request: Request, background_tasks: BackgroundTasks):
    _verify_secret(request)

    payload = await request.json()
    event_type = request.headers.get("X-Gitlab-Event", "")

    log.info(f"Received event: {event_type}")

    if event_type == "Merge Request Hook":
        action = payload.get("object_attributes", {}).get("action")
        mr_iid = payload.get("object_attributes", {}).get("iid")
        project_id = str(payload.get("project", {}).get("id", ""))
        mr_url = payload.get("object_attributes", {}).get("url", "")

        if action == "open" and project_id and mr_iid:
            log.info(f"MR !{mr_iid} opened in project {project_id} — queuing scan")
            background_tasks.add_task(scan_mr, project_id, mr_iid)
        else:
            log.info(f"MR action '{action}' — ignored")

    elif event_type == "Pipeline Hook":
        status = payload.get("object_attributes", {}).get("status")
        pipeline_id = payload.get("object_attributes", {}).get("id")
        project_id = str(payload.get("project", {}).get("id", ""))

        if status == "failed" and project_id and pipeline_id:
            log.info(f"Pipeline #{pipeline_id} failed in project {project_id} — queuing incident response")
            background_tasks.add_task(respond_to_incident, project_id, pipeline_id)
        else:
            log.info(f"Pipeline status '{status}' — ignored")

    else:
        log.info(f"Unhandled event type: {event_type}")

    # Respond immediately — agents run in background so GitLab doesn't time out
    return {"status": "received", "event": event_type}
