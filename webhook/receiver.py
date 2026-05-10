from fastapi import FastAPI, Request
from agents.mr_scanner import scan_mr
from agents.incident_responder import respond_to_incident

app = FastAPI(title="SENTINEL Webhook Receiver")


@app.get("/health")
def health():
    return {"status": "SENTINEL is running"}


@app.post("/webhook/gitlab")
async def gitlab_webhook(request: Request):
    payload = await request.json()
    event_type = request.headers.get("X-Gitlab-Event", "")

    if event_type == "Merge Request Hook":
        action = payload.get("object_attributes", {}).get("action")
        if action == "open":
            # Route to MR security scanner
            project_id = str(payload["project"]["id"])
            mr_iid = payload["object_attributes"]["iid"]
            scan_mr(project_id, mr_iid)

    elif event_type == "Pipeline Hook":
        status = payload.get("object_attributes", {}).get("status")
        if status == "failed":
            # Route to incident responder
            project_id = str(payload["project"]["id"])
            pipeline_id = payload["object_attributes"]["id"]
            respond_to_incident(project_id, pipeline_id)

    return {"status": "received"}
