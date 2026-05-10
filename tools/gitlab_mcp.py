# GitLab MCP client wrapper
# Connects to https://gitlab.com/api/v4/mcp

import os
import httpx

GITLAB_URL = os.getenv("GITLAB_URL", "https://gitlab.com")
GITLAB_TOKEN = os.getenv("GITLAB_TOKEN")

MCP_URL = f"{GITLAB_URL}/api/v4/mcp"

HEADERS = {
    "PRIVATE-TOKEN": GITLAB_TOKEN,
    "Content-Type": "application/json"
}


def get_merge_request_diffs(project_id: str, mr_iid: int) -> dict:
    """Fetch code diffs for a merge request via GitLab API."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/diffs"
    response = httpx.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()


def create_mr_note(project_id: str, mr_iid: int, body: str) -> dict:
    """Post a comment on a merge request."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/merge_requests/{mr_iid}/notes"
    response = httpx.post(url, headers=HEADERS, json={"body": body})
    response.raise_for_status()
    return response.json()


def get_pipeline_jobs(project_id: str, pipeline_id: int) -> dict:
    """Fetch jobs for a pipeline."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs"
    response = httpx.get(url, headers=HEADERS)
    response.raise_for_status()
    return response.json()


def create_issue(project_id: str, title: str, description: str) -> dict:
    """Create a new issue in a GitLab project."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/issues"
    response = httpx.post(url, headers=HEADERS, json={
        "title": title,
        "description": description,
        "labels": ["sentinel", "incident"]
    })
    response.raise_for_status()
    return response.json()


def search_project(project_id: str, scope: str, query: str) -> dict:
    """Search within a GitLab project."""
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/search"
    response = httpx.get(url, headers=HEADERS, params={
        "scope": scope,
        "search": query
    })
    response.raise_for_status()
    return response.json()
