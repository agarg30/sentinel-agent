# SENTINEL — Security & Incident Response Agent

> **Every team has scanners. Nobody has memory.**

Built with **Gemini** + **Google Cloud Agent Builder** + **GitLab MCP Server**

---

## A Story Every Engineering Team Knows

It's 2:47 AM. PagerDuty fires.

Your auth service is returning 500s. Users can't log in. Revenue is bleeding at $4,000 a minute.

Three engineers are on a call, pulling logs, grepping stacktraces, pinging each other on Slack. After two hours, someone finds it — a raw SQL query in the user lookup function, introduced three weeks ago in MR !67.

Here's the part that hurts.

SonarQube flagged it. Right there in the MR. "Potential SQL injection — line 34." The developer saw it, added a comment: *"low risk, will address in next sprint"*, and merged.

The warning lived for exactly 4 days — in a thread nobody would ever reopen.

Then it vanished. Into the void where all dismissed MR comments go.

Your team already has Copilot. SonarQube. Snyk. Dependabot. Daily vulnerability emails. A Slack channel nobody reads.

**The tools aren't broken. They flag everything.**

**The problem is what happens after the flag.**

Dismissed warnings have no memory. They don't follow the code into production. They don't show up when the pipeline burns at 2:47 AM. They don't connect the incident of today to the decision of three weeks ago.

Every team is drowning in alerts with no thread connecting them to consequences.

**SENTINEL is that thread.**

---

## What SENTINEL Does

SENTINEL doesn't replace your scanners. It remembers what they found — and holds your codebase accountable.

- **Prevention Mode** — when an MR is opened, SENTINEL doesn't just flag. It asks: *"Has this pattern caused an incident before? Was a similar warning dismissed in this file last month?"* It posts a warning with context, not just a rule number.
- **Response Mode** — when a pipeline fails, SENTINEL doesn't just read logs. It searches: *"Which dismissed MR warning touched this file? Who merged it? What did they promise?"* It writes the incident report before your engineers finish their first coffee.
- **The Memory Loop** — every dismissed warning is tracked. Every incident is correlated back to its origin. Over time, SENTINEL knows which warnings your team ignores — and which ones always come back to bite.

---

## Before SENTINEL vs After SENTINEL

| Situation | Without SENTINEL | With SENTINEL |
|---|---|---|
| MR opened with SQL injection | SonarQube flags it. Developer dismisses. Warning disappears. | SENTINEL flags it **with history**: *"This pattern caused an incident in this file 6 weeks ago."* |
| Developer dismisses a warning | Comment buried in MR thread forever | Warning logged, tracked, linked to the file and author |
| Pipeline fails at 2 AM | 3 engineers, 2 hours, grep through logs manually | SENTINEL reads logs, searches past warnings, posts root cause analysis + incident issue in minutes |
| Incident post-mortem | "How did this get through?" — nobody knows | "MR !67, March 3rd, dismissed by @dev, marked low risk" — full audit trail |
| New security pattern emerges | Next team makes the same mistake | SENTINEL recognizes the pattern, references the past incident in the next MR warning |
| Monthly security review | Manual, slow, always behind | SENTINEL has been tracking every warning and dismissal in real time — always current |

---

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │         GitLab Events                   │
                        │  (MR opened / Pipeline failed)          │
                        └──────────────┬──────────────────────────┘
                                       │  Webhook
                                       ▼
                        ┌─────────────────────────────────────────┐
                        │      SENTINEL Webhook Receiver          │
                        │         (FastAPI on Cloud Run)          │
                        └──────────────┬──────────────────────────┘
                                       │
                          ┌────────────┴────────────┐
                          │                         │
                          ▼                         ▼
          ┌───────────────────────┐   ┌───────────────────────────┐
          │   MR Scanner Agent   │   │  Incident Responder Agent  │
          │  (Prevention Mode)   │   │    (Response Mode)         │
          └──────────┬───────────┘   └────────────┬───────────────┘
                     │                            │
                     ▼                            ▼
          ┌───────────────────────────────────────────────────────┐
          │              Gemini (via Vertex AI)                   │
          │         Reasoning · Analysis · Decision               │
          └───────────────────────────────────────────────────────┘
                     │                            │
                     ▼                            ▼
          ┌───────────────────────────────────────────────────────┐
          │              GitLab MCP Server                        │
          │  get_merge_request_diffs · create_workitem_note       │
          │  get_pipeline_jobs · create_issue · search            │
          └───────────────────────────────────────────────────────┘
```

---

## Agent Flow

### Mode 1: Prevention (MR Opened)

```
Developer opens MR
        │
        ▼
get_merge_request_diffs ──► Gemini analyzes code for:
                              · SQL injection
                              · Hardcoded secrets
                              · Insecure auth patterns
                              · Vulnerable dependencies
        │
        ▼
create_workitem_note ──► Posts security warning on MR
                          with specific line references
        │
        ▼
Warning stored → tracked for future incident correlation
```

### Mode 2: Response (Pipeline Failed)

```
Pipeline fails
        │
        ▼
get_pipeline_jobs ──► Read failure logs
        │
        ▼
search ──► Find past MR warnings touching same files
        │
        ▼
Gemini correlates: "This failure links to warning in MR !X"
        │
        ▼
create_issue ──► Incident report with:
                  · Root cause analysis
                  · Link to original warning
                  · Suggested fix
                  · Post-mortem template
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent Brain | Gemini 2.0 Flash (Vertex AI) |
| Agent Orchestration | Google Cloud Agent Builder |
| Partner Integration | GitLab MCP Server |
| Backend | Python + FastAPI |
| Hosting | Google Cloud Run |
| Secrets | Google Secret Manager |

---

## Setup

### Prerequisites
- Python 3.11+
- Google Cloud account (Project ID: see `.env`)
- GitLab account with Personal Access Token

### Install

```bash
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
# Edit .env with your GitLab token and GCP project details
```

### Run locally

```bash
python main.py
```

---

## GitLab MCP Tools Used

| Tool | Purpose |
|---|---|
| `get_merge_request_diffs` | Read MR code changes |
| `create_workitem_note` | Post security warnings on MR |
| `get_pipeline_jobs` | Read pipeline failure logs |
| `create_issue` | Create incident reports |
| `search` | Find past related warnings |
| `semantic_code_search` | Find vulnerable patterns in codebase |

---

## License

MIT License — see [LICENSE](LICENSE)
