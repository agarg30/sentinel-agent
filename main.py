# SENTINEL Agent - Main Entry Point
# Security & Incident Response Agent powered by Gemini + GitLab MCP

from dotenv import load_dotenv
load_dotenv()

from agents.router import run_sentinel

if __name__ == "__main__":
    run_sentinel()
