from fastapi import FastAPI
from pydantic import BaseModel
import os
import requests
from urllib.parse import urlparse

app = FastAPI()

# Change this to the grader's path before deployment if needed
SANDBOX_ROOT = os.path.abspath("./sandbox")

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


class ToolRequest(BaseModel):
    tool: str
    arguments: dict


@app.post("/")
def guardrail(req: ToolRequest):

    if req.tool == "read_file":

        path = req.arguments.get("path", "")

        full_path = os.path.realpath(
            os.path.join(SANDBOX_ROOT, path)
        )

        if not full_path.startswith(SANDBOX_ROOT):
            return {
                "action": "block",
                "reason": "outside sandbox",
                "result": None
            }

        if not os.path.exists(full_path):
            return {
                "action": "block",
                "reason": "file not found",
                "result": None
            }

        with open(full_path, "r", encoding="utf-8") as f:
            text = f.read()

        return {
            "action": "allow",
            "reason": "inside sandbox",
            "result": text
        }

    elif req.tool == "fetch_url":

        url = req.arguments.get("url", "")

        parsed = urlparse(url)

        if parsed.hostname not in ALLOWED_HOSTS:
            return {
                "action": "block",
                "reason": "host not allowed",
                "result": None
            }

        try:
            response = requests.get(
                url,
                allow_redirects=False,
                timeout=10
            )

            return {
                "action": "allow",
                "reason": "allowed host",
                "result": response.text
            }

        except Exception as e:
            return {
                "action": "block",
                "reason": str(e),
                "result": None
            }

    return {
        "action": "block",
        "reason": "unknown tool",
        "result": None
    }