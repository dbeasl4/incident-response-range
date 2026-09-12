#!/usr/bin/env python3
"""
Mock Internal API
Responds to any request -- just needs to be reachable so the agent
gets real HTTP responses and the proxy logs real round trips.
"""

from flask import Flask, request, jsonify
import time

app = Flask(__name__)

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/", methods=["GET", "POST"])
def handle(path=""):
    auth = request.headers.get("Authorization", "none")
    print(f"[internal_api] {request.method} /{path} auth={auth}")
    return jsonify({
        "status":    "ok",
        "path":      f"/{path}",
        "timestamp": time.time(),
        "data":      "mock-response"
    })

if __name__ == "__main__":
    print("internal_api serving on :80 (api.internal, db.internal)")
    app.run(host="0.0.0.0", port=80)
