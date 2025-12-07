import json
import os
import random
import string
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CPP_SRC = ROOT / "cpp_backend" / "main.cpp"
INCLUDE_DIR = ROOT / "cpp_backend" / "include"
SCRIPT_PATH = ROOT / "cpp_backend" / "tests" / "docker_run.sh"


def run(cmd, **kwargs):
    print(f"[cmd] {' '.join(cmd)}")
    return subprocess.check_output(cmd, text=True, **kwargs)


def build_and_run_in_docker():
    jwt_secret = "super-secret-dev"
    # Build a shell script executed inside the container.
    SCRIPT_PATH.write_text(
        f"""#!/usr/bin/env bash
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq g++ libssl-dev curl python3
cd /work/cpp_backend
g++ -std=c++17 -O2 -Iinclude ../cpp_backend/main.cpp -lssl -lcrypto -pthread -o /tmp/transfer_service
JWT_SECRET="{jwt_secret}" CPP_PORT=4002 /tmp/transfer_service >/tmp/svc.log 2>&1 &
svc_pid=$!
sleep 1

python3 - <<'PY'
import json, random, string, time, urllib.request

base = "http://127.0.0.1:4002"

def post(path, payload, token=None):
    req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def get(path, token):
    req = urllib.request.Request(base + path)
    req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def random_email():
    return ''.join(random.choices(string.ascii_lowercase, k=6)) + "@example.com"

users = []
for i in range(10):
    email = random_email()
    name = f"User {i}"
    password = "pass1234"
    reg = post("/auth/register", {{"email": email, "name": name, "password": password}})
    users.append({{"email": email, "name": name, "token": reg["accessToken"], "password": password}})

for _ in range(1000):
    u = random.choice(users)
    direction = random.choice(["inbound", "outbound"])
    payload = {{
        "direction": direction,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "amount": round(random.uniform(1, 1000), 2),
    }}
    if direction == "inbound":
        payload["source"] = "acct-" + ''.join(random.choices(string.digits, k=6))
    else:
        payload["destination"] = "acct-" + ''.join(random.choices(string.digits, k=6))
    post("/transfer", payload, token=u["token"])

# Fetch and print record sizes for verification
results = []
for u in users:
    rec = get("/record", token=u["token"])
    results.append({{
        "email": u["email"],
        "inbound": len(rec.get("inbound", [])),
        "outbound": len(rec.get("outbound", [])),
    }})
print(json.dumps(results, indent=2))
PY

kill $svc_pid
"""
    )
    SCRIPT_PATH.chmod(0o755)

    run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT}:/work",
            "ubuntu:22.04",
            "/work/cpp_backend/tests/" + SCRIPT_PATH.name,
        ]
    )


if __name__ == "__main__":
    build_and_run_in_docker()
