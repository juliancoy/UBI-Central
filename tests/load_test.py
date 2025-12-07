"""
Simple load test against the C++ backend running on http://localhost:4002.
Creates 100 accounts then sends 1000 randomized transactions and prints
per-user inbound/outbound counts.

Requires the backend running (see run.py) and the `requests` package:
    pip install requests
"""

import json
import random
import string
import time
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import requests

BASE = "http://localhost:4002"
OUT_DIR = Path(__file__).resolve().parent
ADMIN_KEY = None  # set to string if CPP_ADMIN_KEY is enforced


@dataclass
class User:
    email: str
    name: str
    token: str


def random_email() -> str:
    return "".join(random.choices(string.ascii_lowercase, k=10)) + "@example.com"


def random_timestamp_iso() -> str:
    now = datetime.now(timezone.utc)
    delta = timedelta(seconds=random.randint(0, 30 * 24 * 60 * 60))
    ts = now - delta
    return ts.isoformat(timespec="seconds").replace("+00:00", "Z")


def post(path: str, payload: Dict, token: str = "") -> Dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.post(f"{BASE}{path}", headers=headers, data=json.dumps(payload), timeout=5)
    resp.raise_for_status()
    return resp.json()


def get(path: str, token: str = "", headers: Dict = None) -> Dict:
    headers = headers or {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = requests.get(f"{BASE}{path}", headers=headers, timeout=5)
    resp.raise_for_status()
    return resp.json()


def create_users(n: int = 100) -> List[User]:
    users: List[User] = []
    for i in range(n):
        email = random_email()
        name = f"User {i}"
        password = "pass1234"
        data = post("/auth/register", {"email": email, "name": name, "password": password})
        users.append(User(email=email, name=name, token=data["accessToken"]))
    return users


def fetch_all_users(admin_token: str) -> List[str]:
    headers = {"Authorization": f"Bearer {admin_token}"}
    if ADMIN_KEY:
        headers["x-admin-key"] = ADMIN_KEY
    data = get("/admin/users", headers=headers)
    return [u["email"] for u in data]


def random_tx(direction: str, counterparty: str = "") -> Dict:
    base = {
        "direction": direction,
        "time": random_timestamp_iso(),
        "amount": round(random.uniform(1, 1000), 2),
    }
    if direction == "inbound":
        base["source"] = counterparty or ("acct-" + "".join(random.choices(string.digits, k=8)))
    else:
        base["destination"] = counterparty or ("acct-" + "".join(random.choices(string.digits, k=8)))
    return base


def main():
    users = create_users(100)
    print(f"Created {len(users)} users.")

    # Use first user as admin token for admin endpoints (same token format).
    admin_token = users[0].token
    all_emails = fetch_all_users(admin_token)
    print(f"Fetched {len(all_emails)} users via admin endpoint.")

    for _ in range(1000):
        u = random.choice(users)
        direction = random.choice(["inbound", "outbound"])
        counterparty = random.choice(all_emails) if all_emails else ""
        post("/transfer", random_tx(direction, counterparty), token=u.token)

    summary = []
    top_user = None
    top_total = -1
    top_record = {}
    for u in users:
        rec = get("/record", token=u.token)
        inbound_ct = len(rec.get("inbound", []))
        outbound_ct = len(rec.get("outbound", []))
        total = inbound_ct + outbound_ct
        summary.append({"email": u.email, "inbound": inbound_ct, "outbound": outbound_ct, "total": total})
        if total > top_total:
            top_total = total
            top_user = u
            top_record = rec
    summary.sort(key=lambda x: x["email"])

    counts_path = OUT_DIR / "txn_counts.json"
    counts_path.write_text(json.dumps(summary, indent=2))

    if top_user:
        rec = get("/record", token=top_user.token)
        balance = sum(tx.get("amount", 0) for tx in rec.get("inbound", [])) - sum(
            tx.get("amount", 0) for tx in rec.get("outbound", [])
        )
        top_path = OUT_DIR / "top_user_record.json"
        top_path.write_text(
            json.dumps(
                {
                    "email": top_user.email,
                    "inbound": rec.get("inbound", []),
                    "outbound": rec.get("outbound", []),
                    "balance": balance,
                },
                indent=2,
            )
        )
        print(f"Saved counts to {counts_path} and top user record to {top_path}")
    else:
        print("No users found to summarize.")


if __name__ == "__main__":
    main()
