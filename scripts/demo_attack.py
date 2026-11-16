import argparse
import json
import random
import time
import uuid

import requests

BASE = "http://127.0.0.1:8000"
SOURCE_IPS = {"alice": "10.0.1.11", "bob": "10.0.1.12", "carol": "10.0.1.13",
              "dave": "10.0.1.14", "erin": "10.0.1.15"}


class Client:
    def __init__(self, user):
        self.user = user
        self.session = requests.Session()
        self.session.headers["X-Lab-Source-IP"] = SOURCE_IPS[user]
        response = self.session.post(f"{BASE}/login", timeout=10,
                                     json={"username": user, "password": f"{user}-pass"})
        response.raise_for_status()
        self.session.headers["Authorization"] = f"Bearer {response.json()['access_token']}"

    def get(self, path):
        response = self.session.get(f"{BASE}{path}", timeout=10,
                                    headers={"X-Request-ID": str(uuid.uuid4())})
        print(f"{response.status_code} GET {path}")
        return response


def normal(client, args):
    invoices = [i["id"] for i in client.get("/invoices").json()]
    for invoice_id in random.sample(invoices, 8):
        client.get(f"/invoices/{invoice_id}")
        time.sleep(random.uniform(0.8, 2.0))
    orders = [o["id"] for o in client.get("/orders").json()]
    for order_id in random.sample(orders, 3):
        client.get(f"/orders/{order_id}")
        time.sleep(random.uniform(0.8, 2.0))


def sequential(client, args):
    start = random.randint(1, 150 - args.count)
    print(f"Enumerating invoices {start}..{start + args.count - 1} as {client.user}")
    for invoice_id in range(start, start + args.count):
        client.get(f"/invoices/{invoice_id}")
        time.sleep(random.uniform(0.05, 0.2))


def uuid_attack(client, args):
    with open(args.ownership, encoding="utf-8") as f:
        ownership = json.load(f)
    my_id = ownership["users"][client.user]["id"]
    targets = [d for d, owner in ownership["documents"].items() if owner != my_id]
    random.shuffle(targets)
    print(f"Reading {min(args.count, len(targets))} other users' documents as {client.user}")
    for document_id in targets[: args.count]:
        client.get(f"/documents/{document_id}")
        time.sleep(random.uniform(0.1, 0.3))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["normal", "sequential", "uuid"])
    parser.add_argument("--user", default="bob", choices=sorted(SOURCE_IPS))
    parser.add_argument("--count", type=int, default=45)
    parser.add_argument("--ownership", help="ownership export (needed for the uuid mode)")
    args = parser.parse_args()
    client = Client(args.user)
    {"normal": normal, "sequential": sequential, "uuid": uuid_attack}[args.mode](client, args)


if __name__ == "__main__":
    main()