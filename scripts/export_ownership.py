"""Export who owns what from the lab database (the ownership table).

Used by the leak-based attackers now, and by the authorization-aware detector later.
Run after reset_lab.ps1 and before the traffic run:
    python scripts\\export_ownership.py datasets\\<name>\\ownership.json
"""
import json
import subprocess
import sys
from pathlib import Path


def query(sql):
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "db", "psql", "-U", "bola", "-d", "bola",
         "-At", "-F", ",", "-c", sql],
        check=True, capture_output=True, text=True,
    )
    return [line.split(",") for line in result.stdout.splitlines() if line]


data = {
    "users": {name: {"id": int(i), "role": role}
              for i, name, role in query("SELECT id, username, role FROM users")},
    "invoices": {i: int(o) for i, o in query("SELECT id, owner_id FROM invoices")},
    "orders": {i: int(o) for i, o in query("SELECT id, owner_id FROM orders")},
    "documents": {i: int(o) for i, o in query("SELECT id, owner_id FROM documents")},
}
out = Path(sys.argv[1])
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(data, indent=1), encoding="utf-8")
print({k: len(v) for k, v in data.items()}, "->", out)