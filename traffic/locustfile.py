"""Traffic generator for the bola-detect lab (Locust).

Every request carries a unique X-Request-ID, a simulated timestamp (X-Sim-Time)
and a per-user source IP (X-Lab-Source-IP). Ground truth goes to labels.csv.
Attack scenarios are only active when the ATTACKS environment variable lists them.
"""
import csv
import os
import random
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from locust import HttpUser, between, events, task

SPEEDUP = float(os.environ.get("SPEEDUP", "120"))  # 1 real second = 120 simulated seconds
SEED = int(os.environ.get("SEED", "1"))
LABELS_PATH = os.environ.get("LABELS_PATH", "datasets/labels.csv")
ATTACKS = {a.strip() for a in os.environ.get("ATTACKS", "").split(",") if a.strip()}
SIM_START = datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)

NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin"]
SOURCE_IPS = {
    "alice": "10.0.1.11", "bob": "10.0.1.12", "carol": "10.0.1.13",
    "dave": "10.0.1.14", "erin": "10.0.1.15", "admin": "10.0.9.1",
}
TOTAL_INVOICES = 150  # 5 users x 30 invoices, see seed.py

random.seed(SEED)
_state = {"start": None, "file": None, "writer": None}
_lock = threading.Lock()


def sim_now() -> datetime:
    return SIM_START + timedelta(seconds=(time.monotonic() - _state["start"]) * SPEEDUP)


def write_label(request_id, label, scenario, actor, sim_time, episode):
    with _lock:
        if _state["file"] and not _state["file"].closed:
            _state["writer"].writerow([request_id, label, scenario, actor, sim_time, episode])
            _state["file"].flush()


@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    os.makedirs(os.path.dirname(LABELS_PATH) or ".", exist_ok=True)
    _state["file"] = open(LABELS_PATH, "w", newline="", encoding="utf-8")
    _state["writer"] = csv.writer(_state["file"])
    _state["writer"].writerow(["request_id", "label", "scenario", "actor", "sim_time", "episode"])
    _state["start"] = time.monotonic()


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    with _lock:
        if _state["file"]:
            _state["file"].close()


class LabUser(HttpUser):
    abstract = True
    scenario = "unset"

    def on_start(self):
        self.client.headers["Connection"] = "close"  # avoid stale keep-alive connections
        self.username = self.pick_username()
        self.token = None
        self.episode = ""
        self.last_sim = datetime.min.replace(tzinfo=timezone.utc)
        self.login()
        self.refresh_my_objects()

    def pick_username(self):
        return random.choice(NORMAL_USERS)

    def call(self, method, path, name, scenario=None, expected=(200, 204), gap=None, **kwargs):
        request_id = str(uuid.uuid4())
        if gap is not None:  # inside a burst: simulated time advances by a small gap
            when = self.last_sim + timedelta(seconds=gap)
        else:
            when = max(sim_now(), self.last_sim + timedelta(milliseconds=1))
        self.last_sim = when
        headers = {
            "X-Request-ID": request_id,
            "X-Sim-Time": when.isoformat(),
            "X-Lab-Source-IP": SOURCE_IPS[self.username],
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        label = "attack" if self.episode else "normal"
        write_label(request_id, label, scenario or self.scenario, self.username,
                    headers["X-Sim-Time"], self.episode)
        with self.client.request(method, path, name=name, headers=headers,
                                 catch_response=True, **kwargs) as resp:
            if resp.status_code in expected:
                resp.success()
            else:
                resp.failure(f"unexpected status {resp.status_code}: {getattr(resp, 'error', None)}")
            return resp

    def login(self):
        resp = self.call("POST", "/login", "/login",
                         json={"username": self.username, "password": f"{self.username}-pass"})
        self.token = resp.json()["access_token"]

    def refresh_my_objects(self):
        self.my_invoices = [x["id"] for x in self.call("GET", "/invoices", "/invoices").json()]
        self.my_orders = [x["id"] for x in self.call("GET", "/orders", "/orders").json()]
        self.my_documents = [x["id"] for x in self.call("GET", "/documents", "/documents").json()]


class CasualUser(LabUser):
    weight = 12
    scenario = "casual"
    wait_time = between(2, 8)

    @task(6)
    def list_invoices(self):
        self.call("GET", "/invoices", "/invoices")

    @task(10)
    def view_own_invoice(self):
        self.call("GET", f"/invoices/{random.choice(self.my_invoices)}", "/invoices/{id}")

    @task(4)
    def list_orders(self):
        self.call("GET", "/orders", "/orders")

    @task(4)
    def view_own_order(self):
        self.call("GET", f"/orders/{random.choice(self.my_orders)}", "/orders/{id}")

    @task(2)
    def update_own_order(self):
        status = random.choice(["new", "shipped", "delivered"])
        self.call("PUT", f"/orders/{random.choice(self.my_orders)}", "/orders/{id}",
                  json={"status": status})

    @task(2)
    def update_own_invoice(self):
        self.call("PUT", f"/invoices/{random.choice(self.my_invoices)}", "/invoices/{id}",
                  json={"description": f"Updated {uuid.uuid4().hex[:6]}"})

    @task(4)
    def view_own_document(self):
        self.call("GET", f"/documents/{random.choice(self.my_documents)}", "/documents/{id}")

    @task(1)
    def typo_missing_id(self):
        # normal user mistypes an ID: a harmless 404, labeled normal on purpose
        self.call("GET", f"/invoices/{random.randint(1000, 9999)}", "/invoices/{id}",
                  scenario="typo_404", expected=(404,))


class PowerUser(CasualUser):
    weight = 1
    scenario = "power"

    @task(2)
    def read_many_own_invoices(self):
        # legitimate burst: many distinct IDs, but all of them the user's own
        ids = sorted(random.sample(self.my_invoices, k=random.randint(10, len(self.my_invoices))))
        self.call("GET", f"/invoices/{ids[0]}", "/invoices/{id}", scenario="power_burst")
        for invoice_id in ids[1:]:
            self.call("GET", f"/invoices/{invoice_id}", "/invoices/{id}",
                      scenario="power_burst", gap=random.uniform(0.3, 2.0))


class ExporterUser(LabUser):
    weight = 1
    scenario = "admin"
    wait_time = between(300, 600)  # rare: every 10-20 simulated hours

    def pick_username(self):
        return "admin"

    @task
    def export_invoices(self):
        # legitimate admin bulk export: consecutive IDs across all users
        start = random.randint(1, TOTAL_INVOICES - 59)
        count = random.randint(40, 60)
        self.call("GET", f"/invoices/{start}", "/invoices/{id}", scenario="admin_export")
        for invoice_id in range(start + 1, start + count):
            self.call("GET", f"/invoices/{invoice_id}", "/invoices/{id}",
                      scenario="admin_export", gap=random.uniform(0.1, 0.5))


# ---------------------------------------------------------------------------
# Attackers (inactive unless listed in the ATTACKS environment variable)
# ---------------------------------------------------------------------------

class AttackerUser(LabUser):
    abstract = True
    scenario = "attacker_idle"
    wait_time = between(120, 300)  # real seconds between attack episodes

    def on_start(self):
        super().on_start()
        time.sleep(random.uniform(60, 240))  # let normal traffic build some history first

    def start_episode(self, kind):
        self.episode = f"{kind}-{uuid.uuid4().hex[:8]}"
        self.scenario = f"attack_{kind}"

    def end_episode(self):
        self.episode = ""
        self.scenario = "attacker_idle"


if "sequential" in ATTACKS:

    class SequentialEnumerator(AttackerUser):
        fixed_count = 2

        @task
        def enumerate_invoices(self):
            self.start_episode("sequential")
            try:
                start = random.randint(1, TOTAL_INVOICES - 79)
                count = random.randint(40, 80)
                self.call("GET", f"/invoices/{start}", "/invoices/{id}")
                for invoice_id in range(start + 1, start + count):
                    self.call("GET", f"/invoices/{invoice_id}", "/invoices/{id}",
                              gap=random.uniform(0.05, 0.3))
            finally:
                self.end_episode()