import hashlib
import os

from sqlalchemy import func, select

from db import SessionLocal
from models import Document, Invoice, Order, User

USERS = [
    ("alice", "user"),
    ("bob", "user"),
    ("carol", "user"),
    ("dave", "user"),
    ("erin", "user"),
    ("admin", "admin"),
]
INVOICES_PER_USER = 30
ORDERS_PER_USER = 10
DOCUMENTS_PER_USER = 40


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + "$" + digest.hex()


def seed():
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(User)) > 0:
            return  # already seeded

        users = []
        for name, role in USERS:
            user = User(username=name, password_hash=hash_password(f"{name}-pass"), role=role)
            db.add(user)
            users.append(user)
        db.flush()  # assigns user IDs

        owners = [u for u in users if u.role == "user"]

        # Round-robin creation, so IDs are interleaved between owners
        for i in range(1, INVOICES_PER_USER + 1):
            for u in owners:
                db.add(Invoice(owner_id=u.id, amount_cents=1000 * i,
                               description=f"Invoice {i} of {u.username}"))
        for i in range(1, ORDERS_PER_USER + 1):
            for u in owners:
                db.add(Order(owner_id=u.id, item=f"item-{i}", quantity=i, status="shipped"))
        for i in range(1, DOCUMENTS_PER_USER + 1):
            for u in owners:
                db.add(Document(owner_id=u.id, title=f"Doc {i} of {u.username}",
                                content="Fake confidential content"))
        db.commit()