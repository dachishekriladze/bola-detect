import json
import random
from dataclasses import dataclass

KIND = {"invoice": "invoices", "order": "orders", "document": "documents"}


@dataclass(frozen=True)
class Policy:
    owners: dict
    admins: frozenset
    users: frozenset

    @classmethod
    def from_ownership(cls, ownership):
        owners = {}
        for object_type, key in KIND.items():
            for object_id, owner in ownership[key].items():
                owners[(object_type, object_id)] = owner
        people = ownership["users"].values()
        admins = frozenset(u["id"] for u in people if u["role"] == "admin")
        users = frozenset(u["id"] for u in people if u["role"] != "admin")
        return cls(owners, admins, users)

    @classmethod
    def from_file(cls, path):
        with open(path, encoding="utf-8") as f:
            return cls.from_ownership(json.load(f))

    def owner_of(self, object_type, object_id):
        return self.owners.get((object_type, object_id))

    def is_admin(self, user_id):
        return user_id in self.admins

    def without_objects(self, fraction, seed=0):
        rng = random.Random(seed)
        keys = sorted(self.owners)
        dropped = set(rng.sample(keys, round(len(keys) * fraction)))
        return Policy({k: v for k, v in self.owners.items() if k not in dropped},
                      self.admins, self.users)

    def with_wrong_owners(self, fraction, seed=0):
        rng = random.Random(seed)
        keys = sorted(self.owners)
        wrong = set(rng.sample(keys, round(len(keys) * fraction)))
        owners = dict(self.owners)
        for key in wrong:
            owners[key] = rng.choice(sorted(self.users - {owners[key]}))
        return Policy(owners, self.admins, self.users)