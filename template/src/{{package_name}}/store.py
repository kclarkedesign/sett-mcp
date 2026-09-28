"""A tiny contacts store so the template runs with no external service.

Replace this module with a client for your real system (Salesforce, QuickBooks, an
internal API). The tools in tools.py only need the methods below.
"""

from __future__ import annotations

import json
import uuid
from importlib import resources
from pathlib import Path
from typing import Any

Contact = dict[str, Any]


class ContactNotFound(LookupError):
    pass


class ContactStore:
    def __init__(self, contacts: list[Contact], path: Path | None = None) -> None:
        self._contacts = {c["id"]: c for c in contacts}
        self._path = path

    @classmethod
    def open(cls, package: str, path: Path | None = None) -> ContactStore:
        """Load from `path` if it exists, otherwise from the bundled sample data.

        With a `path`, changes are saved back to it; without one they live in memory.
        """
        if path and path.exists():
            text = path.read_text()
        else:
            text = resources.files(package).joinpath("sample_contacts.json").read_text()
        return cls(json.loads(text), path)

    def search(self, query: str, limit: int) -> list[Contact]:
        q = query.lower()
        hits = [c for c in self._contacts.values() if q in " ".join(str(v) for v in c.values()).lower()]
        return hits[:limit]

    def get(self, contact_id: str) -> Contact:
        try:
            return self._contacts[contact_id]
        except KeyError:
            raise ContactNotFound(contact_id) from None

    def create(self, fields: dict[str, Any]) -> Contact:
        contact = {"id": uuid.uuid4().hex[:8], **fields}
        self._contacts[contact["id"]] = contact
        self._save()
        return contact

    def update(self, contact_id: str, fields: dict[str, Any]) -> Contact:
        contact = self.get(contact_id)
        contact.update(fields)
        self._save()
        return contact

    def delete(self, contact_id: str) -> Contact:
        contact = self.get(contact_id)
        del self._contacts[contact_id]
        self._save()
        return contact

    def _save(self) -> None:
        if self._path:
            self._path.write_text(json.dumps(list(self._contacts.values()), indent=2))
