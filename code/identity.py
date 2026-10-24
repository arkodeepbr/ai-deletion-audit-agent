"""
Identity resolution module.

Builds a mapping from any known email address (current or historical)
to the canonical user_id and full identity record, including historical
hashes and all known identifiers.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Optional

log = logging.getLogger(__name__)


class IdentityResolver:
    """Resolves email addresses (current or historical) to user identities."""

    def __init__(
        self,
        user_identities: list[dict[str, str]],
        user_audit_log: list[dict[str, str]],
    ) -> None:
        # email (lower) → user record
        self._email_to_user: dict[str, dict[str, str]] = {}
        # user_id → user record
        self._uid_to_user: dict[str, dict[str, str]] = {}
        # user_id → set of all known emails (current + historical)
        self._uid_to_all_emails: dict[str, set[str]] = {}
        # user_id → set of all known hashes (current + historical + computed sha256)
        self._uid_to_all_hashes: dict[str, set[str]] = {}

        self._build(user_identities, user_audit_log)

    def _build(
        self,
        identities: list[dict[str, str]],
        audit_log: list[dict[str, str]],
    ) -> None:
        # Index current identities
        for u in identities:
            uid = u["user_id"]
            email = u["email"].strip().lower()
            self._uid_to_user[uid] = u
            self._email_to_user[email] = u
            self._uid_to_all_emails.setdefault(uid, set()).add(email)
            
            eh = u.get("email_hash", "").strip().lower()
            if eh:
                self._uid_to_all_hashes.setdefault(uid, set()).add(eh)
            # Compute sha256 of email
            sha = hashlib.sha256(email.encode("utf-8")).hexdigest()
            self._uid_to_all_hashes.setdefault(uid, set()).add(sha)

        # Add historical emails and hashes from audit log
        for entry in audit_log:
            uid = entry["user_id"]
            field = entry.get("field_name")
            if field == "email":
                old_email = entry.get("old_value", "").strip().lower()
                new_email = entry.get("new_value", "").strip().lower()
                for email in (old_email, new_email):
                    if email:
                        self._uid_to_all_emails.setdefault(uid, set()).add(email)
                        if email not in self._email_to_user and uid in self._uid_to_user:
                            self._email_to_user[email] = self._uid_to_user[uid]
                        sha = hashlib.sha256(email.encode("utf-8")).hexdigest()
                        self._uid_to_all_hashes.setdefault(uid, set()).add(sha)
            elif field == "email_hash":
                old_h = entry.get("old_value", "").strip().lower()
                new_h = entry.get("new_value", "").strip().lower()
                for h in (old_h, new_h):
                    if h:
                        self._uid_to_all_hashes.setdefault(uid, set()).add(h)

        log.info(
            "IdentityResolver: %d unique emails → %d users",
            len(self._email_to_user),
            len(self._uid_to_user),
        )

    def resolve_email(self, email: str) -> Optional[dict[str, str]]:
        """Resolve an email to its user record (current or historical match)."""
        return self._email_to_user.get(email.strip().lower())

    def resolve_uid(self, uid: str) -> Optional[dict[str, str]]:
        """Resolve a user_id to its user record."""
        return self._uid_to_user.get(uid)

    def all_emails_for_user(self, uid: str) -> set[str]:
        """Return all known emails for a user_id (current + historical)."""
        return set(self._uid_to_all_emails.get(uid, set()))

    def all_hashes_for_user(self, uid: str) -> set[str]:
        """Return all known email hashes for a user_id (current + historical + computed)."""
        return set(self._uid_to_all_hashes.get(uid, set()))

    def email_hash_for_user(self, uid: str) -> Optional[str]:
        """Return the primary email_hash for a user_id."""
        u = self._uid_to_user.get(uid)
        return u["email_hash"] if u else None
