"""
Evidence indexer module.

Parses all evidence files (SQL, JSON, log, TXT) and builds a
searchable index mapping (user_id, email, hash) → list of resource records.

Each resource record contains:
  - evidence_id     : file_id from evidence_files.csv
  - system_id       : canonical system holding the record
  - resource_id     : record's unique ID within that system
  - data_category   : deletion rule category (USER_PROFILE, ANALYTICS_PROFILE, ...)
  - state           : PRESENT / ABSENT / ANONYMIZED / REDACTED / BLOCKED / DISABLED / ACTIVE
  - captured_at     : timestamp of the record snapshot
  - file_captured_at: timestamp of the evidence file from evidence_files.csv
  - identifiers     : set of identifier values linking this record to a person
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)

# Maps evidence system names → canonical system_id used in steps_json
_SYSTEM_ALIAS: dict[str, str] = {
    "account_service": "account_service",
    "account_failover_replica": "account_service",
    "account_replication_cluster": "account_service",
    "search_service": "search_service",
    "analytics_platform": "analytics_platform",
    "support_platform": "support_platform",
    "support_replica": "support_platform",
    "integration_service": "integration_service",
    "backup_service": "backup_service",
    "export_service": "export_service",
    "marketing_platform": "marketing_platform",
    "security_service": "security_service",
    "cache_service": "cache_service",
    "identity_service": "identity_service",
    "archive_service": "backup_service",
    "object_storage": "support_platform",
    "object_store": "support_platform",
    "email_delivery_service": "email_delivery_service",
    "legal_service": "legal_service",
    "privacy_case_management": "privacy_case_management",
}

# Maps system_id → deletion rule data_category
_SYSTEM_TO_CATEGORY: dict[str, str] = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE",
    "support_platform": "SUPPORT_MESSAGE",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "export_service": "USER_EXPORT",
    "marketing_platform": "MARKETING_PROFILE",
    "security_service": "SECURITY_AUDIT_LOG",
    "cache_service": "CACHE_ENTRY",
    "identity_service": "SECONDARY_IDENTIFIER",
    "object_storage": "SUPPORT_ATTACHMENT",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "legal_service": "LEGAL_HOLD_RECORD",
}


class ResourceRecord:
    """A single discovered resource potentially belonging to a user."""

    __slots__ = (
        "evidence_id",
        "system_id",
        "resource_id",
        "data_category",
        "state",
        "captured_at",
        "file_captured_at",
        "identifiers",
        "extra",
    )

    def __init__(
        self,
        evidence_id: str,
        system_id: str,
        resource_id: str,
        data_category: str,
        state: str,
        captured_at: str,
        file_captured_at: str,
        identifiers: set[str],
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.evidence_id = evidence_id
        self.system_id = system_id
        self.resource_id = resource_id
        self.data_category = data_category
        self.state = state
        self.captured_at = captured_at
        self.file_captured_at = file_captured_at
        self.identifiers = identifiers
        self.extra = extra or {}

    def __repr__(self) -> str:
        return (
            f"ResourceRecord({self.evidence_id} {self.system_id}/{self.resource_id}"
            f" {self.state} file_cap={self.file_captured_at})"
        )


class EvidenceIndexer:
    """Parses evidence files and builds a searchable resource index."""

    def __init__(self, dataset_dir: Path, evidence_files: list[dict[str, str]]) -> None:
        self.dataset_dir = dataset_dir
        self.evidence_files = evidence_files
        self._ev_meta: dict[str, dict[str, str]] = {
            r["file_id"]: r for r in evidence_files
        }
        self._all_records: list[ResourceRecord] = []
        self._id_index: dict[str, list[ResourceRecord]] = {}

    def build_index(self) -> None:
        """Parse all evidence files and populate the index."""
        for ev in self.evidence_files:
            fid = ev["file_id"]
            fpath = self.dataset_dir / ev["file_path"]
            captured_at = ev["captured_at"]
            if not fpath.exists():
                log.warning("Evidence file missing: %s", fpath)
                continue
            ext = fpath.suffix.lower()
            try:
                if ext == ".sql":
                    records = self._parse_sql(fid, fpath, captured_at)
                elif ext == ".json":
                    records = self._parse_json(fid, fpath, captured_at)
                elif ext == ".log":
                    records = self._parse_log(fid, fpath, captured_at)
                elif ext == ".txt":
                    records = self._parse_txt(fid, fpath, captured_at)
                else:
                    records = []
            except Exception as exc:
                log.warning("Error parsing %s (%s): %s", fpath, fid, exc)
                records = []

            self._all_records.extend(records)
            for rec in records:
                for ident in rec.identifiers:
                    key = ident.lower().strip()
                    if key:
                        self._id_index.setdefault(key, []).append(rec)

        log.info(
            "EvidenceIndexer: %d records, %d identifier keys",
            len(self._all_records),
            len(self._id_index),
        )

    def find_records_for_user(
        self,
        user_id: str,
        all_emails: set[str],
        all_hashes: set[str] | str | None = None,
        audit_at: Optional[str] = None,
    ) -> list[ResourceRecord]:
        """Return all records linked to a user via any identifier, filtered by audit_at."""
        found: dict[str, ResourceRecord] = {}
        keys: set[str] = set()
        keys.add(user_id.lower())
        for email in all_emails:
            keys.add(email.lower())
        if all_hashes:
            if isinstance(all_hashes, str):
                keys.add(all_hashes.lower())
            else:
                for h in all_hashes:
                    keys.add(h.lower())

        for key in keys:
            for rec in self._id_index.get(key, []):
                # Cutoff enforcement: do not use evidence captured after audit_at
                if audit_at:
                    if rec.file_captured_at > audit_at or rec.captured_at > audit_at:
                        continue
                rec_key = f"{rec.evidence_id}:{rec.system_id}:{rec.resource_id}"
                if rec_key not in found:
                    found[rec_key] = rec
        return list(found.values())

    def get_evidence_meta(self, evidence_id: str) -> dict[str, str]:
        return self._ev_meta.get(evidence_id, {})

    # ──────────────────────────────────────────────────────────────
    # Parsers
    # ──────────────────────────────────────────────────────────────

    def _parse_sql(
        self, evidence_id: str, fpath: Path, captured_at: str
    ) -> list[ResourceRecord]:
        """Parse SQLite-compatible SQL snapshot files."""
        records: list[ResourceRecord] = []
        content = fpath.read_text(encoding="utf-8", errors="replace")
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        try:
            conn.executescript(content)
        except Exception as exc:
            log.warning("SQL parse error in %s: %s", fpath.name, exc)
            conn.close()
            return records

        tables = [
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]

        for table in tables:
            if table == "snapshot_scope":
                continue
            try:
                rows = conn.execute(f"SELECT * FROM {table}").fetchall()
            except Exception:
                continue

            for row in rows:
                row_dict = dict(row)
                recs = self._sql_row_to_records(
                    evidence_id, captured_at, table, row_dict
                )
                records.extend(recs)

        conn.close()
        return records

    def _sql_row_to_records(
        self,
        evidence_id: str,
        captured_at: str,
        table: str,
        row: dict[str, Any],
    ) -> list[ResourceRecord]:
        """Convert a SQL table row to ResourceRecord(s), handling JSON payloads and flat rows."""
        # Case A: Tables with JSON record column (e.g. record_json, payload, document)
        json_col = None
        for cand in ("record_json", "payload", "document"):
            if cand in row and row[cand]:
                json_col = cand
                break

        if json_col:
            val = row[json_col]
            if isinstance(val, str):
                try:
                    doc = json.loads(val)
                except Exception:
                    doc = {}
            elif isinstance(doc, dict):
                doc = val
            else:
                doc = {}

            resource_id = doc.get("resource_id") or row.get("resource_id", "")
            if not resource_id:
                return []

            origin_sys = (
                row.get("origin_system")
                or doc.get("origin_system")
                or doc.get("system_id")
                or ""
            )
            collection = (
                row.get("collection_name")
                or doc.get("collection_name")
                or table
            )

            # Guess system from origin_sys or collection
            if origin_sys:
                system_id = _SYSTEM_ALIAS.get(origin_sys, origin_sys)
            else:
                system_id = self._guess_system_from_collection(collection, resource_id)

            data_category = self._category_from_collection_or_id(
                collection, resource_id, system_id
            )

            identifiers: set[str] = set()
            for f in ("customer_reference", "user_id", "subject_reference", "owner_reference"):
                v = doc.get(f) or row.get(f)
                if v:
                    identifiers.add(str(v).strip())
            for f in ("email", "owner_email", "requester_email", "customer_email"):
                v = doc.get(f) or row.get(f)
                if v:
                    identifiers.add(str(v).strip().lower())
            for f in ("email_hash",):
                v = doc.get(f) or row.get(f)
                if v:
                    identifiers.add(str(v).strip().lower())

            # Check inside nested document dict if any
            inner_doc = doc.get("document", {})
            if isinstance(inner_doc, dict):
                for f in ("customer_reference", "user_id"):
                    v = inner_doc.get(f)
                    if v:
                        identifiers.add(str(v).strip())
                for f in ("email", "display_name"):
                    v = inner_doc.get(f)
                    if v:
                        identifiers.add(str(v).strip().lower())

            if not identifiers:
                return []

            # Infer state
            state = self._infer_state_from_record(system_id, doc)
            rec_updated_at = (
                row.get("updated_at")
                or doc.get("updated_at")
                or doc.get("captured_at")
                or captured_at
            )

            return [
                ResourceRecord(
                    evidence_id=evidence_id,
                    system_id=system_id,
                    resource_id=str(resource_id),
                    data_category=data_category,
                    state=state,
                    captured_at=rec_updated_at,
                    file_captured_at=captured_at,
                    identifiers=identifiers,
                    extra=doc,
                )
            ]

        # Case B: search_documents_primary table
        if table == "search_documents_primary":
            resource_id = row.get("resource_id", "")
            if not resource_id:
                return []
            identifiers = set()
            if row.get("email"):
                identifiers.add(str(row["email"]).strip().lower())
            if not identifiers:
                return []
            return [
                ResourceRecord(
                    evidence_id=evidence_id,
                    system_id="search_service",
                    resource_id=str(resource_id),
                    data_category="SEARCH_INDEX_ENTRY",
                    state="PRESENT",
                    captured_at=row.get("indexed_at") or captured_at,
                    file_captured_at=captured_at,
                    identifiers=identifiers,
                    extra=row,
                )
            ]

        # Case C: Standard inventory tables (customer_profiles, customer_search_documents, etc.)
        resource_id = row.get("resource_id", "")
        if not resource_id:
            return []

        identifiers = set()
        for field in ("customer_reference", "subject_reference", "user_id", "owner_reference"):
            val = row.get(field)
            if val:
                identifiers.add(str(val).strip())
        for field in ("email", "owner_email", "requester_email", "customer_email"):
            val = row.get(field)
            if val:
                identifiers.add(str(val).strip().lower())
        for field in ("email_hash",):
            val = row.get(field)
            if val:
                identifiers.add(str(val).strip().lower())

        if not identifiers:
            return []

        system_id, data_category, state = self._classify_flat_sql_row(table, row)
        if not system_id:
            return []

        rec_updated_at = row.get("updated_at") or captured_at

        return [
            ResourceRecord(
                evidence_id=evidence_id,
                system_id=system_id,
                resource_id=str(resource_id),
                data_category=data_category,
                state=state,
                captured_at=rec_updated_at,
                file_captured_at=captured_at,
                identifiers=identifiers,
                extra=row,
            )
        ]

    def _guess_system_from_collection(self, collection: str, resource_id: str) -> str:
        col = collection.lower()
        if "profile" in col:
            return "account_service"
        if "search" in col:
            return "search_service"
        if "analytics" in col:
            return "analytics_platform"
        if "support" in col:
            return "support_platform"
        if "export" in col:
            return "export_service"
        if "connector" in col:
            return "integration_service"
        if "backup" in col:
            return "backup_service"
        if "security" in col or "audit" in col:
            return "security_service"
        return self._guess_system_from_resource_id(resource_id)

    def _category_from_collection_or_id(
        self, collection: str, resource_id: str, system_id: str
    ) -> str:
        rid = resource_id.lower()
        if rid.startswith("tombstone_"):
            return "ACCOUNT_TOMBSTONE"
        if "attachment" in collection.lower() or "attachment" in rid:
            return "SUPPORT_ATTACHMENT"
        return _SYSTEM_TO_CATEGORY.get(system_id, "USER_PROFILE")

    def _classify_flat_sql_row(
        self, table: str, row: dict[str, Any]
    ) -> tuple[str, str, str]:
        """Return (system_id, data_category, state) from a flat inventory table row."""
        t = table.lower()
        if "customer_profiles" in t:
            status = str(row.get("account_status", "")).upper()
            if status in ("ACTIVE", "DELETION_PENDING"):
                state = "PRESENT"
            elif "TOMB" in status:
                state = "PRESENT"
            elif status in ("DELETED", "NOT_FOUND"):
                state = "ABSENT"
            else:
                state = "PRESENT"
            return "account_service", "USER_PROFILE", state

        if "search" in t:
            return "search_service", "SEARCH_INDEX_ENTRY", "PRESENT"

        if "analytics" in t:
            has_pii = any(
                row.get(f) for f in ("email", "phone", "email_hash", "customer_reference")
            )
            state = "PRESENT" if has_pii else "ANONYMIZED"
            return "analytics_platform", "ANALYTICS_PROFILE", state

        if "support" in t:
            has_pii = any(
                row.get(f) for f in ("requester_email", "requester_name", "requester_phone")
            )
            state = "PRESENT" if has_pii else "REDACTED"
            return "support_platform", "SUPPORT_MESSAGE", state

        if "export" in t:
            return "export_service", "USER_EXPORT", "PRESENT"

        if "connector" in t:
            en = row.get("enabled")
            state = "ACTIVE" if (en == 1 or en is True or str(en).lower() == "true") else "DISABLED"
            return "integration_service", "DATA_FLOW", state

        if "backup" in t:
            ra = row.get("restore_allowed")
            state = "ACTIVE" if (ra == 1 or ra is True or str(ra).lower() == "true") else "BLOCKED"
            return "backup_service", "BACKUP_ARCHIVE", state

        if "security" in t or "audit" in t:
            return "security_service", "SECURITY_AUDIT_LOG", "PRESENT"

        return "", "", ""

    def _parse_json(
        self, evidence_id: str, fpath: Path, captured_at: str
    ) -> list[ResourceRecord]:
        """Parse JSON evidence files (snapshot bundles, exports, etc.)."""
        records: list[ResourceRecord] = []
        content = fpath.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            log.warning("JSON parse error in %s: %s", fpath.name, exc)
            return records

        # Format 1: {"snapshots": [...]} - customer_data_snapshot_bundle
        if isinstance(data, dict) and "snapshots" in data:
            for snap in data["snapshots"]:
                system = snap.get("data_store", "")
                collection = snap.get("collection", "")
                snap_at = snap.get("captured_at", captured_at)
                for record in snap.get("records", []):
                    rec = self._json_snapshot_record(
                        evidence_id, system, collection, snap_at, captured_at, record
                    )
                    if rec:
                        records.append(rec)

        # Format 2: {"service_exports": {...}} - service_resource_export
        elif isinstance(data, dict) and "service_exports" in data:
            for service_name, service_data in data["service_exports"].items():
                if isinstance(service_data, dict):
                    for collection_name, items in service_data.items():
                        if isinstance(items, list):
                            for item in items:
                                rec = self._json_export_record(
                                    evidence_id, service_name, collection_name,
                                    captured_at, item
                                )
                                if rec:
                                    records.append(rec)

        # Format 3: {"records": [...]}
        elif isinstance(data, dict) and "records" in data:
            for item in data["records"]:
                if isinstance(item, dict):
                    rec = self._json_flat_record(evidence_id, captured_at, item)
                    if rec:
                        records.append(rec)

        # Format 4: {"entries": [...]}
        elif isinstance(data, dict) and "entries" in data:
            for item in data["entries"]:
                rec = self._json_flat_record(evidence_id, captured_at, item)
                if rec:
                    records.append(rec)

        # Format 5: JSON list
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rec = self._json_flat_record(evidence_id, captured_at, item)
                    if rec:
                        records.append(rec)

        return records

    def _json_snapshot_record(
        self,
        evidence_id: str,
        system: str,
        collection: str,
        captured_at: str,
        file_captured_at: str,
        record: dict[str, Any],
    ) -> ResourceRecord | None:
        """Parse a record from a snapshot bundle."""
        resource_id = record.get("resource_id", "")
        if not resource_id:
            return None

        identifiers: set[str] = set()
        for field in ("customer_reference", "user_id", "subject_reference"):
            val = record.get(field)
            if val:
                identifiers.add(str(val).strip())
        for field in ("email", "phone"):
            val = record.get(field)
            if val:
                identifiers.add(str(val).strip().lower())
        for field in ("email_hash",):
            val = record.get(field)
            if val:
                identifiers.add(str(val).strip().lower())

        doc = record.get("document", {})
        if isinstance(doc, dict):
            for field in ("email", "customer_reference", "display_name"):
                val = doc.get(field)
                if val:
                    identifiers.add(str(val).strip().lower())

        if not identifiers:
            return None

        system_id = _SYSTEM_ALIAS.get(system, system)
        if str(resource_id).lower().startswith("tombstone_"):
            system_id = "identity_service"
            data_category = "ACCOUNT_TOMBSTONE"
        else:
            data_category = _SYSTEM_TO_CATEGORY.get(system_id, "USER_PROFILE")

        state = self._infer_state_from_record(system_id, record)

        return ResourceRecord(
            evidence_id=evidence_id,
            system_id=system_id,
            resource_id=str(resource_id),
            data_category=data_category,
            state=state,
            captured_at=captured_at,
            file_captured_at=file_captured_at,
            identifiers=identifiers,
            extra=record,
        )

    def _json_export_record(
        self,
        evidence_id: str,
        service_name: str,
        collection_name: str,
        captured_at: str,
        item: dict[str, Any],
    ) -> ResourceRecord | None:
        resource_id = item.get("resource_id", "")
        if not resource_id:
            return None

        identifiers: set[str] = set()
        for field in ("customer_reference", "user_id", "subject_reference", "owner_reference"):
            val = item.get(field)
            if val:
                identifiers.add(str(val).strip())
        for field in ("email", "owner_email", "customer_email", "requester_email"):
            val = item.get(field)
            if val:
                identifiers.add(str(val).strip().lower())
        for field in ("email_hash",):
            val = item.get(field)
            if val:
                identifiers.add(str(val).strip().lower())

        # Unpack nested profile if present (e.g. account_service profile_lookups)
        prof = item.get("profile")
        if isinstance(prof, dict):
            for field in ("customer_reference", "user_id"):
                v = prof.get(field)
                if v:
                    identifiers.add(str(v).strip())
            for field in ("email", "phone"):
                v = prof.get(field)
                if v:
                    identifiers.add(str(v).strip().lower())
            for field in ("email_hash",):
                v = prof.get(field)
                if v:
                    identifiers.add(str(v).strip().lower())

        # Unpack search query and hits (e.g. search_service index_queries)
        query = item.get("query")
        if query:
            identifiers.add(str(query).strip().lower())
        hits = item.get("hits")
        if isinstance(hits, dict):
            for d in hits.get("documents", []):
                if isinstance(d, dict):
                    for field in ("customer_reference", "user_id"):
                        v = d.get(field)
                        if v:
                            identifiers.add(str(v).strip())
                    for field in ("email", "phone"):
                        v = d.get(field)
                        if v:
                            identifiers.add(str(v).strip().lower())

        if not identifiers:
            return None

        system_id = _SYSTEM_ALIAS.get(service_name, service_name)
        data_category = _SYSTEM_TO_CATEGORY.get(system_id, "USER_PROFILE")

        # Specific state logic for exports
        if "profile" in item and "status_code" in item:
            sc = item.get("status_code")
            if sc == 404:
                state = "ABSENT"
            elif sc == 200:
                p = item.get("profile") or {}
                has_data = any(p.get(k) for k in ("email", "full_name", "customer_reference", "phone"))
                state = "PRESENT" if has_data else "ABSENT"
            else:
                state = "PRESENT"
        elif "hits" in item:
            h = item.get("hits") or {}
            total = h.get("total", 0)
            state = "PRESENT" if total > 0 else "ABSENT"
        else:
            state = self._infer_state_from_record(system_id, item)

        rec_updated_at = item.get("observed_at") or captured_at

        return ResourceRecord(
            evidence_id=evidence_id,
            system_id=system_id,
            resource_id=str(resource_id),
            data_category=data_category,
            state=state,
            captured_at=rec_updated_at,
            file_captured_at=captured_at,
            identifiers=identifiers,
            extra=item,
        )

    def _json_flat_record(
        self, evidence_id: str, captured_at: str, item: dict[str, Any]
    ) -> ResourceRecord | None:
        resource_id = item.get("resource_id", "")
        if not resource_id:
            return None

        identifiers: set[str] = set()
        for field in ("customer_reference", "user_id", "subject_reference", "owner_reference", "owner_id"):
            val = item.get(field)
            if val:
                identifiers.add(str(val).strip())
        for field in ("email", "owner_email", "customer_email", "requester_email"):
            val = item.get(field)
            if val:
                identifiers.add(str(val).strip().lower())
        for field in ("email_hash",):
            val = item.get(field)
            if val:
                identifiers.add(str(val).strip().lower())

        if not identifiers:
            return None

        system_id = self._guess_system_from_resource_id(str(resource_id))
        data_category = _SYSTEM_TO_CATEGORY.get(system_id, "USER_PROFILE")
        state = self._infer_state_from_record(system_id, item)

        return ResourceRecord(
            evidence_id=evidence_id,
            system_id=system_id,
            resource_id=str(resource_id),
            data_category=data_category,
            state=state,
            captured_at=captured_at,
            file_captured_at=captured_at,
            identifiers=identifiers,
            extra=item,
        )

    def _parse_log(
        self, evidence_id: str, fpath: Path, captured_at: str
    ) -> list[ResourceRecord]:
        """Parse log files with multi-line trace correlation."""
        records: list[ResourceRecord] = []
        content = fpath.read_text(encoding="utf-8", errors="replace")

        # Pass 1: Parse all lines into key-value dicts and build trace correlation
        parsed_lines: list[dict[str, str]] = []
        trace_to_ids: dict[str, set[str]] = {}

        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            kv: dict[str, str] = {}
            for m in re.finditer(r'(\w+)=([^\s"]+|"[^"]*")', line):
                k = m.group(1)
                v = m.group(2).strip('"')
                kv[k] = v

            trace_id = kv.get("trace_id", "")

            # Extract any identifiers on this line
            line_ids: set[str] = set()
            for field in (
                "lookup_key", "subject_key", "correlation_key", "matched_value",
                "customer_reference", "subject_reference", "customer_email",
                "requester_email", "email", "owner_email", "user_id"
            ):
                val = kv.get(field, "")
                if val and val != "null":
                    val_str = val.strip().lower()
                    if val_str:
                        line_ids.add(val_str)

            if trace_id and line_ids:
                trace_to_ids.setdefault(trace_id, set()).update(line_ids)

            kv["_line_ids"] = line_ids
            parsed_lines.append(kv)

        # Pass 2: For each line that references a resource_id, create record
        for kv in parsed_lines:
            event = kv.get("event", "")
            if event.endswith("_started"):
                continue

            resource_id = kv.get("resource_id", "")
            if not resource_id or resource_id == "null":
                continue

            trace_id = kv.get("trace_id", "")
            all_ids = set(kv.get("_line_ids", set()))
            if trace_id in trace_to_ids:
                all_ids.update(trace_to_ids[trace_id])

            if not all_ids:
                continue

            service = kv.get("service", "")
            system_id = _SYSTEM_ALIAS.get(service, service)
            if not system_id:
                system_id = self._guess_system_from_resource_id(resource_id)

            data_category = _SYSTEM_TO_CATEGORY.get(system_id, "USER_PROFILE")
            event = kv.get("event", "")
            state = self._state_from_log_event(event, kv, system_id)

            records.append(
                ResourceRecord(
                    evidence_id=evidence_id,
                    system_id=system_id,
                    resource_id=resource_id,
                    data_category=data_category,
                    state=state,
                    captured_at=captured_at,
                    file_captured_at=captured_at,
                    identifiers=all_ids,
                    extra=kv,
                )
            )

        return records

    def _state_from_log_event(
        self, event: str, kv: dict[str, str], system_id: str
    ) -> str:
        """Determine resource state from a log event."""
        if "profile_lookup" in event:
            rows = kv.get("rows", "1")
            http_status = kv.get("http_status", "200")
            if rows == "0" or http_status == "404":
                return "ABSENT"
            return "PRESENT"

        if "connector_config_read" in event or "connector_heartbeat" in event:
            enabled = kv.get("enabled", "true").lower()
            if enabled in ("false", "0"):
                return "DISABLED"
            return "ACTIVE"

        if "restore_policy_read" in event or "backup_catalog_read" in event:
            restore = kv.get("restore_allowed", "true").lower()
            if restore in ("false", "0"):
                return "BLOCKED"
            return "ACTIVE"

        if "index_query" in event:
            result = kv.get("result", "hit")
            if result == "miss":
                return "ABSENT"
            return "PRESENT"

        if "message_pii_scan" in event:
            # PII was detected
            return "PRESENT"

        if "support_ticket_read" in event or "contact_query" in event:
            req_email = kv.get("requester_email", "null")
            req_name = kv.get("requester_name", "null")
            rows = kv.get("rows", "1")
            if rows == "0":
                return "ABSENT"
            if req_email == "null" and req_name == "null":
                return "REDACTED"
            return "PRESENT"

        if "contact_lookup" in event:
            rows = kv.get("rows", "1")
            if rows == "0":
                return "ABSENT"
            return "PRESENT"

        if "deletion_marker_check" in event:
            marker = kv.get("marker_found", "true").lower()
            if marker == "false":
                return "PRESENT"
            return "ABSENT"

        if "audit_record_read" in event:
            return "PRESENT"

        return "PRESENT"

    def _parse_txt(
        self, evidence_id: str, fpath: Path, captured_at: str
    ) -> list[ResourceRecord]:
        """Parse TXT handover/summary files."""
        records: list[ResourceRecord] = []
        content = fpath.read_text(encoding="utf-8", errors="replace")

        pattern = re.compile(
            r"-\s+\S+\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(\S+)\s+\|\s+(.+)"
        )
        for line in content.split("\n"):
            m = pattern.match(line.strip())
            if not m:
                continue
            system_raw, resource_id, category, status, identifier = (
                m.group(1).strip(),
                m.group(2).strip(),
                m.group(3).strip(),
                m.group(4).strip(),
                m.group(5).strip(),
            )

            system_id = _SYSTEM_ALIAS.get(system_raw, system_raw)
            identifiers: set[str] = set()
            if identifier and identifier.lower() not in ("no direct identifier",):
                identifiers.add(identifier.lower())
            if not identifiers:
                continue

            state = self._state_from_txt_status(status, category)
            data_category = self._category_from_txt_category(category)

            records.append(
                ResourceRecord(
                    evidence_id=evidence_id,
                    system_id=system_id,
                    resource_id=resource_id,
                    data_category=data_category,
                    state=state,
                    captured_at=captured_at,
                    file_captured_at=captured_at,
                    identifiers=identifiers,
                )
            )
        return records

    def _state_from_txt_status(self, status: str, category: str) -> str:
        status = status.upper()
        if status in ("NOT_FOUND", "ABSENT", "DELETED"):
            return "ABSENT"
        if status in ("ANONYMIZED", "ANON"):
            return "ANONYMIZED"
        if status in ("REDACTED",):
            return "REDACTED"
        if status in ("BLOCKED",):
            return "BLOCKED"
        if status in ("DISABLED",):
            return "DISABLED"
        if status in ("ACTIVE",):
            if "DATA_FLOW" in category or "FLOW" in category:
                return "ACTIVE"
            return "PRESENT"
        return "PRESENT"

    def _category_from_txt_category(self, raw: str) -> str:
        mapping = {
            "USER_PROFILE": "USER_PROFILE",
            "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
            "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
            "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
            "DATA_FLOW": "DATA_FLOW",
            "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
            "USER_EXPORT": "USER_EXPORT",
            "MARKETING_PROFILE": "MARKETING_PROFILE",
            "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
            "CACHE_ENTRY": "CACHE_ENTRY",
            "SECONDARY_IDENTIFIER": "SECONDARY_IDENTIFIER",
            "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
            "EMAIL_DELIVERY_LOG": "EMAIL_DELIVERY_LOG",
            "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
            "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
        }
        return mapping.get(raw.upper(), raw)

    def _guess_system_from_resource_id(self, resource_id: str) -> str:
        rid = resource_id.lower()
        if rid.startswith("account_"):
            return "account_service"
        if rid.startswith("tombstone_"):
            return "identity_service"
        if rid.startswith("search_"):
            return "search_service"
        if rid.startswith("analytics_"):
            return "analytics_platform"
        if rid.startswith("support_") or rid.startswith("object_"):
            return "support_platform"
        if rid.startswith("data_flow_"):
            return "integration_service"
        if rid.startswith("backup_"):
            return "backup_service"
        if rid.startswith("export_"):
            return "export_service"
        if rid.startswith("marketing_"):
            return "marketing_platform"
        if rid.startswith("audit_record_"):
            return "security_service"
        if rid.startswith("cache_"):
            return "cache_service"
        return "unknown_service"

    def _infer_state_from_record(self, system_id: str, record: dict[str, Any]) -> str:
        resource_id = str(record.get("resource_id", "")).lower()

        status = str(record.get("account_status", "")).upper()
        if status in ("ACTIVE", "DELETION_PENDING"):
            return "PRESENT"
        if status in ("DELETED",):
            if resource_id.startswith("tombstone_"):
                has_pii = any(
                    record.get(f)
                    for f in ("name", "email", "phone", "email_hash")
                )
                return "PRESENT" if has_pii else "REDACTED"
            return "ABSENT"
        if "TOMBSTONE" in status:
            has_pii = any(
                record.get(f)
                for f in ("name", "email", "phone", "email_hash")
            )
            return "PRESENT" if has_pii else "REDACTED"

        if system_id == "analytics_platform":
            has_pii = any(
                record.get(f)
                for f in ("email", "phone", "email_hash", "user_id", "customer_reference")
            )
            return "PRESENT" if has_pii else "ANONYMIZED"

        if system_id == "support_platform":
            has_pii = any(
                record.get(f)
                for f in ("requester_name", "requester_email", "requester_phone", "email", "phone")
            )
            return "PRESENT" if has_pii else "REDACTED"

        enabled = record.get("enabled")
        if enabled is not None:
            if isinstance(enabled, str):
                return "ACTIVE" if enabled.lower() in ("true", "1") else "DISABLED"
            return "ACTIVE" if enabled else "DISABLED"

        restore = record.get("restore_allowed")
        if restore is not None:
            if isinstance(restore, str):
                return "ACTIVE" if restore.lower() in ("true", "1") else "BLOCKED"
            return "ACTIVE" if restore else "BLOCKED"

        dl = record.get("download_available")
        if dl is not None:
            return "PRESENT" if dl else "ABSENT"

        return "PRESENT"
