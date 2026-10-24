"""
Deletion audit module.

For each deletion request:
1. Determine if the request actually authorizes deletion (NOT_APPLICABLE check)
2. Resolve the requestor's identity (current and historical)
3. Find all evidence records linked to that identity
4. Apply deletion_rules.csv to each record
5. Cross-reference with system_activity for additional context
6. Classify the overall deletion status
7. Build the ordered steps_json array
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from typing import Any, Optional

from identity import IdentityResolver
from evidence_indexer import EvidenceIndexer, ResourceRecord

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Keyword patterns for NOT_APPLICABLE detection
# These indicate requests that do NOT authorize deletion
# ──────────────────────────────────────────────────────────────────────────────
# Non-deletion patterns: only match when the request is PURELY about something else
# Use conservative matching - only clear non-deletion activities
_NON_DELETION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bsubject\s*access\s*request\b",
        r"\bdata\s*access\s*request\b",
        r"\bsar\b",  # Subject Access Request abbreviation
        r"\bwhat\s*data\s*(do\s*you\s*(hold|have)|you\s*have|have\s*you)\b",
        r"\bopt[\s-]?out\s*of\s*(marketing|email\s*marketing|newsletter)\b",
        r"\bdo\s*not\s*sell\s*my\b",
        r"\bpassword\s*reset\b",
        r"\bchange\s*(my\s*)?password\b",
    ]
]

# Deletion patterns: any of these in the text indicates a deletion request
_DELETION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bdelet(e|ion|ed|ing)\b",
        r"\berase(d|\b)",
        r"\berasing\b",
        r"\bremov(e|al|ed|ing)\b.*\b(account|data|profile|personal|record)\b",
        r"\b(account|data|profile|personal)\b.*\bremov(e|al|ed|ing)\b",
        r"\bclose\s*(my\s*)?account\b",
        r"\bclosing\s*(my\s*)?account\b",
        r"\bdisconnect(ed)?\s*(my\s*)?account\b",
        r"\bwipe(d)?\b.*\b(data|account)\b",
        r"\bforget\s*me\b",
        r"\bright\s*to\s*(be\s*forgotten|erasure)\b",
        r"\bpermanently\s*(delete|remove|erase|wipe)\b",
        r"\brtbf\b",
        r"\bsuppression\b",  # French: deletion
        r"\bsupprimer\b",  # French: to delete
        r"\bsupprim(er|é|ée|ez)\b",  # French conjugations
        r"\beliminar\b",  # Spanish: to eliminate
        r"\bborrar\b",  # Spanish: to erase
        r"\bgelöscht\b",  # German: deleted
        r"\blöschen\b",  # German: to delete
        r"\beffacer\b",  # French: to erase
        r"\bexcluir\b",  # Portuguese: to delete
        r"削除",  # Japanese: delete (no \b)
        r"消去",  # Japanese: erase (no \b)
        r"삭제",  # Korean: delete (no \b)
        r"파기",  # Korean: destroy (no \b)
        r"删除",  # Chinese: delete (no \b)
        r"抹掉",  # Chinese: erase (no \b)
        r"\bprivacy\s*(page|request|procedure|proc[eé]dure)\b",  # indicates privacy process
        r"\bgone\b.*\bprofile\b",
        r"\bprofile\b.*\bgone\b",
        r"\bremaining\s*(copy|data|record)\b",
        r"\bhandle\s*(any\s*copies|them)\b",
        r"\bfully\s*(delete|remove|erase)\b",
        r"\b(confirm|verify)\s*(that|the)\s*(account|profile|data)\b.*\b(deleted|removed|gone|absent|erased)\b",
        r"\b(deleted|removed|erased)\s*(account|profile|data)\b",
        r"\bno\s*(longer|more)\s*(identify|identif)\b",
        r"\bcan\s*no\s*longer\s*send\s*my\s*data\b",
        r"\bnot\s*be\s*able\s*to\s*restore\b",
        r"\bcannot\s*(identify|link|trace)\s*me\b",
        r"\bdisable\s*(any\s*)?sync(hronization)?\b",
        r"\bdisable.*integration\b",
        r"\bintegration.*still.*active\b",
    ]
]

# ──────────────────────────────────────────────────────────────────────────────
# Phase ordering as per problem statement:
# FINDING: REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW,
#          REPORT_RESTORE_RISK
# REMEDIATION: DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD, REDACT_RECORD,
#              ANONYMIZE_RECORD
# VERIFICATION: VERIFY_RECORD_ABSENT, VERIFY_RECORD_PRESENT,
#               VERIFY_RECORD_REDACTED, VERIFY_RECORD_ANONYMIZED,
#               VERIFY_DATA_FLOW_DISABLED, VERIFY_RESTORE_BLOCKED
# ──────────────────────────────────────────────────────────────────────────────
_FINDING_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]
_REMEDIATION_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]
_VERIFICATION_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]
_OP_FINDING_RANK = {op: i for i, op in enumerate(_FINDING_ORDER)}
_OP_REMEDIATION_RANK = {op: i for i, op in enumerate(_REMEDIATION_ORDER)}
_OP_VERIFICATION_RANK = {op: i for i, op in enumerate(_VERIFICATION_ORDER)}


def _sort_key(step: dict[str, Any]) -> tuple:
    phase = step["phase"]
    op = step["operation"]
    if phase == "FINDING":
        rank = _OP_FINDING_RANK.get(op, 99)
    elif phase == "REMEDIATION":
        rank = _OP_REMEDIATION_RANK.get(op, 99)
    else:
        rank = _OP_VERIFICATION_RANK.get(op, 99)
    return (rank, step.get("system_id", ""), step.get("resource_id", ""))


# ──────────────────────────────────────────────────────────────────────────────
# Deletion rule required actions
# ──────────────────────────────────────────────────────────────────────────────
_RULE_ACTION: dict[str, str] = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RETAIN",  # retain but block restore
    "DATA_FLOW": "DISABLE",  # not a standard rule but logical
    "ACCOUNT_TOMBSTONE": "REDACT",
}

_COMPLIANT_STATES: dict[str, set[str]] = {
    "DELETE": {"ABSENT"},
    "REDACT": {"REDACTED", "ABSENT"},
    "ANONYMIZE": {"ANONYMIZED", "ABSENT"},
    "RETAIN": {"PRESENT"},
    "DISABLE": {"DISABLED"},
    "BLOCK": {"BLOCKED"},
}


class DeletionAuditor:
    """Audits deletion status for a single deletion request."""

    def __init__(
        self,
        deletion_rules: list[dict[str, str]],
        system_activity: list[dict[str, str]],
        identity_resolver: IdentityResolver,
        ev_indexer: EvidenceIndexer,
    ) -> None:
        self.deletion_rules = {r["data_category"]: r for r in deletion_rules}
        self.system_activity = system_activity
        self.identity_resolver = identity_resolver
        self.ev_indexer = ev_indexer

        # Build activity index: resource_id → list of activities
        self._activity_by_resource: dict[str, list[dict]] = defaultdict(list)
        for act in system_activity:
            self._activity_by_resource[act["resource_id"]].append(act)

        # Build activity index: email/user_id mentioned in details
        self._classify_events: list[dict] = [
            a for a in system_activity if a["event_type"] == "CLASSIFY_REQUEST"
        ]
        # Resource IDs that were classified as non-deletion
        self._non_deletion_resources: set[str] = {
            a["resource_id"] for a in self._classify_events
        }

    def audit(self, request: dict[str, str]) -> dict[str, Any]:
        """Audit a single deletion request and return a result dict."""
        case_id = request["case_id"]
        email = request["email"].strip()
        requested_at = request["requested_at"]
        audit_at = request["audit_at"]
        request_text = request.get("request_text", "")

        # Step 1: Determine if this is a deletion request
        if not self._is_deletion_request(request_text):
            return {
                "case_id": case_id,
                "deletion_status": "NOT_APPLICABLE",
                "steps_json": [],
            }

        # Step 2: Resolve identity
        user = self.identity_resolver.resolve_email(email)
        if user is None:
            # Try to find the user via LINK_RESOURCE_IDENTITY events
            user = self._find_user_via_activity(email)

        if user is None:
            # No known user → may be a ghost account already cleaned up
            # Check system_activity for any DELETE events referencing this email
            return self._handle_unknown_user(case_id, email, audit_at)

        user_id = user["user_id"]
        all_emails = self.identity_resolver.all_emails_for_user(user_id)
        all_hashes = self.identity_resolver.all_hashes_for_user(user_id)

        # Step 3: Find all evidence records for this user at or before audit_at
        records = self.ev_indexer.find_records_for_user(
            user_id, all_emails, all_hashes, audit_at=audit_at
        )

        # Step 4: Also look for resources in system_activity (LINK_RESOURCE_IDENTITY)
        additional_resources = self._get_linked_resources(
            user_id, all_emails, audit_at
        )

        # Step 5: Determine status for each record
        findings: list[dict] = []
        remediations: list[dict] = []
        verifications: list[dict] = []
        is_incomplete = False

        # Process evidence records
        processed_rids: set[str] = set()
        # Key: (system_id, resource_id) → best record (most recent)
        best_records: dict[tuple, ResourceRecord] = {}
        for rec in records:
            key = (rec.system_id, rec.resource_id)
            existing = best_records.get(key)
            if existing is None or rec.captured_at > existing.captured_at:
                best_records[key] = rec

        for (system_id, resource_id), rec in best_records.items():
            result = self._evaluate_record(rec, audit_at)
            if result:
                f_steps, r_steps, v_steps, incomplete = result
                if incomplete:
                    is_incomplete = True
                findings.extend(f_steps)
                remediations.extend(r_steps)
                verifications.extend(v_steps)
                processed_rids.add(resource_id)

        # Process additional resources from activity (not found in evidence files)
        for res_info in additional_resources:
            rid = res_info["resource_id"]
            if rid in processed_rids:
                continue
            result = self._evaluate_activity_resource(res_info, audit_at)
            if result:
                f_steps, r_steps, v_steps, incomplete = result
                if incomplete:
                    is_incomplete = True
                findings.extend(f_steps)
                remediations.extend(r_steps)
                verifications.extend(v_steps)
                processed_rids.add(rid)

        # Step 6: If no evidence found but there was a deletion request,
        # check system_activity for the account resource
        if not findings and not verifications:
            account_result = self._check_account_from_activity(
                user_id, all_emails, audit_at
            )
            if account_result:
                f_steps, r_steps, v_steps, incomplete = account_result
                if incomplete:
                    is_incomplete = True
                findings.extend(f_steps)
                remediations.extend(r_steps)
                verifications.extend(v_steps)

        # Sort steps within each phase
        findings = sorted(findings, key=_sort_key)
        remediations = sorted(remediations, key=_sort_key)
        verifications = sorted(verifications, key=_sort_key)

        if is_incomplete:
            # For INCOMPLETE cases: future verification checks use empty evidence_id
            for v in verifications:
                v["evidence_id"] = ""
            for r in remediations:
                r["evidence_id"] = ""
            all_steps = findings + remediations + verifications
            status = "INCOMPLETE"
        else:
            # For COMPLETE cases: only evidence-backed verification checks
            all_steps = verifications
            status = "COMPLETE"

        for i, step in enumerate(all_steps, 1):
            step["step_no"] = i

        return {
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": all_steps,
        }

    # ──────────────────────────────────────────────────────────────
    # Request classification
    # ──────────────────────────────────────────────────────────────

    def _is_deletion_request(self, text: str) -> bool:
        """
        Return True if the request text authorizes deletion.

        Strategy: Be conservative about NOT_APPLICABLE.
        Only mark NOT_APPLICABLE when text is EXCLUSIVELY about something
        other than deletion (access request, opt-out, etc.) and contains
        NO deletion language whatsoever.

        When in doubt, treat as a deletion request to avoid false NOT_APPLICABLE.
        """
        if not text.strip():
            # Empty text - can't determine, treat as not applicable
            return False

        # First: check if text contains ANY deletion language
        has_deletion = any(p.search(text) for p in _DELETION_PATTERNS)
        if has_deletion:
            return True

        # Second: check if text is purely about something else (non-deletion)
        has_non_deletion = any(p.search(text) for p in _NON_DELETION_PATTERNS)
        if has_non_deletion:
            return False

        # Third: account/profile/data management language that's implicitly deletion
        # Phrases like "close account", "disconnect account", "verify deletion was done"
        implicit_patterns = [
            r"\baccount.*?(deleted|closed|removed|gone|erased)\b",
            r"\b(deleted|closed|removed|gone|erased).*?account\b",
            r"\bprofile.*?(deleted|gone|removed)\b",
            r"\b(inspect|audit|check|verify|confirm)\b.*?\b(actual|systems|remaining|traces|state)\b",
            r"\bstill.*?(active|exists?|found|present|recognized)\b",
            r"\btraces\b.*\b(in|across)\b",
            r"\bdisconnect(ed)?\b.*\baccount\b",
            r"\bforget.*me\b",
            r"\bmy.*data.*gone\b",
            r"\bgone.*data\b",
            r"\bno.*longer.*data\b",
        ]
        for pat in implicit_patterns:
            if re.search(pat, text, re.IGNORECASE):
                return True

        # Default: if text is about privacy/accounts without clear non-deletion context,
        # lean toward treating as deletion (conservative approach to avoid false NOT_APPLICABLE)
        account_related = re.search(
            r"\b(account|profile|data|privacy|personal)\b", text, re.IGNORECASE
        )
        if account_related:
            # If there's account-related language and no clear exclusion, assume deletion
            return True

        return False

    # ──────────────────────────────────────────────────────────────
    # Identity helpers
    # ──────────────────────────────────────────────────────────────

    def _find_user_via_activity(self, email: str) -> Optional[dict]:
        """Find user via LINK_RESOURCE_IDENTITY events mentioning the email."""
        email_lower = email.lower()
        for act in self.system_activity:
            if act["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            details = act.get("details", "")
            if email_lower in details.lower():
                # Extract user_id from details: "... to EMAIL and user_XX"
                m = re.search(r"user_(\d+)", details)
                if m:
                    uid = f"user_{m.group(1)}"
                    user = self.identity_resolver.resolve_uid(uid)
                    if user:
                        return user
        return None

    def _get_linked_resources(
        self, user_id: str, all_emails: set[str], audit_at: str
    ) -> list[dict]:
        """Get resource info from LINK_RESOURCE_IDENTITY events."""
        resources = []
        uid_lower = user_id.lower()
        emails_lower = {e.lower() for e in all_emails}

        for act in self.system_activity:
            if act["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            if act["event_time"] > audit_at:
                continue
            details = act.get("details", "").lower()
            if uid_lower not in details:
                found = False
                for email in emails_lower:
                    if email in details:
                        found = True
                        break
                if not found:
                    continue

            resource_id = act["resource_id"]
            system_id = self._guess_system_from_resource(resource_id, act)
            category = self._category_from_resource(resource_id, system_id)

            # Check the current state from evidence
            resources.append({
                "resource_id": resource_id,
                "system_id": system_id,
                "data_category": category,
                "activity_id": act["activity_id"],
                "details": act.get("details", ""),
            })
        return resources

    def _guess_system_from_resource(self, resource_id: str, act: dict) -> str:
        """Guess system_id from resource_id prefix or activity target."""
        target = act.get("target_system", "")
        if target:
            from evidence_indexer import _SYSTEM_ALIAS
            return _SYSTEM_ALIAS.get(target, target)
        return self.ev_indexer._guess_system_from_resource_id(resource_id)

    def _category_from_resource(self, resource_id: str, system_id: str) -> str:
        from evidence_indexer import _SYSTEM_TO_CATEGORY
        return _SYSTEM_TO_CATEGORY.get(system_id, "USER_PROFILE")

    # ──────────────────────────────────────────────────────────────
    # Record evaluation
    # ──────────────────────────────────────────────────────────────

    def _evaluate_record(
        self, rec: ResourceRecord, audit_at: str
    ) -> Optional[tuple]:
        """
        Evaluate a record against deletion policy.
        Returns (findings, remediations, verifications, is_incomplete) or None.
        """
        # Check system_activity for explicit planned operation on this resource
        act_op = None
        for act in self._activity_by_resource.get(rec.resource_id, []):
            if act["event_type"] in (
                "DELETE_RECORD", "ANONYMIZE_RECORD", "REDACT_RECORD",
                "DISABLE_DATA_FLOW", "BLOCK_RESTORE"
            ):
                act_op = act["event_type"]
                break

        if act_op == "DELETE_RECORD":
            required_action = "DELETE"
        elif act_op == "ANONYMIZE_RECORD":
            required_action = "ANONYMIZE"
        elif act_op == "REDACT_RECORD":
            required_action = "REDACT"
        elif act_op == "DISABLE_DATA_FLOW":
            required_action = "DISABLE"
        elif act_op == "BLOCK_RESTORE":
            required_action = "BLOCK"
        else:
            if rec.data_category == "DATA_FLOW":
                required_action = "DISABLE"
            elif rec.data_category == "ACCOUNT_TOMBSTONE":
                required_action = "REDACT"
            else:
                rule = self.deletion_rules.get(rec.data_category)
                if not rule:
                    return None
                required_action = rule["required_action"]

        state = rec.state

        # ── RETAIN rule ──
        if required_action == "RETAIN":
            # BACKUP_ARCHIVE is RETAIN but restore access must be blocked
            if rec.data_category == "BACKUP_ARCHIVE":
                if state in ("BLOCKED",):
                    return (
                        [],
                        [],
                        [self._step("VERIFY_RESTORE_BLOCKED", rec, rec.evidence_id)],
                        False,
                    )
                else:
                    # Restore is still possible - INCOMPLETE
                    return (
                        [self._step("REPORT_RESTORE_RISK", rec, rec.evidence_id)],
                        [self._step("BLOCK_RESTORE", rec, "")],
                        [self._step("VERIFY_RESTORE_BLOCKED", rec, "")],
                        True,
                    )
            # Security audit logs, legal holds - just verify retention
            return (
                [],
                [],
                [self._step("VERIFY_RECORD_PRESENT", rec, rec.evidence_id)],
                False,
            )

        # ── DELETE rule ──
        if required_action == "DELETE":
            if state == "ABSENT":
                return (
                    [],
                    [],
                    [self._step("VERIFY_RECORD_ABSENT", rec, rec.evidence_id)],
                    False,
                )
            else:
                # Record still exists — INCOMPLETE
                return (
                    [self._step("REPORT_REMAINING_RECORD", rec, rec.evidence_id)],
                    [self._step("DELETE_RECORD", rec, "")],
                    [self._step("VERIFY_RECORD_ABSENT", rec, "")],
                    True,
                )

        # ── REDACT rule ──
        if required_action == "REDACT":
            if state in ("ABSENT", "REDACTED"):
                op = "VERIFY_RECORD_ABSENT" if state == "ABSENT" else "VERIFY_RECORD_REDACTED"
                return ([], [], [self._step(op, rec, rec.evidence_id)], False)
            else:
                return (
                    [self._step("REPORT_EXPOSED_PII", rec, rec.evidence_id)],
                    [self._step("REDACT_RECORD", rec, "")],
                    [self._step("VERIFY_RECORD_REDACTED", rec, "")],
                    True,
                )

        # ── ANONYMIZE rule ──
        if required_action == "ANONYMIZE":
            if state in ("ABSENT", "ANONYMIZED"):
                op = "VERIFY_RECORD_ABSENT" if state == "ABSENT" else "VERIFY_RECORD_ANONYMIZED"
                return ([], [], [self._step(op, rec, rec.evidence_id)], False)
            else:
                return (
                    [self._step("REPORT_EXPOSED_PII", rec, rec.evidence_id)],
                    [self._step("ANONYMIZE_RECORD", rec, "")],
                    [self._step("VERIFY_RECORD_ANONYMIZED", rec, "")],
                    True,
                )

        # ── DATA_FLOW / DISABLE ──
        if rec.data_category == "DATA_FLOW":
            if state in ("DISABLED",):
                return (
                    [],
                    [],
                    [self._step("VERIFY_DATA_FLOW_DISABLED", rec, rec.evidence_id)],
                    False,
                )
            else:
                return (
                    [self._step("REPORT_ACTIVE_DATA_FLOW", rec, rec.evidence_id)],
                    [self._step("DISABLE_DATA_FLOW", rec, "")],
                    [self._step("VERIFY_DATA_FLOW_DISABLED", rec, "")],
                    True,
                )

        # ── BACKUP_ARCHIVE / RETAIN but block restore ──
        if rec.data_category == "BACKUP_ARCHIVE":
            if state in ("BLOCKED",):
                return (
                    [],
                    [],
                    [self._step("VERIFY_RESTORE_BLOCKED", rec, rec.evidence_id)],
                    False,
                )
            else:
                return (
                    [self._step("REPORT_RESTORE_RISK", rec, rec.evidence_id)],
                    [self._step("BLOCK_RESTORE", rec, "")],
                    [self._step("VERIFY_RESTORE_BLOCKED", rec, "")],
                    True,
                )

        return None

    def _evaluate_activity_resource(
        self, res_info: dict, audit_at: str
    ) -> Optional[tuple]:
        """
        Evaluate a resource found via system_activity LINK_RESOURCE_IDENTITY.
        Since we don't have direct evidence of its current state, we check
        system_activity for DELETE/ANONYMIZE events targeting this resource.
        """
        resource_id = res_info["resource_id"]
        system_id = res_info["system_id"]
        category = res_info["data_category"]
        activity_id = res_info["activity_id"]

        # Look for the latest relevant action on this resource
        relevant_acts = sorted(
            [
                a for a in self._activity_by_resource.get(resource_id, [])
                if a["event_time"] <= audit_at
            ],
            key=lambda a: a["event_time"],
            reverse=True,
        )

        rule_action = _RULE_ACTION.get(category, "DELETE")

        # Find the most recent definitive action
        final_state = None
        for act in relevant_acts:
            et = act["event_type"]
            rr = act["reported_result"]
            if rr == "SUCCESS":
                if et == "DELETE_RECORD":
                    final_state = "ABSENT"
                    break
                elif et == "ANONYMIZE_RECORD":
                    final_state = "ANONYMIZED"
                    break
                elif et == "REDACT_RECORD":
                    final_state = "REDACTED"
                    break
                elif et == "DISABLE_DATA_FLOW":
                    final_state = "DISABLED"
                    break
                elif et == "BLOCK_RESTORE":
                    final_state = "BLOCKED"
                    break

        # Build a synthetic ResourceRecord for step generation
        rec = _SyntheticRecord(
            evidence_id=activity_id,
            system_id=system_id,
            resource_id=resource_id,
            data_category=category,
            state=final_state or "PRESENT",
            captured_at=audit_at,
        )

        return self._evaluate_record(rec, audit_at)

    def _check_account_from_activity(
        self, user_id: str, all_emails: set[str], audit_at: str
    ) -> Optional[tuple]:
        """
        When no evidence records exist, check system_activity for account state.
        """
        # Look for account resource linked to this user
        account_rid = None
        for act in self.system_activity:
            if act["event_time"] > audit_at:
                continue
            if act["event_type"] != "DELETE_RECORD":
                continue
            details = act.get("details", "")
            rid = act["resource_id"]
            if not rid.startswith("account_"):
                continue
            if user_id in details:
                account_rid = rid
                break
            for email in all_emails:
                if email in details.lower():
                    account_rid = rid
                    break

        if not account_rid:
            return None

        # Find latest state
        relevant = sorted(
            [
                a for a in self._activity_by_resource.get(account_rid, [])
                if a["event_time"] <= audit_at
            ],
            key=lambda a: a["event_time"],
            reverse=True,
        )

        final_state = "PRESENT"
        evidence_act = ""
        for act in relevant:
            et = act["event_type"]
            rr = act["reported_result"]
            if et == "DELETE_RECORD" and rr == "SUCCESS":
                final_state = "ABSENT"
                evidence_act = act["activity_id"]
                break
            elif et == "DELETE_RECORD":
                final_state = "PRESENT"
                break

        rec = _SyntheticRecord(
            evidence_id=evidence_act,
            system_id="account_service",
            resource_id=account_rid,
            data_category="USER_PROFILE",
            state=final_state,
            captured_at=audit_at,
        )
        return self._evaluate_record(rec, audit_at)

    def _handle_unknown_user(
        self, case_id: str, email: str, audit_at: str
    ) -> dict:
        """Handle case where user cannot be identified."""
        # Check if there's a CLASSIFY_REQUEST for an account associated
        # with this email in system_activity
        for act in self.system_activity:
            if act["event_time"] > audit_at:
                continue
            if act["event_type"] != "CLASSIFY_REQUEST":
                continue
            details = act.get("details", "")
            if email.lower() in details.lower():
                return {
                    "case_id": case_id,
                    "deletion_status": "NOT_APPLICABLE",
                    "steps_json": [],
                }

        # Unknown user with no classification evidence — mark INCOMPLETE
        # with minimal steps indicating the account may need investigation
        return {
            "case_id": case_id,
            "deletion_status": "INCOMPLETE",
            "steps_json": [],
        }

    # ──────────────────────────────────────────────────────────────
    # Step builder
    # ──────────────────────────────────────────────────────────────

    def _step(
        self, operation: str, rec: "ResourceRecord | _SyntheticRecord", evidence_id: str
    ) -> dict[str, Any]:
        """Build a step dict (without step_no, which is assigned later)."""
        op_to_state = {
            "REPORT_REMAINING_RECORD": "PRESENT",
            "REPORT_EXPOSED_PII": "PRESENT",
            "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
            "REPORT_RESTORE_RISK": "ACTIVE",
            "DISABLE_DATA_FLOW": "DISABLED",
            "BLOCK_RESTORE": "BLOCKED",
            "DELETE_RECORD": "ABSENT",
            "REDACT_RECORD": "REDACTED",
            "ANONYMIZE_RECORD": "ANONYMIZED",
            "VERIFY_RECORD_ABSENT": "ABSENT",
            "VERIFY_RECORD_PRESENT": "PRESENT",
            "VERIFY_RECORD_REDACTED": "REDACTED",
            "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
            "VERIFY_RESTORE_BLOCKED": "BLOCKED",
        }
        op_to_phase = {
            "REPORT_REMAINING_RECORD": "FINDING",
            "REPORT_EXPOSED_PII": "FINDING",
            "REPORT_ACTIVE_DATA_FLOW": "FINDING",
            "REPORT_RESTORE_RISK": "FINDING",
            "DISABLE_DATA_FLOW": "REMEDIATION",
            "BLOCK_RESTORE": "REMEDIATION",
            "DELETE_RECORD": "REMEDIATION",
            "REDACT_RECORD": "REMEDIATION",
            "ANONYMIZE_RECORD": "REMEDIATION",
            "VERIFY_RECORD_ABSENT": "VERIFICATION",
            "VERIFY_RECORD_PRESENT": "VERIFICATION",
            "VERIFY_RECORD_REDACTED": "VERIFICATION",
            "VERIFY_RECORD_ANONYMIZED": "VERIFICATION",
            "VERIFY_DATA_FLOW_DISABLED": "VERIFICATION",
            "VERIFY_RESTORE_BLOCKED": "VERIFICATION",
        }

        return {
            "step_no": 0,  # assigned later
            "phase": op_to_phase[operation],
            "system_id": rec.system_id,
            "resource_id": rec.resource_id,
            "operation": operation,
            "state": op_to_state[operation],
            "evidence_id": evidence_id,
        }


class _SyntheticRecord:
    """Minimal record-like object for steps derived from system_activity."""

    def __init__(
        self,
        evidence_id: str,
        system_id: str,
        resource_id: str,
        data_category: str,
        state: str,
        captured_at: str,
    ) -> None:
        self.evidence_id = evidence_id
        self.system_id = system_id
        self.resource_id = resource_id
        self.data_category = data_category
        self.state = state
        self.captured_at = captured_at
