# Evaluation Report: Ghost Data Still Exists

## 1. Executive Summary & Validation Metrics

The deletion-audit agent was evaluated against the official public ground truth (`dataset/sample_output.csv`, 32 validation cases) and demonstrated **100.0% case-level deletion-status accuracy** with **zero dangerous false COMPLETE verdicts**.

### Accuracy Summary Table

| Metric | Score | Details |
|---|---|---|
| **Case-Level Deletion-Status Accuracy** | **100.0%** | **32 / 32 cases correct** |
| **False COMPLETE (Dangerous / Critical Risk)** | **0** | **0 / 32 (0.0%)** |
| **False INCOMPLETE** | **0** | **0 / 32 (0.0%)** |
| **Field-Level Step Accuracy** | **76.7%** | **598 / 780 fields matched** |
| **Sequence Accuracy** | **18.8%** | **6 / 32 exact sequences** |

### Confusion Matrix

| Ground Truth \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE |
|---|---|---|---|
| **COMPLETE** | **10** | 0 | 0 |
| **INCOMPLETE** | 0 | **22** | 0 |
| **NOT_APPLICABLE** | 0 | 0 | 0 |

---

## 2. Failures Found & Improvements Made

During iterative engineering and empirical error analysis against the sample dataset, seven critical failure modes were identified and resolved:

### 1. Multi-Line Distributed Trace Correlation in System Logs
- **Issue**: Distributed logging frameworks (e.g., in `support_replica.log` and `service_events_ap_south_20260915.log`) write multi-line log events sharing a `trace_id`. The initial line recorded the subject's identifier (`lookup_key` or `subject_key`) at `level=DEBUG`, while subsequent lines recorded the target `resource_id` (e.g., `support_002`, `data_flow_9846`) and operations. Single-line log parsers discarded DEBUG logs and could not associate the resource with the user.
- **Fix**: Implemented a two-pass trace-indexing parser in `EvidenceIndexer._parse_log`. Pass 1 aggregates all identifiers across any log level keyed by `trace_id`. Pass 2 propagates the discovered identities to all diagnostic, heartbeat, lookup, and marker events for that trace.

### 2. SQLite Database Snapshot JSON Payload Extraction
- **Issue**: Read replicas and regional databases (`customer_data_read_replica_*.sql`, `customer_data_regional_replicas_*.sql`) use generic container tables (`customer_data_primary`, `customer_data_read_replica`) where records are stored as serialized JSON strings inside a `record_json` column rather than flat relational columns. Flat SQL parsers failed to extract identity keys and status flags.
- **Fix**: Updated `_sql_row_to_records` to detect JSON payload columns (`record_json`, `payload`, `document`), parse the nested JSON structures, extract inner customer references, emails, hashes, and evaluate collection-specific status flags.

### 3. Strict Evidence File Capture Cutoff Enforcement (`captured_at <= audit_at`)
- **Issue**: Multi-snapshot JSON bundles (`customer_data_snapshot_bundle_20260917.json`, `evidence_02`) contained historical snapshot items dated prior to `audit_at`. However, the evidence file itself was captured on `2026-09-17`, after cases with `audit_at = 2026-09-15`. Citing future evidence violates §6.2 and §6.6 of the project contract and caused false `INCOMPLETE` predictions on cases 26, 27, and 28.
- **Fix**: Associated each record with `file_captured_at` from `evidence_files.csv`. The indexer strictly enforces that neither the containing file nor the record timestamp exceeds the case cutoff (`file_captured_at <= audit_at and captured_at <= audit_at`).

### 4. Direct PII vs. Permitted Tombstone / Stable Subject Identifiers
- **Issue**: In `support_platform` tickets and account tombstones, policy rule `REDACT` requires removing direct personal identifiers (name, email, phone) while preserving the stable internal customer reference (`user_id` / `customer_reference`). The preliminary classifier treated `customer_reference` as exposed PII, causing compliant redacted tickets in `evidence_92` to be misclassified as `REPORT_EXPOSED_PII`.
- **Fix**: Refined `_infer_state_from_record` so that support messages and tombstones lacking `requester_name`, `requester_email`, and `requester_phone` are marked `REDACTED`, aligning with Rule 05 and Rule 15.

### 5. Multilingual Word Boundary Regex Failures in CJK Requests
- **Issue**: Python regex word boundaries (`\b`) require transitions between ASCII `\w` and `\W`. Japanese and Korean deletion terms (such as `削除` in Case 14: `完全な削除を依頼します`) failed regex matching with `\b削除\b`, incorrectly flagging authorized deletions as `NOT_APPLICABLE`.
- **Fix**: Stripped ASCII word boundaries from CJK and non-Latin character sets in `_DELETION_PATTERNS`, ensuring reliable multilingual deletion intent detection.

### 6. Planned Operation Inference from Global Workflow Activity
- **Issue**: In complex distributed architectures, an analytics profile or support message might be scheduled for whole-record deletion (`DELETE_RECORD`) or unlinking (`ANONYMIZE_RECORD`).
- **Fix**: The auditor correlates target resources against workflow attempts in `system_activity.csv`, overriding generic data category defaults with the workflow's specific intended action.

### 7. Post-Remediation Verification Step Evidence Formatting
- **Issue**: In incomplete cases, verification checks describe future post-remediation validation rather than point-in-time evidence.
- **Fix**: For `INCOMPLETE` cases, all remediation steps and verification checks enforce `evidence_id = ""` in accordance with §6.3 and §6.6. For `COMPLETE` cases, verification checks cite the participant-visible evidence file proving the compliant state.

---

## 3. Additional Custom Evaluation Cases

To rigorously test edge cases, three additional evaluation test cases were designed, covering complex real-world privacy scenarios:

### Custom Case 1: `case_custom_01` (Active Data Flow Sync Race Condition)
- **Email**: `marcus.vance@customdomain.io`
- **Scenario**: An account was deleted from primary `account_service`, but an active third-party CRM integration (`data_flow_8812`) has scheduled sync enabled. If the sync fires, it can re-ingest customer profile attributes into downstream analytics replicas.
- **Expected Deletion Status**: `INCOMPLETE`
- **Steps**:
  1. `FINDING`: `integration_service` | `data_flow_8812` | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | `evidence_custom_01`
  2. `REMEDIATION`: `integration_service` | `data_flow_8812` | `DISABLE_DATA_FLOW` | `DISABLED` | `""`
  3. `VERIFICATION`: `account_service` | `account_custom_01` | `VERIFY_RECORD_ABSENT` | `ABSENT` | `""`
  4. `VERIFICATION`: `integration_service` | `data_flow_8812` | `VERIFY_DATA_FLOW_DISABLED` | `DISABLED` | `""`
- **Rationale**: Verifies that active data replication pipelines must be disabled prior to considering an account deletion safe from recreation.

### Custom Case 2: `case_custom_02` (Account Tombstone with Unredacted Secondary Phone)
- **Email**: `elena.rostova@privacytest.org`
- **Scenario**: The user requested deletion under GDPR Article 17. The primary user profile was replaced with `tombstone_7719` in `identity_service`. However, the user's secondary mobile phone number (`+33 6 12 34 56 78`) remained in the tombstone record alongside the stable internal identifier.
- **Expected Deletion Status**: `INCOMPLETE`
- **Steps**:
  1. `FINDING`: `identity_service` | `tombstone_7719` | `REPORT_EXPOSED_PII` | `PRESENT` | `evidence_custom_02`
  2. `REMEDIATION`: `identity_service` | `tombstone_7719` | `REDACT_RECORD` | `REDACTED` | `""`
  3. `VERIFICATION`: `identity_service` | `tombstone_7719` | `VERIFY_RECORD_REDACTED` | `REDACTED` | `""`
- **Rationale**: Proves that tombstones may retain ONLY the internal stable reference (`user_id`) and that any residual direct identifiers violate the redaction policy.

### Custom Case 3: `case_custom_03` (Subject Access Request - Non-Deletion Exemption)
- **Email**: `david.chen@testcompany.com`
- **Request Text**: *"Under Article 15 GDPR, please provide a complete copy of all personal data your service holds regarding my account and transaction history. I do not wish to close my account at this time."*
- **Scenario**: The user submitted an explicit Subject Access Request (SAR) for data export/access without authorizing account closure or deletion.
- **Expected Deletion Status**: `NOT_APPLICABLE`
- **Steps**: `[]`
- **Rationale**: Confirms that non-deletion rights requests (SAR, portability, password reset, marketing opt-out) must never trigger deletion workflows or inaccurate audit findings.
