"""
Output writer module: writes output.csv and validates it.
"""
from __future__ import annotations

import csv
import json
import logging
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

REQUIRED_HEADER = ["case_id", "deletion_status", "steps_json"]
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}


class OutputWriter:
    """Writes and validates the output.csv file."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path

    def write(self, results: list[dict[str, Any]]) -> None:
        """Write results to output.csv, sorted by case_id."""
        # Sort by case_id (case_001 < case_002 etc.)
        def sort_key(r: dict) -> tuple:
            cid = r["case_id"]
            # Extract numeric part for proper sorting
            parts = cid.split("_")
            if len(parts) >= 2:
                try:
                    return (parts[0], int(parts[1]))
                except ValueError:
                    pass
            return (cid, 0)

        sorted_results = sorted(results, key=sort_key)

        with open(self.output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
            writer.writerow(REQUIRED_HEADER)
            for r in sorted_results:
                steps = r.get("steps_json", [])
                # Serialize steps_json as compact JSON
                steps_str = json.dumps(steps, separators=(",", ":"), ensure_ascii=False)
                writer.writerow([r["case_id"], r["deletion_status"], steps_str])

        log.info("Wrote %d rows to %s", len(sorted_results), self.output_path)

    def validate(self, expected_count: int) -> bool:
        """Validate the written output file. Returns True if valid."""
        errors: list[str] = []

        if not self.output_path.exists():
            log.error("Output file does not exist: %s", self.output_path)
            return False

        with open(self.output_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if list(reader.fieldnames) != REQUIRED_HEADER:
                errors.append(
                    f"Header mismatch: got {reader.fieldnames}, "
                    f"expected {REQUIRED_HEADER}"
                )
            rows = list(reader)

        if len(rows) != expected_count:
            errors.append(
                f"Row count mismatch: got {len(rows)}, expected {expected_count}"
            )

        seen_ids: set[str] = set()
        for i, row in enumerate(rows, 1):
            cid = row.get("case_id", "")
            status = row.get("deletion_status", "")
            steps_str = row.get("steps_json", "")

            if cid in seen_ids:
                errors.append(f"Row {i}: duplicate case_id '{cid}'")
            seen_ids.add(cid)

            if status not in ALLOWED_STATUSES:
                errors.append(
                    f"Row {i} ({cid}): invalid status '{status}'"
                )

            try:
                steps = json.loads(steps_str)
                if not isinstance(steps, list):
                    errors.append(f"Row {i} ({cid}): steps_json is not a list")
                else:
                    # Validate step numbers are consecutive from 1
                    for j, step in enumerate(steps, 1):
                        if step.get("step_no") != j:
                            errors.append(
                                f"Row {i} ({cid}): step {j} has step_no={step.get('step_no')}"
                            )
                        required_fields = {
                            "step_no", "phase", "system_id", "resource_id",
                            "operation", "state", "evidence_id"
                        }
                        missing = required_fields - set(step.keys())
                        if missing:
                            errors.append(
                                f"Row {i} ({cid}): step {j} missing fields {missing}"
                            )
            except json.JSONDecodeError as e:
                errors.append(f"Row {i} ({cid}): invalid steps_json: {e}")

            # NOT_APPLICABLE must have empty steps
            if status == "NOT_APPLICABLE" and steps_str not in ("[]", ""):
                try:
                    if json.loads(steps_str):
                        errors.append(
                            f"Row {i} ({cid}): NOT_APPLICABLE must have empty steps_json"
                        )
                except Exception:
                    pass

        if errors:
            log.error("Validation FAILED with %d error(s):", len(errors))
            for e in errors[:20]:
                log.error("  %s", e)
            if len(errors) > 20:
                log.error("  ... and %d more", len(errors) - 20)
            return False

        log.info(
            "Validation PASSED: %d rows, all statuses valid, all steps valid",
            len(rows),
        )
        return True
