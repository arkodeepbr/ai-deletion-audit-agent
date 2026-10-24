"""
Data loader module: reads all input CSV/evidence files into memory.
"""
from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class DataLoader:
    """Loads all participant-facing dataset files."""

    def __init__(self, dataset_dir: Path) -> None:
        self.dataset_dir = dataset_dir
        self.deletion_requests: list[dict[str, str]] = []
        self.user_identities: list[dict[str, str]] = []
        self.user_audit_log: list[dict[str, str]] = []
        self.system_activity: list[dict[str, str]] = []
        self.deletion_rules: list[dict[str, str]] = []
        self.evidence_files: list[dict[str, str]] = []

    def load(self) -> None:
        """Load all CSV files from dataset directory."""
        self.deletion_requests = self._load_csv("deletion_requests.csv")
        log.info("  deletion_requests: %d rows", len(self.deletion_requests))

        self.user_identities = self._load_csv("user_identities.csv")
        log.info("  user_identities: %d rows", len(self.user_identities))

        self.user_audit_log = self._load_csv("user_audit_log.csv")
        log.info("  user_audit_log: %d rows", len(self.user_audit_log))

        self.system_activity = self._load_csv("system_activity.csv")
        log.info("  system_activity: %d rows", len(self.system_activity))

        self.deletion_rules = self._load_csv("deletion_rules.csv")
        log.info("  deletion_rules: %d rows", len(self.deletion_rules))

        self.evidence_files = self._load_csv("evidence_files.csv")
        log.info("  evidence_files: %d rows", len(self.evidence_files))

    def _load_csv(self, filename: str) -> list[dict[str, str]]:
        path = self.dataset_dir / filename
        if not path.exists():
            log.error("Required file missing: %s", path)
            raise FileNotFoundError(f"Required file missing: {path}")
        with open(path, encoding="utf-8", errors="replace") as f:
            return list(csv.DictReader(f))
