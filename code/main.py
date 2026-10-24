"""
Ghost Data Still Exists - Deletion Audit Agent
Entry point: processes all deletion requests and generates output.csv

Usage:
    python code/main.py                     # process dataset/deletion_requests.csv
    python code/main.py --sample            # process dataset/sample_deletion_requests.csv → sample_output_pred.csv
    python code/main.py --input PATH        # process custom input
    python code/main.py --output PATH       # write to custom output path
"""
from __future__ import annotations

import argparse
import sys
import logging
from pathlib import Path

# Ensure the code directory is on the path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

from loader import DataLoader
from identity import IdentityResolver
from evidence_indexer import EvidenceIndexer
from auditor import DeletionAuditor
from output_writer import OutputWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("main")


def run(input_path: Path, output_path: Path, dataset_dir: Path) -> list:
    """Run the audit pipeline on the given input file."""
    # 1. Load all input data
    log.info("Loading datasets from %s ...", dataset_dir)
    loader = DataLoader(dataset_dir)
    loader.load()

    # Override deletion_requests with input_path
    import csv
    with open(input_path, encoding="utf-8", errors="replace") as f:
        requests = list(csv.DictReader(f))
    log.info("Processing %d requests from %s", len(requests), input_path)

    # 2. Build identity resolver
    log.info("Building identity resolver...")
    identity_resolver = IdentityResolver(
        loader.user_identities,
        loader.user_audit_log,
    )

    # 3. Parse and index evidence files
    log.info("Indexing evidence files...")
    ev_indexer = EvidenceIndexer(dataset_dir, loader.evidence_files)
    ev_indexer.build_index()

    # 4. Run deletion audit for each case
    log.info("Running deletion audit for %d cases...", len(requests))
    auditor = DeletionAuditor(
        loader.deletion_rules,
        loader.system_activity,
        identity_resolver,
        ev_indexer,
    )

    results = []
    for i, req in enumerate(requests, 1):
        if i % 50 == 0:
            log.info("  Processed %d/%d", i, len(requests))
        result = auditor.audit(req)
        results.append(result)

    # 5. Write output
    log.info("Writing output to %s", output_path)
    writer = OutputWriter(output_path)
    writer.write(results)

    # 6. Validate output
    log.info("Validating output...")
    writer.validate(len(requests))

    log.info("Done. Output: %s", output_path)
    _print_summary(results)
    return results


def _print_summary(results: list) -> None:
    from collections import Counter
    counts = Counter(r["deletion_status"] for r in results)
    print("\n=== Audit Summary ===")
    print(f"Total cases:    {len(results)}")
    print(f"COMPLETE:       {counts.get('COMPLETE', 0)}")
    print(f"INCOMPLETE:     {counts.get('INCOMPLETE', 0)}")
    print(f"NOT_APPLICABLE: {counts.get('NOT_APPLICABLE', 0)}")
    print("=====================\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ghost Data Still Exists - Deletion Audit Agent"
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Process sample requests (for evaluation)",
    )
    parser.add_argument("--input", type=Path, help="Input CSV path")
    parser.add_argument("--output", type=Path, help="Output CSV path")
    args = parser.parse_args()

    dataset_dir = REPO_ROOT / "dataset"
    if not dataset_dir.exists():
        log.error("dataset/ directory not found at %s", dataset_dir)
        sys.exit(1)

    if args.sample:
        input_path = dataset_dir / "sample_deletion_requests.csv"
        output_path = REPO_ROOT / "sample_output_pred.csv"
    elif args.input:
        input_path = args.input
        output_path = args.output or (REPO_ROOT / "output.csv")
    else:
        input_path = dataset_dir / "deletion_requests.csv"
        output_path = args.output or (REPO_ROOT / "output.csv")

    if not input_path.exists():
        log.error("Input file not found: %s", input_path)
        sys.exit(1)

    run(input_path, output_path, dataset_dir)


if __name__ == "__main__":
    main()
