"""
Evaluation script: compares agent predictions against known ground truth
(sample_output.csv) and reports accuracy metrics.

Usage:
    python code/evaluate.py
    python code/evaluate.py --pred output.csv --truth dataset/sample_output.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from collections import Counter
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


REPO_ROOT = Path(__file__).resolve().parent.parent


def load_csv(path: Path) -> dict[str, dict]:
    with open(path, encoding="utf-8") as f:
        return {row["case_id"]: row for row in csv.DictReader(f)}


def compare_steps(pred_steps: list[dict], truth_steps: list[dict]) -> dict:
    """Compare two step arrays. Returns field-level and sequence metrics."""
    correct_count = 0
    total_fields = 0
    step_fields = ["phase", "system_id", "resource_id", "operation", "state"]

    # Compare step by step (up to shorter length)
    for i, (p, t) in enumerate(zip(pred_steps, truth_steps)):
        for field in step_fields:
            total_fields += 1
            if p.get(field) == t.get(field):
                correct_count += 1

    # Sequence accuracy: 1 if all steps match in order
    seq_correct = pred_steps == truth_steps if pred_steps and truth_steps else (not pred_steps and not truth_steps)

    return {
        "field_correct": correct_count,
        "field_total": total_fields,
        "sequence_correct": seq_correct,
        "pred_len": len(pred_steps),
        "truth_len": len(truth_steps),
    }


def evaluate(pred_path: Path, truth_path: Path) -> None:
    pred = load_csv(pred_path)
    truth = load_csv(truth_path)

    common_cases = set(pred.keys()) & set(truth.keys())
    missing_in_pred = set(truth.keys()) - set(pred.keys())
    extra_in_pred = set(pred.keys()) - set(truth.keys())

    print(f"\n{'='*60}")
    print("DELETION AUDIT EVALUATION REPORT")
    print(f"{'='*60}")
    print(f"Ground truth cases: {len(truth)}")
    print(f"Prediction cases:   {len(pred)}")
    print(f"Common cases:       {len(common_cases)}")
    if missing_in_pred:
        print(f"Missing in pred:    {sorted(missing_in_pred)}")
    if extra_in_pred:
        print(f"Extra in pred:      {sorted(extra_in_pred)}")

    # ── Status accuracy ──
    status_correct = 0
    false_complete = []   # Predicted COMPLETE when truth is INCOMPLETE/NOT_APPLICABLE
    false_incomplete = []
    confusion: dict[str, Counter] = {}

    # ── Step accuracy ──
    total_field_correct = 0
    total_field_total = 0
    sequence_correct_count = 0

    for cid in sorted(common_cases):
        p_row = pred[cid]
        t_row = truth[cid]

        p_status = p_row["deletion_status"]
        t_status = t_row["deletion_status"]

        # Confusion matrix
        confusion.setdefault(t_status, Counter())[p_status] += 1

        if p_status == t_status:
            status_correct += 1
        else:
            if p_status == "COMPLETE" and t_status != "COMPLETE":
                false_complete.append(cid)
            elif t_status == "COMPLETE" and p_status != "COMPLETE":
                false_incomplete.append(cid)

        # Step comparison
        try:
            p_steps = json.loads(p_row["steps_json"])
            t_steps = json.loads(t_row["steps_json"])
        except Exception:
            continue

        step_metrics = compare_steps(p_steps, t_steps)
        total_field_correct += step_metrics["field_correct"]
        total_field_total += step_metrics["field_total"]
        if step_metrics["sequence_correct"]:
            sequence_correct_count += 1

    n = len(common_cases)
    status_accuracy = status_correct / n * 100 if n > 0 else 0
    field_accuracy = total_field_correct / total_field_total * 100 if total_field_total > 0 else 0
    seq_accuracy = sequence_correct_count / n * 100 if n > 0 else 0

    print(f"\n-- Status Accuracy --")
    print(f"  Correct:  {status_correct}/{n} ({status_accuracy:.1f}%)")
    print(f"  False COMPLETE (dangerous): {len(false_complete)} → {false_complete}")
    print(f"  False INCOMPLETE: {len(false_incomplete)} → {false_incomplete}")

    print(f"\n-- Confusion Matrix (truth rows, pred cols) --")
    all_statuses = ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]
    header = f"{'':20s}" + "".join(f"{s:16s}" for s in all_statuses)
    print(header)
    for t_s in all_statuses:
        if t_s not in confusion:
            continue
        row_str = f"{t_s:20s}"
        for p_s in all_statuses:
            cnt = confusion[t_s].get(p_s, 0)
            row_str += f"{cnt:<16d}"
        print(row_str)

    print(f"\n-- Step-Level Accuracy --")
    print(f"  Field-level: {total_field_correct}/{total_field_total} ({field_accuracy:.1f}%)")
    print(f"  Sequence:    {sequence_correct_count}/{n} ({seq_accuracy:.1f}%)")

    print(f"\n-- Per-Case Breakdown --")
    for cid in sorted(common_cases):
        p_status = pred[cid]["deletion_status"]
        t_status = truth[cid]["deletion_status"]
        marker = "✓" if p_status == t_status else "✗"
        print(f"  {marker} {cid}: pred={p_status:15s} truth={t_status}")

    print(f"\n{'='*60}")
    print(f"SUMMARY: Status accuracy={status_accuracy:.1f}%, "
          f"Field accuracy={field_accuracy:.1f}%, "
          f"Sequence accuracy={seq_accuracy:.1f}%")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate deletion audit predictions")
    parser.add_argument(
        "--pred",
        type=Path,
        default=REPO_ROOT / "output.csv",
        help="Prediction CSV file",
    )
    parser.add_argument(
        "--truth",
        type=Path,
        default=REPO_ROOT / "dataset" / "sample_output.csv",
        help="Ground truth CSV file",
    )
    args = parser.parse_args()

    if not args.pred.exists():
        print(f"Error: prediction file not found: {args.pred}")
        sys.exit(1)
    if not args.truth.exists():
        print(f"Error: truth file not found: {args.truth}")
        sys.exit(1)

    evaluate(args.pred, args.truth)
