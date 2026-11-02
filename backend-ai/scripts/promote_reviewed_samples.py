"""Turn reviewed pilot traffic into permanent regression + training data.

Workflow (see PILOT_CHECKLIST):
  1. Run with GATEWAY_SECURITY_MODE=monitor. Export `gateway_request_would_block` events (prompt_preview) and
     any attacks your team found that were NOT flagged.
  2. A reviewer labels each row  malicious | benign  (CSV or JSON, columns: prompt|prompt_preview|text, label,
     optional category, optional untrusted_content).
  3. python scripts/promote_reviewed_samples.py reviewed.csv
  4. python scripts/train_ml_layer.py          # retrains the classifier, prints the honest leave-one-set-out score
  5. pytest tests/test_detection_accuracy.py   # every promoted sample is now a regression test

Samples are de-duplicated by normalised text and written to tests/data/detection_pilot_set1.json.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "tests", "data", "detection_pilot_set1.json")
PROMPT_KEYS = ("prompt", "prompt_preview", "text", "content")
VALID = {"malicious", "benign"}


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def read_rows(path: str) -> list[dict]:
    if path.lower().endswith(".json"):
        data = json.load(open(path, encoding="utf-8"))
        return data if isinstance(data, list) else data.get("samples", [])
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def normalise_row(row: dict) -> dict | None:
    prompt = next((str(row[k]).strip() for k in PROMPT_KEYS if row.get(k)), "")
    label = str(row.get("label") or "").strip().lower()
    if not prompt or label not in VALID:
        return None
    category = str(row.get("category") or "").strip() or ("pilot_attack" if label == "malicious" else "pilot_benign")
    sample = {"category": category, "label": label, "prompt": prompt}
    untrusted = str(row.get("untrusted_content") or "").strip()
    if untrusted:
        sample["untrusted_content"] = untrusted
    return sample


def promote(rows: list[dict], out_path: str = OUT) -> tuple[int, int, int]:
    existing = json.load(open(out_path, encoding="utf-8")) if os.path.exists(out_path) else []
    seen = {_norm(c["prompt"] + c.get("untrusted_content", "")) for c in existing}
    added = skipped = invalid = 0
    for row in rows:
        sample = normalise_row(row)
        if sample is None:
            invalid += 1
            continue
        key = _norm(sample["prompt"] + sample.get("untrusted_content", ""))
        if key in seen:
            skipped += 1
            continue
        seen.add(key)
        sample["id"] = f"p{len(existing):04d}"
        existing.append(sample)
        added += 1
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, ensure_ascii=False, indent=1)
    return added, skipped, invalid


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    added, skipped, invalid = promote(read_rows(sys.argv[1]))
    print(f"added {added}, duplicates skipped {skipped}, invalid rows (missing prompt or label) {invalid}")
    print("next: python scripts/train_ml_layer.py && pytest tests/test_detection_accuracy.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())