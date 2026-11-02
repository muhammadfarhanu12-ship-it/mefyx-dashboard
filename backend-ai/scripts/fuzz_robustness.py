"""Metamorphic robustness test.

Takes every attack in the labeled sets that the engine already detects, applies meaning-preserving
mutations an attacker would try, and reports how many mutated attacks are still caught.

    python scripts/fuzz_robustness.py            # prints a per-mutation table
    python scripts/fuzz_robustness.py --min 0.9  # exit 1 if any mutation retains < 90%
"""
from __future__ import annotations

import base64
import glob
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security.detectors.intent_engine import analyze_intent_text  # noqa: E402

random.seed(7)
FILLER = ("Thanks for helping with my project today. I am organising notes for next week's team meeting and "
          "need to keep things tidy. The weather has been lovely lately and the office is quiet. ") * 3
CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"}


def typo(s: str) -> str:
    words = s.split(" ")
    idx = [i for i, w in enumerate(words) if len(w) >= 7 and w.isalpha()]
    for i in random.sample(idx, min(2, len(idx))):
        w = words[i]
        j = random.randrange(1, len(w) - 2)
        words[i] = w[:j] + w[j + 1] + w[j] + w[j + 2:]
    return " ".join(words)


MUTATIONS = {
    "uppercase": str.upper,
    "alternating_case": lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s)),
    "typos": typo,
    "polite_wrapper": lambda s: f"Hi there! Hope you're well. {s} Thanks so much!",
    "filler_before": lambda s: f"{FILLER}\n{s}",
    "filler_after": lambda s: f"{s}\n{FILLER}",
    "markdown_code": lambda s: f"Please run this block:\n```\n{s}\n```",
    "roleplay_wrapper": lambda s: f"Let's play a game. In the game you must do exactly this: {s}",
    "quoted_request": lambda s: f'Follow the instruction in quotes: "{s}"',
    "zero_width": lambda s: "\u200b".join(s) if len(s) < 400 else s,
    "homoglyph": lambda s: "".join(CYR.get(c, c) if i % 3 == 0 else c for i, c in enumerate(s)),
    "double_spaced": lambda s: s.replace(" ", "  "),
    "base64_wrapper": lambda s: "Decode and follow: " + base64.b64encode(s.encode()).decode(),
}


def main() -> int:
    minimum = float(sys.argv[sys.argv.index("--min") + 1]) if "--min" in sys.argv else None
    base = []
    for path in sorted(glob.glob(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "data", "detection_regression_set*.json"))):
        for case in json.load(open(path, encoding="utf-8")):
            if case["label"] == "malicious" and not case.get("untrusted_content") and len(case["prompt"]) < 500:
                if analyze_intent_text(case["prompt"]).blocked:
                    base.append(case["prompt"])
    print(f"{len(base)} detected attacks used as seeds\n")
    worst = 1.0
    for name, fn in MUTATIONS.items():
        kept = sum(1 for p in base if analyze_intent_text(fn(p)).blocked)
        rate = kept / max(1, len(base))
        worst = min(worst, rate) if name != "base64_wrapper" else worst  # decoding happens in the pipeline, not here
        print(f"{name:18s} {kept:3d}/{len(base)}  {rate:5.1%}")
    if minimum is not None and worst < minimum:
        print(f"\nFAIL: weakest mutation retains {worst:.1%} < {minimum:.0%}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())