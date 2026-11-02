"""Train / retrain the learned classifier and export it for dependency-free inference.

    pip install scikit-learn            # development only; NOT needed in production
    python scripts/train_ml_layer.py    # reads tests/data/detection_regression_set*.json (+ pilot set)

Add reviewed pilot samples first with:  python scripts/promote_reviewed_samples.py reviewed.json
The script prints a leave-one-set-out estimate (train on all other sets, test on the held-out set), which
is the honest accuracy figure, then writes app/security/models/intent_model.json.
"""
from __future__ import annotations

import glob
import json
import math
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import numpy as np  # noqa: E402
from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402

from app.security.detectors import ml_classifier as ml  # noqa: E402

FRAUD_WORDS = ("fraud",)


def klass(case: dict) -> str:
    if case["label"] != "malicious":
        return "benign"
    return "fraud" if any(w in case["category"] for w in FRAUD_WORDS) else "injection"


def text_of(case: dict) -> str:
    return ml.build_text(case["prompt"], case.get("untrusted_content"))


def fit(cases: list[dict]):
    texts = [text_of(c) for c in cases]
    labels = [klass(c) for c in cases]
    word = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True)
    from scipy.sparse import hstack
    X = hstack([word.fit_transform(texts), char.fit_transform(texts)]).tocsr()
    clf = LogisticRegression(C=10, class_weight="balanced", max_iter=5000)
    clf.fit(X, labels)
    return word, char, clf


def p_malicious(word, char, clf, cases: list[dict]) -> np.ndarray:
    from scipy.sparse import hstack
    texts = [text_of(c) for c in cases]
    X = hstack([word.transform(texts), char.transform(texts)]).tocsr()
    probs = clf.predict_proba(X)
    return 1.0 - probs[:, list(clf.classes_).index("benign")]


def main() -> None:
    paths = sorted(glob.glob(os.path.join(ROOT, "tests", "data", "detection_regression_set*.json")))
    paths += sorted(glob.glob(os.path.join(ROOT, "tests", "data", "detection_pilot_set*.json")))
    sets = {os.path.basename(p): json.load(open(p, encoding="utf-8")) for p in paths}
    print("sets:", {k: len(v) for k, v in sets.items()})

    pooled_p, pooled_y = [], []
    for held in sets:
        train = [c for k, v in sets.items() if k != held for c in v]
        w, ch, clf = fit(train)
        p = p_malicious(w, ch, clf, sets[held])
        y = np.array([c["label"] == "malicious" for c in sets[held]])
        pooled_p += list(p)
        pooled_y += list(y)
    p, y = np.array(pooled_p), np.array(pooled_y)
    print("\nLeave-one-set-out (honest estimate):")
    for t in (0.5, 0.55, 0.6, 0.65, 0.7):
        print(f"  threshold {t}: recall={((p >= t) & y).sum() / y.sum():.3f}  false-positive rate={((p >= t) & ~y).sum() / (~y).sum():.3f}")

    cases = [c for v in sets.values() for c in v]
    word, char, clf = fit(cases)
    classes = list(clf.classes_)
    nfw = len(word.vocabulary_)
    coef = clf.coef_
    if coef.shape[0] == 1:  # binary fallback
        coef = np.vstack([-coef[0], coef[0]])
    def pack(vec, offset):
        out = {}
        for term, idx in vec.vocabulary_.items():
            out[term] = [float(vec.idf_[idx])] + [round(float(coef[k, offset + idx]), 6) for k in range(len(classes))]
            out[term][0] = round(out[term][0], 6)
        return out
    model = {
        "version": 1, "classes": classes, "intercept": [round(float(v), 6) for v in clf.intercept_],
        "word": pack(word, 0), "char": pack(char, nfw),
        "trained_on": {k: len(v) for k, v in sets.items()},
        "reference": [],
    }
    # reference predictions so tests can prove the pure-Python path equals scikit-learn
    from scipy.sparse import hstack
    sample = cases[:: max(1, len(cases) // 12)][:12]
    X = hstack([word.transform([text_of(c) for c in sample]), char.transform([text_of(c) for c in sample])]).tocsr()
    for c, probs in zip(sample, clf.predict_proba(X)):
        model["reference"].append({"text": text_of(c), "probs": {cls: round(float(v), 6) for cls, v in zip(classes, probs)}})
    os.makedirs(os.path.dirname(ml.MODEL_PATH), exist_ok=True)
    with open(ml.MODEL_PATH, "w", encoding="utf-8") as fh:
        json.dump(model, fh, ensure_ascii=False, separators=(",", ":"))
    print(f"\nwrote {ml.MODEL_PATH}  ({os.path.getsize(ml.MODEL_PATH) / 1024:.0f} KB, {len(model['word'])} word + {len(model['char'])} char features)")


if __name__ == "__main__":
    main()