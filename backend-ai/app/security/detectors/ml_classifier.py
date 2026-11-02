"""Learned prompt-threat classifier (pure Python inference).

A multinomial logistic regression over TF-IDF word 1-2-grams and character 3-5-grams, trained by
``scripts/train_ml_layer.py`` and exported to ``app/security/models/intent_model.json``.  Inference here
reproduces scikit-learn's feature extraction exactly (verified in the test-suite against stored reference
probabilities), so production needs no ML dependency.

Why it exists: phrase/concept rules plateau at ~60% recall on never-seen wordings, while this layer
generalises across them (leave-one-set-out: ~91% recall at ~2% false positives).  It is an *assist*:
the final verdict is ``rules OR classifier``; the classifier's threshold is configurable and the whole
layer can be switched off (ML_LAYER_ENABLED=false).
"""
from __future__ import annotations

import json
import math
import os
import re
import threading
from collections import Counter
from typing import Optional

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "intent_model.json")
MAX_CHARS = 1500
_ROLE_PREFIX = re.compile(r"(?im)^\s*(?:user|system|assistant|tool|function)\s*:\s*")
_WORD = re.compile(r"(?u)\b\w\w+\b")
_WS = re.compile(r"\s\s+")

_lock = threading.Lock()
_model: Optional[dict] = None
_load_failed = False


def _load() -> Optional[dict]:
    global _model, _load_failed
    if _model is not None or _load_failed:
        return _model
    with _lock:
        if _model is None and not _load_failed:
            try:
                with open(MODEL_PATH, encoding="utf-8") as fh:
                    _model = json.load(fh)
            except Exception:  # missing/corrupt model must never break scanning
                _load_failed = True
    return _model


def reset_for_tests() -> None:
    global _model, _load_failed
    _model, _load_failed = None, False


def _word_ngrams(text: str) -> list[str]:
    tokens = _WORD.findall(text)
    grams = list(tokens)
    grams.extend(f"{a} {b}" for a, b in zip(tokens, tokens[1:]))
    return grams


def _char_wb_ngrams(text: str, lo: int = 3, hi: int = 5) -> list[str]:
    out: list[str] = []
    for word in _WS.sub(" ", text).split():
        w = f" {word} "
        w_len = len(w)
        for n in range(lo, hi + 1):
            offset = 0
            out.append(w[offset:offset + n])
            while offset + n < w_len:
                offset += 1
                out.append(w[offset:offset + n])
            if offset == 0:
                break
    return out


def _contrib(grams: list[str], vocab: dict, logits: list[float]) -> None:
    counts = Counter(g for g in grams if g in vocab)
    if not counts:
        return
    weights = {g: (1.0 + math.log(c)) * vocab[g][0] for g, c in counts.items()}
    norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
    for g, w in weights.items():
        x = w / norm
        coefs = vocab[g][1:]
        for k, coef in enumerate(coefs):
            logits[k] += coef * x


def build_text(prompt: str, untrusted: Optional[str] = None) -> str:
    text = _ROLE_PREFIX.sub("", prompt or "")[:MAX_CHARS]
    if untrusted and untrusted.strip():
        text = f"{text} || {untrusted[:MAX_CHARS]}"
    return text.lower()


def predict_proba(text: str) -> Optional[dict[str, float]]:
    """Class probabilities for already-built, lower-cased text, or None if no model is available."""
    model = _load()
    if model is None:
        return None
    logits = list(model["intercept"])
    _contrib(_word_ngrams(text), model["word"], logits)
    _contrib(_char_wb_ngrams(text), model["char"], logits)
    peak = max(logits)
    exps = [math.exp(v - peak) for v in logits]
    total = sum(exps)
    return {cls: e / total for cls, e in zip(model["classes"], exps)}


def classify(prompt: str, untrusted: Optional[str] = None) -> Optional[dict]:
    """Returns {"p_malicious", "label"("fraud"|"injection"), "probs"} or None when unavailable."""
    probs = predict_proba(build_text(prompt, untrusted))
    if probs is None:
        return None
    p_mal = 1.0 - probs.get("benign", 0.0)
    label = "fraud" if probs.get("fraud", 0.0) > probs.get("injection", 0.0) else "injection"
    return {"p_malicious": p_mal, "label": label, "probs": probs}