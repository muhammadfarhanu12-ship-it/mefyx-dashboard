"""Adapter: turns IntentEngine verdicts into DetectionMatch objects for the enforcement layer."""
from __future__ import annotations

from app.core.config import settings
from app.security.detectors import ml_classifier
from app.security.detectors.intent_engine import IntentVerdict, analyze_intent_text
from app.security.utils.types import DetectionMatch, SeverityLevel

_LABELS = {
    "injection": "prompt_injection_override",
    "persona": "prompt_injection_jailbreak_persona",
    "extraction": "prompt_injection_system_prompt_extraction",
    "indirect": "prompt_injection_indirect_content",
    "tool_abuse": "prompt_injection_agent_tool_abuse",
    "exfiltration": "prompt_injection_data_exfiltration",
    "obfuscation": "prompt_injection_obfuscated_payload",
    "financial_fraud": "financial_fraud_request",
}


def _to_matches(verdict: IntentVerdict, source: str) -> list[DetectionMatch]:
    if not verdict.blocked:
        return []
    matches: list[DetectionMatch] = []
    for category in verdict.categories or ["injection"]:
        sigs = [s for s in verdict.signals if s.category == category]
        if not sigs:
            continue
        top = max(sigs, key=lambda s: s.weight)
        severity = SeverityLevel.CRITICAL if verdict.score >= 85 else SeverityLevel.HIGH
        matches.append(
            DetectionMatch(
                detector="sentinel_intent_engine",
                label=_LABELS.get(category, "prompt_injection_override"),
                reason=f"{top.name.replace('_', ' ')} detected in {source}",
                confidence=round(min(0.99, max(0.6, verdict.score / 100.0)), 3),
                severity=severity,
                metadata={
                    "score": verdict.score,
                    "rule": top.name,
                    "variant": top.variant,
                    "obfuscated": verdict.obfuscated,
                    "source": source,
                    "signals": [s.name for s in sigs][:6],
                },
            )
        )
    return matches


def ml_verdict(prompt: str, untrusted_text: str | None = None) -> dict | None:
    """Learned-classifier verdict, or None when the layer is disabled/unavailable or below threshold."""
    if not getattr(settings, "ML_LAYER_ENABLED", True):
        return None
    result = ml_classifier.classify(prompt or "", untrusted_text)
    if result is None or result["p_malicious"] < float(getattr(settings, "ML_BLOCK_THRESHOLD", 0.70)):
        return None
    return result


def intent_detections(prompt: str, *, untrusted_text: str | None = None) -> list[DetectionMatch]:
    """Scan the user prompt and any untrusted content: phrase/concept rules OR the learned classifier."""
    out = _to_matches(analyze_intent_text(prompt or ""), "user_prompt")
    if untrusted_text and untrusted_text.strip():
        out.extend(_to_matches(analyze_intent_text(untrusted_text, untrusted=True), "untrusted_content"))
    ml = ml_verdict(prompt, untrusted_text)
    if ml is not None:
        score = int(round(ml["p_malicious"] * 100))
        out.append(
            DetectionMatch(
                detector="sentinel_ml_classifier",
                label="financial_fraud_request" if ml["label"] == "fraud" else "prompt_injection_ml_classifier",
                reason="learned classifier flagged the request as malicious",
                confidence=round(min(0.99, ml["p_malicious"]), 3),
                severity=SeverityLevel.CRITICAL if score >= 90 else SeverityLevel.HIGH,
                metadata={"score": score, "rule": "ml_classifier", "source": "ml", "probs": {k: round(v, 3) for k, v in ml["probs"].items()}},
            )
        )
    return out