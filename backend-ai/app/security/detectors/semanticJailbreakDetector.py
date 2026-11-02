from __future__ import annotations

import re
from typing import List, Dict, Any

from app.security.policies.jailbreakPolicy import JailbreakPolicy
from app.security.utils.text import jaccard_similarity, normalize_text, similarity
from app.security.utils.types import DetectionMatch, SeverityLevel

jailbreak_policy = JailbreakPolicy()


# =========================================================
# ADVANCED JAILBREAK PATTERNS
# =========================================================

JAILBREAK_REGEXES = [
    # NOTE: bare words such as "act as", "pretend you are", "dan" (a common first name) and
    # "system prompt" are NOT jailbreaks by themselves; they used to block ordinary requests
    # ("act as a travel guide", "what is a system prompt?"). Each pattern below needs an
    # attack-specific companion. Broader multilingual/obfuscated coverage lives in intent_engine.
    re.compile(r"\bignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+instructions\b", re.I),
    re.compile(r"\b(imagine you are|roleplay|role-play|act as|pretend (?:you are|to be))\b[^.\n]{0,80}\b(no\s+(?:ethical\s+)?(?:restrictions|rules|filters|limits|guidelines)|unrestricted|unfiltered|uncensored|without\s+(?:any\s+)?(?:restrictions|rules|filters|limits)|jailbr\w+|evil\w*)\b", re.I),
    re.compile(r"\bdeveloper mode\s+(?:enabled|activated)\b", re.I),
    re.compile(r"\bgod mode\s+(?:enabled|activated|on)\b", re.I),
    re.compile(r"\bDAN\b(?=[^.\n]{0,60}\b(?:mode|jailbreak|no\s+restrictions|do anything|ignore|unrestricted|you are|who)\b)"),
    re.compile(r"\b(?:with|has|have|having)\s+no\s+(?:ethical\s+)?(?:restrictions|limits|rules|filters)\b", re.I),
    re.compile(r"\bdo anything now\b", re.I),
    re.compile(r"\byou are now\b.*\bunrestricted\b", re.I),
    re.compile(r"\b(?:reveal|show|print|repeat|output|leak|dump|display|tell me)\b[^.\n]{0,30}\b(?:your|the)\s+(?:hidden\s+|secret\s+|initial\s+)?system prompt\b", re.I),
]


# =========================================================
# MULTI-TURN ATTACK SIGNALS
# =========================================================

STAGED_ATTACK_MARKERS = [
    "hypothetically",
    "for educational purposes",
    "just pretend",
    "fictional scenario",
    "in a simulation",
    "ignore safety",
    "no policy applies",
    "research mode",
]


# =========================================================
# CONTEXT BUILDING
# =========================================================

def _history_blob(history: List[str] | None) -> str:
    if not history:
        return ""
    return "\n".join(str(h or "") for h in history[-10:])


def _normalize(text: str) -> str:
    return normalize_text(text).lower().strip()


# =========================================================
# ATTACK INTENT SCORING
# =========================================================

def _compute_intent_boost(text: str) -> float:

    boost = 0.0

    for marker in STAGED_ATTACK_MARKERS:
        if marker in text:
            boost += 0.12

    return min(boost, 0.5)


# =========================================================
# MAIN DETECTOR
# =========================================================

def detect_semantic_jailbreak(
    content: str,
    history: List[str] | None = None,
) -> List[DetectionMatch]:

    findings: List[DetectionMatch] = []

    normalized_content = _normalize(content)
    history_content = _history_blob(history)

    combined = _normalize(f"{history_content}\n{normalized_content}")

    # Do not classify an explicitly quoted attack phrase as an attack when the
    # surrounding request is clearly educational and contains no unquoted
    # operational instruction. Other detectors still inspect the full text.
    quoted_attack = re.search(
        r"(['\"“]).{0,180}\b(?:ignore\s+(?:all\s+)?previous instructions|system prompt|developer mode|jailbreak)\b.{0,180}?\1",
        combined,
        re.I,
    )
    educational_framing = re.search(
        r"\b(?:security training|security awareness|educational|awareness slide|documenting|paper about|explain why|translate the sentence|compar(?:e|es))\b",
        combined,
        re.I,
    )
    unquoted_text = re.sub(
        r"(['\"“]).{0,180}\b(?:ignore\s+(?:all\s+)?previous instructions|system prompt|developer mode|jailbreak)\b.{0,180}?\1",
        " ",
        combined,
        flags=re.I,
    )
    actionable_target = re.search(
        r"\b(?:reveal|show|output|send|steal|exfiltrate|execute|transfer|invoke|call|run)\b.{0,80}\b(?:system prompt|hidden prompt|secret|password|token|funds|wallet|tool)\b",
        unquoted_text,
        re.I,
    )
    if quoted_attack and educational_framing and not actionable_target:
        return []

    base_risk = 0.0

    # =====================================================
    # 1. REGEX JAILBREAK DETECTION (IMPROVED)
    # =====================================================

    for regex in JAILBREAK_REGEXES:

        if regex.search(combined):

            findings.append(
                DetectionMatch(
                    detector="semantic_jailbreak",
                    label="regex_jailbreak",
                    reason="Direct jailbreak pattern detected",
                    confidence=0.90,
                    severity=jailbreak_policy.severity_for_score(0.90),
                    metadata={"pattern": regex.pattern},
                )
            )

            base_risk += 0.35

    # =====================================================
    # 2. SEMANTIC SIMILARITY (IMPROVED FUSION)
    # =====================================================

    for phrase in jailbreak_policy.patterns:

        seq_sim = similarity(combined, phrase)
        token_sim = jaccard_similarity(combined, phrase)

        # weighted fusion (IMPORTANT FIX)
        semantic_score = (seq_sim * 0.6) + (token_sim * 0.4)

        if semantic_score >= jailbreak_policy.semantic_threshold:

            findings.append(
                DetectionMatch(
                    detector="semantic_jailbreak",
                    label="semantic_jailbreak",
                    reason="Semantic similarity to jailbreak pattern",
                    confidence=semantic_score,
                    severity=jailbreak_policy.severity_for_score(
                        semantic_score
                    ),
                    metadata={
                        "phrase": phrase,
                        "seq_sim": round(seq_sim, 4),
                        "token_sim": round(token_sim, 4),
                    },
                )
            )

            base_risk += semantic_score * 0.25

    # =====================================================
    # 3. MULTI-TURN ATTACK PROGRESSION
    # =====================================================

    if history:

        recent = [_normalize(h) for h in history[-6:]]

        staged_hits = sum(
            1
            for msg in recent
            for marker in STAGED_ATTACK_MARKERS
            if marker in msg
        )

        if staged_hits >= 2:

            findings.append(
                DetectionMatch(
                    detector="semantic_jailbreak",
                    label="multi_turn_jailbreak",
                    reason="Multi-turn jailbreak progression detected",
                    confidence=0.78,
                    severity=jailbreak_policy.severity_for_score(0.78),
                    metadata={
                        "staged_hits": staged_hits,
                        "history_length": len(history),
                    },
                )
            )

            base_risk += 0.30

    # =====================================================
    # 4. INTENT BOOSTING (CRITICAL UPGRADE)
    # =====================================================

    intent_boost = _compute_intent_boost(combined)

    base_risk += intent_boost

    # =====================================================
    # 5. FINAL ESCALATION
    # =====================================================

    base_risk = min(base_risk, 1.0)

    if base_risk >= 0.85:
        severity = SeverityLevel.CRITICAL
    elif base_risk >= 0.65:
        severity = SeverityLevel.HIGH
    elif base_risk >= 0.40:
        severity = SeverityLevel.MEDIUM
    else:
        severity = SeverityLevel.LOW

    # attach global escalation signal
    if len(findings) >= 2:
        findings.append(
            DetectionMatch(
                detector="semantic_jailbreak",
                label="attack_chain_detected",
                reason="Multiple jailbreak vectors detected",
                confidence=min(0.95, base_risk),
                severity=severity,
                metadata={"signal_count": len(findings)},
            )
        )

    return findings