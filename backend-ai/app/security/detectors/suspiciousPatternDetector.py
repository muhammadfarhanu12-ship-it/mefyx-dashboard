from __future__ import annotations

import re
import unicodedata
from typing import List

from app.security.utils.types import DetectionMatch, SeverityLevel


# =========================================================
# NORMALIZATION LAYER (CRITICAL FIX)
# =========================================================

def _normalize(text: str) -> str:
    if not text:
        return ""

    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()


# =========================================================
# EXPANDED PATTERN SET (HARDENED)
# =========================================================

SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern, SeverityLevel, float]] = [

    # -----------------------------------------------------
    # SQL INJECTION (EXPANDED)
    # -----------------------------------------------------
    (
        "sql_injection",
        re.compile(
            r"("
            r"\bunion\b\s+(?:all\s+)?\bselect\b|"
            r"\bdrop\b\s+(?:table|database)\b|"
            r"['\"]\s*or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|"
            r"\bor\s+1\s*=\s*1\b|"
            r";\s*(?:drop|delete|truncate|shutdown|update|insert)\b|"
            r"['\"]\s*(?:--|#)|;\s*--|"
            r"\binformation_schema\b|"
            r"\bsleep\s*\(\s*\d+\s*\)|"
            r"\bbenchmark\s*\("
            r")",
            re.I,
        ),
        SeverityLevel.HIGH,
        0.85,
    ),

    # -----------------------------------------------------
    # COMMAND INJECTION (EXPANDED)
    # -----------------------------------------------------
    (
        "command_injection",
        re.compile(
            r"("
            r"rm\s+-rf\s+(?:/|~|\*|\$)|"
            r"powershell\s+-enc|"
            r"cmd\.exe\s*/c|"
            r"bash\s+-c\s+['\"]?\s*(?:curl|wget|nc|rm|cat\s+/etc)|"
            r"(?:curl|wget)\s+\S+[^\n]{0,80}\|\s*(?:sudo\s+)?(?:sh|bash)\b|"
            r";\s*shutdown\b|"
            r"\|\s*(?:sh|bash)\b|"
            r"&&\s*(?:rm\s+-|curl\s|wget\s|nc\s|chmod\s+[0-7+]|sudo\s|cat\s+/etc/|bash\s+-)|"
            r"\$\(\s*(?:curl|wget|nc|bash|sh|rm|cat\s+/etc)|"
            r"`\s*(?:curl|wget|nc|rm\s|bash|sh\s|cat\s+/etc)"
            r")",
            re.I,
        ),
        SeverityLevel.CRITICAL,
        0.95,
    ),

    # -----------------------------------------------------
    # CREDENTIAL EXTRACTION
    # -----------------------------------------------------
    (
        "credential_harvest",
        re.compile(
            r"(api\s*key|secret|token|password|auth\s*key)"
            r".{0,50}"
            r"(print|dump|reveal|show|extract|log)",
            re.I,
        ),
        SeverityLevel.HIGH,
        0.88,
    ),

    # -----------------------------------------------------
    # PROMPT SPLIT / MULTI-STAGE ATTACK
    # -----------------------------------------------------
    (
        "prompt_split_attack",
        re.compile(
            r"(part\s+\d+\s*/\s*\d+|"
            r"continue in next message|"
            r"do not evaluate yet|"
            r"wait for next instruction|"
            r"step\s*\d+)",
            re.I,
        ),
        SeverityLevel.MEDIUM,
        0.65,
    ),

    # -----------------------------------------------------
    # DATA EXFILTRATION ATTEMPTS
    # -----------------------------------------------------
    (
        "data_exfiltration",
        re.compile(
            r"(database|db)\s*(dump|export|extract)|"
            r"(all\s+users|all\s+records|full\s+table)",
            re.I,
        ),
        SeverityLevel.HIGH,
        0.80,
    ),
]


# =========================================================
# MAIN DETECTOR
# =========================================================

_EDU_QUESTION = re.compile(
    r"^\s*(?:please\s+|can\s+you\s+|could\s+you\s+)?(?:explain|define|describe|what(?:'s|\s+is|\s+are|\s+does)|why|"
    r"how\s+(?:does|do|can|to)\b[^.?\n]{0,50}\b(?:prevent|stop|work|detect|defend|mitigate|protect|block))",
    re.I,
)
_CODE_ATTACK_LABELS = ("sql", "xss", "script", "command", "shell", "path_traversal")


def detect_suspicious_patterns(content: str) -> List[DetectionMatch]:

    findings: List[DetectionMatch] = []

    text = _normalize(content)
    # Teaching about an attack class ("what is SQL injection and how do prepared statements stop
    # it?") is not an attack. Only code-attack labels are exempted, and only for pure questions.
    educational_question = bool(_EDU_QUESTION.search(text))

    total_risk = 0.0

    # -----------------------------------------------------
    # PATTERN MATCHING
    # -----------------------------------------------------
    for label, pattern, severity, confidence in SUSPICIOUS_PATTERNS:

        if pattern.search(text):
            if educational_question and any(tag in label for tag in _CODE_ATTACK_LABELS):
                continue

            findings.append(
                DetectionMatch(
                    detector="suspicious_pattern",
                    label=label,
                    reason=f"Suspicious pattern detected: {label}",
                    confidence=confidence,
                    severity=severity,
                    metadata={"pattern": pattern.pattern},
                )
            )

            # accumulate risk
            total_risk += confidence

    # -----------------------------------------------------
    # ESCALATION LOGIC (IMPORTANT FIX)
    # -----------------------------------------------------
    if len(findings) >= 2:

        findings.append(
            DetectionMatch(
                detector="suspicious_pattern",
                label="multi_vector_attack",
                reason="Multiple attack patterns detected",
                confidence=min(0.95, total_risk),
                severity=SeverityLevel.CRITICAL,
                metadata={
                    "pattern_count": len(findings),
                    "risk_score": round(total_risk, 4),
                },
            )
        )

    return findings