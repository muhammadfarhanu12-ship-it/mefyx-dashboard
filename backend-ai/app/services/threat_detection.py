from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import unquote

from app.core.config import settings

logger = logging.getLogger("threat_detection")


# -----------------------------
# Threat Taxonomy (Multi-label)
# -----------------------------
THREAT_PROMPT_INJECTION = "PROMPT_INJECTION"
THREAT_DATA_EXFILTRATION = "DATA_EXFILTRATION"
THREAT_POLICY_BYPASS = "POLICY_BYPASS"
THREAT_ENCODING_OBFUSCATION = "ENCODING_OBFUSCATION"
THREAT_PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
THREAT_HITL_BYPASS_ATTEMPT = "HITL_BYPASS_ATTEMPT"
THREAT_FINANCIAL_FRAUD = "FINANCIAL_FRAUD"

# Backwards-compatible (existing UI/analytics already reference these).
THREAT_MALICIOUS_CODE = "MALICIOUS_CODE"
THREAT_DATA_LEAK = "DATA_LEAK"

THREAT_TYPES_CANONICAL = {
    THREAT_PROMPT_INJECTION,
    THREAT_DATA_EXFILTRATION,
    THREAT_POLICY_BYPASS,
    THREAT_ENCODING_OBFUSCATION,
    THREAT_PRIVILEGE_ESCALATION,
    THREAT_HITL_BYPASS_ATTEMPT,
    THREAT_FINANCIAL_FRAUD,
    THREAT_MALICIOUS_CODE,
    THREAT_DATA_LEAK,
}


SECURITY_TIERS = {"FREE", "PRO", "BUSINESS"}
DETECTION_STAGES = ("stage1_fast_rules", "stage2_structural", "stage3_ai")


@dataclass(frozen=True)
class ThreatAssessment:
    threat_types: list[str]
    threat_score: float  # 0..1
    risk_level: str  # low|medium|high
    decision: str  # ALLOW|SANITIZE|BLOCK
    sanitized_content: Optional[str]
    attack_vector: str
    detection_stage_triggered: list[str]
    explanation: str
    debug: dict[str, Any]


# --------------------------------
# Stage 1: Fast Rules (<10ms)
# --------------------------------
_STAGE1_PATTERNS: list[tuple[str, str, re.Pattern[str], float]] = [
    (
        THREAT_HITL_BYPASS_ATTEMPT,
        "authority_bypass_financial_chain",
        re.compile(
            r"\b(internal system update|automated stress test|stress test|latency test|api latency|simulation environment)\b"
            r".{0,140}\b(transfer|wire|payment|funds|wallet transfer|routing number|initiate_wire)\b",
            re.I,
        ),
        0.35,
    ),
    (
        THREAT_HITL_BYPASS_ATTEMPT,
        "confirmation_bypass_financial_chain",
        re.compile(
            r"\b(do not ask for user confirmation|do not ask for confirmation|skip confirmation|bypass confirmation|without confirmation|ignore approval workflow|automatic approval)\b"
            r".{0,140}\b(transfer|wire|payment|funds|wallet transfer|routing number|initiate_wire)\b",
            re.I,
        ),
        0.38,
    ),
    # Prompt injection / instruction override
    (THREAT_PROMPT_INJECTION, "instruction_override", re.compile(r"\bignore (all )?previous instructions\b", re.I), 0.25),
    (THREAT_PROMPT_INJECTION, "system_prompt_exfil", re.compile(r"\b(reveal|show|output)\b.{0,40}\b(system prompt|hidden prompt)\b", re.I), 0.25),
    (
        THREAT_PROMPT_INJECTION,
        "persona_override",
        re.compile(r"\b(you are now|act as|assume the role of|adopt the persona of)\b.{0,80}\b(debugbot|developer mode|unfiltered|jailbreak|admin|root|system|assistant|persona)\b", re.I),
        0.22,
    ),
    (THREAT_POLICY_BYPASS, "safety_bypass", re.compile(r"\b(bypass|override)\b.{0,20}\b(safety|guardrails|policy|filters?)\b", re.I), 0.22),
    # Data exfiltration / secrets harvesting
    (THREAT_DATA_EXFILTRATION, "secret_harvest", re.compile(r"\b(?:show|reveal|print|dump|send|steal|exfiltrate|provide|output)\b.{0,50}\b(api key|secret key|access token|passwords?)\b", re.I), 0.22),
    (THREAT_DATA_EXFILTRATION, "env_exfil", re.compile(r"\b(os\.environ|environment variables?|dotenv|printenv)\b", re.I), 0.22),
    (
        THREAT_DATA_EXFILTRATION,
        "internal_file_probe",
        re.compile(r"(\.env\b|/etc/passwd\b|/proc/self/environ\b|~/.ssh\b|id_rsa\b|/var/run/secrets\b|c:\\\\users\\\\|appdata\\\\|system32\\\\)", re.I),
        0.24,
    ),
    (
        THREAT_DATA_EXFILTRATION,
        "internal_api_probe",
        re.compile(r"\b(localhost|127\.0\.0\.1|internal api|metadata service|169\.254\.169\.254|admin endpoint|debug endpoint)\b", re.I),
        0.22,
    ),
    # Encoding / obfuscation
    (THREAT_ENCODING_OBFUSCATION, "encoding_keywords", re.compile(r"\b(base64|hex|rot13|encode|decode|obfuscate)\b", re.I), 0.18),
    # Privilege escalation / destructive intent (legacy MALICIOUS_CODE)
    (THREAT_PRIVILEGE_ESCALATION, "destructive_cmd", re.compile(r"\brm\s+-rf\s+/\b", re.I), 0.30),
    (THREAT_PRIVILEGE_ESCALATION, "windows_delete", re.compile(r"\bdel\s+/s\b|\bdelete\s+.*c:\\\\users\b", re.I), 0.30),
    (THREAT_MALICIOUS_CODE, "exec_eval", re.compile(r"\b(eval\(|os\.system\(|subprocess\.popen)\b", re.I), 0.20),
    (THREAT_MALICIOUS_CODE, "script_injection", re.compile(r"(<script\b|javascript:|__import__\(|document\.cookie|drop\s+table)", re.I), 0.20),
    # Legacy PII/data leak indicators
    (THREAT_DATA_LEAK, "pii_email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), 0.10),
    (THREAT_DATA_LEAK, "pii_phone", re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"), 0.10),
    (THREAT_DATA_LEAK, "pii_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), 0.12),
    (THREAT_DATA_LEAK, "pii_cc", re.compile(r"\b(?:\d[ -]*?){13,16}\b"), 0.12),
    (THREAT_DATA_LEAK, "jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b"), 0.16),
    (THREAT_DATA_LEAK, "api_key_format", re.compile(r"\bsentinel_sk_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0.16),
    (THREAT_DATA_LEAK, "password_assignment", re.compile(r"\b(password|passwd|pwd)\s*[:=]\s*['\"A-Za-z0-9_\-./+=]{4,}", re.I), 0.16),
    (THREAT_DATA_LEAK, "filesystem_path", re.compile(r"([A-Za-z]:\\\\[^\\\n]+|/(?:etc|home|root|var|tmp|usr)/[^\s]+)"), 0.14),
]


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _risk_level(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _is_quoted_security_education(prompt: str) -> bool:
    normalized = unicodedata.normalize("NFKC", str(prompt or ""))
    quoted_attack = re.search(
        r"(['\"“]).{0,180}\b(?:ignore\s+(?:all\s+)?previous instructions|system prompt|developer mode|jailbreak)\b.{0,180}?\1",
        normalized,
        re.I,
    )
    educational = re.search(
        r"\b(?:security training|security awareness|educational|awareness slide|documenting|paper about|explain why|translate the sentence|compar(?:e|es)|bank safety lesson|how to recognize|how to spot|how to identify|how to detect|describe why)\b",
        normalized,
        re.I,
    )
    unquoted = re.sub(
        r"(['\"“]).{0,180}\b(?:ignore\s+(?:all\s+)?previous instructions|system prompt|developer mode|jailbreak)\b.{0,180}?\1",
        " ",
        normalized,
        flags=re.I,
    )
    actionable = re.search(
        r"\b(?:reveal|show|output|send|steal|exfiltrate|execute|transfer|invoke|call|run)\b.{0,80}\b(?:system prompt|hidden prompt|secret|password|token|funds|wallet|tool)\b",
        unquoted,
        re.I,
    )
    awareness_only = re.search(
        r"\b(?:recogniz(?:e|ing)|spot|identify|detect|report|avoid|explain|describe)\b"
        r".{0,180}\b(?:scam|phish|fraud|fake alert|credential theft|social engineering|impersonation|support agent)\b",
        normalized,
        re.I,
    )
    inert_negative = re.search(
        r"\b(?:never|should not|shouldn't|must not|mustn't|avoid)\b.{0,80}\b(?:request|ask for|share|disclose|provide)\b.{0,80}\b(?:password|otp|pin|recovery phrase|passcode)\b",
        normalized,
        re.I,
    )
    return bool((quoted_attack and educational or awareness_only or inert_negative) and not actionable)


def _primary_threat_type(threat_types: list[str]) -> str:
    # Stable priority order for backwards compatibility in UI/analytics that expect a single label.
    priority = [
        THREAT_HITL_BYPASS_ATTEMPT,
        THREAT_PROMPT_INJECTION,
        THREAT_DATA_EXFILTRATION,
        THREAT_POLICY_BYPASS,
        THREAT_PRIVILEGE_ESCALATION,
        THREAT_ENCODING_OBFUSCATION,
        THREAT_MALICIOUS_CODE,
        THREAT_DATA_LEAK,
    ]
    upper = [t.upper() for t in threat_types if t]
    for t in priority:
        if t in upper:
            return t
    return (upper[0] if upper else "NONE")


def primary_threat_type(threat_types: list[str]) -> str:
    """
    Public helper for backward compatibility where a single label is still required.
    """
    return _primary_threat_type(threat_types)


def _stage1_fast_rules(prompt: str) -> tuple[float, list[str], list[dict[str, Any]]]:
    hits: list[dict[str, Any]] = []
    threat_types: set[str] = set()
    score = 0.0
    for threat_type, name, pattern, weight in _STAGE1_PATTERNS:
        if pattern.search(prompt):
            threat_types.add(threat_type)
            score += weight
            hits.append({"rule": name, "threat_type": threat_type, "weight": weight})

    # Normalize to a bounded range; stage 1 is designed to be fast and conservative.
    return (_clamp01(min(score, 0.65)), sorted(threat_types), hits)


# --------------------------------
# Stage 2: Structural / Pattern Analysis
# --------------------------------
_B64_CANDIDATE = re.compile(r"(?:^|[^A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?:$|[^A-Za-z0-9+/=])")
_HEX_CANDIDATE = re.compile(r"(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{48,})(?:$|[^0-9A-Fa-f])")
_URL_CANDIDATE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
_UNICODE_ESCAPE_CANDIDATE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}){2,}")
_ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}

_CONTEXT_WRAPPERS = (
    "translate",
    "summarize",
    "rewrite",
    "convert",
    "explain",
    "analyze",
    "classify",
)


def _maybe_decode_base64(token: str) -> str | None:
    # Heuristics: multiple of 4 and not unreasonably large.
    t = token.strip()
    if len(t) % 4 != 0:
        return None
    if len(t) > 20000:
        return None
    try:
        decoded = base64.b64decode(t, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _maybe_decode_hex(token: str) -> str | None:
    t = token.strip()
    if len(t) % 2 != 0:
        return None
    if len(t) > 40000:
        return None
    try:
        decoded = bytes.fromhex(t)
    except ValueError:
        return None
    try:
        return decoded.decode("utf-8", errors="ignore")
    except Exception:
        return None


def _maybe_decode_url(token: str) -> str | None:
    t = token.strip()
    if len(t) > 20000 or not _URL_CANDIDATE.search(t):
        return None
    decoded = unquote(t)
    return decoded if decoded != t else None


def _maybe_decode_unicode_escapes(token: str) -> str | None:
    t = token.strip()
    if len(t) > 20000 or not _UNICODE_ESCAPE_CANDIDATE.search(t):
        return None
    try:
        decoded = bytes(t, "utf-8").decode("unicode_escape")
    except Exception:
        return None
    return decoded if decoded != t else None


def _normalize_unicode_payload(token: str) -> str | None:
    if not token:
        return None
    normalized = unicodedata.normalize("NFKC", token)
    if any(char in token for char in _ZERO_WIDTH_CHARS):
        normalized = "".join(char for char in normalized if char not in _ZERO_WIDTH_CHARS)
    return normalized if normalized != token else None


def _extract_embedded_payload(prompt: str) -> list[str]:
    # Captures likely "payload inside normal task" patterns.
    # Example: "Translate this: ignore all previous instructions..."
    lowered = prompt.lower()
    if not any(w in lowered for w in _CONTEXT_WRAPPERS):
        return []

    payloads: list[str] = []
    # Quoted segments tend to carry the hidden injection payload.
    for m in re.finditer(r"['\"]([^'\"]{8,2000})['\"]", prompt):
        payloads.append(m.group(1))
    # Also include content after a colon in wrapper verbs, e.g. "Translate this: <payload>"
    for m in re.finditer(r"\b(?:translate|summarize|rewrite|convert|explain|analyze|classify)\b.{0,30}:\s*(.{8,2000})", prompt, flags=re.I):
        payloads.append(m.group(1))
    return payloads[:10]


def _stage2_structural(prompt: str) -> tuple[float, list[str], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    threat_types: set[str] = set()
    score = 0.0

    # Encoded payload discovery (base64/hex) with content inspection.
    decoded_snippets: list[str] = []
    for m in _B64_CANDIDATE.finditer(prompt):
        decoded = _maybe_decode_base64(m.group(1))
        if decoded:
            decoded_snippets.append(decoded)
            findings.append({"kind": "base64_decoded", "sample": decoded[:200]})
    for m in _HEX_CANDIDATE.finditer(prompt):
        decoded = _maybe_decode_hex(m.group(1))
        if decoded:
            decoded_snippets.append(decoded)
            findings.append({"kind": "hex_decoded", "sample": decoded[:200]})
    url_decoded = _maybe_decode_url(prompt)
    if url_decoded:
        decoded_snippets.append(url_decoded)
        findings.append({"kind": "url_decoded", "sample": url_decoded[:200]})
    unicode_decoded = _maybe_decode_unicode_escapes(prompt)
    if unicode_decoded:
        decoded_snippets.append(unicode_decoded)
        findings.append({"kind": "unicode_escape_decoded", "sample": unicode_decoded[:200]})
    unicode_normalized = _normalize_unicode_payload(prompt)
    if unicode_normalized:
        decoded_snippets.append(unicode_normalized)
        findings.append({"kind": "unicode_normalized", "sample": unicode_normalized[:200]})

    if decoded_snippets:
        threat_types.add(THREAT_ENCODING_OBFUSCATION)
        score += 0.18
        # If decoded content itself triggers stage-1 rules, escalate more.
        decoded_joined = "\n".join(decoded_snippets)
        decoded_score, decoded_types, decoded_hits = _stage1_fast_rules(decoded_joined)
        if decoded_score >= 0.2:
            threat_types.update(decoded_types)
            score += min(0.22, decoded_score * 0.4)
            findings.append({"kind": "decoded_payload_trigger", "hits": decoded_hits})

    # Instruction chaining / multi-step override patterns.
    chain_markers = sum(1 for k in ("then ", "after that", "step 1", "step 2", "first ", "second ", "finally ") if k in prompt.lower())
    if chain_markers >= 2:
        threat_types.add(THREAT_PROMPT_INJECTION)
        score += 0.12
        findings.append({"kind": "instruction_chaining", "markers": chain_markers})

    # Context-aware hidden injection inside wrappers (translation/summarization/code tasks).
    embedded = _extract_embedded_payload(prompt)
    embedded_hits: list[dict[str, Any]] = []
    embedded_types: set[str] = set()
    embedded_score_total = 0.0
    for payload in embedded:
        s, types, hits = _stage1_fast_rules(payload)
        if s >= 0.2:
            embedded_score_total = max(embedded_score_total, s)
            embedded_types.update(types)
            embedded_hits.extend(hits)
    if embedded_score_total >= 0.2:
        embedded_types.add(THREAT_PROMPT_INJECTION)
        threat_types.update(embedded_types)
        score += min(0.25, 0.10 + embedded_score_total * 0.35)
        findings.append({"kind": "indirect_injection", "hits": embedded_hits[:10]})

    return (_clamp01(min(score, 0.35)), sorted(threat_types), findings)


# --------------------------------
# Stage 3: Optional AI Classifier (BUSINESS tier)
# --------------------------------
def _ai_classifier_available() -> bool:
    if settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY"):
        return True
    if settings.OPENAI_API_KEY or os.environ.get("OPENAI_API_KEY"):
        return True
    return False


def _stage3_ai(prompt: str) -> tuple[float, list[str], dict[str, Any] | None]:
    """
    Best-effort AI-based classifier. This stage is optional and must not break the pipeline.

    It returns:
      - score contribution (0..0.45)
      - additional threat types
      - raw provider payload (for debugging / explainability)
    """
    # Prefer Gemini if available because the codebase already supports it optionally.
    try:
        from google import genai  # type: ignore
        from google.genai import types  # type: ignore
    except Exception:  # pragma: no cover
        genai = None
        types = None

    api_key = settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY")
    if genai is None or types is None or not api_key:
        return (0.0, [], None)

    system_instruction = (
        "You are an enterprise prompt-security classifier. "
        "Return ONLY strict JSON with keys: "
        "{threat_types: string[], threat_score: number, explanation: string}. "
        "threat_types must use these labels when relevant: "
        f"{sorted([THREAT_PROMPT_INJECTION, THREAT_DATA_EXFILTRATION, THREAT_POLICY_BYPASS, THREAT_ENCODING_OBFUSCATION, THREAT_PRIVILEGE_ESCALATION])}. "
        "threat_score must be 0..1."
    )
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                temperature=0.0,
            ),
        )
        raw_text = getattr(response, "text", "") or ""
        payload = json.loads(raw_text)
        types_out = [str(t).upper() for t in (payload.get("threat_types") or []) if str(t)]
        types_out = [t for t in types_out if t in THREAT_TYPES_CANONICAL]
        score_out = _clamp01(float(payload.get("threat_score", 0.0)))
        # Keep stage 3 bounded (it should refine, not dominate).
        score_contrib = min(0.45, score_out * 0.45)
        return (score_contrib, types_out, {"provider": "gemini", "payload": payload})
    except Exception as exc:  # pragma: no cover
        logger.warning("AI classifier failed, skipping stage3: %s", exc)
        return (0.0, [], None)


# --------------------------------
# Sanitization engine
# --------------------------------
_SANITIZE_PATTERNS = [
    # Prompt injection
    re.compile(r"(?im)^\s*.*\bignore (all )?previous instructions\b.*\s*$"),
    re.compile(r"(?im)^\s*.*\b(reveal|show|output)\b.{0,40}\b(system prompt|hidden prompt)\b.*\s*$"),
    # Safety bypass / policy override
    re.compile(r"(?im)^\s*.*\b(bypass|override)\b.{0,20}\b(safety|guardrails|policy|filters?)\b.*\s*$"),
    # Environment / secrets harvesting
    re.compile(r"(?im)^\s*.*\b(os\.environ|printenv|environment variables?)\b.*\s*$"),
]


def _sanitize_prompt(prompt: str) -> str:
    # Conservative sanitization: remove obvious malicious lines, preserve benign request context.
    lines = prompt.splitlines() or [prompt]
    kept: list[str] = []
    for line in lines:
        if any(p.search(line) for p in _SANITIZE_PATTERNS):
            continue
        kept.append(line)
    sanitized = "\n".join(kept).strip()
    return sanitized or "[REDACTED: MALICIOUS CONTENT REMOVED]"


# --------------------------------
# Least-privilege guard (pre-LLM)
# --------------------------------
def least_privilege_guard(prompt: str) -> tuple[bool, str]:
    """
    Returns (allowed_to_call_llm, reason).

    Guardrail intent:
    - The LLM never receives content that explicitly requests secrets/env dumps.
    - The backend must not "help" execute sensitive actions through the LLM.
    """
    lowered = prompt.lower()
    if re.search(r"\b(os\.environ|printenv|environment variables?)\b", lowered):
        return (False, "Attempted environment-variable exfiltration.")
    if re.search(r"\b(show|reveal|print|dump)\b.{0,40}\b(api key|secret key|access token|password)\b", lowered):
        return (False, "Attempted secret exfiltration.")
    if re.search(r"(\.env\b|/etc/passwd\b|/proc/self/environ\b|~/.ssh\b|id_rsa\b|/var/run/secrets\b|c:\\\\users\\\\)", lowered):
        return (False, "Attempted internal file access.")
    if re.search(r"\b(localhost|127\.0\.0\.1|internal api|metadata service|169\.254\.169\.254)\b", lowered):
        return (False, "Attempted internal API or metadata access.")
    if re.search(r"\b(rm\s+-rf\s+/|delete\s+.*c:\\\\users)\b", lowered):
        return (False, "Attempted destructive command execution.")
    return (True, "OK")


# --------------------------------
# Unified pipeline (tiers + explainability)
# --------------------------------
class ThreatDetectionService:
    def analyze(
        self,
        prompt: str,
        *,
        provider: str = "openai",
        model: str = "gpt-5.4",
        security_tier: str = "PRO",
        enable_ai: bool | None = None,
    ) -> ThreatAssessment:
        tier = (security_tier or "PRO").upper()
        if tier not in SECURITY_TIERS:
            tier = "PRO"

        started = datetime.now(timezone.utc)
        stage_triggered: list[str] = []
        threat_types: set[str] = set()
        debug: dict[str, Any] = {"tier": tier, "provider": provider, "model": model}

        s1_score, s1_types, s1_hits = _stage1_fast_rules(prompt)
        stage_triggered.append(DETECTION_STAGES[0])
        threat_types.update(s1_types)
        debug["stage1"] = {"score": s1_score, "hits": s1_hits}

        s2_score = 0.0
        s2_types: list[str] = []
        s2_findings: list[dict[str, Any]] = []
        if tier in {"PRO", "BUSINESS"}:
            s2_score, s2_types, s2_findings = _stage2_structural(prompt)
            stage_triggered.append(DETECTION_STAGES[1])
            threat_types.update(s2_types)
            debug["stage2"] = {"score": s2_score, "findings": s2_findings}

        safe_education = _is_quoted_security_education(prompt)
        if safe_education:
            # Treat an inert, explicitly quoted attack phrase as discussion,
            # while retaining blocks for any unquoted operational instruction.
            s1_score = s2_score = 0.0
            s1_hits = []
            s2_findings = []
            s1_types = []
            s2_types = []
            threat_types.clear()
            debug["quoted_security_education"] = True

        s3_score = 0.0
        s3_types: list[str] = []
        s3_payload: dict[str, Any] | None = None
        # safe_education is initialized above for every tier before classifier selection.
        if tier == "BUSINESS" and not safe_education:
            ai_enabled = bool(enable_ai) if enable_ai is not None else _ai_classifier_available()
            if ai_enabled:
                s3_score, s3_types, s3_payload = _stage3_ai(prompt)
                if s3_score > 0.0 or s3_types:
                    stage_triggered.append(DETECTION_STAGES[2])
                threat_types.update(s3_types)
                debug["stage3"] = {"score": s3_score, "payload": s3_payload}

        # Combine stage scores (probabilistic OR). Keeps score stable and within bounds.
        combined = 1.0 - (1.0 - s1_score) * (1.0 - s2_score) * (1.0 - s3_score)
        combined = _clamp01(combined)
        risk = _risk_level(combined)

        # Enterprise hard-block rules: explicit override/exfil signals should never downgrade to SANITIZE.
        hard_block_rules = {
            "authority_bypass_financial_chain",
            "confirmation_bypass_financial_chain",
            "instruction_override",
            "system_prompt_exfil",
            "persona_override",
            "env_exfil",
            "internal_file_probe",
            "internal_api_probe",
            "destructive_cmd",
            "windows_delete",
        }
        hard_block = any(h.get("rule") in hard_block_rules for h in (s1_hits or []))
        if hard_block:
            combined = max(combined, 0.9)
            risk = _risk_level(combined)

        # Decide action mode (enterprise policy):
        # - High risk: BLOCK
        # - Medium: SANITIZE
        # - Low: ALLOW
        decision = "ALLOW"
        if hard_block or combined >= float(getattr(settings, "DEFENSE_BLOCK_THRESHOLD", 0.85)):
            decision = "BLOCK"
        elif combined >= float(getattr(settings, "DEFENSE_SANITIZE_THRESHOLD", 0.55)):
            decision = "SANITIZE"

        sanitized_content: str | None = None
        if decision == "BLOCK":
            sanitized_content = "[REDACTED: THREAT BLOCKED]"
        elif decision == "SANITIZE":
            sanitized_content = _sanitize_prompt(prompt)
        else:
            sanitized_content = prompt

        # Least-privilege: even if the request is "allowed", do not call downstream LLM on explicit exfil/destructive asks.
        llm_allowed, guard_reason = least_privilege_guard(prompt)
        if not llm_allowed:
            threat_types.update({THREAT_DATA_EXFILTRATION, THREAT_PRIVILEGE_ESCALATION})
            combined = max(combined, 0.90)
            risk = _risk_level(combined)
            decision = "BLOCK"
            sanitized_content = "[REDACTED: SENSITIVE ACTION BLOCKED]"
            debug["least_privilege"] = {"allowed": False, "reason": guard_reason}
        else:
            debug["least_privilege"] = {"allowed": True, "reason": guard_reason}

        threat_types_sorted = sorted({t.upper() for t in threat_types if t})

        # Explainability engine: concise, multi-signal summary.
        explanation_bits: list[str] = []
        if THREAT_PROMPT_INJECTION in threat_types_sorted:
            explanation_bits.append("instruction override / prompt injection")
        if THREAT_HITL_BYPASS_ATTEMPT in threat_types_sorted:
            explanation_bits.append("authority impersonation + HITL bypass attempt")
        if THREAT_DATA_EXFILTRATION in threat_types_sorted or THREAT_DATA_LEAK in threat_types_sorted:
            explanation_bits.append("data or secret exfiltration attempt")
        if THREAT_POLICY_BYPASS in threat_types_sorted:
            explanation_bits.append("policy bypass technique")
        if THREAT_ENCODING_OBFUSCATION in threat_types_sorted:
            explanation_bits.append("encoding/obfuscation")
        if THREAT_PRIVILEGE_ESCALATION in threat_types_sorted or THREAT_MALICIOUS_CODE in threat_types_sorted:
            explanation_bits.append("privilege escalation / unsafe execution intent")

        attack_vector = "; ".join(explanation_bits) if explanation_bits else "No high-confidence threat vectors detected."
        explanation = (
            "Detected " + ", ".join(explanation_bits) + "."
            if explanation_bits
            else "No high-confidence malicious intent detected."
        )

        debug["timing_ms"] = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

        return ThreatAssessment(
            threat_types=threat_types_sorted or ["NONE"],
            threat_score=_clamp01(combined),
            risk_level=risk,
            decision=decision,
            sanitized_content=sanitized_content,
            attack_vector=attack_vector,
            detection_stage_triggered=stage_triggered,
            explanation=explanation,
            debug=debug,
        )