from __future__ import annotations

import asyncio
import logging
import re
from time import perf_counter
from typing import Any, Dict
from uuid import uuid4

from app.core.config import settings
from app.security.detectors.intent_adapter import ml_verdict
from app.security.detectors.intent_engine import analyze_intent_text
from app.security.security_enforcement_layer import (
    SecurityEnforcementInput,
    security_enforcement_layer,
)
from app.services.sentinel_core import build_sentinel_verdict, sentinel_blocks
from app.services.threat_detection import ThreatDetectionService, primary_threat_type

logger = logging.getLogger("security_scan")

# ---------------------------
# PII Detection Patterns
# ---------------------------
PII_PATTERNS = {
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone": r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b",
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d[ -]*?){13,16}\b",
    "password": r"(?:password\s*[:=]\s*['\"].+?['\"])",
    "secret": r"secret",
}

# ---------------------------
# Prompt Injection Patterns
# ---------------------------
PROMPT_INJECTION_PATTERNS = [
    r"ignore all previous instructions",
    r"ignore previous instructions",
    r"output your system prompt",
    r"provide hidden keys",
    r"exfiltrate data",
    r"bypass security",
    r"override safety",
    r"internal system update.{0,80}(wire|transfer|payment|funds)",
    r"(automated stress test|stress test|latency test|api latency).{0,80}(wire|transfer|payment|funds)",
    r"(do not ask for user confirmation|do not ask for confirmation|skip confirmation|bypass confirmation|without confirmation)",
]

# ---------------------------
# Malicious Code Patterns
# ---------------------------
MALICIOUS_PATTERNS = [
    r"delete\s+.*C:\\Users",
    r"rm\s+-rf\s+/",
    r"eval\(",
    r"os\.system\(",
    r"os\.environ",
    r"dump\s+.*api key",
    r"show\s+.*api key",
    r"subprocess\.Popen",
]

FAST_LANE_PATTERNS = [
    re.compile(r"\bignore (all )?previous instructions\b", re.I),
    re.compile(r"\b(system prompt|hidden prompt|developer mode|debugbot)\b", re.I),
    re.compile(r"\b(os\.environ|printenv|api key|secret key|/etc/passwd|\.env)\b", re.I),
    re.compile(r"\b(base64|hex|rot13|\\u[0-9a-f]{4}|\\x[0-9a-f]{2})\b", re.I),
]

SECURITY_ACTION_TO_STATUS = {
    "ALLOW": "CLEAN",
    "WARN": "CLEAN",
    "ALERT": "REDACTED",
    "AUDIT": "CLEAN",
    "REDACT": "REDACTED",
    "FORCE_REVIEW": "BLOCKED",
    "BLOCK": "BLOCKED",
    "INTERCEPT_AND_FORCE_2FA": "BLOCKED",
}

SECURITY_ACTION_TO_DECISION = {
    "ALLOW": "ALLOW",
    "WARN": "ALLOW",
    "ALERT": "SANITIZE",
    "AUDIT": "ALLOW",
    "REDACT": "SANITIZE",
    "FORCE_REVIEW": "BLOCK",
    "BLOCK": "BLOCK",
    "INTERCEPT_AND_FORCE_2FA": "BLOCK",
}


def detect_injection(prompt: str) -> bool:
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, prompt, flags=re.IGNORECASE):
            return True
    return False


def detect_hitl_bypass_attempt(prompt: str) -> bool:
    normalized = str(prompt or "").lower()
    financial_terms = ("wire", "transfer", "payment", "funds", "wallet", "routing number", "initiate_wire")
    bypass_terms = (
        "do not ask for user confirmation",
        "do not ask for confirmation",
        "skip confirmation",
        "bypass confirmation",
        "without confirmation",
        "ignore approval workflow",
        "automatic approval",
    )
    authority_terms = (
        "internal system update",
        "automated stress test",
        "stress test",
        "latency test",
        "api latency",
        "system maintenance",
        "simulation environment",
    )

    has_financial = any(term in normalized for term in financial_terms)
    has_bypass = any(term in normalized for term in bypass_terms)
    has_authority_cover = any(term in normalized for term in authority_terms)
    return bool(has_financial and (has_bypass or has_authority_cover))


def detect_malicious(prompt: str) -> bool:
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, prompt, flags=re.IGNORECASE):
            return True
    return False


def scan_pii(prompt: str) -> bool:
    for pattern in PII_PATTERNS.values():
        if re.search(pattern, prompt, flags=re.IGNORECASE):
            return True
    return False


def redact_sensitive_data(prompt: str) -> str:
    sanitized = prompt
    for key, pattern in PII_PATTERNS.items():
        sanitized = re.sub(pattern, f"[REDACTED_{key.upper()}]", sanitized, flags=re.IGNORECASE)
    return sanitized


def classify_threat(prompt: str) -> str:
    if detect_hitl_bypass_attempt(prompt):
        return "HITL_BYPASS_ATTEMPT"
    if detect_injection(prompt):
        return "PROMPT_INJECTION"
    if detect_malicious(prompt):
        return "MALICIOUS_CODE"
    if scan_pii(prompt):
        return "DATA_LEAK"
    return "NONE"


def _risk_level_from_score(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _looks_like_low_risk_education(text: str, enforcement_payload: dict[str, Any] | None) -> bool:
    normalized = str(text or "").lower()
    if not any(term in normalized for term in ("article", "awareness", "educational", "explains", "discusses", "user education", "training")):
        return False
    if any(term in normalized for term in ("send money", "transfer tokens", "private key", "seed phrase", "call transfer", "execute payment", "withdraw all")):
        return False
    enforcement_payload = enforcement_payload or {}
    action = str(enforcement_payload.get("action") or "ALLOW").upper()
    risk = int(enforcement_payload.get("risk_score") or 0)
    categories = set(_rich_indirect_fields(enforcement_payload).get("detected_categories") or [])
    dangerous_categories = {"financial_action", "crypto_transfer", "credential_access", "tool_execution_request", "data_exfiltration"}
    return action in {"ALLOW", "WARN"} and risk <= 45 and not (categories & dangerous_categories)


def _serialize_enforcement_result(enforcement: Any) -> dict[str, Any]:
    if enforcement is None:
        return {}
    decode = enforcement.decode_result
    return {
        "correlation_id": enforcement.correlation_id,
        "action": enforcement.action.value,
        "severity": enforcement.severity.value,
        "risk_score": enforcement.risk_score,
        "confidence": enforcement.confidence,
        "requires_2fa": enforcement.requires_2fa,
        "review_required": enforcement.review_required,
        "session_id": enforcement.session_id,
        "conversation_id": enforcement.conversation_id,
        "sanitized_prompt": enforcement.sanitized_prompt,
        "wrapped_untrusted_content": enforcement.wrapped_untrusted_content,
        "detections": [
            {
                "detector": finding.detector,
                "label": finding.label,
                "reason": finding.reason,
                "confidence": finding.confidence,
                "severity": finding.severity.value,
                "metadata": finding.metadata,
            }
            for finding in (enforcement.detections or [])
        ],
        "policy_matches": [
            {
                "policy_name": policy.policy_name,
                "policy_version": policy.policy_version,
                "action": policy.action.value,
                "severity": policy.severity.value,
                "score": policy.score,
                "matched_keywords": policy.matched_keywords,
                "matched_bypass_phrases": policy.matched_bypass_phrases,
                "metadata": policy.metadata,
            }
            for policy in (enforcement.policy_matches or [])
        ],
        "decode": {
            "content": getattr(decode, "content", ""),
            "max_depth_reached": getattr(decode, "max_depth_reached", 0),
            "timed_out": bool(getattr(decode, "timed_out", False)),
            "truncated": bool(getattr(decode, "truncated", False)),
            "artifacts": [
                {
                    "encoding": artifact.encoding,
                    "depth": artifact.depth,
                    "entropy_before": artifact.entropy_before,
                    "entropy_after": artifact.entropy_after,
                    "suspicious": artifact.suspicious,
                    "original_fragment": artifact.original_fragment[:220],
                    "decoded_fragment": artifact.decoded_fragment[:220],
                }
                for artifact in (getattr(decode, "artifacts", []) or [])
            ],
        }
        if decode is not None
        else None,
        "tool_interception": dict(enforcement.tool_interception or {}),
        "context_summary": dict(enforcement.context_summary or {}),
        "telemetry": dict(enforcement.telemetry or {}),
        "output_findings": [
            {
                "finding_type": finding.finding_type,
                "value_preview": finding.value_preview,
                "confidence": finding.confidence,
                "severity": finding.severity.value,
                "action": finding.action.value,
                "masked_value": finding.masked_value,
                "metadata": finding.metadata,
            }
            for finding in (enforcement.output_findings or [])
        ],
        "explanation": enforcement.explanation,
    }


def _threat_types_from_enforcement(enforcement_payload: dict[str, Any]) -> list[str]:
    threat_types: set[str] = set()

    hitl_bypass_confirmation_terms = {
        "do not ask for confirmation",
        "do not ask for user confirmation",
        "skip confirmation",
        "bypass confirmation",
        "no verification needed",
        "no approval needed",
    }
    hitl_bypass_financial_terms = {
        "transfer",
        "wire",
        "payment",
        "send money",
        "move funds",
        "funds",
    }
    hitl_bypass_authority_terms = {
        "automated",
        "system update",
        "internal system update",
        "stress test",
        "latency update",
        "test the api latency",
    }

    for finding in enforcement_payload.get("detections", []) or []:
        label = str(finding.get("label") or "").lower()
        detector = str(finding.get("detector") or "").lower()
        reason = str(finding.get("reason") or "").lower()
        metadata = finding.get("metadata") if isinstance(finding.get("metadata"), dict) else {}
        # An indirect-injection finding whose own verdict is "allow" or "warn" below the
        # block threshold is informational. Previously only "warn" was exempt, so a
        # detector reporting "No indirect prompt injection signals detected" still
        # forced PROMPT_INJECTION (and therefore BLOCK) on benign finance/code prompts.
        low_risk_indirect_warning = (
            detector == "indirect_prompt_injection_detector"
            and str(metadata.get("verdict") or "").lower() in {"allow", "warn"}
            and int(metadata.get("risk_score") or 0) < 71
        )
        blob = " ".join([label, detector, reason])
        if not low_risk_indirect_warning and any(token in blob for token in ("jailbreak", "prompt", "policy", "injection")):
            threat_types.add("PROMPT_INJECTION")
        if any(token in blob for token in ("sql", "command", "credential_harvest")):
            threat_types.add("MALICIOUS_CODE")
        # Phone numbers / e-mail addresses / low-confidence PII are everywhere in ordinary text and are
        # handled by redaction; only high-confidence sensitive identifiers escalate to a DATA_LEAK block.
        try:
            finding_confidence = float(finding.get("confidence") or 0.0)
        except (TypeError, ValueError):
            finding_confidence = 0.0
        weak_pii = label in {"pii_phone", "pii_email", "pii_ip_address"} or finding_confidence < 0.7
        if not weak_pii and any(token in blob for token in ("pii", "email", "ssn", "iban", "credit_card")):
            threat_types.add("DATA_LEAK")
        if "indirect" in blob and not low_risk_indirect_warning:
            threat_types.add("PROMPT_INJECTION")
        if "financial_fraud" in blob:
            threat_types.add("FINANCIAL_FRAUD")
        if "hitl_bypass_attempt" in blob or "authority_impersonation" in blob:
            threat_types.add("HITL_BYPASS_ATTEMPT")
            threat_types.add("AUTHORITY_IMPERSONATION")

    for policy_match in enforcement_payload.get("policy_matches", []) or []:
        threat_types.add("POLICY_BYPASS")

        bypass_hits = [
            str(item).lower()
            for item in (policy_match.get("matched_bypass_phrases") or [])
        ]
        keyword_hits = [
            str(item).lower()
            for item in (policy_match.get("matched_keywords") or [])
        ]
        semantic_hits = [
            str(item).lower()
            for item in ((policy_match.get("metadata") or {}).get("semantic_hits") or [])
        ]
        hit_blob = " ".join(bypass_hits + keyword_hits + semantic_hits)

        has_confirmation_bypass = any(
            token in hit_blob
            for token in hitl_bypass_confirmation_terms
        )
        has_financial_action = any(
            token in hit_blob
            for token in hitl_bypass_financial_terms
        )
        has_authority_cover = any(
            token in hit_blob
            for token in hitl_bypass_authority_terms
        )

        if has_financial_action and (has_confirmation_bypass or has_authority_cover):
            threat_types.add("HITL_BYPASS_ATTEMPT")
            threat_types.add("AUTHORITY_IMPERSONATION")

    tool_interception = enforcement_payload.get("tool_interception")
    if isinstance(tool_interception, dict):
        tool_reason = str(tool_interception.get("reason") or "").upper()
        if "HITL_BYPASS_ATTEMPT" in tool_reason:
            threat_types.add("HITL_BYPASS_ATTEMPT")
            threat_types.add("AUTHORITY_IMPERSONATION")

    if enforcement_payload.get("decode", {}).get("artifacts"):
        threat_types.add("ENCODING_OBFUSCATION")
    return sorted(threat_types)


def _rich_indirect_fields(enforcement_payload: dict[str, Any]) -> dict[str, Any]:
    categories: set[str] = set()
    matched_signals: list[dict[str, Any]] = []
    decoded_variants: list[dict[str, Any]] = []
    recommended_action = None

    for finding in enforcement_payload.get("detections", []) or []:
        metadata = finding.get("metadata") or {}
        for category in metadata.get("detected_categories") or []:
            categories.add(str(category))
        matched_signals.extend(
            item for item in (metadata.get("matched_signals") or [])
            if isinstance(item, dict)
        )
        decoded_variants.extend(
            item for item in (metadata.get("decoded_variants") or [])
            if isinstance(item, dict)
        )
        if metadata.get("recommended_action"):
            recommended_action = metadata.get("recommended_action")

    if enforcement_payload.get("decode", {}).get("artifacts"):
        categories.add("encoded_instruction")
        for artifact in enforcement_payload.get("decode", {}).get("artifacts") or []:
            encoding = str(artifact.get("encoding") or "")
            if encoding:
                categories.add(f"{encoding}_payload" if encoding in {"morse", "base64", "hex"} else "encoded_payload")
            decoded = str(artifact.get("decoded_fragment") or "").strip()
            if decoded:
                decoded_variants.append(
                    {
                        "source": encoding or "decode_layer",
                        "text": decoded,
                        "confidence": 0.85 if encoding == "morse" else 0.8,
                    }
                )

    return {
        "verdict": "block"
        if str(enforcement_payload.get("action") or "").upper() in {"BLOCK", "FORCE_REVIEW", "INTERCEPT_AND_FORCE_2FA"}
        else "warn"
        if str(enforcement_payload.get("action") or "").upper() == "WARN"
        else "allow",
        "detected_categories": sorted(categories),
        "matched_signals": matched_signals,
        "decoded_variants": decoded_variants,
        "recommended_action": recommended_action
        or (
            "Block tool execution and require human approval."
            if str(enforcement_payload.get("action") or "").upper() in {"BLOCK", "FORCE_REVIEW", "INTERCEPT_AND_FORCE_2FA"}
            else "Allow."
        ),
    }


def _enforcement_to_scan_result(
    prompt: str,
    *,
    provider: str,
    model: str,
    security_tier: str,
    enforcement_payload: dict[str, Any],
) -> Dict[str, Any]:
    action = str(enforcement_payload.get("action") or "BLOCK").upper()
    status = SECURITY_ACTION_TO_STATUS.get(action, "BLOCKED")
    decision = SECURITY_ACTION_TO_DECISION.get(action, "BLOCK")
    threat_types = _threat_types_from_enforcement(enforcement_payload) or ["POLICY_BYPASS"]
    original_threat_type = classify_threat(prompt)
    if original_threat_type in {"MALICIOUS_CODE", "DATA_LEAK"}:
        threat_types = [original_threat_type]
    threat_type = primary_threat_type(threat_types)
    threat_score = max(0.5, min(1.0, float(enforcement_payload.get("risk_score", 90)) / 100.0))
    sanitized_content = str(enforcement_payload.get("sanitized_prompt") or prompt or "")
    explanation = str(enforcement_payload.get("explanation") or "Blocked by security enforcement layer.")
    attack_vector = "security policy enforcement / pre-execution interception"

    sentinel_verdict = build_sentinel_verdict(
        {
            "threat_types": threat_types,
            "threat_score": threat_score,
            "decision": decision,
            "explanation": explanation,
            "attack_vector": attack_vector,
            "sanitized_content": sanitized_content,
            "debug": {"stage1": {"hits": [{"rule": "security_enforcement_layer"}]}},
        },
        provider=provider,
        model=model,
        security_tier=security_tier,
    )
    if sentinel_blocks(sentinel_verdict):
        status = "BLOCKED"
        decision = "BLOCK"
    rich_fields = _rich_indirect_fields(enforcement_payload)

    return {
        "status": status,
        "decision": decision,
        "verdict": rich_fields["verdict"],
        "threat_type": threat_type,
        "threat_types": threat_types,
        "threat_score": max(float(threat_score), float(sentinel_verdict.get("threat_score") or 0.0)),
        "risk_score": int(enforcement_payload.get("risk_score") or round(threat_score * 100)),
        "sentinel_verdict": sentinel_verdict,
        "risk_level": _risk_level_from_score(threat_score),
        "risk_level_detail": str(enforcement_payload.get("severity") or "").lower(),
        "detected_categories": rich_fields["detected_categories"],
        "matched_signals": rich_fields["matched_signals"],
        "decoded_variants": rich_fields["decoded_variants"],
        "attack_vector": attack_vector,
        "detection_stage_triggered": ["security_enforcement_pre_model"],
        "explanation": explanation,
        "sanitized_content": sanitized_content,
        "provider": provider,
        "model": model,
        "security_tier": security_tier,
        "security_enforcement": enforcement_payload,
        "requires_2fa": bool(enforcement_payload.get("requires_2fa")),
        "review_required": bool(enforcement_payload.get("review_required")),
        "recommended_action": rich_fields["recommended_action"],
    }


def _assessment_to_scan_result(
    assessment: Any,
    *,
    provider: str,
    model: str,
    security_tier: str,
    enforcement_payload: dict[str, Any] | None = None,
    original_prompt: str | None = None,
) -> Dict[str, Any]:
    primary = primary_threat_type(assessment.threat_types)
    status_map = {"ALLOW": "CLEAN", "SANITIZE": "REDACTED", "BLOCK": "BLOCKED"}
    status = status_map.get(assessment.decision, "CLEAN")
    sentinel_verdict = build_sentinel_verdict(
        assessment,
        provider=provider,
        model=model,
        security_tier=security_tier,
    )
    status_value = status
    decision_value = assessment.decision
    threat_types = list(assessment.threat_types)
    threat_score_value = max(float(assessment.threat_score or 0.0), float(sentinel_verdict.get("threat_score") or 0.0))
    risk_level_value = assessment.risk_level
    sanitized_content = assessment.sanitized_content
    explanation = assessment.explanation
    attack_vector = assessment.attack_vector
    detection_stage_triggered = list(assessment.detection_stage_triggered or [])
    requires_2fa = False
    review_required = False
    risk_score = int(round(threat_score_value * 100))

    if enforcement_payload:
        enforcement_action = str(enforcement_payload.get("action") or "ALLOW").upper()
        enforcement_threat_types = _threat_types_from_enforcement(enforcement_payload)
        if enforcement_threat_types:
            merged = set(threat_types)
            merged.update(enforcement_threat_types)
            threat_types = sorted(merged)
            primary = primary_threat_type(threat_types)

        enforcement_risk_score = int(enforcement_payload.get("risk_score") or 0)
        risk_score = max(risk_score, enforcement_risk_score)
        threat_score_value = max(threat_score_value, enforcement_risk_score / 100.0)
        risk_level_value = _risk_level_from_score(threat_score_value)
        requires_2fa = bool(enforcement_payload.get("requires_2fa"))
        review_required = bool(enforcement_payload.get("review_required"))

        if enforcement_action in {"INTERCEPT_AND_FORCE_2FA", "BLOCK", "FORCE_REVIEW"}:
            status_value = "BLOCKED"
            decision_value = "BLOCK"
            sanitized_content = enforcement_payload.get("sanitized_prompt") or sanitized_content
            explanation = str(enforcement_payload.get("explanation") or explanation)
            attack_vector = "pre-execution security enforcement"
            detection_stage_triggered.append("security_enforcement_pre_model")
        elif enforcement_action == "REDACT" and status_value == "CLEAN":
            status_value = "REDACTED"
            decision_value = "SANITIZE"
            sanitized_content = enforcement_payload.get("sanitized_prompt") or sanitized_content
            detection_stage_triggered.append("security_enforcement_pre_model")

    if _looks_like_low_risk_education(original_prompt or sanitized_content, enforcement_payload):
        threat_types = [item for item in threat_types if item != "PROMPT_INJECTION"] or ["NONE"]
        primary = primary_threat_type(threat_types)
        threat_score_value = min(threat_score_value, 0.20)
        risk_score = min(risk_score, 20)
        risk_level_value = "low"
        status_value = "CLEAN"
        decision_value = "ALLOW"
        explanation = "Educational or awareness content without an actionable agent, tool, wallet, credential, or data-exfiltration command."

    merged_for_verdict = {
        "threat_types": threat_types,
        "threat_score": threat_score_value,
        "decision": decision_value,
        "explanation": explanation,
        "attack_vector": attack_vector,
        "sanitized_content": sanitized_content,
        "debug": getattr(assessment, "debug", {}) if hasattr(assessment, "debug") else {},
    }
    sentinel_verdict = build_sentinel_verdict(
        merged_for_verdict,
        provider=provider,
        model=model,
        security_tier=security_tier,
    )
    if sentinel_blocks(sentinel_verdict):
        status_value = "BLOCKED"
        decision_value = "BLOCK"
    rich_fields = _rich_indirect_fields(enforcement_payload or {})

    return {
        "status": status_value,
        "decision": decision_value,
        "verdict": rich_fields["verdict"],
        "threat_type": primary,
        "threat_types": threat_types,
        "threat_score": max(float(threat_score_value), float(sentinel_verdict.get("threat_score") or 0.0)),
        "risk_score": risk_score,
        "sentinel_verdict": sentinel_verdict,
        "risk_level": risk_level_value,
        "risk_level_detail": str((enforcement_payload or {}).get("severity") or risk_level_value).lower(),
        "detected_categories": rich_fields["detected_categories"],
        "matched_signals": rich_fields["matched_signals"],
        "decoded_variants": rich_fields["decoded_variants"],
        "attack_vector": attack_vector,
        "detection_stage_triggered": sorted(set(detection_stage_triggered)),
        "explanation": explanation,
        "sanitized_content": sanitized_content,
        "provider": provider,
        "model": model,
        "security_tier": security_tier,
        "security_enforcement": enforcement_payload or {},
        "requires_2fa": requires_2fa,
        "review_required": review_required,
        "recommended_action": rich_fields["recommended_action"],
    }


def _rules_only_scan_result(
    prompt: str,
    *,
    provider: str,
    model: str,
    security_tier: str,
    enforcement_payload: dict[str, Any] | None = None,
) -> Dict[str, Any]:
    if enforcement_payload:
        action = str(enforcement_payload.get("action") or "ALLOW").upper()
        if action in {"INTERCEPT_AND_FORCE_2FA", "BLOCK", "FORCE_REVIEW"}:
            return _enforcement_to_scan_result(
                prompt,
                provider=provider,
                model=model,
                security_tier=security_tier,
                enforcement_payload=enforcement_payload,
            )

    threat_type = classify_threat(prompt)
    threat_types = [threat_type] if threat_type != "NONE" else ["NONE"]
    sanitized_content = prompt
    status = "CLEAN"
    decision = "ALLOW"
    threat_score = 0.1
    risk_level = "low"
    attack_vector = "No high-confidence threat vectors detected."
    explanation = "No high-confidence malicious intent detected."

    if threat_type == "PROMPT_INJECTION":
        status = "BLOCKED"
        decision = "BLOCK"
        threat_score = 0.95
        risk_level = "high"
        sanitized_content = "[REDACTED: PROMPT INJECTION DETECTED]"
        attack_vector = "instruction override / prompt injection"
        explanation = "Detected instruction override / prompt injection."
    elif threat_type == "HITL_BYPASS_ATTEMPT":
        status = "BLOCKED"
        decision = "BLOCK"
        threat_score = 0.99
        risk_level = "high"
        sanitized_content = "[REDACTED: HITL BYPASS ATTEMPT DETECTED]"
        attack_vector = "authority impersonation and confirmation bypass in financial context"
        explanation = "Detected authority impersonation + confirmation bypass around financial execution."
    elif threat_type == "MALICIOUS_CODE":
        status = "BLOCKED"
        decision = "BLOCK"
        threat_score = 0.97
        risk_level = "high"
        sanitized_content = "[REDACTED: MALICIOUS CONTENT REMOVED]"
        attack_vector = "privilege escalation / unsafe execution intent"
        explanation = "Detected malicious code or unsafe execution intent."
    elif threat_type == "DATA_LEAK":
        status = "BLOCKED"
        decision = "BLOCK"
        threat_score = 0.65
        risk_level = "medium"
        sanitized_content = redact_sensitive_data(prompt)
        attack_vector = "data or secret exfiltration attempt"
        explanation = "Detected sensitive data indicators and blocked the payload."

    sentinel_verdict = build_sentinel_verdict(
        {
            "threat_types": threat_types,
            "threat_score": threat_score,
            "decision": decision,
            "explanation": explanation,
            "attack_vector": attack_vector,
            "sanitized_content": sanitized_content,
            "debug": {"stage1": {"hits": [{"rule": "rules_only_fallback", "threat_type": threat_type}]}} ,
        },
        provider=provider,
        model=model,
        security_tier=security_tier,
    )

    if sentinel_blocks(sentinel_verdict):
        status = "BLOCKED"
        decision = "BLOCK"

    if enforcement_payload:
        threat_score = max(threat_score, float(enforcement_payload.get("risk_score") or 0) / 100.0)

    return {
        "status": status,
        "decision": decision,
        "threat_type": threat_type,
        "threat_types": threat_types,
        "threat_score": max(float(threat_score), float(sentinel_verdict.get("threat_score") or 0.0)),
        "risk_score": int(round(threat_score * 100)),
        "sentinel_verdict": sentinel_verdict,
        "risk_level": risk_level,
        "attack_vector": attack_vector,
        "detection_stage_triggered": ["stage1_fast_rules", "rules_only_fallback"],
        "explanation": explanation,
        "sanitized_content": sanitized_content,
        "provider": provider,
        "model": model,
        "security_tier": security_tier,
        "security_enforcement": enforcement_payload or {},
        "requires_2fa": bool((enforcement_payload or {}).get("requires_2fa")),
        "review_required": bool((enforcement_payload or {}).get("review_required")),
    }


def _fail_safe_scan_result(
    prompt: str,
    *,
    provider: str,
    model: str,
    security_tier: str,
    untrusted_content: str | None = None,
    reason: str = "scan_incomplete",
) -> Dict[str, Any]:
    """Result used when the full scan could not finish (timeout / crash / oversized input).

    The old fallback returned the English-only rules result, which missed most attacks, and the
    gateway then forwarded the request. Here the fast, pure intent engine always runs; and unless
    SCAN_FAIL_MODE=open, anything it cannot positively clear is blocked (fail-closed).
    """
    base = _rules_only_scan_result(
        prompt, provider=provider, model=model, security_tier=security_tier, enforcement_payload=None
    )
    if str(base.get("status") or "").upper() == "BLOCKED":
        return base

    verdict = analyze_intent_text(prompt or "")
    untrusted_verdict = analyze_intent_text(untrusted_content, untrusted=True) if untrusted_content else None
    ml_hit = ml_verdict(prompt or "", untrusted_content)
    flagged = verdict.blocked or bool(untrusted_verdict and untrusted_verdict.blocked) or ml_hit is not None
    fail_closed = str(getattr(settings, "SCAN_FAIL_MODE", "closed") or "closed").lower() != "open"
    if not (flagged or fail_closed):
        return base

    categories = set(verdict.categories) | set(untrusted_verdict.categories if untrusted_verdict else [])
    if ml_hit is not None and ml_hit["label"] == "fraud":
        categories.add("financial_fraud")
    if "financial_fraud" in categories:
        threat_type, vector = "FINANCIAL_FRAUD", "financial fraud / scam request"
    elif flagged:
        threat_type, vector = "PROMPT_INJECTION", "instruction override / prompt injection"
    else:
        threat_type, vector = "POLICY_BYPASS", "security scan could not complete"
    explanation = (
        "Detected malicious intent while the full scan was unavailable."
        if flagged
        else "The security scan could not complete in time, so the request was blocked (fail-closed)."
    )
    score = 0.95 if flagged else 0.85
    sentinel_verdict = build_sentinel_verdict(
        {
            "threat_types": [threat_type],
            "threat_score": score,
            "decision": "BLOCK",
            "explanation": explanation,
            "attack_vector": vector,
            "sanitized_content": "[REDACTED: REQUEST BLOCKED]",
            "debug": {"stage1": {"hits": [{"rule": reason, "threat_type": threat_type}]}},
        },
        provider=provider,
        model=model,
        security_tier=security_tier,
    )
    result = dict(base)
    result.update(
        {
            "status": "BLOCKED",
            "decision": "BLOCK",
            "threat_type": threat_type,
            "threat_types": [threat_type],
            "threat_score": max(score, float(sentinel_verdict.get("threat_score") or 0.0)),
            "risk_score": int(round(score * 100)),
            "sentinel_verdict": sentinel_verdict,
            "risk_level": "high",
            "attack_vector": vector,
            "detection_stage_triggered": ["stage1_fast_rules", reason],
            "explanation": explanation,
            "sanitized_content": "[REDACTED: REQUEST BLOCKED]",
        }
    )
    return result


def _is_suspicious_or_large_prompt(prompt: str) -> bool:
    if len(prompt) >= int(getattr(settings, "SCAN_SUSPICIOUS_PROMPT_LENGTH", 4000) or 4000):
        return True
    return any(pattern.search(prompt) for pattern in FAST_LANE_PATTERNS)


def _dynamic_scan_timeout_seconds(prompt: str) -> float:
    base_timeout = max(0.05, float(getattr(settings, "SCAN_BASE_TIMEOUT_SECONDS", 6.0) or 6.0))
    max_timeout = max(base_timeout, float(getattr(settings, "SCAN_MAX_TIMEOUT_SECONDS", 12.0) or 12.0))
    per_2k_chars = max(0.0, float(getattr(settings, "SCAN_TIMEOUT_PER_2K_CHARS", 1.5) or 1.5))
    timeout = base_timeout + ((max(0, len(prompt) - 1) // 2000) * per_2k_chars)
    if _is_suspicious_or_large_prompt(prompt):
        timeout += 1.0
    return min(timeout, max_timeout)


def scan_prompt(
    prompt: str,
    provider: str = "openai",
    model: str = "gpt-5.4",
    security_tier: str = "PRO",
    enable_ai: bool | None = None,
    enforcement_input: SecurityEnforcementInput | None = None,
) -> Dict[str, Any]:
    enforcement_payload: dict[str, Any] = {}
    enforcement_result_obj = None
    effective_prompt = prompt

    try:
        if enforcement_input is None:
            enforcement_input = SecurityEnforcementInput(
                prompt=prompt,
                session_id=f"stateless-scan-{uuid4().hex}",
            )
        enforcement_result = security_enforcement_layer.pre_model_enforce(enforcement_input)
        enforcement_result_obj = enforcement_result
        enforcement_payload = _serialize_enforcement_result(enforcement_result)
        effective_prompt = str(enforcement_payload.get("sanitized_prompt") or prompt)
        action = str(enforcement_payload.get("action") or "ALLOW").upper()
        if action in {"INTERCEPT_AND_FORCE_2FA", "BLOCK", "FORCE_REVIEW"}:
            return _enforcement_to_scan_result(
                prompt=prompt,
                provider=provider,
                model=model,
                security_tier=security_tier,
                enforcement_payload=enforcement_payload,
            )
    except Exception:
        logger.exception("Security enforcement pre-check failed; denying request.")
        # A broken pre-model control must never fall through to the legacy path,
        # which may permit downstream execution when its detectors miss a variant.
        return _enforcement_to_scan_result(
            prompt=prompt,
            provider=provider,
            model=model,
            security_tier=security_tier,
            enforcement_payload={
                "action": "BLOCK",
                "risk_score": 100,
                "severity": "CRITICAL",
                "sanitized_prompt": "[REDACTED: SECURITY CHECK UNAVAILABLE]",
                "explanation": "Request blocked because the security check could not be completed.",
                "detections": [],
                "policy_matches": [],
            },
        )

    original_threat_type = classify_threat(prompt)
    if original_threat_type in {"DATA_LEAK", "MALICIOUS_CODE"}:
        return _rules_only_scan_result(
            prompt,
            provider=provider,
            model=model,
            security_tier=security_tier,
            enforcement_payload=enforcement_payload,
        )

    assessment = ThreatDetectionService().analyze(
        effective_prompt,
        provider=provider,
        model=model,
        security_tier=security_tier,
        enable_ai=enable_ai,
    )
    result = _assessment_to_scan_result(
        assessment,
        provider=provider,
        model=model,
        security_tier=security_tier,
        enforcement_payload=enforcement_payload,
        original_prompt=prompt,
    )

    # Output leak prevention pass on explanation + sanitized content.
    try:
        output_basis = "\n".join(
            item
            for item in [
                str(result.get("explanation") or ""),
                str(result.get("sanitized_content") or ""),
            ]
            if item
        )
        if output_basis:
            if enforcement_result_obj is None:
                enforcement_result_obj = security_enforcement_layer.pre_model_enforce(
                    SecurityEnforcementInput(prompt=effective_prompt)
                )
            post = security_enforcement_layer.post_model_enforce_output(
                enforcement=enforcement_result_obj,
                output_text=output_basis,
            )
            post_payload = _serialize_enforcement_result(post)
            if post_payload.get("output_findings"):
                result["security_enforcement"]["output_findings"] = post_payload.get("output_findings")
                post_action = str(post_payload.get("action") or "").upper()
                if post_action == "BLOCK":
                    result["status"] = "BLOCKED"
                    result["decision"] = "BLOCK"
                elif post_action == "REDACT" and result["status"] == "CLEAN":
                    result["status"] = "REDACTED"
                    result["decision"] = "SANITIZE"
    except Exception:
        logger.exception("Output leak scan failed; preserving original scan result.")

    return result


async def scan_prompt_with_resilience(
    prompt: str,
    *,
    provider: str = "openai",
    model: str = "gpt-5.4",
    security_tier: str = "PRO",
    session_id: str | None = None,
    conversation_id: str | None = None,
    conversation_history: list[str] | None = None,
    untrusted_content: str | None = None,
    tool_name: str | None = None,
    tool_args: dict[str, Any] | None = None,
    two_factor_code: str | None = None,
    user_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[Dict[str, Any], dict[str, Any]]:
    started_at = perf_counter()
    input_size = len(prompt)
    suspicious_or_large = _is_suspicious_or_large_prompt(prompt)
    retry_attempts = max(1, min(int(getattr(settings, "SCAN_RETRY_ATTEMPTS", 2) or 2), 2))
    timeout_seconds = _dynamic_scan_timeout_seconds(prompt)

    enforcement_input = SecurityEnforcementInput(
        prompt=prompt,
        session_id=session_id,
        conversation_id=conversation_id,
        conversation_history=conversation_history,
        untrusted_content=untrusted_content,
        tool_name=tool_name,
        tool_args=tool_args,
        two_factor_code=two_factor_code,
        user_id=user_id,
        metadata=metadata,
    )

    best_effort_result = _fail_safe_scan_result(
        prompt,
        provider=provider,
        model=model,
        security_tier=security_tier,
        untrusted_content=untrusted_content,
        reason="scan_timeout_or_error_fallback",
    )

    logger.info(
        "Prompt scan started input_size=%s suspicious_or_large=%s security_tier=%s timeout_seconds=%.2f retry_attempts=%s",
        input_size,
        suspicious_or_large,
        security_tier,
        timeout_seconds,
        retry_attempts,
    )

    if suspicious_or_large and timeout_seconds <= 0.05:
        total_duration_ms = int((perf_counter() - started_at) * 1000)
        return best_effort_result, {
            "status": "warning",
            "message": "Scan took longer than expected, partial analysis returned",
            "partial": True,
            "input_size": input_size,
            "retry_attempts": retry_attempts,
            "attempts_used": 0,
            "timeout_seconds": timeout_seconds,
            "suspicious_or_large": suspicious_or_large,
            "lightweight_precheck_used": True,
            "duration_ms": total_duration_ms,
            "result": {
                "status": best_effort_result.get("status"),
                "threat_type": best_effort_result.get("threat_type"),
                "threat_score": best_effort_result.get("threat_score"),
                "risk_score": best_effort_result.get("risk_score"),
            },
        }

    last_error: Exception | None = None
    for attempt in range(1, retry_attempts + 1):
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(
                    scan_prompt,
                    prompt,
                    provider=provider,
                    model=model,
                    security_tier=security_tier,
                    enable_ai=(False if suspicious_or_large else None),
                    enforcement_input=enforcement_input,
                ),
                timeout=timeout_seconds,
            )
            total_duration_ms = int((perf_counter() - started_at) * 1000)
            logger.info(
                "Prompt scan finished input_size=%s suspicious_or_large=%s attempt=%s duration_ms=%s status=%s",
                input_size,
                suspicious_or_large,
                attempt,
                total_duration_ms,
                result.get("status"),
            )
            return result, {
                "status": "ok",
                "message": "Scan completed successfully.",
                "partial": False,
                "input_size": input_size,
                "retry_attempts": retry_attempts,
                "attempts_used": attempt,
                "timeout_seconds": timeout_seconds,
                "suspicious_or_large": suspicious_or_large,
                "lightweight_precheck_used": suspicious_or_large,
                "duration_ms": total_duration_ms,
            }
        except asyncio.TimeoutError as exc:
            last_error = exc
            logger.warning(
                "Prompt scan timeout input_size=%s suspicious_or_large=%s attempt=%s timeout_seconds=%.2f",
                input_size,
                suspicious_or_large,
                attempt,
                timeout_seconds,
            )
        except Exception as exc:
            last_error = exc
            logger.exception(
                "Prompt scan failed input_size=%s suspicious_or_large=%s attempt=%s",
                input_size,
                suspicious_or_large,
                attempt,
            )

    total_duration_ms = int((perf_counter() - started_at) * 1000)
    warning_message = "Scan took longer than expected, partial analysis returned"
    logger.warning(
        "Prompt scan fallback returned input_size=%s suspicious_or_large=%s duration_ms=%s fallback_status=%s",
        input_size,
        suspicious_or_large,
        total_duration_ms,
        best_effort_result.get("status"),
    )
    return best_effort_result, {
        "status": "warning",
        "message": warning_message,
        "partial": True,
        "input_size": input_size,
        "retry_attempts": retry_attempts,
        "attempts_used": retry_attempts,
        "timeout_seconds": timeout_seconds,
        "suspicious_or_large": suspicious_or_large,
        "lightweight_precheck_used": True,
        "duration_ms": total_duration_ms,
        "error": str(last_error) if last_error else None,
        "result": {
            "status": best_effort_result.get("status"),
            "threat_type": best_effort_result.get("threat_type"),
            "threat_score": best_effort_result.get("threat_score"),
            "risk_score": best_effort_result.get("risk_score"),
        },
    }