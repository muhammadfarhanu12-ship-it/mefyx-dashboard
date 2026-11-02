from __future__ import annotations

from typing import Any, Iterable

from app.services.threat_detection import (
    THREAT_DATA_EXFILTRATION,
    THREAT_DATA_LEAK,
    THREAT_ENCODING_OBFUSCATION,
    THREAT_MALICIOUS_CODE,
    THREAT_POLICY_BYPASS,
    THREAT_PRIVILEGE_ESCALATION,
    THREAT_PROMPT_INJECTION,
    ThreatAssessment,
)

SENTINEL_BLOCK_THRESHOLD = 0.5
THREAT_HITL_BYPASS_ATTEMPT = "HITL_BYPASS_ATTEMPT"
THREAT_AUTHORITY_IMPERSONATION = "AUTHORITY_IMPERSONATION"
THREAT_FINANCIAL_FRAUD = "FINANCIAL_FRAUD"


def sentinel_category_for_threats(threat_types: Iterable[str]) -> str:
    normalized = {str(threat_type).upper() for threat_type in threat_types if str(threat_type)}

    if THREAT_HITL_BYPASS_ATTEMPT in normalized or THREAT_AUTHORITY_IMPERSONATION in normalized:
        return THREAT_HITL_BYPASS_ATTEMPT
    if THREAT_FINANCIAL_FRAUD in normalized:
        return "Financial Fraud"
    if THREAT_ENCODING_OBFUSCATION in normalized:
        return "Obfuscation"
    if normalized.intersection({THREAT_PROMPT_INJECTION, THREAT_POLICY_BYPASS}):
        return "Injection"
    if normalized.intersection({THREAT_DATA_LEAK}):
        return "PII"
    if normalized.intersection({THREAT_DATA_EXFILTRATION, THREAT_PRIVILEGE_ESCALATION, THREAT_MALICIOUS_CODE}):
        return "Malicious"
    return "Clean"


def sentinel_blocks(verdict: dict[str, Any]) -> bool:
    return str(verdict.get("execution_output") or "").upper() == "BLOCKED" or float(verdict.get("threat_score") or 0.0) >= SENTINEL_BLOCK_THRESHOLD


def _coerce_assessment_fields(assessment: ThreatAssessment | dict[str, Any]) -> dict[str, Any]:
    if isinstance(assessment, ThreatAssessment):
        debug = assessment.debug or {}
        return {
            "threat_types": assessment.threat_types,
            "threat_score": assessment.threat_score,
            "decision": assessment.decision,
            "explanation": assessment.explanation,
            "attack_vector": assessment.attack_vector,
            "sanitized_content": assessment.sanitized_content,
            "debug": debug,
            "provider": str(debug.get("provider") or "").strip(),
            "model": str(debug.get("model") or "").strip(),
            "security_tier": str(debug.get("tier") or "").strip().upper(),
        }

    debug = assessment.get("debug") or {}
    return {
        "threat_types": assessment.get("threat_types") or [],
        "threat_score": float(assessment.get("threat_score") or 0.0),
        "decision": str(assessment.get("decision") or "ALLOW").upper(),
        "explanation": str(assessment.get("explanation") or "").strip(),
        "attack_vector": str(assessment.get("attack_vector") or "").strip(),
        "sanitized_content": assessment.get("sanitized_content"),
        "debug": debug,
        "provider": str(assessment.get("provider") or debug.get("provider") or "").strip(),
        "model": str(assessment.get("model") or debug.get("model") or "").strip(),
        "security_tier": str(assessment.get("security_tier") or debug.get("tier") or "").strip().upper(),
    }


def _stage_rule_names(fields: dict[str, Any]) -> set[str]:
    debug = fields.get("debug") or {}
    stage1_hits = (((debug.get("stage1") or {}).get("hits")) or [])
    return {str(hit.get("rule")) for hit in stage1_hits if isinstance(hit, dict) and hit.get("rule")}


def _specific_attack_vector(fields: dict[str, Any], category: str) -> str:
    threat_types = {str(threat_type).upper() for threat_type in fields.get("threat_types") or [] if str(threat_type)}
    rule_names = _stage_rule_names(fields)

    if category == THREAT_HITL_BYPASS_ATTEMPT:
        return "Authority Impersonation via confirmation bypass"

    if category == "Financial Fraud":
        return "Financial Fraud / Scam Request"

    if category == "Obfuscation":
        if threat_types.intersection({THREAT_DATA_EXFILTRATION, THREAT_DATA_LEAK}):
            return "Obfuscated PII Leak Attempt"
        if threat_types.intersection({THREAT_PROMPT_INJECTION, THREAT_POLICY_BYPASS}):
            return "Obfuscated Instruction Override Attempt"
        return "Hidden Obfuscation Payload"

    if "persona_override" in rule_names:
        return "Instruction Hijacking via Roleplay"
    if rule_names.intersection({"instruction_override", "system_prompt_exfil", "safety_bypass"}):
        return "Instruction Override"
    if rule_names.intersection({"secret_harvest", "env_exfil", "internal_file_probe", "internal_api_probe"}):
        return "Sensitive Secret Exfiltration Attempt"
    if rule_names.intersection({"jwt_token", "api_key_format", "password_assignment", "pii_email", "pii_phone", "pii_ssn", "pii_cc", "filesystem_path"}):
        return "PII or Credential Leak Attempt"
    if rule_names.intersection({"destructive_cmd", "windows_delete", "exec_eval", "script_injection"}):
        return "Code Injection / Unsafe Execution Intent"

    attack_vector = str(fields.get("attack_vector") or "").strip()
    if attack_vector and attack_vector != "No high-confidence threat vectors detected.":
        return attack_vector[:300]
    if category == "Clean":
        return "No high-confidence threat vectors detected."
    return "Suspicious activity detected."


def _normalized_threat_score(fields: dict[str, Any], category: str) -> float:
    score = max(0.0, min(1.0, float(fields.get("threat_score") or 0.0)))
    if category == THREAT_HITL_BYPASS_ATTEMPT:
        return max(score, 0.95)
    if category == "Obfuscation":
        return max(score, 0.72)
    if category == "Financial Fraud":
        return max(score, 0.92)
    if category == "Injection":
        return max(score, 0.85)
    if category == "PII":
        return max(score, 0.65)
    if category == "Malicious":
        return max(score, 0.9)
    if fields.get("decision") in {"BLOCK", "SANITIZE"}:
        return max(score, SENTINEL_BLOCK_THRESHOLD)
    return min(score, 0.49)


def build_sentinel_verdict(
    assessment: ThreatAssessment | dict[str, Any],
    *,
    execution_output: str | None = None,
    provider: str | None = None,
    model: str | None = None,
    security_tier: str | None = None,
) -> dict[str, Any]:
    fields = _coerce_assessment_fields(assessment)
    category = sentinel_category_for_threats(fields["threat_types"])
    threat_score = _normalized_threat_score(fields, category)
    provider_value = str(provider or fields.get("provider") or "unknown").strip() or "unknown"
    model_value = str(model or fields.get("model") or "unknown").strip() or "unknown"
    security_tier_value = str(security_tier or fields.get("security_tier") or "PRO").strip().upper() or "PRO"

    if category == "Clean" and threat_score >= SENTINEL_BLOCK_THRESHOLD:
        category = "Malicious"

    attack_vector = _specific_attack_vector(fields, category)
    blocked = category != "Clean" or threat_score >= SENTINEL_BLOCK_THRESHOLD

    if blocked:
        detail = attack_vector
        execution_value = "BLOCKED"
    else:
        explanation = str(fields.get("explanation") or "").strip()
        detail = explanation or "No high-confidence threat indicators were detected."
        execution_value = execution_output or "PASSTHROUGH_APPROVED"

    return {
        "provider": provider_value,
        "model": model_value,
        "security_tier": security_tier_value,
        "threat_score": max(0.0, min(1.0, threat_score)),
        "category": category,
        "detail": detail,
        "execution_output": execution_value,
    }