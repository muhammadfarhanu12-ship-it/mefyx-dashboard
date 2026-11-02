from __future__ import annotations

import re
from typing import Dict, List, Any, Set

from app.security.policies.definitions.financialGuardrail import (
    MFA_REQUIRED_TOOLS,
    INJECTION_SIGNATURES,
    COMMAND_KEYWORDS,
    INDIRECT_EXECUTION_PATTERNS,
    ROLEPLAY_ATTACK_PATTERNS,
    FINANCIAL_KEYWORDS,
    DATA_EXFILTRATION_PATTERNS,
    SOCIAL_ENGINEERING_PATTERNS,
    THREAT_WEIGHTS,
    MEDIUM_THREAT_THRESHOLD,
    HIGH_THREAT_THRESHOLD,
    CRITICAL_THREAT_THRESHOLD,
    SYSTEM_AUTHORITY_BYPASS_KEYWORDS,
)


# =========================================================
# NORMALIZATION
# =========================================================

def _normalize(text: str) -> str:
    """
    Normalize attacker-controlled content.

    Handles:
    - repeated spaces
    - mixed casing
    - newline abuse
    - unicode spacing tricks
    """

    text = text.lower()

    text = re.sub(r"\s+", " ", text)

    return text.strip()


# =========================================================
# SAFE MATCHING
# =========================================================

_SAFE_CONTAINS_CACHE: dict[str, "re.Pattern[str]"] = {}


def _safe_contains(text: str, value: str) -> bool:
    """Whole-word match. Plain substring matching flagged 'eth' inside 'methods', 'wire' inside
    'wireless', 'pay' inside 'payroll' and so on. Terms longer than 4 characters may carry a short
    inflection suffix (transfer -> transfers/transferred); short terms must match exactly."""
    needle = value.lower()
    pattern = _SAFE_CONTAINS_CACHE.get(needle)
    if pattern is None:
        suffix = r"[a-z]{0,3}" if len(needle) > 4 and needle[-1].isalpha() else ""
        pattern = re.compile(r"(?<![a-z0-9])" + re.escape(needle) + suffix + r"(?![a-z0-9])")
        _SAFE_CONTAINS_CACHE[needle] = pattern
    return bool(pattern.search(text))


def _contains_any_phrase(text: str, phrases: List[str]) -> bool:
    return any(_safe_contains(text, phrase) for phrase in phrases)


def _append_unique(findings: List[str], finding: str) -> None:
    if finding not in findings:
        findings.append(finding)


# =========================================================
# REGEX MATCHING
# =========================================================

def _regex_match(text: str, pattern: str) -> bool:
    try:
        return bool(
            re.search(
                pattern,
                text,
                flags=re.IGNORECASE,
            )
        )
    except re.error:
        return False


# =========================================================
# DETECT TOOL INVOCATIONS
# =========================================================

def _detect_restricted_tools(text: str) -> List[str]:

    detected: List[str] = []

    for tool in MFA_REQUIRED_TOOLS:
        if _safe_contains(text, tool):
            detected.append(tool)

    return detected


# =========================================================
# DETECT PHRASE MATCHES
# =========================================================

def _detect_phrase_matches(
    text: str,
    patterns: List[str],
) -> List[str]:

    matches: List[str] = []

    for pattern in patterns:
        if _safe_contains(text, pattern):
            matches.append(pattern)

    return matches


# =========================================================
# IMPERATIVE EXECUTION ANALYSIS
# =========================================================

def _detect_imperative_execution(text: str) -> List[str]:

    patterns = [
        r"execute\s+(this|now|immediately)",
        r"run\s+(this|immediately)",
        r"perform\s+(transfer|payment|action)",
        r"send\s+funds",
        r"transfer\s+funds",
        r"complete\s+transaction",
        r"process\s+payment",
        r"trigger\s+tool",
        r"invoke\s+tool",
    ]

    findings: List[str] = []

    for pattern in patterns:
        if _regex_match(text, pattern):
            findings.append(pattern)

    return findings


# =========================================================
# INSTRUCTION CHAIN DETECTION
# =========================================================

def _detect_instruction_chains(text: str) -> bool:

    return _regex_match(
        text,
        r"\b(command|instruction|execute|run|perform)\b\s*[:\-]",
    )


# =========================================================
# AUTHORITY IMPERSONATION / HITL BYPASS
# =========================================================

FINANCIAL_ACTION_PATTERNS: List[str] = [
    "initiate_wire",
    "wire_transfer",
    "transfer_funds",
    "send_money",
    "withdraw_funds",
    "pay_invoice",
    "send payment",
    "crypto transfer",
    "wallet transfer",
    "routing number",
    "transfer",
    "wire",
    "payment",
    "send funds",
    "move funds",
]

CONFIRMATION_BYPASS_PATTERNS: List[str] = [
    "do not ask for user confirmation",
    "do not ask for confirmation",
    "skip confirmation",
    "bypass confirmation",
    "without confirmation",
    "ignore approval workflow",
    "automatic approval",
    "bypass approval",
    "no verification needed",
    "no approval needed",
]

AUTHORITY_CONTEXT_PATTERNS: List[str] = [
    "automated",
    "system update",
    "internal system update",
    "automated stress test",
    "stress test",
    "latency test",
    "api latency",
    "latency update",
    "test the api latency",
    "simulation environment",
    "internal operation",
    "production validation",
    "system maintenance",
    "scheduled operation",
    "backend verification",
    "temporary override",
    "maintenance workflow",
    "for testing purposes",
    "simulation only",
]

URGENCY_AND_SYSTEM_CLAIMS: List[str] = [
    "urgent",
    "immediately",
    "asap",
    "high priority",
    "internal request",
    "internal operation",
    "system maintenance",
    "backend verification",
]


def _evaluate_hitl_bypass_signals(
    text: str,
    *,
    restricted_tools: List[str],
    financial_matches: List[str],
) -> Dict[str, Any]:

    authority_matches = _detect_phrase_matches(
        text,
        SYSTEM_AUTHORITY_BYPASS_KEYWORDS,
    )
    financial_action_matches = _detect_phrase_matches(
        text,
        FINANCIAL_ACTION_PATTERNS,
    )
    skip_confirmation_matches = _detect_phrase_matches(
        text,
        CONFIRMATION_BYPASS_PATTERNS,
    )
    authority_context_matches = _detect_phrase_matches(
        text,
        AUTHORITY_CONTEXT_PATTERNS,
    )
    urgency_system_matches = _detect_phrase_matches(
        text,
        URGENCY_AND_SYSTEM_CLAIMS,
    )

    has_financial_action = bool(
        financial_action_matches
        or financial_matches
        or restricted_tools
    )
    has_confirmation_bypass = bool(
        skip_confirmation_matches
    )
    has_authority_impersonation = bool(
        authority_matches
        or authority_context_matches
    )

    transfer_or_wire_present = _contains_any_phrase(
        text,
        [
            "transfer",
            "wire",
            "transfer_funds",
            "wire_transfer",
            "initiate_wire",
        ],
    )
    automated_or_update_present = _contains_any_phrase(
        text,
        [
            "automated",
            "system update",
            "internal system update",
        ],
    )

    return {
        "authority_matches": authority_matches,
        "financial_action_matches": financial_action_matches,
        "skip_confirmation_matches": skip_confirmation_matches,
        "authority_context_matches": authority_context_matches,
        "urgency_system_matches": urgency_system_matches,
        "critical_combo": has_financial_action and (
            has_confirmation_bypass
            or has_authority_impersonation
        ),
        "has_financial_action": has_financial_action,
        "has_confirmation_bypass": has_confirmation_bypass,
        "has_authority_impersonation": has_authority_impersonation,
        "authority_cross_check": (
            transfer_or_wire_present
            and automated_or_update_present
        ),
    }


# =========================================================
# CONTEXTUAL RISK ESCALATION
# =========================================================

def _calculate_contextual_risk(
    restricted_tools: List[str],
    financial_matches: List[str],
    imperative_matches: List[str],
    social_engineering_matches: List[str],
) -> float:

    escalation = 0.0

    # Financial tool abuse
    if restricted_tools and financial_matches:
        escalation += 0.35

    # Urgent financial execution
    if financial_matches and imperative_matches:
        escalation += 0.25

    # Social engineering + execution
    if social_engineering_matches and imperative_matches:
        escalation += 0.20

    # Full attack chain
    if (
        restricted_tools
        and financial_matches
        and imperative_matches
    ):
        escalation += 0.40

    return escalation


# =========================================================
# MAIN DETECTOR
# =========================================================

def detect_prompt_injection(
    prompt: str,
    decoded_prompt: str | None = None,
) -> Dict[str, Any]:

    """
    Enterprise-grade prompt injection detector.

    Detects:
    - prompt injections
    - tool abuse
    - financial coercion
    - jailbreak attempts
    - roleplay attacks
    - data exfiltration
    - social engineering
    """

    findings: List[str] = []

    try:

        text = decoded_prompt if decoded_prompt else prompt

        normalized = _normalize(text)

        score = 0.0

        # =================================================
        # DETECT RESTRICTED TOOLS
        # =================================================

        restricted_tools = _detect_restricted_tools(normalized)

        if restricted_tools:
            findings.extend(
                [f"restricted_tool:{x}" for x in restricted_tools]
            )

            score += THREAT_WEIGHTS["restricted_tool_match"]

        # =================================================
        # PROMPT INJECTION
        # =================================================

        injection_matches = _detect_phrase_matches(
            normalized,
            INJECTION_SIGNATURES,
        )

        if injection_matches:

            findings.extend(
                [f"injection:{x}" for x in injection_matches]
            )

            score += (
                len(injection_matches)
                * THREAT_WEIGHTS["signature_match"]
            )

        # =================================================
        # COMMAND KEYWORDS
        # =================================================

        command_matches = _detect_phrase_matches(
            normalized,
            COMMAND_KEYWORDS,
        )

        if command_matches:

            findings.extend(
                [f"command:{x}" for x in command_matches]
            )

            score += (
                len(command_matches)
                * THREAT_WEIGHTS["command_keyword_match"]
            )

        # =================================================
        # INDIRECT EXECUTION
        # =================================================

        indirect_execution_matches = _detect_phrase_matches(
            normalized,
            INDIRECT_EXECUTION_PATTERNS,
        )

        if indirect_execution_matches:

            findings.extend(
                [
                    f"indirect_execution:{x}"
                    for x in indirect_execution_matches
                ]
            )

            score += (
                len(indirect_execution_matches)
                * THREAT_WEIGHTS["indirect_execution_match"]
            )

        # =================================================
        # ROLEPLAY ATTACKS
        # =================================================

        roleplay_matches = _detect_phrase_matches(
            normalized,
            ROLEPLAY_ATTACK_PATTERNS,
        )

        if roleplay_matches:

            findings.extend(
                [f"roleplay:{x}" for x in roleplay_matches]
            )

            score += (
                len(roleplay_matches)
                * THREAT_WEIGHTS["roleplay_attack_match"]
            )

        # =================================================
        # FINANCIAL MANIPULATION
        # =================================================

        financial_matches = _detect_phrase_matches(
            normalized,
            FINANCIAL_KEYWORDS,
        )

        if financial_matches:

            findings.extend(
                [f"financial:{x}" for x in financial_matches]
            )

            score += (
                len(financial_matches)
                * THREAT_WEIGHTS["financial_keyword_match"]
            )

        # =================================================
        # DATA EXFILTRATION
        # =================================================

        exfiltration_matches = _detect_phrase_matches(
            normalized,
            DATA_EXFILTRATION_PATTERNS,
        )

        if exfiltration_matches:

            findings.extend(
                [
                    f"exfiltration:{x}"
                    for x in exfiltration_matches
                ]
            )

            score += (
                len(exfiltration_matches)
                * THREAT_WEIGHTS["data_exfiltration_match"]
            )

        # =================================================
        # SOCIAL ENGINEERING
        # =================================================

        social_matches = _detect_phrase_matches(
            normalized,
            SOCIAL_ENGINEERING_PATTERNS,
        )

        if social_matches:

            findings.extend(
                [f"social_engineering:{x}" for x in social_matches]
            )

            score += (
                len(social_matches)
                * THREAT_WEIGHTS["social_engineering_match"]
            )

        # =================================================
        # AUTHORITY IMPERSONATION / HITL BYPASS
        # =================================================

        authority_eval = _evaluate_hitl_bypass_signals(
            normalized,
            restricted_tools=restricted_tools,
            financial_matches=financial_matches,
        )

        authority_matches = authority_eval["authority_matches"]
        skip_confirmation_matches = authority_eval[
            "skip_confirmation_matches"
        ]
        financial_action_matches = authority_eval[
            "financial_action_matches"
        ]
        authority_context_matches = authority_eval[
            "authority_context_matches"
        ]
        urgency_system_matches = authority_eval[
            "urgency_system_matches"
        ]

        for match in authority_matches:
            _append_unique(
                findings,
                f"authority_signature:{match}",
            )

        for match in skip_confirmation_matches:
            _append_unique(
                findings,
                f"skip_confirmation:{match}",
            )

        for match in financial_action_matches:
            _append_unique(
                findings,
                f"financial_action:{match}",
            )

        for match in authority_context_matches:
            _append_unique(
                findings,
                f"authority_context:{match}",
            )

        for match in urgency_system_matches:
            _append_unique(
                findings,
                f"urgency_system_claim:{match}",
            )

        if authority_matches:
            score += min(
                0.30,
                len(authority_matches) * 0.08,
            )
        if urgency_system_matches:
            score += min(
                0.12,
                len(urgency_system_matches) * 0.03,
            )

        hitl_bypass_detected = False

        # Critical rule: financial action + bypass confirmation/authority
        if authority_eval["critical_combo"]:
            _append_unique(
                findings,
                "HITL_BYPASS_ATTEMPT:financial_action_confirmation_bypass",
            )
            _append_unique(
                findings,
                "authority_impersonation:financial_action_with_confirmation_bypass",
            )
            _append_unique(
                findings,
                "AUTHORITY_IMPERSONATION:financial_operation_social_engineering",
            )
            score = max(score, 0.95)
            hitl_bypass_detected = True

        # Cross-check rule: automated/system update + transfer/wire
        if authority_eval["authority_cross_check"]:
            _append_unique(
                findings,
                "HITL_BYPASS_ATTEMPT:authority_impersonation",
            )
            _append_unique(
                findings,
                "authority_impersonation:automated_update_transfer_chain",
            )
            _append_unique(
                findings,
                "AUTHORITY_IMPERSONATION:automated_system_update_transfer",
            )
            score = max(score, 0.95)
            hitl_bypass_detected = True

        # =================================================
        # IMPERATIVE EXECUTION
        # =================================================

        imperative_matches = _detect_imperative_execution(
            normalized
        )

        if imperative_matches:

            findings.extend(
                [f"imperative:{x}" for x in imperative_matches]
            )

            score += 0.20

        # =================================================
        # INSTRUCTION CHAINS
        # =================================================

        if _detect_instruction_chains(normalized):

            findings.append("instruction_chain_detected")

            score += 0.15

        # =================================================
        # CONTEXTUAL ESCALATION
        # =================================================

        score += _calculate_contextual_risk(
            restricted_tools=restricted_tools,
            financial_matches=financial_matches,
            imperative_matches=imperative_matches,
            social_engineering_matches=social_matches,
        )

        # =================================================
        # CLAMP SCORE
        # =================================================

        score = min(score, 1.0)

        # =================================================
        # RISK LEVELS
        # =================================================

        if score >= CRITICAL_THREAT_THRESHOLD:
            risk_level = "CRITICAL"

        elif score >= HIGH_THREAT_THRESHOLD:
            risk_level = "HIGH"

        elif score >= MEDIUM_THREAT_THRESHOLD:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        # =================================================
        # ACTION DECISION
        # =================================================

        is_flagged = score >= MEDIUM_THREAT_THRESHOLD

        is_high_risk = score >= HIGH_THREAT_THRESHOLD

        should_block = score >= CRITICAL_THREAT_THRESHOLD

        attack_categories: Set[str] = {
            finding.split(":")[0]
            for finding in findings
            if ":" in finding
        }

        verdict_label = (
            "Authority Impersonation"
            if "HITL_BYPASS_ATTEMPT" in attack_categories
            else "Clean"
            if risk_level == "LOW"
            else "Threat Detected"
        )

        category = (
            "HITL_BYPASS_ATTEMPT"
            if "HITL_BYPASS_ATTEMPT" in attack_categories
            else verdict_label
        )

        recommended_action = (
            "BLOCK"
            if should_block or hitl_bypass_detected
            else "REVIEW"
            if is_flagged
            else "ALLOW"
        )

        return {
            "is_flagged": is_flagged,
            "is_high_risk": is_high_risk,
            "should_block": should_block,
            "risk_level": risk_level,
            "severity": risk_level,
            "threat_score": round(score, 4),
            "restricted_tool_calls": restricted_tools,
            "matched_findings": findings,
            "attack_categories": list(attack_categories),
            "verdict_label": verdict_label,
            "category": category,
            "recommended_action": recommended_action,
        }

    except Exception as exc:

        return {
            "is_flagged": True,
            "is_high_risk": True,
            "should_block": True,
            "risk_level": "CRITICAL",
            "threat_score": 1.0,
            "restricted_tool_calls": [],
            "matched_findings": [
                f"detector_failure:{str(exc)}"
            ],
            "attack_categories": ["system_failure"],
        }