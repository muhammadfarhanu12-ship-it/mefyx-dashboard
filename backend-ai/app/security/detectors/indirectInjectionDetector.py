from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable, List

from app.security.utils.types import DetectionMatch, SeverityLevel


# =========================================================
# NORMALIZATION
# =========================================================

def _normalize(text: str) -> str:
    """
    Normalize attacker-controlled input:
    - unicode normalization
    - whitespace cleanup
    - lowercase
    """
    if not text:
        return ""

    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()


def _credential_skeleton(text: str) -> str:
    """Fold common Cyrillic lookalikes only for credential indicator matching."""
    return _normalize(text).translate(str.maketrans({
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "у": "y",
    }))


# =========================================================
# EXTENDED INDIRECT INJECTION PATTERNS
# =========================================================

INDIRECT_INJECTION_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    (
        "untrusted_instruction_embedding",
        re.compile(
            r"<untrusted_data>.*?(ignore|override|bypass|execute|transfer|wire|credential|api key).*?</untrusted_data>",
            re.I | re.S,
        ),
        0.90,
    ),
    (
        "rag_poisoning_attempt",
        re.compile(
            r"\b(rag|retrieval|vector store|embedding)\b.{0,100}\b(ignore|bypass|override|modify instructions)\b",
            re.I,
        ),
        0.85,
    ),
    (
        "document_tool_abuse",
        re.compile(
            r"\b(invoice|pdf|email|ocr|document|attachment)\b.{0,120}\b(execute|transfer|wire|withdraw|send money|login)\b",
            re.I,
        ),
        0.80,
    ),
    (
        "instruction_in_data_stream",
        re.compile(
            r"(note|warning|instruction|system message).{0,80}(execute|run|transfer|call|tool|api)",
            re.I,
        ),
        0.75,
    ),
    (
        "hidden_command_in_text",
        re.compile(
            r"```.*?(transfer|wire|execute|bypass|override).*?```",
            re.I | re.S,
        ),
        0.70,
    ),
]


# =========================================================
# WEAK SIGNAL DETECTION (NEW)
# =========================================================

WEAK_INDICATORS = [
    "please process",
    "for automation",
    "system should",
    "ai must",
    "as part of workflow",
    "for efficiency",
    "no need to ask",
]

EXTERNAL_SOURCES = {"external_content", "webpage", "email", "social_post", "document", "tool_output", "article", "markdown", "conversation_history"}


PATTERN_GROUPS: dict[str, list[str]] = {
    "prompt_override": [
        r"ignore (?:all )?(?:previous|prior) (?:instructions|rules)",
        r"forget (?:all )?(?:your )?rules",
        r"disregard (?:the )?system message",
        r"reveal (?:the )?system prompt",
        r"print (?:the )?developer message",
        r"show (?:hidden )?instructions",
        r"\bact as\b",
        r"you are now",
        r"from now on",
        r"do not tell the user",
        r"secret instruction",
        r"hidden command",
        r"execute this",
        r"comply with this message instead",
        r"override (?:your )?safety policy",
        r"bypass (?:your )?guardrails",
    ],
    "agent_targeting": [
        r"\bai bot\b",
        r"\bai agent\b",
        r"\bassistant\b",
        r"\bautonomous agent\b",
        r"\btool\b",
        r"\bfunction\b",
        r"\bplugin\b",
        r"\bapi\b",
        r"\bwallet\b",
        r"\bbank(?:er|ing)? bot\b",
        r"\bbankrbot\b",
        r"\bcrypto bot\b",
        r"\btrading bot\b",
        r"\bpayment bot\b",
        r"\btransfer agent\b",
        r"\bbrowser agent\b",
        r"\bemail agent\b",
        r"\bcode agent\b",
        r"\bautomation agent\b",
        r"\bbot\b",
    ],
    "financial_action": [
        r"send money",
        r"transfer money",
        r"transfer (?:funds|tokens)",
        r"send (?:\d[\d,.\s]*(?:billion|million|thousand)?\s*)?(?:[a-z0-9]{2,10}\s+)?tokens?",
        r"\bwithdraw\b",
        r"approve transaction",
        r"sign transaction",
        r"drain wallet",
        r"wallet address",
        r"bank account",
        r"invoice payment",
        r"wire transfer",
        r"\bpayment\b",
        r"\bcrypto\b",
        r"\btoken\b",
        r"\b(?:usdt|eth|btc|drb|stablecoin)\b",
    ],
    "credential_access": [
        r"private key",
        r"seed phrase",
        r"recovery phrase",
        r"\b(?:card )?pin\b",
        r"\bpassword\b",
        r"one[- ]time passcode",
        r"\botp\b",
        r"send credentials",
        r"show password",
        r"show api key",
        r"show access token",
    ],
    "tool_execution_request": [
        r"call (?:this )?tool",
        r"execute (?:this )?function",
        r"run (?:this )?api",
        r"invoke (?:the )?plugin",
        r"submit (?:this )?transaction",
        r"send (?:this )?request",
        r"approve (?:this )?action",
        r"forward (?:this )?instruction",
        r"tag (?:this )?bot",
        r"pass (?:this )?message to (?:the )?agent",
        r"treat this as user authorization",
        r"call (?:the )?[a-z0-9_ -]*(?:tool|function|api)",
    ],
    "data_exfiltration": [
        r"reveal secrets?",
        r"upload files?",
        r"leak data",
        r"export database",
        r"email (?:the )?logs",
        r"dump environment variables",
        r"send internal notes",
        r"reveal hidden policy",
        r"reveal system prompt",
        r"print (?:the )?developer message",
    ],
    "multilingual_signal": [
        r"pichli instructions ignore karo",
        r"purani instructions ignore karo",
        r"system prompt dikhao",
        r"hidden command",
        r"secret message",
        r"banker bot",
        r"bankrbot",
        r"wallet mein bhej do",
        r"bhej do",
        r"raqam transfer kar do",
        r"paise bhej do",
        r"tokens? mere wallet mein",
        r"private key dikhao",
        r"seed phrase dikhao",
        r"otp bhejo",
        r"contrasena muestra",
        r"mostrar prompt del sistema",
        r"ignora las instrucciones anteriores",
        r"ignorer les instructions precedentes",
        r"zeige den system prompt",
    ],
}


def _compile(patterns: Iterable[str]) -> list[re.Pattern]:
    return [re.compile(pattern, re.I | re.S) for pattern in patterns]


COMPILED_GROUPS = {category: _compile(patterns) for category, patterns in PATTERN_GROUPS.items()}


def _find_group(text: str, category: str) -> list[dict[str, Any]]:
    normalized = _normalize(text)
    hits: list[dict[str, Any]] = []
    for pattern in COMPILED_GROUPS.get(category, []):
        for match in pattern.finditer(normalized):
            signal = match.group(0).strip()
            if signal and signal not in [item["signal"] for item in hits]:
                hits.append({"category": category, "signal": signal, "pattern": pattern.pattern})
    return hits


def detect_prompt_override(text: str) -> list[dict[str, Any]]:
    return _find_group(text, "prompt_override")


def detect_agent_targeting(text: str) -> list[dict[str, Any]]:
    return _find_group(text, "agent_targeting")


def detect_financial_or_crypto_action(text: str) -> list[dict[str, Any]]:
    return _find_group(text, "financial_action") + _find_group(text, "credential_access")


def detect_tool_execution_request(text: str) -> list[dict[str, Any]]:
    return _find_group(text, "tool_execution_request")


def detect_data_exfiltration_request(text: str) -> list[dict[str, Any]]:
    return _find_group(text, "data_exfiltration")


def detect_multilingual_signals(text: str) -> list[dict[str, Any]]:
    return _find_group(text, "multilingual_signal")


def _context_is_untrusted(context: dict[str, Any] | None) -> bool:
    ctx = context or {}
    source = str(ctx.get("source") or "").lower()
    if ctx.get("trusted") is False:
        return True
    return source in EXTERNAL_SOURCES and ctx.get("trusted") is not True


def _risk_level(score: int) -> str:
    if score >= 86:
        return "critical"
    if score >= 46:
        return "high"
    if score >= 21:
        return "medium"
    return "low"


def _verdict(score: int) -> str:
    if score >= 71:
        return "block"
    if score >= 21:
        return "warn"
    return "allow"


def detect_indirect_prompt_injection(text: str, context: dict | None = None) -> dict:
    """
    Rich indirect prompt-injection detector for untrusted, decoded, translated,
    or extracted content. It intentionally scores combinations of signals; an
    article merely discussing prompt injection should not become critical unless
    it contains an actionable command to an agent/tool/wallet/API.
    """
    context = context or {}
    variant_source = str(context.get("variant_source") or "original")
    decode_signals = set(context.get("decode_signals") or [])
    untrusted = _context_is_untrusted(context)
    encoded_source = any(token in variant_source for token in ("morse", "base64", "hex", "url")) or bool(
        decode_signals & {
            "morse_payload_detected",
            "base64_payload_decoded",
            "hex_payload_decoded",
            "url_encoded_payload_detected",
        }
    )
    unicode_obfuscated = bool(decode_signals & {"zero_width_chars_detected"})

    groups = {
        "prompt_override": detect_prompt_override(text),
        "agent_targeting": detect_agent_targeting(text),
        "financial_action": _find_group(text, "financial_action"),
        "credential_access": _find_group(text, "credential_access"),
        "tool_execution_request": detect_tool_execution_request(text),
        "data_exfiltration": detect_data_exfiltration_request(text),
        "multilingual_signal": detect_multilingual_signals(text),
    }
    if not untrusted:
        # Role-assignment phrases are ordinary in a user's own prompt ("act as a tutor"); they are
        # only an override signal when found inside untrusted/retrieved content.
        _weak = {"act as", "you are now", "from now on", "execute this"}
        groups["prompt_override"] = [h for h in groups["prompt_override"] if str(h.get("signal", "")).lower() not in _weak]
    normalized_text = _credential_skeleton(text)
    quoted_attack = re.search(
        r"(['\"â€œ]).{0,180}\b(?:ignore\s+(?:all\s+)?previous instructions|reveal (?:the )?system prompt|print (?:the )?developer message|developer mode|jailbreak)\b.{0,180}?\1",
        normalized_text,
        re.I,
    )
    educational_framing = re.search(
        r"\b(?:security training|security awareness|educational|awareness slide|documenting|paper about|explain why|translate the sentence|compar(?:e|es))\b",
        normalized_text,
        re.I,
    )
    unquoted_attack = re.sub(
        r"(['\"â€œ]).{0,180}\b(?:ignore\s+(?:all\s+)?previous instructions|reveal (?:the )?system prompt|print (?:the )?developer message|developer mode|jailbreak)\b.{0,180}?\1",
        " ",
        normalized_text,
        flags=re.I,
    )
    unquoted_action = re.search(
        r"\b(?:reveal|show|output|send|steal|exfiltrate|execute|transfer|invoke|call|run|print)\b.{0,80}"
        r"\b(?:system prompt|hidden prompt|developer message|secret|password|token|funds|wallet|tool)\b",
        unquoted_attack,
        re.I,
    )
    if quoted_attack and educational_framing and not unquoted_action:
        groups["prompt_override"] = []
        groups["data_exfiltration"] = []

    credential_solicitation = bool(
        re.search(
            r"\b(?:pin|password|otp|one[- ]time passcode|passcode|recovery phrase|seed phrase|private key|security code|cvv)\b"
            r".{0,100}\b(?:ask(?:s|ed)?|request(?:s|ed)?|require(?:s|d)?|demand(?:s|ed)?|tell(?:s|ing)?|instruct(?:s|ed)?|urge(?:s|d)?|need(?:s|ed)?)\b"
            r".{0,100}\b(?:share|provide|enter|send|tell|give|confirm|verify|disclose|reveal|submit)\b"
            r"|\b(?:ask(?:s|ed)?|request(?:s|ed)?|tell(?:s|ing)?|instruct(?:s|ed)?|urge(?:s|d)?|need(?:s|ed)?)\b"
            r".{0,100}\b(?:share|provide|enter|send|tell|give|confirm|verify|disclose|reveal|submit|for)\b"
            r".{0,100}\b(?:pin|password|otp|one[- ]time passcode|passcode|recovery phrase|seed phrase|private key|security code|cvv)\b"
            r"|\b(?:share|provide|enter|send|tell|give|confirm|verify|disclose|reveal|submit)\b"
            r".{0,100}\b(?:pin|password|otp|one[- ]time passcode|passcode|recovery phrase|seed phrase|private key|security code|cvv)\b",
            normalized_text,
            re.I,
        )
        or re.search(
            r"\b(?:ask(?:s|ed)?|request(?:s|ed)?|require(?:s|d)?|demand(?:s|ed)?|tell(?:s|ing)?|instruct(?:s|ed)?|urge(?:s|d)?|need(?:s|ed)?)\b"
            r".{0,80}\b(?:(?:the|your|their|customer's|account holder's)\s+)?"
            r"(?:pin|password|otp|one[- ]time passcode|passcode|recovery phrase|seed phrase|private key|security code|cvv)\b"
            r"|\breply with\b.{0,50}\b(?:pin|password|otp|one[- ]time passcode|passcode|recovery phrase|seed phrase|private key|security code|cvv)\b",
            normalized_text,
            re.I,
        )
    )
    education_request = bool(
        re.search(
            r"\b(?:how to|explain|teach|describe|recogniz(?:e|ing)|spot|identify|detect|report|avoid|review|analy[sz]e|list)\b"
            r".{0,160}\b(?:scam|phish|fraud|fake (?:bank )?alerts?|credential theft|social engineering|impersonation|safety lesson|suspicious sms|safe account practices|red flags)\b",
            normalized_text,
            re.I,
        )
        or re.search(
            r"\b(?:can|should|would)\b.{0,60}\b(?:legitimate|real|official)\b.{0,80}"
            r"\b(?:ask|request|read|disclose|share)\b.{0,40}\b(?:otp|passcode|pin|password|recovery phrase)\b",
            normalized_text,
            re.I,
        )
        or re.search(
            r"\b(?:never|do\s+not|don't|must\s+not|should\s+not|shouldn't)\s+(?:give|share|send|tell|reveal|provide|enter|disclose)\b",
            normalized_text,
            re.I,
        )
        or re.search(
            r"\b(?:what\s+(?:should|do|can|steps)\s+(?:i|we)|what\s+steps|should\s+i|is\s+(?:this|it)\s+(?:a\s+)?(?:scam|safe|legit)|how\s+(?:do|can)\s+i\s+(?:recover|secure|protect|report))\b",
            normalized_text,
            re.I,
        )
        or re.search(
            r"\b(?:never|should not|shouldn't|must not|mustn't|will not|won't|do not|don't)\b.{0,60}\b(?:request|ask for|ask(?:\s+\w+){1,3}\s+for)\b.{0,60}"
            r"\b(?:pin|password|otp|one[- ]time passcode|passcode|recovery phrase|seed phrase|private key|security code|cvv)\b",
            normalized_text,
            re.I,
        )
    )
    # A plain informational question ("explain what a seed phrase is", "what is an OTP") only
    # *mentions* credentials/wallets; it is not an instruction to an agent. Without this,
    # security education scored as critical credential theft.
    informational_question = bool(
        re.match(r"\s*(?:please\s+)?(?:can\s+you\s+)?(?:explain|what\s+(?:is|are|does)|define|describe|why\s+(?:is|are|do|does)|how\s+(?:does|do)\s+(?:a|an|the)?|compare|list|summari[sz]e|recommend|which|tell\s+me\s+about|give\s+me\s+(?:a|an|the|five|three|some)\s+(?:summary|overview|list|comparison))\b", normalized_text, re.I)
    )
    if (
        informational_question
        and not credential_solicitation
        and not (groups["prompt_override"] or groups["tool_execution_request"] or groups["data_exfiltration"])
    ):
        groups["credential_access"] = []
        groups["agent_targeting"] = []
        groups["financial_action"] = []

    if credential_solicitation and not education_request:
        groups["credential_access"].append(
            {"category": "credential_access", "signal": "credential solicitation", "pattern": "credential_solicitation"}
        )
    categories: set[str] = set()
    matched_signals: list[dict[str, Any]] = []

    for category, hits in groups.items():
        if not hits:
            continue
        categories.add(category)
        for hit in hits:
            severity = "critical" if category in {"financial_action", "credential_access", "data_exfiltration"} else "high"
            matched_signals.append(
                {
                    "category": category,
                    "signal": hit["signal"],
                    "variant_source": variant_source,
                    "severity": severity,
                }
            )

    if groups["financial_action"] and re.search(r"\b(?:crypto|token|tokens|usdt|eth|btc|drb|stablecoin|wallet)\b", _normalize(text), re.I):
        categories.add("crypto_transfer")

    if encoded_source:
        categories.update({"encoded_instruction"})
        if "morse" in variant_source or "morse_payload_detected" in decode_signals:
            categories.add("morse_payload")
        if "base64" in variant_source:
            categories.add("base64_payload")
        if "hex" in variant_source:
            categories.add("hex_payload")

    if unicode_obfuscated:
        categories.add("unicode_obfuscation")

    actionable = bool(
        groups["financial_action"]
        or groups["credential_access"]
        or groups["tool_execution_request"]
        or groups["data_exfiltration"]
    )
    agent_directed = bool(groups["agent_targeting"])
    suspicious_wording = bool(groups["prompt_override"] or groups["multilingual_signal"])

    score = 0
    if groups["prompt_override"]:
        score += 50
    elif suspicious_wording:
        score += 10
    if encoded_source:
        score += 15
    if agent_directed:
        score += 20
    if groups["financial_action"]:
        score += 25
    if groups["credential_access"]:
        score += 25
    if credential_solicitation and not education_request:
        # Treat an explicit request to disclose an authentication secret as a
        # high-risk credential theft signal; mere discussion of credentials
        # remains a lower-level signal.
        score = max(score, 85)
    if groups["tool_execution_request"]:
        score += 20
    if groups["data_exfiltration"]:
        score += 20
    if groups["prompt_override"] and groups["data_exfiltration"]:
        score = max(score, 85)
    if groups["multilingual_signal"]:
        score += 10
    if unicode_obfuscated:
        score += 10
    if encoded_source and (suspicious_wording or actionable or agent_directed):
        score += 15
    if encoded_source and actionable:
        score += 20
    if untrusted and agent_directed and actionable:
        score += 20
    if context.get("operation") in {"tool_call", "financial_action", "code_execution", "data_access"} and actionable:
        score += 15

    # Clear agent-directed financial/crypto commands should block even when no
    # external context is supplied; this catches bot instructions in pasted data.
    if agent_directed and groups["financial_action"]:
        score = max(score, 85)
    if groups["credential_access"] and (agent_directed or untrusted):
        score = max(score, 80)
    if groups["prompt_override"] and groups["tool_execution_request"]:
        score = max(score, 72)
    if encoded_source and agent_directed and actionable:
        score = max(score, 90)

    # Educational/awareness text without an actionable target should stay below
    # block thresholds even if it mentions prompt injection terminology.
    educational_context = bool(
        re.search(r"\b(article|awareness|educational|training|example|discusses|explaining|guide|lesson)\b", _normalize(text), re.I)
        or context.get("trusted") is True
    )
    if educational_context and not actionable and not agent_directed and groups["prompt_override"]:
        score = min(score, 45)
    if not actionable and not agent_directed and not encoded_source and not groups["prompt_override"]:
        score = min(score, 35)

    score = max(0, min(100, score))
    risk_level = _risk_level(score)
    verdict = _verdict(score)
    if untrusted and actionable and (agent_directed or encoded_source):
        verdict = "block"
        score = max(score, 80)
        risk_level = _risk_level(score)

    if score > 0:
        categories.add("indirect_prompt_injection")

    explanation = "No indirect prompt injection signals detected."
    recommended_action = "Allow."
    if verdict == "block":
        explanation = "External or decoded content contains an actionable instruction targeting an agent, tool, wallet, API, or sensitive operation."
        recommended_action = "Block tool execution and require human approval."
    elif verdict == "warn":
        explanation = "Suspicious prompt-injection or agent-directed wording was detected, but the action chain is incomplete."
        recommended_action = "Warn, isolate untrusted content, and require review before tool execution."

    return {
        "verdict": verdict,
        "risk_score": score,
        "risk_level": risk_level,
        "detected_categories": sorted(categories),
        "matched_signals": matched_signals,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "context": {
            "untrusted": untrusted,
            "variant_source": variant_source,
            "encoded_source": encoded_source,
        },
    }


# =========================================================
# INDIRECT INJECTION DETECTOR (HARDENED)
# =========================================================

def detect_indirect_injection(content: str) -> List[DetectionMatch]:

    findings: List[DetectionMatch] = []

    text = _normalize(content)

    base_score = 0.0

    # ---------------------------------------------
    # Strong pattern matches
    # ---------------------------------------------
    for label, pattern, confidence in INDIRECT_INJECTION_PATTERNS:

        if pattern.search(text):

            findings.append(
                DetectionMatch(
                    detector="indirect_injection",
                    label=label,
                    reason=f"Indirect injection pattern detected: {label}",
                    confidence=confidence,
                    severity=SeverityLevel.HIGH
                    if confidence >= 0.8
                    else SeverityLevel.MEDIUM,
                    metadata={"pattern": pattern.pattern},
                )
            )

            base_score += confidence

    # ---------------------------------------------
    # Weak semantic signals (important upgrade)
    # ---------------------------------------------
    weak_hits = 0

    for phrase in WEAK_INDICATORS:
        if phrase in text:
            weak_hits += 1

    if weak_hits >= 2:

        findings.append(
            DetectionMatch(
                detector="indirect_injection",
                label="weak_signal_chain",
                reason="Multiple weak instruction signals detected",
                confidence=0.65,
                severity=SeverityLevel.MEDIUM,
                metadata={"weak_hits": weak_hits},
            )
        )

        base_score += 0.30

    # ---------------------------------------------
    # Escalation logic (critical improvement)
    # ---------------------------------------------
    if len(findings) >= 2:

        findings.append(
            DetectionMatch(
                detector="indirect_injection",
                label="multi_vector_attack",
                reason="Multiple indirect injection vectors detected",
                confidence=min(0.95, base_score),
                severity=SeverityLevel.HIGH,
                metadata={"pattern_count": len(findings)},
            )
        )

    return findings