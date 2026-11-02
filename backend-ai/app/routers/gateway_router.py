from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.tier import RECOMMENDED_MODELS, TIER_LIMITS, normalize_tier, require_scan_entitlement, tier_limits_for
from app.middleware.auth_middleware import get_current_user
from app.middleware.rate_limiter import check_rate_limit
from app.schemas.api_schema import fail, ok
from app.schemas.gateway_schema import GatewayChatRequest, GatewayChatResponse, GatewaySecurity, GatewayUsage
from app.security.redaction_engine import redact_sensitive_data
from app.services.ai_providers import ProviderConfigurationError, ProviderFailure, get_provider
from app.services.ai_providers.base import estimate_messages_tokens
from app.services.dashboard_service import tier_for, utcnow
from app.services.gateway_service import (
    count_gateway_usage_since,
    record_gateway_audit,
    record_gateway_usage,
)
from app.services.dashboard_service import record_security_findings_audit_events
from app.services.security_service import scan_prompt_with_resilience

router = APIRouter(tags=["gateway"])


IMPLEMENTED_GATEWAY_PROVIDERS: dict[str, dict[str, str]] = {
    "openai": {"label": "OpenAI"},
    "gemini": {"label": "Google Gemini"},
    "anthropic": {"label": "Anthropic / Claude"},
    "xai": {"label": "xAI / Grok"},
}

COMING_SOON_GATEWAY_PROVIDERS: list[dict[str, str]] = [
    {
        "id": "local_custom",
        "label": "Local / Custom",
        "status": "enterprise_connector_required",
        "reason": "Enterprise connector required",
        "disabled_reason": "Enterprise connector required",
    },
]

SECURITY_PROFILES = ["standard", "strict", "financial_guardrail", "maximum_lockdown"]


def _provider_configured(provider_id: str) -> bool:
    if provider_id == "openai":
        return bool(str(settings.OPENAI_API_KEY or "").strip())
    if provider_id == "gemini":
        return bool(str(settings.GEMINI_API_KEY or "").strip())
    if provider_id == "anthropic":
        return bool(str(settings.ANTHROPIC_API_KEY or "").strip())
    if provider_id == "xai":
        return bool(str(settings.XAI_API_KEY or "").strip())
    return False


def _messages_to_prompt(payload: GatewayChatRequest) -> str:
    return "\n".join(f"{message.role}: {message.content}" for message in payload.messages or [])


def _scannable_messages(payload: GatewayChatRequest) -> list:
    """Messages whose text is treated as potentially attacker-controlled.

    ``system``/``assistant`` roles are authored by the authenticated API caller and the model, and
    legitimately contain defensive wording; scanning them as attacks blocked ordinary system
    prompts. Set GATEWAY_SCAN_NON_USER_ROLES=true to scan every role. If a request has no user
    message at all, everything is scanned (nothing is silently skipped).
    """
    messages = list(payload.messages or [])
    if getattr(settings, "GATEWAY_SCAN_NON_USER_ROLES", False):
        return messages
    user_messages = [m for m in messages if m.role == "user"]
    return user_messages or messages


def _messages_to_scan_prompt(payload: GatewayChatRequest) -> str:
    return "\n".join(f"{message.role}: {message.content}" for message in _scannable_messages(payload))


def _policy_names(scan_result: dict[str, Any]) -> list[str]:
    enforcement = scan_result.get("security_enforcement") if isinstance(scan_result.get("security_enforcement"), dict) else {}
    return [
        str(policy.get("policy_name"))
        for policy in enforcement.get("policy_matches") or []
        if isinstance(policy, dict) and str(policy.get("policy_name") or "").strip()
    ]


def _tool_context_from_metadata(metadata: dict[str, Any] | None) -> tuple[str | None, dict[str, Any] | None]:
    if not isinstance(metadata, dict):
        return None, None

    raw_tool_name = str(metadata.get("tool_name") or "").strip()
    tool_name = raw_tool_name if raw_tool_name and raw_tool_name.lower() != "none" else None
    tool_args = metadata.get("tool_args") if isinstance(metadata.get("tool_args"), dict) else {}
    financial_risk = metadata.get("financial_risk") if isinstance(metadata.get("financial_risk"), dict) else {}

    merged_args = {
        **tool_args,
        **({"financial_risk": financial_risk} if financial_risk else {}),
    }
    return tool_name, merged_args or None


def _error_response(*, status_code: int, code: str, message: str, request_id: str, details: Any | None = None) -> JSONResponse:
    payload_details = {"request_id": request_id, **(details if isinstance(details, dict) else {})}
    body = fail(code=code, message=message, details=payload_details).model_dump(mode="json")
    if body.get("error"):
        body["error"]["request_id"] = request_id
    return JSONResponse(status_code=status_code, content=body)


def _minimum_tier_for_model(provider: str, model: str) -> str | None:
    for tier_name in ("FREE", "PRO", "BUSINESS"):
        limits = TIER_LIMITS[tier_name]
        if model in limits.allowed_models.get(provider, frozenset()):
            return tier_name
    return None


def _model_disabled_reason(*, active_plan: str, provider_key_configured: bool, provider: str, model: str) -> str | None:
    required_plan = _minimum_tier_for_model(provider, model)
    if required_plan and TIER_LIMITS[required_plan].name != active_plan:
        from app.core.tier import tier_rank

        if tier_rank(active_plan) < tier_rank(required_plan):
            return f"{required_plan} required"
    if not provider_key_configured:
        return "Provider key missing"
    return None


@router.get("/capabilities")
async def gateway_capabilities(current_user: dict = Depends(get_current_user)):
    active_plan = normalize_tier(tier_for(current_user))
    active_limits = tier_limits_for(active_plan)
    supported_providers: list[dict[str, Any]] = []

    for provider_id, provider_meta in IMPLEMENTED_GATEWAY_PROVIDERS.items():
        all_models = sorted(
            {
                model
                for limits in TIER_LIMITS.values()
                for model in limits.allowed_models.get(provider_id, frozenset())
            }
        )
        key_configured = _provider_configured(provider_id)
        allowed_models = active_limits.allowed_models.get(provider_id, frozenset())
        models: list[dict[str, Any]] = []
        for model in all_models:
            model_allowed_by_plan = model in allowed_models
            reason = _model_disabled_reason(
                active_plan=active_plan,
                provider_key_configured=key_configured,
                provider=provider_id,
                model=model,
            )
            models.append(
                {
                    "id": model,
                    "label": model,
                    "recommended": model in RECOMMENDED_MODELS.get(provider_id, frozenset()),
                    "required_plan": _minimum_tier_for_model(provider_id, model),
                    "allowed_by_plan": model_allowed_by_plan,
                    "enabled": bool(key_configured and model_allowed_by_plan),
                    "executable": bool(key_configured and model_allowed_by_plan),
                    "reason": reason,
                    "disabled_reason": reason,
                }
            )

        executable = any(model["enabled"] for model in models)
        provider_reason = None if executable else ("Provider key missing" if not key_configured else "No executable models for active plan")
        provider_status = "available" if executable else ("provider_key_missing" if not key_configured else "locked_by_plan")
        supported_providers.append(
            {
                "id": provider_id,
                "label": provider_meta["label"],
                "implemented": True,
                "key_configured": key_configured,
                "provider_key_configured": key_configured,
                "configured": key_configured,
                "enabled": executable,
                "executable": executable,
                "status": provider_status,
                "reason": provider_reason,
                "disabled_reason": provider_reason,
                "configuration_status": "configured" if key_configured else "missing_provider_key",
                "models": models,
            }
        )

    for provider in COMING_SOON_GATEWAY_PROVIDERS:
        supported_providers.append(
            {
                **provider,
                "implemented": False,
                "key_configured": False,
                "provider_key_configured": False,
                "configured": False,
                "enabled": False,
                "executable": False,
                "configuration_status": provider["status"],
                "models": [],
            }
        )

    return ok(
        {
            "gateway_enabled": True,
            "gateway_active": True,
            "active_plan": active_plan,
            "plan_limits": {
                "monthly_requests": active_limits.monthly_requests,
                "requests_per_minute": active_limits.requests_per_minute,
                "max_prompt_chars": active_limits.max_prompt_chars,
                "audit_retention_days": active_limits.audit_retention_days,
            },
            "guardrails": {
                "prompt_limit_chars": active_limits.max_prompt_chars,
                "request_rate_per_minute": active_limits.requests_per_minute,
                "monthly_quota": active_limits.monthly_requests,
                "audit_retention_days": active_limits.audit_retention_days,
                "allowed_providers": sorted(active_limits.allowed_models.keys()),
                "allowed_models": {
                    provider: sorted(models)
                    for provider, models in active_limits.allowed_models.items()
                    if provider in IMPLEMENTED_GATEWAY_PROVIDERS
                },
                "max_security_profile": SECURITY_PROFILES[-1],
                "api_key_limit": active_limits.max_api_keys,
                "team_invitations": "team_dashboard" in active_limits.features,
                "mfa_hitl_available": "mfa_2fa" in active_limits.features or "human_review" in active_limits.features,
                "financial_guardrail_available": "enterprise_policy" in active_limits.features or active_plan in {"PRO", "BUSINESS"},
            },
            "providers": supported_providers,
            "supported_providers": supported_providers,
            "security_profiles": SECURITY_PROFILES,
            "allowed_security_profiles": SECURITY_PROFILES,
        }
    )


async def _enforce_gateway_tier(
    *,
    request: Request,
    current_user: dict[str, Any],
    provider: str,
    model: str,
    prompt: str,
    request_id: str,
):
    active_tier = normalize_tier(tier_for(current_user))
    try:
        limits = require_scan_entitlement(
            active_tier=active_tier,
            requested_tier=active_tier,
            provider=provider,
            model=model,
            prompt=prompt,
        )
    except HTTPException as exc:
        action = "model_denied" if exc.status_code == status.HTTP_403_FORBIDDEN else "quota_exceeded"
        await record_gateway_audit(
            request,
            current_user,
            action=action,
            provider=provider,
            model=model,
            request_id=request_id,
            prompt_preview=prompt,
            severity="WARNING",
        )
        raise

    identifier = str(current_user.get("id") or current_user.get("_id") or current_user.get("email") or "anonymous")
    try:
        check_rate_limit(identifier, "gateway_chat", limits.requests_per_minute, 60)
    except HTTPException:
        await record_gateway_audit(
            request,
            current_user,
            action="quota_exceeded",
            provider=provider,
            model=model,
            request_id=request_id,
            prompt_preview=prompt,
            severity="WARNING",
            metadata={"limit_type": "rate"},
        )
        raise

    month_start = utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    used = await count_gateway_usage_since(request, current_user, month_start)
    if used >= limits.monthly_requests:
        await record_gateway_audit(
            request,
            current_user,
            action="quota_exceeded",
            provider=provider,
            model=model,
            request_id=request_id,
            prompt_preview=prompt,
            severity="WARNING",
            metadata={"limit_type": "monthly", "used": used, "limit": limits.monthly_requests},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={"message": "Monthly gateway quota exceeded.", "used": used, "limit": limits.monthly_requests},
        )
    return limits


@router.post("/chat")
async def gateway_chat(payload: GatewayChatRequest, request: Request, current_user: dict = Depends(get_current_user)):
    request_id = getattr(request.state, "request_id", None) or ""
    prompt = _messages_to_prompt(payload)
    scan_text = _messages_to_scan_prompt(payload)
    tool_name, tool_args = _tool_context_from_metadata(payload.metadata)

    try:
        await _enforce_gateway_tier(
            request=request,
            current_user=current_user,
            provider=payload.provider,
            model=payload.model,
            prompt=prompt,
            request_id=request_id,
        )
    except HTTPException as exc:
        code = "model_denied" if exc.status_code == status.HTTP_403_FORBIDDEN else "quota_exceeded"
        message = "Requested provider/model is not available for the active plan." if code == "model_denied" else "Gateway quota exceeded."
        return _error_response(status_code=exc.status_code, code=code, message=message, request_id=request_id)

    scan_result, scan_runtime = await scan_prompt_with_resilience(
        scan_text,
        provider=payload.provider,
        model=payload.model,
        security_tier=normalize_tier(tier_for(current_user)),
        session_id=str(current_user.get("id") or current_user.get("_id") or ""),
        conversation_id=str(payload.metadata.get("conversation_id")) if payload.metadata and payload.metadata.get("conversation_id") else None,
        conversation_history=[message.content for message in _scannable_messages(payload)],
        tool_name=tool_name,
        tool_args=tool_args,
        user_id=str(current_user.get("id") or current_user.get("_id") or ""),
        metadata={
            "route": "gateway_chat",
            "project": payload.project,
            "app_name": payload.app_name,
            "client_metadata": payload.metadata or {},
        },
    )
    status_value = str(scan_result.get("status") or "").upper()
    decision = str(scan_result.get("decision") or "ALLOW").lower()
    risk_score = int(scan_result.get("risk_score") or 0)
    security_payload = {
        "decision": decision,
        "risk_score": risk_score,
        "threat_type": scan_result.get("threat_type"),
        "matched_policies": _policy_names(scan_result),
        "status": status_value or "CLEAN",
        "requires_2fa": bool(scan_result.get("requires_2fa")),
        "review_required": bool(scan_result.get("review_required")),
    }

    would_block = status_value in {"BLOCKED", "REDACTED"} or decision == "block"
    monitor_only = getattr(settings, "GATEWAY_SECURITY_MODE", "enforce") == "monitor"
    if would_block and monitor_only:
        # Shadow mode: record what enforcement would have done, but let the request through.
        security_payload["mode"] = "monitor"
        security_payload["would_block"] = True
        await record_gateway_audit(
            request,
            current_user,
            action="gateway_request_would_block",
            provider=payload.provider,
            model=payload.model,
            request_id=request_id,
            prompt_preview=prompt,
            severity="WARNING",
            metadata={
                "risk_score": risk_score,
                "scan_runtime": scan_runtime.get("status"),
                "decision": decision,
                "threat_type": scan_result.get("threat_type"),
                "matched_policies": _policy_names(scan_result),
                "mode": "monitor",
            },
        )
        await record_security_findings_audit_events(
            request,
            current_user,
            scan_result=scan_result,
            resource="gateway",
            provider=payload.provider,
            model=payload.model,
            prompt_preview=prompt,
            request_id=request_id,
        )

    if would_block and not monitor_only:
        await record_gateway_usage(
            request,
            current_user,
            provider=payload.provider,
            model=payload.model,
            usage=GatewayUsage(input_tokens=estimate_messages_tokens(payload.messages or []), output_tokens=0, total_tokens=estimate_messages_tokens(payload.messages or []), estimated=True),
            status="blocked",
            security_decision=decision,
            request_id=request_id,
            prompt_preview=prompt,
        )
        await record_gateway_audit(
            request,
            current_user,
            action="gateway_request_blocked",
            provider=payload.provider,
            model=payload.model,
            request_id=request_id,
            prompt_preview=prompt,
            severity="CRITICAL",
            metadata={
                "risk_score": risk_score,
                "scan_runtime": scan_runtime.get("status"),
                "decision": decision,
                "matched_policies": _policy_names(scan_result),
                "prompt_preview": prompt,
            },
        )
        await record_security_findings_audit_events(
            request,
            current_user,
            scan_result=scan_result,
            resource="gateway",
            provider=payload.provider,
            model=payload.model,
            prompt_preview=prompt,
            request_id=request_id,
        )
        return _error_response(
            status_code=status.HTTP_403_FORBIDDEN,
            code="policy_blocked",
            message="Request blocked by Mefyx policy.",
            request_id=request_id,
            details={"security": security_payload},
        )

    try:
        provider = get_provider(payload.provider)
        provider_response = await provider.generate(
            messages=payload.messages or [],
            model=payload.model,
            temperature=payload.temperature,
            max_tokens=payload.max_tokens,
        )
    except ProviderConfigurationError:
        await record_gateway_audit(
            request,
            current_user,
            action="provider_not_configured",
            provider=payload.provider,
            model=payload.model,
            request_id=request_id,
            prompt_preview=prompt,
            severity="WARNING",
            metadata={"code": "provider_not_configured"},
        )
        return _error_response(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code="provider_not_configured",
            message=f"{payload.provider} provider is not configured.",
            request_id=request_id,
        )
    except ProviderFailure as exc:
        await record_gateway_audit(
            request,
            current_user,
            action=exc.code if exc.code in {"provider_auth_error", "provider_model_unavailable"} else "provider_error",
            provider=payload.provider,
            model=payload.model,
            request_id=request_id,
            prompt_preview=prompt,
            severity="WARNING",
            metadata={"code": exc.code, "retryable": exc.retryable, "prompt_preview": prompt},
        )
        return _error_response(
            status_code=status.HTTP_502_BAD_GATEWAY,
            code=exc.code,
            message="AI provider request failed safely.",
            request_id=request_id,
            details={"retryable": exc.retryable},
        )

    usage = provider_response.usage
    await record_gateway_usage(
        request,
        current_user,
        provider=provider_response.provider,
        model=provider_response.model,
        usage=usage,
        status="allowed",
        security_decision=decision,
        request_id=request_id,
        prompt_preview=prompt,
    )
    await record_gateway_audit(
        request,
        current_user,
        action="gateway_request_allowed",
        provider=provider_response.provider,
        model=provider_response.model,
        request_id=request_id,
        prompt_preview=prompt,
        severity="INFO",
        metadata={
            "risk_score": risk_score,
            "total_tokens": usage.total_tokens,
            "decision": decision,
            "matched_policies": _policy_names(scan_result),
            "prompt_preview": prompt,
        },
    )
    response = GatewayChatResponse(
        provider=provider_response.provider,
        model=provider_response.model,
        content=redact_sensitive_data(provider_response.content),
        usage=usage,
        security=GatewaySecurity(**security_payload),
        request_id=request_id,
    )
    return ok(response.model_dump(mode="json"))