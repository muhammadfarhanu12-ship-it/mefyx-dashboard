from __future__ import annotations

from urllib.parse import parse_qs

from fastapi import HTTPException, Request

from app.middleware.public_rate_limiter import check_public_rate_limit
from app.core.config import settings
from app.services.turnstile_service import verify_turnstile


def rate_limit_public_form(action: str, *, limit: int = 5, window_seconds: int = 900):
    """Runs before the handler (including every mounted legacy route alias)."""
    async def guard(request: Request) -> dict:
        # Uvicorn alone resolves trusted proxies. Raw forwarding headers are untrusted.
        client_ip = request.client.host if request.client else "unknown"
        await check_public_rate_limit(
            client_ip, scope=f"public:{action}:ip", limit=limit,
            window_seconds=window_seconds, request=request,
        )
        form_encoded = "application/x-www-form-urlencoded" in request.headers.get("content-type", "").lower()
        try:
            if form_encoded:
                parsed = parse_qs((await request.body()).decode("utf-8"), keep_blank_values=True)
                payload = {key: values[0] for key, values in parsed.items()}
            else:
                payload = await request.json()
        except ValueError:
            raise HTTPException(400, "Invalid form request.") from None
        if not isinstance(payload, dict):
            raise HTTPException(400, "Invalid form request.")

        # Match _extract_login_payload exactly: form username wins over email.
        # A second email field must not let callers choose a different rate bucket.
        email = payload.get("username") if form_encoded and "username" in payload else payload.get("email")
        if isinstance(email, str) and email.strip():
            await check_public_rate_limit(
                email.strip().lower()[:320], scope=f"public:{action}:email", limit=limit,
                window_seconds=window_seconds, request=request,
            )
        return payload

    return guard


def protect_public_form(action: str, *, limit: int = 5, window_seconds: int = 900):
    """Rate limit and verify CAPTCHA for the contact form before any side effects."""
    rate_limit = rate_limit_public_form(action, limit=limit, window_seconds=window_seconds)

    async def guard(request: Request) -> None:
        payload = await rate_limit(request)
        await verify_turnstile(payload.get("turnstile_token"), action=action)

    return guard


def protect_auth_form(action: str, *, limit: int = 5, window_seconds: int = 900):
    """Rate limit auth endpoints and, when AUTH_REQUIRE_TURNSTILE is on, verify a Turnstile token."""
    rate_limit = rate_limit_public_form(action, limit=limit, window_seconds=window_seconds)

    async def guard(request: Request) -> None:
        payload = await rate_limit(request)
        if settings.AUTH_REQUIRE_TURNSTILE:
            await verify_turnstile(payload.get("turnstile_token"), action=action)

    return guard