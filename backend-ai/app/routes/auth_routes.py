from __future__ import annotations

import json
import logging
from typing import Any
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import ValidationError

from app.dependencies.public_forms import protect_auth_form
from app.middleware.auth_middleware import decode_token, get_current_user
from app.middleware.public_rate_limiter import check_public_rate_limit
from app.models.user_model import user_model
from app.schemas.api_schema import ApiResponse, ok
from app.schemas.auth_schema import (
    ForgotPasswordRequest,
    LogoutRequest,
    MessageResponse,
    RefreshTokenRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    Token,
    VerifyEmailRequest,
)
from app.schemas.user_schema import LoginRequest, SignupRequest, UserResponse
from app.services.auth_service import (
    authenticate_user,
    create_user,
    get_user_by_id,
    issue_password_reset_token,
    resend_verification_email,
    reset_password_for_user,
    verify_email_token_for_user,
)
from app.services.dashboard_service import record_audit_event
from app.services.session_service import (
    create_refresh_session,
    revoke_refresh_session,
    rotate_refresh_session,
)
from app.utils.client_ip import get_client_ip
from app.utils.token_generator import create_access_token

router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _normalize_email(value: str) -> str:
    return value.strip().lower()


def _mask_email(value: str) -> str:
    """Keep logs useful for support without storing full addresses."""
    local, _, domain = str(value).partition("@")
    return f"{local[:2]}***@{domain}" if domain else "***"


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "unknown")


def _client_identifier(request: Request) -> str:
    return get_client_ip(request)


def _no_store(response: Response) -> None:
    # Token responses must never be cached by browsers or intermediaries.
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


async def _apply_auth_rate_limit(
    *, request: Request, scope: str, email: str | None = None, limit: int, window_seconds: int
) -> None:
    # Mongo-backed and shared across workers. The old in-memory limiter was per-process,
    # so every extra worker/instance multiplied the effective limit.
    await check_public_rate_limit(
        _client_identifier(request), scope=f"{scope}:ip", limit=limit, window_seconds=window_seconds, request=request
    )
    if email:
        await check_public_rate_limit(
            _normalize_email(email), scope=f"{scope}:email", limit=limit, window_seconds=window_seconds, request=request
        )


# TODO: move this to a Mongo collection so IPs can be added/removed without a redeploy.
BLOCKED_IPS: set[str] = set()


def _reject_if_blocked_ip(request: Request) -> None:
    client_id = _client_identifier(request)
    if client_id in BLOCKED_IPS:
        logger.warning("Blocked IP attempted auth request_id=%s", _request_id(request))
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


async def _build_token_response(*, user: UserResponse, extra_claims: dict | None = None) -> Token:
    token_payload = {"sub": user.email, "user_id": user.id, **(extra_claims or {})}
    access_token = create_access_token(data=token_payload)
    refresh_token = await create_refresh_session(user_id=user.id, email=user.email, extra_claims=extra_claims)
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        role=user.role,
        user=user,
    )


async def _record_auth_audit_event(
    request: Request,
    *,
    action: str,
    email: str,
    success: bool,
    user_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    pseudo_user = {
        "id": user_id or email,
        "_id": user_id or email,
        "email": email,
        "organization_name": email.split("@", 1)[1] if "@" in email else email,
        "tier": "FREE",
        "role": "user",
        "is_active": True,
        "is_verified": success,
        "monthly_limit": 0,
    }
    try:
        await record_audit_event(
            request,
            current_user=pseudo_user,
            action=action,
            resource="auth",
            severity="INFO" if success else "WARNING",
            metadata={
                "request_id": _request_id(request),
                "ip_address": _client_identifier(request),
                "auth_method": "Password",
                "client": "Web browser",
                "user_agent": (request.headers.get("user-agent") or "")[:256],
                **(metadata or {}),
            },
        )
    except Exception:
        logger.exception("Failed to persist auth audit action=%s request_id=%s", action, _request_id(request))


async def _extract_login_payload(request: Request) -> LoginRequest:
    content_type = request.headers.get("content-type", "").lower()
    try:
        if "application/json" in content_type:
            return LoginRequest.model_validate(await request.json())
        body = (await request.body()).decode("utf-8", errors="ignore")
        parsed = parse_qs(body, keep_blank_values=True)
        return LoginRequest.model_validate(
            {
                "email": (parsed.get("username") or parsed.get("email") or [""])[0],
                "password": (parsed.get("password") or [""])[0],
            }
        )
    except ValidationError as exc:
        # pydantic's `input` field would echo the submitted password back to the caller. Drop it.
        safe_errors = [{"loc": list(e.get("loc", [])), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=safe_errors) from exc
    except (ValueError, json.JSONDecodeError) as exc:
        # Malformed JSON used to surface as a 500.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Malformed request body") from exc


@router.post("/signup", response_model=ApiResponse[MessageResponse], status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(protect_auth_form("signup"))])
async def signup(payload: SignupRequest, request: Request):
    logger.info("Signup requested request_id=%s email=%s", _request_id(request), _mask_email(str(payload.email)))
    signup_result = await create_user(payload)
    logger.info("Signup completed request_id=%s", _request_id(request))
    return ok(
        MessageResponse(
            message="Verification email sent successfully.",
            email=signup_result.user.email,
            email_sent=True,
        )
    )


@router.post("/login", response_model=ApiResponse[Token], dependencies=[Depends(protect_auth_form("login"))])
async def login(request: Request, response: Response):
    _reject_if_blocked_ip(request)
    login_payload = await _extract_login_payload(request)
    normalized_email = _normalize_email(str(login_payload.email))
    logger.info("Login requested request_id=%s email=%s", _request_id(request), _mask_email(normalized_email))
    try:
        user = await authenticate_user(normalized_email, login_payload.password)
        serialized_user = UserResponse.model_validate(user_model(user))
        await _record_auth_audit_event(
            request, action="login_success", email=normalized_email, success=True, user_id=str(serialized_user.id),
        )
        token_response = await _build_token_response(user=serialized_user)
        _no_store(response)
        logger.info("Login succeeded request_id=%s", _request_id(request))
        return ok(token_response)
    except HTTPException as exc:
        # Expected failure (bad credentials, unverified, inactive): no stack trace, so attackers
        # cannot flood the logs with tracebacks.
        await _record_auth_audit_event(request, action="login_failed", email=normalized_email, success=False)
        logger.warning("Login rejected request_id=%s status=%s", _request_id(request), exc.status_code)
        raise
    except Exception:
        await _record_auth_audit_event(request, action="login_failed", email=normalized_email, success=False)
        logger.exception("Login crashed request_id=%s", _request_id(request))
        raise


@router.post("/refresh", response_model=ApiResponse[Token])
async def refresh_token(payload: RefreshTokenRequest, request: Request, response: Response):
    await _apply_auth_rate_limit(request=request, scope="auth_refresh", limit=20, window_seconds=300)
    token_data = decode_token(payload.refresh_token, expected_type="refresh")
    user = await get_user_by_id(str(token_data.user_id))
    if user is None or str(user.get("email", "")).lower() != str(token_data.email).lower():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not bool(user.get("is_active", True)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive")
    if not bool(user.get("is_verified", False)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")

    serialized_user = UserResponse.model_validate(user_model(user))
    new_refresh_token = await rotate_refresh_session(token_data, user_id=serialized_user.id, email=serialized_user.email)
    access_token = create_access_token(data={"sub": serialized_user.email, "user_id": serialized_user.id})
    _no_store(response)
    return ok(Token(access_token=access_token, refresh_token=new_refresh_token, token_type="bearer", user=serialized_user))


@router.post("/logout", response_model=ApiResponse[MessageResponse])
async def logout(request: Request, payload: LogoutRequest | None = None):
    await _apply_auth_rate_limit(request=request, scope="auth_logout", limit=30, window_seconds=300)
    if payload and payload.refresh_token:
        try:
            token_data = decode_token(payload.refresh_token, expected_type="refresh")
            await revoke_refresh_session(token_data, reason="logout")
        except HTTPException:
            logger.info("Logout received an invalid or expired refresh token; returning success anyway")
    return ok(MessageResponse(message="Logged out successfully."))


@router.post("/forgot-password", response_model=ApiResponse[MessageResponse],
             dependencies=[Depends(protect_auth_form("forgot_password"))])
async def forgot_password(payload: ForgotPasswordRequest, request: Request):
    logger.info("Forgot-password requested request_id=%s", _request_id(request))
    await issue_password_reset_token(str(payload.email))
    return ok(MessageResponse(message="If an account exists, a password reset email has been sent."))


@router.post("/resend-verification", response_model=ApiResponse[MessageResponse],
             dependencies=[Depends(protect_auth_form("resend_verification", limit=1, window_seconds=60))])
async def resend_verification(payload: ResendVerificationRequest, request: Request):
    logger.info("Resend verification requested request_id=%s", _request_id(request))
    result = await resend_verification_email(str(payload.email))
    return ok(MessageResponse(message=result.message, email=str(payload.email), email_sent=result.email_sent))


# NOTE: a GET that changes state is consumed by email-security scanners that prefetch links, and
# the token travels in the URL (proxy logs, Referer). Prefer POST only: have the frontend page read
# the token from the URL and POST it, then delete this GET route.
@router.get("/verify-email", response_model=ApiResponse[MessageResponse])
async def verify_email_get(request: Request, token: str | None = Query(default=None, max_length=2048)):
    await _apply_auth_rate_limit(request=request, scope="auth_verify_email", limit=10, window_seconds=900)
    user = await verify_email_token_for_user(token)
    return ok(MessageResponse(message="Email verified successfully.", email=user.email, email_sent=True))


@router.post("/verify-email", response_model=ApiResponse[MessageResponse])
async def verify_email_post(payload: VerifyEmailRequest, request: Request):
    await _apply_auth_rate_limit(request=request, scope="auth_verify_email", limit=10, window_seconds=900)
    user = await verify_email_token_for_user(payload.token)
    return ok(MessageResponse(message="Email verified successfully.", email=user.email, email_sent=True))


@router.post("/reset-password", response_model=ApiResponse[MessageResponse],
             dependencies=[Depends(protect_auth_form("reset_password", limit=10))])
async def reset_password(payload: ResetPasswordRequest, request: Request):
    logger.info("Reset-password requested request_id=%s", _request_id(request))
    await reset_password_for_user(payload.token, payload.new_password)
    return ok(MessageResponse(message="Password reset completed successfully."))


@router.get("/me", response_model=ApiResponse[UserResponse])
async def read_auth_me(current_user: dict = Depends(get_current_user)):
    return ok(UserResponse.model_validate(user_model(current_user)))