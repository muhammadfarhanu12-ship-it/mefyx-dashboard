from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

BACKEND_ROOT = Path(__file__).resolve().parents[2]
# Load only the backend's real local .env file for development.
# Existing platform environment variables still win because override=False.
load_dotenv(BACKEND_ROOT / ".env", override=False)


_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off"}


def _resolve_env_value(name: str, aliases: tuple[str, ...] = ()) -> str | None:
    for key in (name, *aliases):
        value = os.getenv(key)
        if value is not None:
            return value
    return None


def _env_str(name: str, default: str | None = None, aliases: tuple[str, ...] = ()) -> str | None:
    raw = _resolve_env_value(name, aliases=aliases)
    if raw is None:
        return default
    cleaned = raw.strip()
    if cleaned == "":
        return default
    return cleaned


def _env_bool(name: str, default: bool, aliases: tuple[str, ...] = ()) -> bool:
    raw = _resolve_env_value(name, aliases=aliases)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return default


def _env_int(name: str, default: int, aliases: tuple[str, ...] = ()) -> int:
    raw = _resolve_env_value(name, aliases=aliases)
    if raw is None:
        return default
    try:
        return int(str(raw).strip())
    except Exception:
        return default


def _env_float(name: str, default: float, aliases: tuple[str, ...] = ()) -> float:
    raw = _resolve_env_value(name, aliases=aliases)
    if raw is None:
        return default
    try:
        return float(str(raw).strip())
    except Exception:
        return default


class Settings:
    def __init__(self) -> None:
        self.API_KEY_PREFIX: str = _env_str("API_KEY_PREFIX", "sentinel_sk_gateway_") or "sentinel_sk_gateway_"
        self.API_KEY_MASK: str = _env_str("API_KEY_MASK", "sentinel_sk_****") or "sentinel_sk_****"

        self.PROJECT_NAME: str = _env_str("PROJECT_NAME", "Mefyx Gateway") or "Mefyx Gateway"
        self.API_V1_PREFIX: str = _env_str("API_V1_PREFIX", "/api") or "/api"
        self.MONGODB_URI: str = _env_str("MONGODB_URI", aliases=("MONGO_URI",)) or ""
        self.MONGO_URI: str = self.MONGODB_URI
        self.MONGO_DB_NAME: str = _env_str("MONGO_DB_NAME", "sentinel_dashboard") or "sentinel_dashboard"

        self.JWT_SECRET: str = _env_str("JWT_SECRET", "") or ""
        self.ADMIN_JWT_SECRET: str = _env_str("ADMIN_JWT_SECRET", aliases=("ADMIN_TOKEN_SECRET",)) or self.JWT_SECRET
        self.JWT_ALGORITHM: str = _env_str("JWT_ALGORITHM", "HS256") or "HS256"
        self.JWT_ISSUER: str = _env_str("JWT_ISSUER", "sentinelcore") or "sentinelcore"
        self.JWT_AUDIENCE: str = _env_str("JWT_AUDIENCE", "sentinelcore-api") or "sentinelcore-api"
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = _env_int("ACCESS_TOKEN_EXPIRE_MINUTES", 15)
        self.REFRESH_TOKEN_EXPIRE_MINUTES: int = _env_int("REFRESH_TOKEN_EXPIRE_MINUTES", 10080)
        self.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = _env_int("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES", 30)
        self.API_KEY_SECRET: str = _env_str("API_KEY_SECRET", "") or ""

        self.LOG_LEVEL: str = _env_str("LOG_LEVEL", "INFO") or "INFO"
        self.APP_ENV: str = _env_str("APP_ENV", _env_str("ENVIRONMENT", "development")) or "development"
        self.CORS_ORIGINS: str = _env_str("CORS_ORIGINS", "*", aliases=("ALLOWED_ORIGINS",)) or "*"
        self.ENABLE_DEMO_MODE: bool = _env_bool("ENABLE_DEMO_MODE", False)
        self.DEMO_USER_EMAIL: str = _env_str("DEMO_USER_EMAIL", "demo@example.com") or "demo@example.com"
        self.TEST_API_KEY: str = _env_str("TEST_API_KEY", "test_key_123") or "test_key_123"
        self.ADMIN_BOOTSTRAP_EMAIL: str | None = _env_str(
            "ADMIN_BOOTSTRAP_EMAIL",
            aliases=("ADMIN_EMAIL", "SENTINEL_ADMIN_EMAIL"),
        )
        self.ADMIN_BOOTSTRAP_PASSWORD: str | None = _env_str(
            "ADMIN_BOOTSTRAP_PASSWORD",
            aliases=("ADMIN_PASSWORD", "SENTINEL_ADMIN_PASSWORD"),
        )
        self.ADMIN_LOGIN_ALERT_EMAIL: str | None = _env_str(
            "ADMIN_LOGIN_ALERT_EMAIL",
            default=self.ADMIN_BOOTSTRAP_EMAIL,
            aliases=("SENTINEL_ADMIN_ALERT_EMAIL",),
        )

        self.GEMINI_API_KEY: str | None = _env_str("GEMINI_API_KEY")
        self.OPENAI_API_KEY: str | None = _env_str("OPENAI_API_KEY")
        self.ANTHROPIC_API_KEY: str | None = _env_str("ANTHROPIC_API_KEY")
        self.XAI_API_KEY: str | None = _env_str("XAI_API_KEY")
        self.AI_PROVIDER: str | None = _env_str("AI_PROVIDER", "gemini")
        self.FALLBACK_AI_PROVIDER: str | None = _env_str("FALLBACK_AI_PROVIDER", "openai")
        self.AI_PROVIDER_TIMEOUT_SECONDS: float = _env_float("AI_PROVIDER_TIMEOUT_SECONDS", 30.0)
        self.FRONTEND_URL: str = _env_str("FRONTEND_URL", "https://sentinel-core-arei.vercel.app") or "https://sentinel-core-arei.vercel.app"
        self.ADMIN_FRONTEND_URL: str | None = _env_str(
            "ADMIN_FRONTEND_URL",
            "https://sentinel-admin-beta.vercel.app",
            aliases=("ADMIN_PANEL_URL",),
        )
        self.BACKEND_PUBLIC_URL: str = _env_str("BACKEND_PUBLIC_URL", "https://sentinel-core-xcrz.onrender.com") or "https://sentinel-core-xcrz.onrender.com"
        self.AUTH_VERIFY_EMAIL_PATH: str = _env_str("AUTH_VERIFY_EMAIL_PATH", "/verify-email") or "/verify-email"
        self.AUTH_RESET_PASSWORD_PATH: str = _env_str("AUTH_RESET_PASSWORD_PATH", "/reset-password") or "/reset-password"
        self.EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES: int = _env_int("EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES", 30)
        self.AUTH_DEBUG_TOKEN_LOGGING: bool = _env_bool("AUTH_DEBUG_TOKEN_LOGGING", False)
        self.OAUTH_STATE_EXPIRE_MINUTES: int = _env_int("OAUTH_STATE_EXPIRE_MINUTES", 10)
        self.OAUTH_FRONTEND_CALLBACK_PATH: str = _env_str("OAUTH_FRONTEND_CALLBACK_PATH", "/oauth/callback") or "/oauth/callback"
        self.GOOGLE_OAUTH_CLIENT_ID: str | None = _env_str("GOOGLE_OAUTH_CLIENT_ID")
        self.GOOGLE_OAUTH_CLIENT_SECRET: str | None = _env_str("GOOGLE_OAUTH_CLIENT_SECRET")
        self.GOOGLE_OAUTH_SCOPES: str = _env_str("GOOGLE_OAUTH_SCOPES", "openid,email,profile") or "openid,email,profile"
        self.GITHUB_OAUTH_CLIENT_ID: str | None = _env_str("GITHUB_OAUTH_CLIENT_ID")
        self.GITHUB_OAUTH_CLIENT_SECRET: str | None = _env_str("GITHUB_OAUTH_CLIENT_SECRET")
        self.GITHUB_OAUTH_SCOPES: str = _env_str("GITHUB_OAUTH_SCOPES", "read:user,user:email") or "read:user,user:email"
        self.FACEBOOK_OAUTH_CLIENT_ID: str | None = _env_str("FACEBOOK_OAUTH_CLIENT_ID")
        self.FACEBOOK_OAUTH_CLIENT_SECRET: str | None = _env_str("FACEBOOK_OAUTH_CLIENT_SECRET")
        self.FACEBOOK_OAUTH_SCOPES: str = _env_str("FACEBOOK_OAUTH_SCOPES", "email,public_profile") or "email,public_profile"
        self.APPLE_OAUTH_CLIENT_ID: str | None = _env_str("APPLE_OAUTH_CLIENT_ID")
        self.APPLE_OAUTH_TEAM_ID: str | None = _env_str("APPLE_OAUTH_TEAM_ID")
        self.APPLE_OAUTH_KEY_ID: str | None = _env_str("APPLE_OAUTH_KEY_ID")
        self.APPLE_OAUTH_PRIVATE_KEY: str | None = _env_str("APPLE_OAUTH_PRIVATE_KEY")
        self.APPLE_OAUTH_SCOPES: str = _env_str("APPLE_OAUTH_SCOPES", "name,email") or "name,email"
        self.BLOCKED_EMAIL_DOMAINS: str = _env_str("BLOCKED_EMAIL_DOMAINS", "") or ""
        self.AUTH_TEST_FLOW_ENABLED: bool = _env_bool("AUTH_TEST_FLOW_ENABLED", False)

        self.TURNSTILE_SECRET_KEY: str | None = _env_str("TURNSTILE_SECRET_KEY")
        self.TURNSTILE_ALLOWED_HOSTNAMES: str = _env_str("TURNSTILE_ALLOWED_HOSTNAMES", "") or ""
        # When true, signup/login/forgot/reset/resend require a valid Cloudflare Turnstile token.
        # Enable only once the web app renders the widget on those pages.
        self.AUTH_REQUIRE_TURNSTILE: bool = (os.getenv("AUTH_REQUIRE_TURNSTILE", "false") or "false").strip().lower() in {"1", "true", "yes", "on"}
        self.TURNSTILE_TIMEOUT_SECONDS: float = _env_float("TURNSTILE_TIMEOUT_SECONDS", 10.0)
        self.PUBLIC_RATE_LIMIT_BACKEND: str = _env_str(
            "PUBLIC_RATE_LIMIT_BACKEND", "mongo" if self.is_production else "memory"
        ) or "mongo"
        self.PUBLIC_RATE_LIMIT_TIMEOUT_SECONDS: float = _env_float("PUBLIC_RATE_LIMIT_TIMEOUT_SECONDS", 3.0)

        self.MAX_REQUEST_SIZE_BYTES: int = _env_int("MAX_REQUEST_SIZE_BYTES", 1048576)
        self.MAX_UPLOAD_SIZE_BYTES: int = _env_int("MAX_UPLOAD_SIZE_BYTES", 5242880)
        self.ALLOWED_UPLOAD_TYPES: str = _env_str(
            "ALLOWED_UPLOAD_TYPES",
            "text/plain,application/json,text/csv,application/pdf,application/xml",
        ) or "text/plain,application/json,text/csv,application/pdf,application/xml"
        self.ALLOWED_FILE_EXTENSIONS: str = _env_str("ALLOWED_FILE_EXTENSIONS", ".txt,.json,.csv,.pdf,.xml") or ".txt,.json,.csv,.pdf,.xml"
        self.HSTS_ENABLED: bool = _env_bool("HSTS_ENABLED", True)
        self.HSTS_MAX_AGE: int = _env_int("HSTS_MAX_AGE", 31536000)
        self.HSTS_INCLUDE_SUBDOMAINS: bool = _env_bool("HSTS_INCLUDE_SUBDOMAINS", True)
        self.HSTS_PRELOAD: bool = _env_bool("HSTS_PRELOAD", True)

        self.CREEM_API_KEY: str | None = _env_str("CREEM_API_KEY")
        self.CREEM_WEBHOOK_SECRET: str | None = _env_str("CREEM_WEBHOOK_SECRET")
        self.CREEM_PRODUCT_ID_PRO: str | None = _env_str("CREEM_PRODUCT_ID_PRO")
        self.CREEM_PRODUCT_ID_BUSINESS: str | None = _env_str("CREEM_PRODUCT_ID_BUSINESS")
        self.CREEM_TEST_MODE: bool = _env_bool("CREEM_TEST_MODE", True)

        self.REMEDIATION_ENABLED: bool = _env_bool("REMEDIATION_ENABLED", True)
        self.REMEDIATION_THREAT_SCORE_THRESHOLD: float = _env_float("REMEDIATION_THREAT_SCORE_THRESHOLD", 0.9)

        self.DEFENSE_WS_ALERT_THRESHOLD: float = _env_float("DEFENSE_WS_ALERT_THRESHOLD", 0.8)
        self.DEFENSE_REPEAT_ATTACK_THRESHOLD: float = _env_float("DEFENSE_REPEAT_ATTACK_THRESHOLD", 0.8)
        self.DEFENSE_REPEAT_ATTACK_WINDOW_SECONDS: int = _env_int("DEFENSE_REPEAT_ATTACK_WINDOW_SECONDS", 600)
        self.DEFENSE_REPEAT_ATTACK_COUNT: int = _env_int("DEFENSE_REPEAT_ATTACK_COUNT", 3)
        self.DEFENSE_TEMP_BLOCK_SECONDS: int = _env_int("DEFENSE_TEMP_BLOCK_SECONDS", 600)
        self.DEFENSE_SANITIZE_THRESHOLD: float = _env_float("DEFENSE_SANITIZE_THRESHOLD", 0.55)
        self.DEFENSE_BLOCK_THRESHOLD: float = _env_float("DEFENSE_BLOCK_THRESHOLD", 0.85)
        self.SCAN_BASE_TIMEOUT_SECONDS: float = _env_float("SCAN_BASE_TIMEOUT_SECONDS", 6.0)
        self.SCAN_MAX_TIMEOUT_SECONDS: float = _env_float("SCAN_MAX_TIMEOUT_SECONDS", 12.0)
        self.SCAN_TIMEOUT_PER_2K_CHARS: float = _env_float("SCAN_TIMEOUT_PER_2K_CHARS", 1.5)
        self.SCAN_RETRY_ATTEMPTS: int = _env_int("SCAN_RETRY_ATTEMPTS", 2)
        # What to do when a prompt scan times out or crashes: "closed" (default) blocks the request
        # unless the fast rules positively clear it; "open" forwards it with a partial-scan flag.
        # Developer-authored "system" and model-authored "assistant" messages routinely mention attacks
        # ("never reveal these instructions"). Scan them only if explicitly requested.
        self.GATEWAY_SCAN_NON_USER_ROLES: bool = (os.getenv("GATEWAY_SCAN_NON_USER_ROLES", "false") or "false").strip().lower() in {"1", "true", "yes", "on"}
        # "enforce" blocks flagged requests (default). "monitor" never blocks: it forwards the request and
        # records a `gateway_request_would_block` audit event so accuracy can be measured on real traffic.
        _mode = (os.getenv("GATEWAY_SECURITY_MODE", "enforce") or "enforce").strip().lower()
        self.GATEWAY_SECURITY_MODE: str = _mode if _mode in {"enforce", "monitor"} else "enforce"
        # Learned classifier layer (pure-Python, trained model shipped in app/security/models/).
        # Final verdict = rules OR classifier. Raise the threshold for fewer false positives, lower it for
        # more recall; disable entirely with ML_LAYER_ENABLED=false.
        self.ML_LAYER_ENABLED: bool = (os.getenv("ML_LAYER_ENABLED", "true") or "true").strip().lower() in {"1", "true", "yes", "on"}
        try:
            _thr = float(os.getenv("ML_BLOCK_THRESHOLD", "0.70"))
        except ValueError:
            _thr = 0.70
        self.ML_BLOCK_THRESHOLD: float = min(0.99, max(0.30, _thr))
        self.SCAN_FAIL_MODE: str = "open" if (os.getenv("SCAN_FAIL_MODE", "closed") or "closed").strip().lower() == "open" else "closed"
        self.SCAN_SYNC_LOG_BUDGET_SECONDS: float = _env_float("SCAN_SYNC_LOG_BUDGET_SECONDS", 0.25)
        self.SCAN_SUSPICIOUS_PROMPT_LENGTH: int = _env_int("SCAN_SUSPICIOUS_PROMPT_LENGTH", 4000)

        self.SENTINEL_ENABLE_DECODER: bool = _env_bool("SENTINEL_ENABLE_DECODER", True)
        self.SENTINEL_ENABLE_JAILBREAK_DETECTION: bool = _env_bool("SENTINEL_ENABLE_JAILBREAK_DETECTION", True)
        self.SENTINEL_ENABLE_OUTPUT_SCANNER: bool = _env_bool("SENTINEL_ENABLE_OUTPUT_SCANNER", True)
        self.SENTINEL_ENABLE_CONTEXT_MONITOR: bool = _env_bool("SENTINEL_ENABLE_CONTEXT_MONITOR", True)
        self.SENTINEL_RISK_THRESHOLD: int = _env_int("SENTINEL_RISK_THRESHOLD", 70)
        self.SENTINEL_MAX_DECODE_DEPTH: int = _env_int("SENTINEL_MAX_DECODE_DEPTH", 3)
        self.SENTINEL_MAX_DECODE_PAYLOAD_CHARS: int = _env_int("SENTINEL_MAX_DECODE_PAYLOAD_CHARS", 24000)
        self.SENTINEL_DECODE_TIMEOUT_MS: int = _env_int("SENTINEL_DECODE_TIMEOUT_MS", 400)
        self.SENTINEL_POLICY_DIR: str | None = _env_str("SENTINEL_POLICY_DIR")
        self.SENTINEL_UNTRUSTED_OPEN_DELIMITER: str = _env_str("SENTINEL_UNTRUSTED_OPEN_DELIMITER", "<UNTRUSTED_DATA>") or "<UNTRUSTED_DATA>"
        self.SENTINEL_UNTRUSTED_CLOSE_DELIMITER: str = _env_str("SENTINEL_UNTRUSTED_CLOSE_DELIMITER", "</UNTRUSTED_DATA>") or "</UNTRUSTED_DATA>"
        self.SENTINEL_REQUIRE_2FA_FOR_SENSITIVE_TOOLS: bool = _env_bool("SENTINEL_REQUIRE_2FA_FOR_SENSITIVE_TOOLS", True)
        self.SENTINEL_ENABLE_2FA_ENFORCEMENT: bool = _env_bool("SENTINEL_ENABLE_2FA_ENFORCEMENT", True)
        self.SENTINEL_2FA_STATIC_CODE: str | None = _env_str("SENTINEL_2FA_STATIC_CODE")
        self.SENTINEL_2FA_ALLOW_DEMO_BYPASS: bool = _env_bool("SENTINEL_2FA_ALLOW_DEMO_BYPASS", False)

        self.RESEND_API_KEY: str | None = _env_str("RESEND_API_KEY")
        self.EMAIL_FROM_ADDRESS: str = _env_str("EMAIL_FROM_ADDRESS", "Mefyx <noreply@mefyx.com>") or "Mefyx <noreply@mefyx.com>"
        self.REMEDIATION_EMAIL_ENABLED: bool = _env_bool("REMEDIATION_EMAIL_ENABLED", True)
        self.REMEDIATION_EMAIL_TO: str | None = _env_str("REMEDIATION_EMAIL_TO")

        self.REMEDIATION_WEBHOOK_URLS: str = _env_str("REMEDIATION_WEBHOOK_URLS", "") or ""
        self.REMEDIATION_WEBHOOK_TIMEOUT_SECONDS: float = _env_float("REMEDIATION_WEBHOOK_TIMEOUT_SECONDS", 3.0)

        self.SENTRY_DSN: str | None = _env_str("SENTRY_DSN")
        self.SENTRY_ENVIRONMENT: str = _env_str("SENTRY_ENVIRONMENT", "production") or "production"
        self.SENTRY_TRACES_SAMPLE_RATE: float = _env_float("SENTRY_TRACES_SAMPLE_RATE", 0.1)

        self._normalize_values()
        self._validate_values()

    def _normalize_values(self) -> None:
        verify_path = str(self.AUTH_VERIFY_EMAIL_PATH or "").strip() or "/verify-email"
        reset_path = str(self.AUTH_RESET_PASSWORD_PATH or "").strip() or "/reset-password"
        if not verify_path.startswith("/"):
            verify_path = f"/{verify_path}"
        if not reset_path.startswith("/"):
            reset_path = f"/{reset_path}"

        self.AUTH_VERIFY_EMAIL_PATH = verify_path
        self.AUTH_RESET_PASSWORD_PATH = reset_path
        self.ADMIN_BOOTSTRAP_EMAIL = str(self.ADMIN_BOOTSTRAP_EMAIL or "").strip().lower() or None
        self.ADMIN_LOGIN_ALERT_EMAIL = str(self.ADMIN_LOGIN_ALERT_EMAIL or "").strip().lower() or None

    def _validate_values(self) -> None:
        required = {
            "MONGODB_URI": str(self.MONGODB_URI or "").strip(),
            "JWT_SECRET": str(self.JWT_SECRET or "").strip(),
            "API_KEY_SECRET": str(self.API_KEY_SECRET or "").strip(),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError("Missing required environment variables: " + ", ".join(missing))

        if str(self.JWT_SECRET).lower() in {"change-me", "changeme", "your_secret_here"}:
            raise ValueError("JWT_SECRET must be set to a non-placeholder value")
        if str(self.API_KEY_SECRET).lower() in {"change-me", "changeme", "your_secret_here"}:
            raise ValueError("API_KEY_SECRET must be set to a non-placeholder value")
        placeholder_fragments = {
            "replace-with",
            "placeholder",
            "your-",
            "example-secret",
            "test-secret",
        }
        for secret_name, secret_value in {
            "JWT_SECRET": str(self.JWT_SECRET or ""),
            "API_KEY_SECRET": str(self.API_KEY_SECRET or ""),
        }.items():
            normalized_secret = secret_value.strip().lower()
            if any(fragment in normalized_secret for fragment in placeholder_fragments):
                raise ValueError(f"{secret_name} must not contain placeholder text")
            if self.is_production and len(secret_value) < 32:
                raise ValueError(f"{secret_name} must be at least 32 characters in production")

        if self.is_production:
            if not self.TURNSTILE_SECRET_KEY or not self.turnstile_allowed_hostnames:
                raise ValueError("TURNSTILE_SECRET_KEY and TURNSTILE_ALLOWED_HOSTNAMES are required in production")
            if self.TURNSTILE_SECRET_KEY in {
                "1x0000000000000000000000000000000AA",
                "2x0000000000000000000000000000000AA",
                "3x0000000000000000000000000000000AA",
            }:
                raise ValueError("Turnstile test keys cannot be used in production")
            if self.PUBLIC_RATE_LIMIT_BACKEND != "mongo":
                raise ValueError("PUBLIC_RATE_LIMIT_BACKEND must be mongo in production")
            if self.CORS_ORIGINS.strip() == "*":
                raise ValueError("CORS_ORIGINS must be explicit in production")
            if self.ENABLE_DEMO_MODE:
                raise ValueError("ENABLE_DEMO_MODE cannot be enabled in production")
            if self.AUTH_TEST_FLOW_ENABLED:
                raise ValueError("AUTH_TEST_FLOW_ENABLED cannot be enabled in production")
            if self.SENTINEL_2FA_ALLOW_DEMO_BYPASS:
                raise ValueError("SENTINEL_2FA_ALLOW_DEMO_BYPASS cannot be enabled in production")

        if bool(self.ADMIN_BOOTSTRAP_EMAIL) != bool(self.ADMIN_BOOTSTRAP_PASSWORD):
            raise ValueError(
                "ADMIN_BOOTSTRAP_EMAIL and ADMIN_BOOTSTRAP_PASSWORD must either both be set or both be omitted"
            )

        if self.PUBLIC_RATE_LIMIT_BACKEND not in {"mongo", "memory"}:
            raise ValueError("PUBLIC_RATE_LIMIT_BACKEND must be mongo or memory")
        if not 0 < self.TURNSTILE_TIMEOUT_SECONDS <= 30:
            raise ValueError("TURNSTILE_TIMEOUT_SECONDS must be between 0 and 30")
        if not 0 < self.PUBLIC_RATE_LIMIT_TIMEOUT_SECONDS <= 10:
            raise ValueError("PUBLIC_RATE_LIMIT_TIMEOUT_SECONDS must be between 0 and 10")
        if any(
            ":" in host or "/" in host or "*" in host or " " in host
            for host in self.turnstile_allowed_hostnames
        ):
            raise ValueError("TURNSTILE_ALLOWED_HOSTNAMES must contain exact hostnames without schemes, ports or wildcards")

        api_key_prefix = str(self.API_KEY_PREFIX or "").strip()
        if not api_key_prefix.startswith("sentinel_sk_"):
            raise ValueError("API_KEY_PREFIX must start with 'sentinel_sk_'")
        if not api_key_prefix.endswith("_"):
            raise ValueError("API_KEY_PREFIX must end with '_'")

        if int(self.SENTINEL_RISK_THRESHOLD) < 1 or int(self.SENTINEL_RISK_THRESHOLD) > 100:
            raise ValueError("SENTINEL_RISK_THRESHOLD must be between 1 and 100")
        if int(self.SENTINEL_MAX_DECODE_DEPTH) < 1 or int(self.SENTINEL_MAX_DECODE_DEPTH) > 8:
            raise ValueError("SENTINEL_MAX_DECODE_DEPTH must be between 1 and 8")

    @property
    def turnstile_allowed_hostnames(self) -> set[str]:
        return {host.strip().lower().rstrip(".") for host in self.TURNSTILE_ALLOWED_HOSTNAMES.split(",") if host.strip()}

    @property
    def cors_origins_list(self) -> list[str]:
        raw = (self.CORS_ORIGINS or "").strip()
        baseline_origins = [
            "https://sentinel-core-arei.vercel.app",
            "https://sentinel-admin-beta.vercel.app",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
        ]
        if raw and raw != "*":
            origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
            default_candidates = (self.FRONTEND_URL, self.ADMIN_FRONTEND_URL) if self.is_production else (
                self.FRONTEND_URL,
                self.ADMIN_FRONTEND_URL,
                *baseline_origins,
            )
            for origin in default_candidates:
                normalized = str(origin or "").strip()
                if normalized and normalized not in origins:
                    origins.append(normalized)
            return origins

        defaults: list[str] = []
        default_candidates = (self.FRONTEND_URL, self.ADMIN_FRONTEND_URL) if self.is_production else (
            self.FRONTEND_URL,
            self.ADMIN_FRONTEND_URL,
            *baseline_origins,
        )
        for origin in default_candidates:
            normalized = str(origin or "").strip()
            if normalized and normalized not in defaults:
                defaults.append(normalized)
        return defaults

    @property
    def allowed_upload_types_list(self) -> list[str]:
        raw = (self.ALLOWED_UPLOAD_TYPES or "").strip()
        if not raw:
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    @property
    def allowed_file_extensions_list(self) -> list[str]:
        raw = (self.ALLOWED_FILE_EXTENSIONS or "").strip()
        if not raw:
            return []
        return [ext.strip() for ext in raw.split(",") if ext.strip()]

    @property
    def remediation_webhook_urls_list(self) -> list[str]:
        raw = (self.REMEDIATION_WEBHOOK_URLS or "").strip()
        if not raw:
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    @property
    def blocked_email_domains_list(self) -> list[str]:
        raw = (self.BLOCKED_EMAIL_DOMAINS or "").strip().lower()
        if not raw:
            return []
        return [domain.strip() for domain in raw.split(",") if domain.strip()]

    @property
    def is_production(self) -> bool:
        return str(self.APP_ENV or "").strip().lower() in {"prod", "production"}


settings = Settings()