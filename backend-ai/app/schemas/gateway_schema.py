from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


GatewayRole = Literal["system", "user", "assistant"]
GatewayProvider = Literal["gemini", "openai", "anthropic", "xai"]
JsonPrimitive = str | int | float | bool | None


class GatewayMessage(BaseModel):
    role: GatewayRole = "user"
    content: str = Field(..., min_length=1, max_length=12000)

    @field_validator("content")
    @classmethod
    def clean_content(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("message content is required")
        return normalized


class GatewayChatRequest(BaseModel):
    provider: GatewayProvider = "gemini"
    model: str = Field(default="gemini-1.5-flash", max_length=128)
    prompt: str | None = Field(default=None, min_length=1, max_length=25000)
    messages: list[GatewayMessage] | None = Field(default=None, max_length=50)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None, ge=1, le=8192)
    metadata: dict[str, Any] | None = Field(default=None)
    project: str | None = Field(default=None, max_length=120)
    app_name: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def validate_prompt_or_messages(self) -> "GatewayChatRequest":
        if self.messages:
            return self
        if self.prompt and self.prompt.strip():
            self.messages = [GatewayMessage(role="user", content=self.prompt)]
            return self
        raise ValueError("prompt or messages is required")

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None

        def safe_metadata_value(item: Any) -> JsonPrimitive | list[Any] | dict[str, Any]:
            if isinstance(item, (str, int, float, bool)) or item is None:
                return item
            if isinstance(item, list):
                return [safe_metadata_value(child) for child in item[:50]]
            if isinstance(item, dict):
                return {
                    str(child_key)[:80]: safe_metadata_value(child_value)
                    for child_key, child_value in list(item.items())[:50]
                }
            return str(item)

        safe: dict[str, Any] = {}
        for key, item in value.items():
            safe[str(key)[:80]] = safe_metadata_value(item)
        return safe


class GatewayUsage(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    estimated_cost: float = 0.0
    estimated: bool = True


class GatewaySecurity(BaseModel):
    decision: str
    risk_score: int = 0
    threat_type: str | None = None
    matched_policies: list[str] = Field(default_factory=list)
    status: str
    requires_2fa: bool = False
    review_required: bool = False
    # Set only in GATEWAY_SECURITY_MODE=monitor, when enforcement would have blocked the request.
    mode: str | None = None
    would_block: bool = False


class GatewayChatResponse(BaseModel):
    provider: str
    model: str
    content: str
    usage: GatewayUsage
    security: GatewaySecurity
    request_id: str


class GatewayProviderError(BaseModel):
    code: str
    message: str
    provider: str | None = None
    retryable: bool = False