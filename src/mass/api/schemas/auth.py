"""Authentication schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, EmailStr

from mass.api.schemas.common import IDMixin, TimestampMixin, PaginationMeta


class TokenRequest(BaseModel):
    """Request for access token."""

    model_config = ConfigDict(extra="forbid")

    grant_type: str = Field(default="client_credentials", description="OAuth2 grant type")
    client_id: str | None = Field(default=None, description="Client ID (API key prefix)")
    client_secret: str | None = Field(default=None, description="Client secret (API key)")
    scope: str | None = Field(default=None, description="Requested scopes")


class TokenResponse(BaseModel):
    """Access token response."""

    model_config = ConfigDict(extra="forbid")

    access_token: str = Field(..., description="The access token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    scope: str | None = Field(default=None, description="Granted scopes")


class APIKeyCreate(BaseModel):
    """Request to create an API key."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Key name")
    description: str | None = Field(default=None, max_length=1000, description="Key description")
    expires_at: datetime | None = Field(default=None, description="Expiration time (optional)")
    scopes: list[str] | None = Field(default=None, description="Allowed scopes")


class APIKeyResponse(IDMixin, TimestampMixin):
    """API key response (key is only shown once on creation)."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Key name")
    description: str | None = Field(default=None, description="Key description")
    key_prefix: str = Field(..., description="Key prefix for identification")
    key: str | None = Field(default=None, description="Full key (only shown on creation)")
    is_active: bool = Field(..., description="Whether the key is active")
    expires_at: datetime | None = Field(default=None, description="Expiration time")
    last_used_at: datetime | None = Field(default=None, description="Last usage time")
    use_count: int = Field(default=0, description="Number of times the key has been used")
    scopes: list[str] | None = Field(default=None, description="Allowed scopes")


class APIKeyListResponse(BaseModel):
    """List of API keys."""

    model_config = ConfigDict(extra="forbid")

    items: list[APIKeyResponse] = Field(..., description="List of API keys")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class UserResponse(IDMixin, TimestampMixin):
    """User response schema."""

    model_config = ConfigDict(extra="forbid")

    email: EmailStr = Field(..., description="User email")
    full_name: str | None = Field(default=None, description="User's full name")
    is_active: bool = Field(..., description="Whether the user is active")
    is_verified: bool = Field(..., description="Whether the email is verified")
    roles: list[str] = Field(default_factory=list, description="User roles")


class RoleResponse(IDMixin):
    """Role response schema."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Role name")
    description: str | None = Field(default=None, description="Role description")
    permissions: list[str] = Field(..., description="Role permissions")
    is_system: bool = Field(..., description="Whether this is a system role")
