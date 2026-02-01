from pydantic import BaseModel, ConfigDict, Field, field_validator


class UserSignUp(BaseModel):
    username: str = Field(..., min_length=3, max_length=42)
    password: str

    @field_validator("username")
    def validate_username(cls, v: str) -> str:
        v = v.strip().lower()
        if not v.isalnum() and "_" not in v:
            raise ValueError("Username must contain only letters, numbers, and underscores")
        return v

    @field_validator("password")
    def validate_password(cls, v: str) -> str:
        # TODO: (Optional) add complexity checks
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role_id: int


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    def validate_new_password(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters")
        return v


class UserUpdate(BaseModel):
    username: str | None = Field(None, min_length=3, max_length=42)

    @field_validator("username")
    def validate_username(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if not v.isalnum() and "_" not in v:
            raise ValueError("Username must contain only letters, numbers, and underscores")
        return v


class PasswordResetRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=42)
