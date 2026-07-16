"""
Identity domain request/response schemas.
"""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from app.domains.identity.domain.enums import UserRole


class RegisterRequest(BaseModel):
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str
    company_name: str = Field(min_length=1, max_length=200)
    mobile_number: str | None = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int


class UserResponse(BaseModel):
    id: str
    first_name: str
    last_name: str
    email: str
    role: UserRole
    company_id: str
    department: str | None = None
    designation: str | None = None
    is_active: bool
    created_at: datetime


class AuthResponse(BaseModel):
    user: UserResponse
    token: TokenResponse


class CreateUserRequest(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    role: UserRole = UserRole.SECURITY_ANALYST
    department: str | None = None
    designation: str | None = None
    phone: str | None = None
    password: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ForgotPasswordResponse(BaseModel):
    message: str
    # Only populated when the API is running in a non-production
    # environment, so developers can test the flow without SMTP
    # configured. Never returned in production - see AuthService.
    dev_reset_token: str | None = None


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
