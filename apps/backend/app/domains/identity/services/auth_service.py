"""
Authentication service (FRS Part 1, Section 3).
"""

import hashlib
import secrets

from app.config.settings import get_settings
from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.domain.enums import UserRole
from app.domains.identity.repositories.password_reset_repository import (
    PasswordResetRepository,
)
from app.domains.identity.repositories.user_repository import UserRepository
from app.domains.identity.schemas import LoginRequest, RegisterRequest
from app.domains.organization.domain.aggregates.company import Company
from app.domains.organization.repositories.company_repository import (
    CompanyRepository,
)
from app.platform import get_logger
from app.platform.errors.exceptions import (
    ConflictException,
    UnauthorizedException,
    ValidationException,
)
from app.platform.security.jwt import create_access_token
from app.platform.security.password import (
    hash_password,
    validate_password_policy,
    verify_password,
)

logger = get_logger(__name__)


class AuthService:
    """
    Handles registration, login, token issuance, and password reset.
    """

    def __init__(self) -> None:
        self._users = UserRepository()
        self._companies = CompanyRepository()
        self._resets = PasswordResetRepository()

    async def register(self, request: RegisterRequest) -> tuple[User, str]:
        if not validate_password_policy(request.password):
            raise ValidationException(
                "Password must be 12-72 characters and include "
                "uppercase, lowercase, a number, and a special character."
            )

        existing = await self._users.find_by_email(request.email)

        if existing is not None:
            raise ConflictException("A user with this email already exists.")

        company = await self._companies.find_by_name(request.company_name)

        first_user_in_company = company is None

        if company is None:
            company = Company(
                id=CompanyRepository.new_id(),
                name=request.company_name,
            )
            await self._companies.create(company)

        user = User(
            id=UserRepository.new_id(),
            first_name=request.first_name,
            last_name=request.last_name,
            email=request.email.lower(),
            password_hash=hash_password(request.password),
            company_id=company.id,
            role=(
                UserRole.COMPANY_ADMIN
                if first_user_in_company
                else UserRole.SECURITY_ANALYST
            ),
            mobile_number=request.mobile_number,
        )

        await self._users.create(user)

        token = self._issue_token(user)

        return user, token

    async def login(self, request: LoginRequest) -> tuple[User, str]:
        user = await self._users.find_by_email(request.email)

        if user is None or not verify_password(request.password, user.password_hash):
            raise UnauthorizedException("Invalid email or password.")

        if not user.is_active:
            raise UnauthorizedException("This account has been disabled.")

        token = self._issue_token(user)

        return user, token

    async def forgot_password(self, email: str) -> str | None:
        """
        FR-003: generate a reset token valid for 30 minutes and "send" a
        reset link. No SMTP provider is wired up yet (see
        organization.company_settings.smtp), so for now the link is
        logged server-side. In non-production environments the raw
        token is also returned to the caller so the flow can be tested
        end-to-end without email.

        Always returns without error whether or not the email exists,
        to avoid leaking which emails are registered.
        """

        user = await self._users.find_by_email(email)

        if user is None:
            logger.info("Password reset requested for unknown email: %s", email)
            return None

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

        await self._resets.create(user.id, token_hash)

        reset_link = f"/reset-password?token={raw_token}"
        logger.info("Password reset link for %s: %s", user.email, reset_link)

        settings = get_settings()
        return raw_token if settings.debug else None

    async def reset_password(self, token: str, new_password: str) -> None:
        if not validate_password_policy(new_password):
            raise ValidationException(
                "Password must be 12-72 characters and include "
                "uppercase, lowercase, a number, and a special character."
            )

        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        record = await self._resets.find_valid(token_hash)

        if record is None:
            raise UnauthorizedException("This reset link is invalid or has expired.")

        await self._users.update_password(
            record["user_id"], hash_password(new_password)
        )
        await self._resets.mark_used(record["_id"])
        await self._resets.invalidate_all_for_user(record["user_id"])

    def _issue_token(self, user: User) -> str:
        return create_access_token(
            subject=user.id,
            claims={
                "email": user.email,
                "company_id": user.company_id,
                "role": user.role.value,
            },
        )
