"""
Authentication routes (FRS Part 1, Section 3).
"""

from fastapi import APIRouter, Depends, Request

from app.config.settings import get_settings
from app.domains.audit.domain.enums import AuditAction, AuditResult
from app.domains.audit.services.audit_service import AuditService, client_ip
from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.schemas import (
    AuthResponse,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserResponse,
)
from app.domains.identity.services.auth_service import AuthService
from app.platform import get_logger
from app.platform.errors.exceptions import UnauthorizedException
from app.platform.security.dependencies import get_current_user
from app.shared.kernel.responses import ResponseBuilder

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])

logger = get_logger(__name__)


def _to_auth_response(user: User, token: str) -> AuthResponse:
    settings = get_settings()

    return AuthResponse(
        user=UserResponse(
            id=user.id,
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            role=user.role,
            company_id=user.company_id,
            department=user.department,
            designation=user.designation,
            is_active=user.is_active,
            created_at=user.created_at,
        ),
        token=TokenResponse(
            access_token=token,
            expires_in_minutes=settings.jwt_expiry_minutes,
        ),
    )


@auth_router.post("/register", summary="Register a new user and company")
async def register(payload: RegisterRequest, request: Request):
    user, token = await AuthService().register(payload)

    logger.info("User registered: %s", user.email)

    await AuditService().record(
        AuditAction.USER_REGISTERED,
        company_id=user.company_id,
        user_id=user.id,
        target=user.email,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success(
        "Registration successful.",
        _to_auth_response(user, token).model_dump(),
    )


@auth_router.post("/login", summary="Authenticate and receive a JWT")
async def login(payload: LoginRequest, request: Request):
    audit = AuditService()

    try:
        user, token = await AuthService().login(payload)
    except UnauthorizedException:
        await audit.record(
            AuditAction.LOGIN_FAILED,
            target=payload.email,
            ip_address=client_ip(request),
            result=AuditResult.FAILURE,
        )
        raise

    logger.info("User logged in: %s", user.email)

    await audit.record(
        AuditAction.LOGIN_SUCCESS,
        company_id=user.company_id,
        user_id=user.id,
        target=user.email,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success(
        "Login successful.",
        _to_auth_response(user, token).model_dump(),
    )


@auth_router.post("/logout", summary="Log out and record an audit event")
async def logout(request: Request, current_user: User = Depends(get_current_user)):
    """
    JWTs are stateless and are not tracked server-side, so there is no
    session to invalidate here (FR-004). The client is responsible for
    discarding its token; this endpoint exists to record the audit
    event the FRS requires.
    """

    await AuditService().record(
        AuditAction.LOGOUT,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=current_user.email,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success("Logged out.", None)


@auth_router.post("/forgot-password", summary="Request a password reset link")
async def forgot_password(payload: ForgotPasswordRequest, request: Request):
    dev_token = await AuthService().forgot_password(payload.email)

    await AuditService().record(
        AuditAction.PASSWORD_RESET_REQUESTED,
        target=payload.email,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success(
        "If an account exists for that email, a reset link has been sent.",
        ForgotPasswordResponse(
            message="Check your email for a password reset link.",
            dev_reset_token=dev_token,
        ).model_dump(),
    )


@auth_router.post("/reset-password", summary="Reset password using a reset token")
async def reset_password(payload: ResetPasswordRequest, request: Request):
    await AuthService().reset_password(payload.token, payload.new_password)

    await AuditService().record(
        AuditAction.PASSWORD_RESET_COMPLETED,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success("Password has been reset. Please sign in.", None)


@auth_router.get("/me", summary="Return the authenticated user")
async def me(current_user: User = Depends(get_current_user)):
    return ResponseBuilder.success(
        "Current user retrieved.",
        UserResponse(
            id=current_user.id,
            first_name=current_user.first_name,
            last_name=current_user.last_name,
            email=current_user.email,
            role=current_user.role,
            company_id=current_user.company_id,
            department=current_user.department,
            designation=current_user.designation,
            is_active=current_user.is_active,
            created_at=current_user.created_at,
        ).model_dump(),
    )
