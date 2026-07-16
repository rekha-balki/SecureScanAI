"""
User management routes (FRS Section 5).
"""

from fastapi import APIRouter, Depends, Request

from app.domains.audit.domain.enums import AuditAction
from app.domains.audit.services.audit_service import AuditService, client_ip
from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.domain.enums import UserRole
from app.domains.identity.repositories.user_repository import UserRepository
from app.domains.identity.schemas import CreateUserRequest, UserResponse
from app.platform.errors.exceptions import ConflictException, ValidationException
from app.platform.security.dependencies import get_current_user, require_roles
from app.platform.security.password import hash_password, validate_password_policy
from app.shared.kernel.responses import ResponseBuilder

users_router = APIRouter(prefix="/users", tags=["Users"])


def _to_response(user: User) -> dict:
    return UserResponse(
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
    ).model_dump()


@users_router.get("", summary="List users in the current company")
async def list_users(current_user: User = Depends(get_current_user)):
    repo = UserRepository()

    users = await repo.list_by_company(current_user.company_id)

    return ResponseBuilder.success(
        "Users retrieved.",
        [_to_response(u) for u in users],
    )


@users_router.post(
    "",
    summary="Create a company user",
)
async def create_user(
    payload: CreateUserRequest,
    request: Request,
    current_user: User = Depends(
        require_roles(UserRole.COMPANY_ADMIN, UserRole.PLATFORM_ADMIN)
    ),
):
    repo = UserRepository()

    if not validate_password_policy(payload.password):
        raise ValidationException(
            "Password must be 12-72 characters and include "
            "uppercase, lowercase, a number, and a special character."
        )

    existing = await repo.find_by_email(payload.email)

    if existing is not None:
        raise ConflictException("A user with this email already exists.")

    user = User(
        id=UserRepository.new_id(),
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        company_id=current_user.company_id,
        role=payload.role,
        department=payload.department,
        designation=payload.designation,
        phone=payload.phone,
    )

    await repo.create(user)

    await AuditService().record(
        AuditAction.USER_CREATED,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=user.email,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success("User created.", _to_response(user))


@users_router.post("/{user_id}/deactivate", summary="Deactivate a user")
async def deactivate_user(
    user_id: str,
    request: Request,
    current_user: User = Depends(
        require_roles(UserRole.COMPANY_ADMIN, UserRole.PLATFORM_ADMIN)
    ),
):
    repo = UserRepository()

    await repo.set_active(user_id, False)

    await AuditService().record(
        AuditAction.USER_DEACTIVATED,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=user_id,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success("User deactivated.", {"id": user_id})
