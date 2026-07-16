"""
FastAPI security dependencies.
"""

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.domain.enums import UserRole
from app.domains.identity.repositories.user_repository import UserRepository
from app.platform.errors.exceptions import ForbiddenException, UnauthorizedException
from app.platform.security.jwt import TokenError, decode_access_token

_bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> User:
    if credentials is None:
        raise UnauthorizedException("Missing authentication credentials.")

    try:
        payload = decode_access_token(credentials.credentials)
    except TokenError as exc:
        raise UnauthorizedException(str(exc)) from exc

    user_id = payload.get("sub")

    if not user_id:
        raise UnauthorizedException("Invalid token payload.")

    user = await UserRepository().find_by_id(user_id)

    if user is None or not user.is_active:
        raise UnauthorizedException("Account not found or disabled.")

    return user


def require_roles(*roles: UserRole):
    """
    Dependency factory restricting an endpoint to the given roles.
    """

    async def _dependency(user: User = Depends(get_current_user)) -> User:
        if roles and user.role not in roles:
            raise ForbiddenException(
                "You do not have permission to perform this action."
            )
        return user

    return _dependency
