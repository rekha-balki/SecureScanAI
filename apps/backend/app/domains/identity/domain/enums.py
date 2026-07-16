"""
Identity domain enums.
"""

from enum import Enum


class UserRole(str, Enum):
    """
    Platform user roles (FRS Section 2).
    """

    PLATFORM_ADMIN = "platform_admin"
    COMPANY_ADMIN = "company_admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    AUDITOR = "auditor"


class CompanyStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
