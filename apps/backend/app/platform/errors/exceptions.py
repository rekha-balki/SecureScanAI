class SecureScanException(Exception):
    """Base exception for SecureScan AI."""

    pass


class ResourceNotFoundException(SecureScanException):
    pass


class ValidationException(SecureScanException):
    pass


class UnauthorizedException(SecureScanException):
    pass


class ForbiddenException(SecureScanException):
    pass


class ConflictException(SecureScanException):
    pass