"""Custom exceptions."""
from datetime import datetime
from typing import Any


class AuthServiceException(Exception):
    """Base exception for Auth Service."""

    def __init__(
        self,
        detail: str,
        error_code: str,
        status_code: int = 500,
    ) -> None:
        """
        Initialize exception.

        Args:
            detail: Human-readable error message
            error_code: Machine-readable error code
            status_code: HTTP status code
        """
        self.detail = detail
        self.error_code = error_code
        self.status_code = status_code
        self.timestamp = datetime.utcnow()
        super().__init__(detail)

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to dictionary."""
        return {
            "detail": self.detail,
            "error_code": self.error_code,
            "timestamp": self.timestamp.isoformat() + "Z",
        }


# 401 Unauthorized Exceptions
class InvalidCredentialsError(AuthServiceException):
    """Invalid username or password."""

    def __init__(self, detail: str = "Invalid username or password") -> None:
        super().__init__(
            detail=detail,
            error_code="INVALID_CREDENTIALS",
            status_code=401,
        )


class TokenExpiredError(AuthServiceException):
    """Token has expired."""

    def __init__(self, detail: str = "Token has expired") -> None:
        super().__init__(
            detail=detail,
            error_code="TOKEN_EXPIRED",
            status_code=401,
        )


class TokenInvalidError(AuthServiceException):
    """Token is invalid."""

    def __init__(self, detail: str = "Invalid token") -> None:
        super().__init__(
            detail=detail,
            error_code="TOKEN_INVALID",
            status_code=401,
        )


class TokenRevokedError(AuthServiceException):
    """Token has been revoked."""

    def __init__(self, detail: str = "Token has been revoked") -> None:
        super().__init__(
            detail=detail,
            error_code="TOKEN_REVOKED",
            status_code=401,
        )


class TokenBlacklistedError(AuthServiceException):
    """Token is in blacklist."""

    def __init__(self, detail: str = "Token has been blacklisted") -> None:
        super().__init__(
            detail=detail,
            error_code="TOKEN_BLACKLISTED",
            status_code=401,
        )


# 403 Forbidden Exceptions
class InsufficientPermissionsError(AuthServiceException):
    """User has insufficient permissions."""

    def __init__(
        self, detail: str = "Insufficient permissions to perform this action"
    ) -> None:
        super().__init__(
            detail=detail,
            error_code="INSUFFICIENT_PERMISSIONS",
            status_code=403,
        )


class UserInactiveError(AuthServiceException):
    """User account is inactive."""

    def __init__(self, detail: str = "User account is inactive") -> None:
        super().__init__(
            detail=detail,
            error_code="USER_INACTIVE",
            status_code=403,
        )


class RoleRequiredError(AuthServiceException):
    """Specific role is required."""

    def __init__(self, role: str) -> None:
        super().__init__(
            detail=f"Role '{role}' is required for this action",
            error_code="ROLE_REQUIRED",
            status_code=403,
        )


# 400 Bad Request Exceptions
class InvalidInputError(AuthServiceException):
    """Invalid input data."""

    def __init__(self, detail: str = "Invalid input data") -> None:
        super().__init__(
            detail=detail,
            error_code="INVALID_INPUT",
            status_code=400,
        )


class PasswordTooWeakError(AuthServiceException):
    """Password does not meet strength requirements."""

    def __init__(
        self,
        detail: str = "Password does not meet strength requirements",
    ) -> None:
        super().__init__(
            detail=detail,
            error_code="PASSWORD_TOO_WEAK",
            status_code=400,
        )


class InvalidPasswordError(AuthServiceException):
    """Current password is incorrect."""

    def __init__(self, detail: str = "Current password is incorrect") -> None:
        super().__init__(
            detail=detail,
            error_code="INVALID_PASSWORD",
            status_code=400,
        )


# 404 Not Found Exceptions
class UserNotFoundError(AuthServiceException):
    """User not found."""

    def __init__(self, detail: str = "User not found") -> None:
        super().__init__(
            detail=detail,
            error_code="USER_NOT_FOUND",
            status_code=404,
        )


class RoleNotFoundError(AuthServiceException):
    """Role not found."""

    def __init__(self, detail: str = "Role not found") -> None:
        super().__init__(
            detail=detail,
            error_code="ROLE_NOT_FOUND",
            status_code=404,
        )


# 409 Conflict Exceptions
class UserAlreadyExistsError(AuthServiceException):
    """User with this login already exists."""

    def __init__(
        self, detail: str = "User with this login already exists"
    ) -> None:
        super().__init__(
            detail=detail,
            error_code="USER_ALREADY_EXISTS",
            status_code=409,
        )


class RoleAlreadyExistsError(AuthServiceException):
    """Role with this name already exists."""

    def __init__(
        self, detail: str = "Role with this name already exists"
    ) -> None:
        super().__init__(
            detail=detail,
            error_code="ROLE_ALREADY_EXISTS",
            status_code=409,
        )


class RoleAlreadyAssignedError(AuthServiceException):
    """User already has this role."""

    def __init__(self, detail: str = "User already has this role") -> None:
        super().__init__(
            detail=detail,
            error_code="ROLE_ALREADY_ASSIGNED",
            status_code=409,
        )


# Database Exceptions
class DatabaseError(AuthServiceException):
    """Database operation failed."""

    def __init__(self, detail: str = "Database operation failed") -> None:
        super().__init__(
            detail=detail,
            error_code="DATABASE_ERROR",
            status_code=500,
        )


class RedisError(AuthServiceException):
    """Redis operation failed."""

    def __init__(self, detail: str = "Redis operation failed") -> None:
        super().__init__(
            detail=detail,
            error_code="REDIS_ERROR",
            status_code=500,
        )
