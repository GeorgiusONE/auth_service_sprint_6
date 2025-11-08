"""Security utilities - JWT and password hashing."""
import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import settings

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordHasher:
    """Password hashing utilities using bcrypt."""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            plain_password: Plain text password to verify
            hashed_password: Hashed password to compare against

        Returns:
            True if password matches, False otherwise
        """
        return pwd_context.verify(plain_password, hashed_password)


def create_access_token(
    user_id: str,
    login: str,
    roles: list[str],
    version: int = 1,
    expires_delta: timedelta | None = None,
) -> str:
    """
    Create JWT access token.

    Args:
        user_id: User ID
        login: User login
        roles: List of user roles
        version: Token version for logout_all functionality
        expires_delta: Custom expiration time (default: 15 minutes from settings)

    Returns:
        Encoded JWT access token
    """
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)

    now = datetime.utcnow()
    expire = now + expires_delta

    payload = {
        "sub": user_id,  # Subject - user ID
        "login": login,
        "roles": roles,
        "token_type": "access",
        "jti": str(uuid.uuid4()),  # JWT ID for blacklist
        "version": version,  # Token version for logout_all
        "exp": expire,  # Expiration time
        "iat": now,  # Issued at
    }

    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def create_refresh_token(user_id: str, expires_delta: timedelta | None = None) -> str:
    """
    Create JWT refresh token.

    Args:
        user_id: User ID
        expires_delta: Custom expiration time (default: 30 days from settings)

    Returns:
        Encoded JWT refresh token
    """
    if expires_delta is None:
        expires_delta = timedelta(days=settings.refresh_token_expire_days)

    now = datetime.utcnow()
    expire = now + expires_delta

    payload = {
        "sub": user_id,  # Subject - user ID
        "token_type": "refresh",
        "jti": str(uuid.uuid4()),  # JWT ID for Redis storage
        "exp": expire,  # Expiration time
        "iat": now,  # Issued at
    }

    encoded_jwt = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode JWT token without validation.

    Args:
        token: JWT token string

    Returns:
        Decoded token payload

    Raises:
        JWTError: If token cannot be decoded
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_signature": True, "verify_exp": True},
        )
        return payload
    except JWTError as e:
        raise JWTError(f"Could not decode token: {str(e)}")


def verify_token(token: str, expected_type: str = "access") -> dict[str, Any]:
    """
    Verify and decode JWT token.

    Args:
        token: JWT token string
        expected_type: Expected token type ('access' or 'refresh')

    Returns:
        Decoded token payload

    Raises:
        JWTError: If token is invalid, expired, or wrong type
    """
    try:
        payload = decode_token(token)

        # Verify token type
        token_type = payload.get("token_type")
        if token_type != expected_type:
            raise JWTError(f"Invalid token type. Expected '{expected_type}', got '{token_type}'")

        return payload

    except JWTError as e:
        raise JWTError(f"Token verification failed: {str(e)}")


def get_token_jti(token: str) -> str:
    """
    Extract JTI (JWT ID) from token without full validation.

    Args:
        token: JWT token string

    Returns:
        JTI string

    Raises:
        JWTError: If token cannot be decoded or has no JTI
    """
    try:
        # Decode without verification to get JTI even if expired
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_signature": False, "verify_exp": False},
        )
        jti = payload.get("jti")
        if not jti:
            raise JWTError("Token has no JTI")
        return jti
    except JWTError as e:
        raise JWTError(f"Could not extract JTI: {str(e)}")


def get_token_expiry(token: str) -> datetime | None:
    """
    Get expiration time from token.

    Args:
        token: JWT token string

    Returns:
        Expiration datetime or None if not present
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_signature": False, "verify_exp": False},
        )
        exp = payload.get("exp")
        if exp:
            return datetime.fromtimestamp(exp)
        return None
    except JWTError:
        return None


def generate_device_fingerprint(user_agent: str, ip_address: str) -> str:
    """
    Generate device fingerprint from User-Agent and IP address.

    Args:
        user_agent: Browser/device User-Agent string
        ip_address: Client IP address

    Returns:
        SHA256 hash as device fingerprint
    """
    data = f"{user_agent}:{ip_address}"
    return hashlib.sha256(data.encode()).hexdigest()


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength.

    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit"

    special_chars = '!@#$%^&*(),.?":{}|<>'
    if not any(c in special_chars for c in password):
        return False, "Password must contain at least one special character"

    return True, ""
