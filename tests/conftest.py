"""
Pytest configuration and fixtures for testing Auth Service.
"""

import asyncio
from typing import AsyncGenerator, Generator
from datetime import datetime, timedelta
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from src.main import app
from src.core.config import get_settings
from src.core.security import PasswordHasher, create_access_token, create_refresh_token
from src.db.postgres import Base, get_session
from src.db.redis_db import get_redis
from src.models.entity import User, Role, UserRole
from fakeredis import FakeAsyncRedis


# Test database URL (in-memory SQLite for tests)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

settings = get_settings()


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Test database engine and session
@pytest.fixture(scope="function")
async def test_engine():
    """Create a test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    await engine.dispose()


@pytest.fixture(scope="function")
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session_maker = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    
    async with async_session_maker() as session:
        yield session


@pytest.fixture(scope="function")
async def test_redis():
    """Create a fake Redis client for testing."""
    redis = FakeAsyncRedis()
    yield redis
    await redis.flushall()
    await redis.aclose()


# Override FastAPI dependencies
@pytest.fixture(scope="function")
async def client(test_session: AsyncSession, test_redis) -> AsyncGenerator[AsyncClient, None]:
    """Create an async HTTP client for testing with overridden dependencies."""
    
    async def override_get_session():
        yield test_session
    
    async def override_get_redis():
        return test_redis
    
    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_redis] = override_get_redis
    
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test"
    ) as ac:
        yield ac
    
    app.dependency_overrides.clear()


# Test data fixtures
@pytest.fixture
async def test_user(test_session: AsyncSession) -> User:
    """Create a test user."""
    password_hasher = PasswordHasher()
    user = User(
        login="testuser",
        password=password_hasher.hash_password("TestPass123!"),
        first_name="Test",
        last_name="User",
        is_active=True,
        is_superuser=False,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest.fixture
async def test_inactive_user(test_session: AsyncSession) -> User:
    """Create an inactive test user."""
    password_hasher = PasswordHasher()
    user = User(
        login="inactive_user",
        password=password_hasher.hash_password("TestPass123!"),
        first_name="Inactive",
        last_name="User",
        is_active=False,
        is_superuser=False,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest.fixture
async def test_superuser(test_session: AsyncSession) -> User:
    """Create a test superuser."""
    password_hasher = PasswordHasher()
    user = User(
        login="superuser",
        password=password_hasher.hash_password("SuperPass123!"),
        first_name="Super",
        last_name="User",
        is_active=True,
        is_superuser=True,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest.fixture
async def test_admin_user(test_session: AsyncSession, test_admin_role: Role) -> User:
    """Create a test admin user with admin role."""
    password_hasher = PasswordHasher()
    user = User(
        login="adminuser",
        password=password_hasher.hash_password("AdminPass123!"),
        first_name="Admin",
        last_name="User",
        is_active=True,
        is_superuser=False,
    )
    test_session.add(user)
    await test_session.flush()
    
    # Assign admin role
    user_role = UserRole(user_id=user.id, role_id=test_admin_role.id)
    test_session.add(user_role)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest.fixture
async def test_subscriber_role(test_session: AsyncSession) -> Role:
    """Create a subscriber role."""
    role = Role(
        name="subscriber",
        description="Basic subscriber role",
    )
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)
    return role


@pytest.fixture
async def test_admin_role(test_session: AsyncSession) -> Role:
    """Create an admin role."""
    role = Role(
        name="admin",
        description="Administrator role",
    )
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)
    return role


@pytest.fixture
async def test_premium_role(test_session: AsyncSession) -> Role:
    """Create a premium role."""
    role = Role(
        name="premium",
        description="Premium subscriber role",
    )
    test_session.add(role)
    await test_session.commit()
    await test_session.refresh(role)
    return role


# Token fixtures
@pytest.fixture
def test_access_token(test_user: User) -> str:
    """Create a test access token for test_user."""
    token_data = {
        "user_id": str(test_user.id),
        "login": test_user.login,
        "roles": [],
        "version": 1,
    }
    return create_access_token(token_data)


@pytest.fixture
def test_superuser_access_token(test_superuser: User) -> str:
    """Create a test access token for test_superuser."""
    token_data = {
        "user_id": str(test_superuser.id),
        "login": test_superuser.login,
        "roles": [],
        "version": 1,
    }
    return create_access_token(token_data)


@pytest.fixture
def test_admin_access_token(test_admin_user: User) -> str:
    """Create a test access token for test_admin_user."""
    token_data = {
        "user_id": str(test_admin_user.id),
        "login": test_admin_user.login,
        "roles": ["admin"],
        "version": 1,
    }
    return create_access_token(token_data)


@pytest.fixture
def test_refresh_token(test_user: User) -> str:
    """Create a test refresh token for test_user."""
    return create_refresh_token(str(test_user.id))


@pytest.fixture
def test_expired_token(test_user: User) -> str:
    """Create an expired access token for testing."""
    token_data = {
        "user_id": str(test_user.id),
        "login": test_user.login,
        "roles": [],
        "version": 1,
    }
    # Create token with negative expiration (already expired)
    return create_access_token(token_data, expires_delta=timedelta(seconds=-60))


# Helper fixtures
@pytest.fixture
def auth_headers(test_access_token: str) -> dict:
    """Create authentication headers with Bearer token."""
    return {"Authorization": f"Bearer {test_access_token}"}


@pytest.fixture
def superuser_auth_headers(test_superuser_access_token: str) -> dict:
    """Create authentication headers for superuser."""
    return {"Authorization": f"Bearer {test_superuser_access_token}"}


@pytest.fixture
def admin_auth_headers(test_admin_access_token: str) -> dict:
    """Create authentication headers for admin."""
    return {"Authorization": f"Bearer {test_admin_access_token}"}


# Test data constants
TEST_USER_CREATE_DATA = {
    "login": "newuser",
    "password": "NewUserPass123!",
    "first_name": "New",
    "last_name": "User",
}

TEST_LOGIN_DATA = {
    "login": "testuser",
    "password": "TestPass123!",
}

TEST_INVALID_LOGIN_DATA = {
    "login": "testuser",
    "password": "WrongPassword",
}

TEST_ROLE_CREATE_DATA = {
    "name": "moderator",
    "description": "Moderator role with limited admin access",
}

TEST_PASSWORD_CHANGE_DATA = {
    "old_password": "TestPass123!",
    "new_password": "NewSecurePass456!",
}
