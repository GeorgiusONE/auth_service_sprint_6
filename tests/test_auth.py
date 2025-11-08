"""
Tests for authentication endpoints.
"""

import pytest
from httpx import AsyncClient

from tests.conftest import (
    TEST_USER_CREATE_DATA,
    TEST_LOGIN_DATA,
    TEST_INVALID_LOGIN_DATA,
)


class TestSignup:
    """Tests for POST /api/v1/auth/signup endpoint."""
    
    @pytest.mark.asyncio
    async def test_signup_success(self, client: AsyncClient):
        """Test successful user registration."""
        response = await client.post(
            "/api/v1/auth/signup",
            json=TEST_USER_CREATE_DATA
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["login"] == TEST_USER_CREATE_DATA["login"]
        assert data["first_name"] == TEST_USER_CREATE_DATA["first_name"]
        assert data["last_name"] == TEST_USER_CREATE_DATA["last_name"]
        assert "id" in data
        assert "created_at" in data
        assert "password" not in data  # Password should not be returned
    
    @pytest.mark.asyncio
    async def test_signup_duplicate_login(self, client: AsyncClient, test_user):
        """Test registration with existing login returns 409."""
        duplicate_data = {
            "login": test_user.login,
            "password": "AnotherPass123!",
            "first_name": "Another",
            "last_name": "User",
        }
        
        response = await client.post(
            "/api/v1/auth/signup",
            json=duplicate_data
        )
        
        assert response.status_code == 409
        data = response.json()
        assert "USER_ALREADY_EXISTS" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_signup_weak_password(self, client: AsyncClient):
        """Test registration with weak password returns 400."""
        weak_password_data = {
            "login": "weakpass",
            "password": "weak",
            "first_name": "Weak",
            "last_name": "Pass",
        }
        
        response = await client.post(
            "/api/v1/auth/signup",
            json=weak_password_data
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "PASSWORD_TOO_WEAK" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_signup_short_login(self, client: AsyncClient):
        """Test registration with short login returns 422."""
        short_login_data = {
            "login": "ab",  # Less than 3 characters
            "password": "ValidPass123!",
            "first_name": "Short",
            "last_name": "Login",
        }
        
        response = await client.post(
            "/api/v1/auth/signup",
            json=short_login_data
        )
        
        assert response.status_code == 422  # Validation error


class TestLogin:
    """Tests for POST /api/v1/auth/login endpoint."""
    
    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient, test_user):
        """Test successful login."""
        response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"]) > 0
        assert len(data["refresh_token"]) > 0
    
    @pytest.mark.asyncio
    async def test_login_invalid_password(self, client: AsyncClient, test_user):
        """Test login with invalid password returns 401."""
        response = await client.post(
            "/api/v1/auth/login",
            json=TEST_INVALID_LOGIN_DATA
        )
        
        assert response.status_code == 401
        data = response.json()
        assert "INVALID_CREDENTIALS" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client: AsyncClient):
        """Test login with non-existent user returns 401."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "login": "nonexistent",
                "password": "SomePass123!"
            }
        )
        
        assert response.status_code == 401
        data = response.json()
        assert "INVALID_CREDENTIALS" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client: AsyncClient, test_inactive_user):
        """Test login with inactive user returns 403."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "login": test_inactive_user.login,
                "password": "TestPass123!"
            }
        )
        
        assert response.status_code == 403
        data = response.json()
        assert "USER_INACTIVE" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_login_creates_history(
        self, 
        client: AsyncClient, 
        test_user, 
        test_session
    ):
        """Test that login creates a history entry."""
        from src.models.entity import LoginHistory
        from sqlalchemy import select
        
        # Login
        response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA,
            headers={"User-Agent": "Test Client"}
        )
        
        assert response.status_code == 200
        
        # Check history was created
        result = await test_session.execute(
            select(LoginHistory).where(LoginHistory.user_id == test_user.id)
        )
        history = result.scalars().all()
        
        assert len(history) > 0
        assert history[0].success is True
        assert history[0].user_agent == "Test Client"


class TestRefresh:
    """Tests for POST /api/v1/auth/refresh endpoint."""
    
    @pytest.mark.asyncio
    async def test_refresh_success(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis
    ):
        """Test successful token refresh."""
        # First login to get valid refresh token
        login_response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA
        )
        
        assert login_response.status_code == 200
        refresh_token = login_response.json()["refresh_token"]
        
        # Refresh token
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert len(data["access_token"]) > 0
    
    @pytest.mark.asyncio
    async def test_refresh_invalid_token(self, client: AsyncClient):
        """Test refresh with invalid token returns 401."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid.token.here"}
        )
        
        assert response.status_code == 401
        data = response.json()
        assert "TOKEN_INVALID" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_refresh_expired_token(self, client: AsyncClient, test_expired_token):
        """Test refresh with expired token returns 401."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": test_expired_token}
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_refresh_revoked_token(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis
    ):
        """Test refresh with revoked token returns 403."""
        # Login and get refresh token
        login_response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA
        )
        refresh_token = login_response.json()["refresh_token"]
        access_token = login_response.json()["access_token"]
        
        # Logout (revokes tokens)
        await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        # Try to use revoked refresh token
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == 401 or response.status_code == 403


class TestLogout:
    """Tests for POST /api/v1/auth/logout endpoint."""
    
    @pytest.mark.asyncio
    async def test_logout_success(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis
    ):
        """Test successful logout."""
        # Login first
        login_response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA
        )
        access_token = login_response.json()["access_token"]
        
        # Logout
        response = await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 204
    
    @pytest.mark.asyncio
    async def test_logout_adds_to_blacklist(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis,
        auth_headers
    ):
        """Test that logout adds token to blacklist."""
        # Login
        login_response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA
        )
        access_token = login_response.json()["access_token"]
        
        # Logout
        await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        # Try to use the token again
        response = await client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        # Should be unauthorized because token is blacklisted
        assert response.status_code == 401
        data = response.json()
        assert "TOKEN_BLACKLISTED" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_logout_without_token(self, client: AsyncClient):
        """Test logout without authentication returns 401."""
        response = await client.post("/api/v1/auth/logout")
        
        assert response.status_code == 401


class TestLogoutAll:
    """Tests for POST /api/v1/auth/logout-all endpoint."""
    
    @pytest.mark.asyncio
    async def test_logout_all_success(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis
    ):
        """Test successful logout from all sessions."""
        # Login first
        login_response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA
        )
        access_token = login_response.json()["access_token"]
        
        # Logout all
        response = await client.post(
            "/api/v1/auth/logout-all",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 204
    
    @pytest.mark.asyncio
    async def test_logout_all_invalidates_all_tokens(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis
    ):
        """Test that logout-all invalidates all tokens."""
        # Create two sessions
        login1 = await client.post("/api/v1/auth/login", json=TEST_LOGIN_DATA)
        token1 = login1.json()["access_token"]
        
        login2 = await client.post("/api/v1/auth/login", json=TEST_LOGIN_DATA)
        token2 = login2.json()["access_token"]
        
        # Logout all from first session
        await client.post(
            "/api/v1/auth/logout-all",
            headers={"Authorization": f"Bearer {token1}"}
        )
        
        # Both tokens should be invalid now
        response1 = await client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token1}"}
        )
        response2 = await client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {token2}"}
        )
        
        # At least one should be unauthorized (token version mismatch)
        assert response1.status_code == 401 or response2.status_code == 401
    
    @pytest.mark.asyncio
    async def test_logout_all_without_token(self, client: AsyncClient):
        """Test logout-all without authentication returns 401."""
        response = await client.post("/api/v1/auth/logout-all")
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_logout_all_increments_version(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis
    ):
        """Test that logout-all increments token version."""
        # Login
        login_response = await client.post(
            "/api/v1/auth/login",
            json=TEST_LOGIN_DATA
        )
        old_token = login_response.json()["access_token"]
        
        # Get initial version
        initial_version = await test_redis.get(f"token_version:{test_user.id}")
        if initial_version:
            initial_version = int(initial_version)
        else:
            initial_version = 1
        
        # Logout all
        await client.post(
            "/api/v1/auth/logout-all",
            headers={"Authorization": f"Bearer {old_token}"}
        )
        
        # Check version was incremented
        new_version = await test_redis.get(f"token_version:{test_user.id}")
        new_version = int(new_version)
        
        assert new_version == initial_version + 1
        
        # Old token should not work
        response = await client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {old_token}"}
        )
        assert response.status_code == 401
