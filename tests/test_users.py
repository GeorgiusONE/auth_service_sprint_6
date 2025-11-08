"""
Tests for users endpoints.
"""

import pytest
from httpx import AsyncClient

from tests.conftest import TEST_PASSWORD_CHANGE_DATA


class TestGetCurrentUser:
    """Tests for GET /api/v1/users/me endpoint."""
    
    @pytest.mark.asyncio
    async def test_get_me_success(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test successful retrieval of current user info."""
        response = await client.get(
            "/api/v1/users/me",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_user.id)
        assert data["login"] == test_user.login
        assert data["first_name"] == test_user.first_name
        assert data["last_name"] == test_user.last_name
        assert "is_superuser" in data
        assert "roles" in data
        assert isinstance(data["roles"], list)
        assert "created_at" in data
        assert "password" not in data  # Password should never be returned
    
    @pytest.mark.asyncio
    async def test_get_me_with_roles(
        self, 
        client: AsyncClient, 
        test_user,
        test_subscriber_role,
        test_session,
        auth_headers
    ):
        """Test that roles are returned with user info."""
        from src.models.entity import UserRole
        
        # Assign role to user
        user_role = UserRole(user_id=test_user.id, role_id=test_subscriber_role.id)
        test_session.add(user_role)
        await test_session.commit()
        
        response = await client.get(
            "/api/v1/users/me",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["roles"]) > 0
        assert any(role["name"] == "subscriber" for role in data["roles"])
    
    @pytest.mark.asyncio
    async def test_get_me_without_token(self, client: AsyncClient):
        """Test getting user info without authentication returns 401."""
        response = await client.get("/api/v1/users/me")
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_get_me_with_invalid_token(self, client: AsyncClient):
        """Test getting user info with invalid token returns 401."""
        response = await client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        
        assert response.status_code == 401
        data = response.json()
        assert "TOKEN_INVALID" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_get_me_superuser(
        self, 
        client: AsyncClient, 
        test_superuser,
        superuser_auth_headers
    ):
        """Test that superuser flag is correctly returned."""
        response = await client.get(
            "/api/v1/users/me",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["is_superuser"] is True


class TestGetLoginHistory:
    """Tests for GET /api/v1/users/me/login-history endpoint."""
    
    @pytest.mark.asyncio
    async def test_get_login_history_success(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test successful retrieval of login history."""
        # Create some login history
        from src.models.entity import LoginHistory
        from src.services.user import UserService
        
        user_service = UserService(db=None, redis=None)
        
        # Login to create history
        await client.post(
            "/api/v1/auth/login",
            json={"login": "testuser", "password": "TestPass123!"},
            headers={"User-Agent": "Test Browser"}
        )
        
        response = await client.get(
            "/api/v1/users/me/login-history",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "size" in data
        assert "pages" in data
        assert isinstance(data["items"], list)
        assert data["page"] == 1
        assert data["size"] == 20  # Default size
    
    @pytest.mark.asyncio
    async def test_get_login_history_with_pagination(
        self, 
        client: AsyncClient, 
        test_user,
        test_session,
        auth_headers
    ):
        """Test login history pagination."""
        from src.models.entity import LoginHistory
        
        # Create multiple history entries
        for i in range(5):
            history = LoginHistory(
                user_id=test_user.id,
                user_agent=f"Browser {i}",
                ip_address=f"192.168.1.{i}",
                fingerprint=f"fingerprint_{i}",
                success=True
            )
            test_session.add(history)
        await test_session.commit()
        
        # Get first page with size=2
        response = await client.get(
            "/api/v1/users/me/login-history?page=1&size=2",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) <= 2
        assert data["page"] == 1
        assert data["size"] == 2
        assert data["total"] >= 5
        assert data["pages"] >= 3  # At least 3 pages for 5+ items with size=2
    
    @pytest.mark.asyncio
    async def test_get_login_history_sorted_by_date(
        self, 
        client: AsyncClient, 
        test_user,
        test_session,
        auth_headers
    ):
        """Test that login history is sorted by login_at DESC."""
        from src.models.entity import LoginHistory
        from datetime import datetime, timedelta
        
        # Create history with different timestamps
        now = datetime.utcnow()
        for i in range(3):
            history = LoginHistory(
                user_id=test_user.id,
                user_agent=f"Browser {i}",
                ip_address="192.168.1.1",
                fingerprint="test",
                success=True,
                login_at=now - timedelta(hours=i)
            )
            test_session.add(history)
        await test_session.commit()
        
        response = await client.get(
            "/api/v1/users/me/login-history",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check that items are sorted by login_at descending
        if len(data["items"]) > 1:
            for i in range(len(data["items"]) - 1):
                current = data["items"][i]["login_at"]
                next_item = data["items"][i + 1]["login_at"]
                assert current >= next_item
    
    @pytest.mark.asyncio
    async def test_get_login_history_boundary_values(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test pagination with boundary values."""
        # Test page=0 (should default to 1)
        response = await client.get(
            "/api/v1/users/me/login-history?page=0",
            headers=auth_headers
        )
        assert response.status_code == 422 or response.json()["page"] >= 1
        
        # Test size=0 (should fail validation)
        response = await client.get(
            "/api/v1/users/me/login-history?size=0",
            headers=auth_headers
        )
        assert response.status_code == 422
        
        # Test size > 100 (should fail validation)
        response = await client.get(
            "/api/v1/users/me/login-history?size=101",
            headers=auth_headers
        )
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_get_login_history_without_token(self, client: AsyncClient):
        """Test getting login history without authentication returns 401."""
        response = await client.get("/api/v1/users/me/login-history")
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_get_login_history_includes_all_fields(
        self, 
        client: AsyncClient, 
        test_user,
        test_session,
        auth_headers
    ):
        """Test that all login history fields are returned."""
        from src.models.entity import LoginHistory
        
        # Create a history entry
        history = LoginHistory(
            user_id=test_user.id,
            user_agent="Mozilla/5.0",
            ip_address="192.168.1.100",
            fingerprint="test_fingerprint_hash",
            success=True
        )
        test_session.add(history)
        await test_session.commit()
        
        response = await client.get(
            "/api/v1/users/me/login-history",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        if len(data["items"]) > 0:
            item = data["items"][0]
            assert "id" in item
            assert "user_agent" in item
            assert "ip_address" in item
            assert "fingerprint" in item
            assert "login_at" in item
            assert "success" in item


class TestChangePassword:
    """Tests for PUT /api/v1/users/me/password endpoint."""
    
    @pytest.mark.asyncio
    async def test_change_password_success(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test successful password change."""
        response = await client.put(
            "/api/v1/users/me/password",
            json=TEST_PASSWORD_CHANGE_DATA,
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "success" in data["message"].lower()
    
    @pytest.mark.asyncio
    async def test_change_password_triggers_logout_all(
        self, 
        client: AsyncClient, 
        test_user,
        test_redis
    ):
        """Test that password change triggers logout from all devices."""
        # Login to get token
        login_response = await client.post(
            "/api/v1/auth/login",
            json={"login": "testuser", "password": "TestPass123!"}
        )
        old_token = login_response.json()["access_token"]
        
        # Change password
        response = await client.put(
            "/api/v1/users/me/password",
            json=TEST_PASSWORD_CHANGE_DATA,
            headers={"Authorization": f"Bearer {old_token}"}
        )
        
        assert response.status_code == 200
        
        # Old token should not work anymore
        response = await client.get(
            "/api/v1/users/me",
            headers={"Authorization": f"Bearer {old_token}"}
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_change_password_can_login_with_new(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test that can login with new password after change."""
        # Change password
        await client.put(
            "/api/v1/users/me/password",
            json=TEST_PASSWORD_CHANGE_DATA,
            headers=auth_headers
        )
        
        # Try to login with new password
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "login": "testuser",
                "password": TEST_PASSWORD_CHANGE_DATA["new_password"]
            }
        )
        
        assert response.status_code == 200
        assert "access_token" in response.json()
    
    @pytest.mark.asyncio
    async def test_change_password_invalid_old_password(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test password change with incorrect old password returns 400."""
        response = await client.put(
            "/api/v1/users/me/password",
            json={
                "old_password": "WrongOldPass123!",
                "new_password": "NewSecurePass456!"
            },
            headers=auth_headers
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "INVALID_PASSWORD" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_change_password_weak_new_password(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test password change with weak new password returns 400."""
        response = await client.put(
            "/api/v1/users/me/password",
            json={
                "old_password": "TestPass123!",
                "new_password": "weak"
            },
            headers=auth_headers
        )
        
        assert response.status_code == 400
        data = response.json()
        assert "PASSWORD_TOO_WEAK" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_change_password_without_token(self, client: AsyncClient):
        """Test changing password without authentication returns 401."""
        response = await client.put(
            "/api/v1/users/me/password",
            json=TEST_PASSWORD_CHANGE_DATA
        )
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_change_password_same_as_old(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test changing password to the same value."""
        response = await client.put(
            "/api/v1/users/me/password",
            json={
                "old_password": "TestPass123!",
                "new_password": "TestPass123!"
            },
            headers=auth_headers
        )
        
        # Should succeed (no restriction against same password)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_change_password_missing_fields(
        self, 
        client: AsyncClient, 
        test_user,
        auth_headers
    ):
        """Test password change with missing fields returns 422."""
        # Missing new_password
        response = await client.put(
            "/api/v1/users/me/password",
            json={"old_password": "TestPass123!"},
            headers=auth_headers
        )
        
        assert response.status_code == 422
        
        # Missing old_password
        response = await client.put(
            "/api/v1/users/me/password",
            json={"new_password": "NewPass123!"},
            headers=auth_headers
        )
        
        assert response.status_code == 422
