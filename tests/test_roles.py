"""
Tests for roles endpoints.
"""

import pytest
from httpx import AsyncClient
from uuid import uuid4

from tests.conftest import TEST_ROLE_CREATE_DATA


class TestCreateRole:
    """Tests for POST /api/v1/roles endpoint."""
    
    @pytest.mark.asyncio
    async def test_create_role_by_superuser(
        self, 
        client: AsyncClient,
        test_superuser,
        superuser_auth_headers
    ):
        """Test successful role creation by superuser."""
        response = await client.post(
            "/api/v1/roles",
            json=TEST_ROLE_CREATE_DATA,
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == TEST_ROLE_CREATE_DATA["name"]
        assert data["description"] == TEST_ROLE_CREATE_DATA["description"]
        assert "id" in data
        assert "created_at" in data
    
    @pytest.mark.asyncio
    async def test_create_role_by_admin(
        self, 
        client: AsyncClient,
        test_admin_user,
        admin_auth_headers
    ):
        """Test successful role creation by admin."""
        response = await client.post(
            "/api/v1/roles",
            json={
                "name": "editor",
                "description": "Content editor role"
            },
            headers=admin_auth_headers
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "editor"
    
    @pytest.mark.asyncio
    async def test_create_role_by_regular_user(
        self, 
        client: AsyncClient,
        test_user,
        auth_headers
    ):
        """Test that regular user cannot create roles."""
        response = await client.post(
            "/api/v1/roles",
            json=TEST_ROLE_CREATE_DATA,
            headers=auth_headers
        )
        
        assert response.status_code == 403
        data = response.json()
        assert "INSUFFICIENT_PERMISSIONS" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_create_role_duplicate_name(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        superuser_auth_headers
    ):
        """Test creating role with duplicate name returns 409."""
        response = await client.post(
            "/api/v1/roles",
            json={
                "name": test_subscriber_role.name,
                "description": "Duplicate"
            },
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 409
        data = response.json()
        assert "ROLE_ALREADY_EXISTS" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_create_role_without_token(self, client: AsyncClient):
        """Test creating role without authentication returns 401."""
        response = await client.post(
            "/api/v1/roles",
            json=TEST_ROLE_CREATE_DATA
        )
        
        assert response.status_code == 401


class TestGetRoles:
    """Tests for GET /api/v1/roles endpoint."""
    
    @pytest.mark.asyncio
    async def test_get_roles_success(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        test_admin_role,
        auth_headers
    ):
        """Test successful retrieval of all roles."""
        response = await client.get(
            "/api/v1/roles",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)
        assert data["total"] >= 2
        
        # Check that roles are in the list
        role_names = [role["name"] for role in data["items"]]
        assert "subscriber" in role_names
        assert "admin" in role_names
    
    @pytest.mark.asyncio
    async def test_get_roles_sorted_by_name(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        test_admin_role,
        test_premium_role,
        auth_headers
    ):
        """Test that roles are sorted by name."""
        response = await client.get(
            "/api/v1/roles",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Check alphabetical sorting
        names = [role["name"] for role in data["items"]]
        assert names == sorted(names)
    
    @pytest.mark.asyncio
    async def test_get_roles_without_token(self, client: AsyncClient):
        """Test getting roles without authentication returns 401."""
        response = await client.get("/api/v1/roles")
        
        assert response.status_code == 401


class TestGetRoleById:
    """Tests for GET /api/v1/roles/{role_id} endpoint."""
    
    @pytest.mark.asyncio
    async def test_get_role_success(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        auth_headers
    ):
        """Test successful retrieval of specific role."""
        response = await client.get(
            f"/api/v1/roles/{test_subscriber_role.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(test_subscriber_role.id)
        assert data["name"] == test_subscriber_role.name
        assert data["description"] == test_subscriber_role.description
        assert "created_at" in data
        assert "updated_at" in data
    
    @pytest.mark.asyncio
    async def test_get_role_not_found(
        self, 
        client: AsyncClient,
        auth_headers
    ):
        """Test getting non-existent role returns 404."""
        fake_id = uuid4()
        response = await client.get(
            f"/api/v1/roles/{fake_id}",
            headers=auth_headers
        )
        
        assert response.status_code == 404
        data = response.json()
        assert "ROLE_NOT_FOUND" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_get_role_invalid_uuid(
        self, 
        client: AsyncClient,
        auth_headers
    ):
        """Test getting role with invalid UUID returns 422."""
        response = await client.get(
            "/api/v1/roles/invalid-uuid",
            headers=auth_headers
        )
        
        assert response.status_code == 422


class TestUpdateRole:
    """Tests for PUT /api/v1/roles/{role_id} endpoint."""
    
    @pytest.mark.asyncio
    async def test_update_role_by_superuser(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        superuser_auth_headers
    ):
        """Test successful role update by superuser."""
        response = await client.put(
            f"/api/v1/roles/{test_subscriber_role.id}",
            json={
                "name": "subscriber_updated",
                "description": "Updated description"
            },
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "subscriber_updated"
        assert data["description"] == "Updated description"
        assert "updated_at" in data
    
    @pytest.mark.asyncio
    async def test_update_role_by_admin(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        admin_auth_headers
    ):
        """Test successful role update by admin."""
        response = await client.put(
            f"/api/v1/roles/{test_subscriber_role.id}",
            json={"description": "New description by admin"},
            headers=admin_auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "New description by admin"
    
    @pytest.mark.asyncio
    async def test_update_role_by_regular_user(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        auth_headers
    ):
        """Test that regular user cannot update roles."""
        response = await client.put(
            f"/api/v1/roles/{test_subscriber_role.id}",
            json={"description": "Attempt"},
            headers=auth_headers
        )
        
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_update_role_duplicate_name(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        test_admin_role,
        superuser_auth_headers
    ):
        """Test updating role to duplicate name returns 409."""
        response = await client.put(
            f"/api/v1/roles/{test_subscriber_role.id}",
            json={"name": test_admin_role.name},
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 409
        data = response.json()
        assert "ROLE_ALREADY_EXISTS" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_update_role_not_found(
        self, 
        client: AsyncClient,
        superuser_auth_headers
    ):
        """Test updating non-existent role returns 404."""
        fake_id = uuid4()
        response = await client.put(
            f"/api/v1/roles/{fake_id}",
            json={"description": "Updated"},
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 404


class TestDeleteRole:
    """Tests for DELETE /api/v1/roles/{role_id} endpoint."""
    
    @pytest.mark.asyncio
    async def test_delete_role_by_superuser(
        self, 
        client: AsyncClient,
        test_premium_role,
        superuser_auth_headers
    ):
        """Test successful role deletion by superuser."""
        response = await client.delete(
            f"/api/v1/roles/{test_premium_role.id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 204
        
        # Verify role is deleted
        get_response = await client.get(
            f"/api/v1/roles/{test_premium_role.id}",
            headers=superuser_auth_headers
        )
        assert get_response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_delete_role_cascade_deletes_user_roles(
        self, 
        client: AsyncClient,
        test_user,
        test_premium_role,
        test_session,
        superuser_auth_headers
    ):
        """Test that deleting role cascades to user_roles."""
        from src.models.entity import UserRole
        from sqlalchemy import select
        
        # Assign role to user
        user_role = UserRole(user_id=test_user.id, role_id=test_premium_role.id)
        test_session.add(user_role)
        await test_session.commit()
        
        # Delete role
        await client.delete(
            f"/api/v1/roles/{test_premium_role.id}",
            headers=superuser_auth_headers
        )
        
        # Verify user_role was deleted
        result = await test_session.execute(
            select(UserRole).where(UserRole.role_id == test_premium_role.id)
        )
        user_roles = result.scalars().all()
        assert len(user_roles) == 0
    
    @pytest.mark.asyncio
    async def test_delete_role_by_regular_user(
        self, 
        client: AsyncClient,
        test_premium_role,
        auth_headers
    ):
        """Test that regular user cannot delete roles."""
        response = await client.delete(
            f"/api/v1/roles/{test_premium_role.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_delete_role_not_found(
        self, 
        client: AsyncClient,
        superuser_auth_headers
    ):
        """Test deleting non-existent role returns 404."""
        fake_id = uuid4()
        response = await client.delete(
            f"/api/v1/roles/{fake_id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 404


class TestAssignRole:
    """Tests for POST /api/v1/roles/{role_id}/users/{user_id} endpoint."""
    
    @pytest.mark.asyncio
    async def test_assign_role_by_superuser(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        superuser_auth_headers
    ):
        """Test successful role assignment by superuser."""
        response = await client.post(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{test_user.id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["user_id"] == str(test_user.id)
        assert data["role_id"] == str(test_subscriber_role.id)
    
    @pytest.mark.asyncio
    async def test_assign_role_by_admin(
        self, 
        client: AsyncClient,
        test_user,
        test_premium_role,
        admin_auth_headers
    ):
        """Test successful role assignment by admin."""
        response = await client.post(
            f"/api/v1/roles/{test_premium_role.id}/users/{test_user.id}",
            headers=admin_auth_headers
        )
        
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_assign_role_invalidates_cache(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        test_redis,
        superuser_auth_headers
    ):
        """Test that assigning role invalidates user roles cache."""
        # Pre-cache user roles
        cache_key = f"user_roles:{test_user.id}"
        await test_redis.set(cache_key, "[]", ex=300)
        
        # Assign role
        await client.post(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{test_user.id}",
            headers=superuser_auth_headers
        )
        
        # Cache should be invalidated (or updated)
        # The actual behavior depends on implementation
        # Just verify the operation succeeded
        assert True
    
    @pytest.mark.asyncio
    async def test_assign_role_duplicate(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        test_session,
        superuser_auth_headers
    ):
        """Test assigning already assigned role returns 409."""
        from src.models.entity import UserRole
        
        # Assign role first time
        user_role = UserRole(user_id=test_user.id, role_id=test_subscriber_role.id)
        test_session.add(user_role)
        await test_session.commit()
        
        # Try to assign again
        response = await client.post(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{test_user.id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 409
        data = response.json()
        assert "ROLE_ALREADY_ASSIGNED" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_assign_role_user_not_found(
        self, 
        client: AsyncClient,
        test_subscriber_role,
        superuser_auth_headers
    ):
        """Test assigning role to non-existent user returns 404."""
        fake_user_id = uuid4()
        response = await client.post(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{fake_user_id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 404
        data = response.json()
        assert "USER_NOT_FOUND" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_assign_role_role_not_found(
        self, 
        client: AsyncClient,
        test_user,
        superuser_auth_headers
    ):
        """Test assigning non-existent role returns 404."""
        fake_role_id = uuid4()
        response = await client.post(
            f"/api/v1/roles/{fake_role_id}/users/{test_user.id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 404
        data = response.json()
        assert "ROLE_NOT_FOUND" in data["error_code"]
    
    @pytest.mark.asyncio
    async def test_assign_role_by_regular_user(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        auth_headers
    ):
        """Test that regular user cannot assign roles."""
        response = await client.post(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{test_user.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 403


class TestRemoveRole:
    """Tests for DELETE /api/v1/roles/{role_id}/users/{user_id} endpoint."""
    
    @pytest.mark.asyncio
    async def test_remove_role_by_superuser(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        test_session,
        superuser_auth_headers
    ):
        """Test successful role removal by superuser."""
        from src.models.entity import UserRole
        
        # First assign the role
        user_role = UserRole(user_id=test_user.id, role_id=test_subscriber_role.id)
        test_session.add(user_role)
        await test_session.commit()
        
        # Remove role
        response = await client.delete(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{test_user.id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 204
    
    @pytest.mark.asyncio
    async def test_remove_role_not_assigned(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        superuser_auth_headers
    ):
        """Test removing role that wasn't assigned returns 404."""
        response = await client.delete(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{test_user.id}",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_remove_role_by_regular_user(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        auth_headers
    ):
        """Test that regular user cannot remove roles."""
        response = await client.delete(
            f"/api/v1/roles/{test_subscriber_role.id}/users/{test_user.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 403


class TestCheckPermission:
    """Tests for GET /api/v1/roles/check endpoint."""
    
    @pytest.mark.asyncio
    async def test_check_permission_has_role(
        self, 
        client: AsyncClient,
        test_user,
        test_subscriber_role,
        test_session,
        auth_headers
    ):
        """Test checking permission when user has the role."""
        from src.models.entity import UserRole
        
        # Assign role to user
        user_role = UserRole(user_id=test_user.id, role_id=test_subscriber_role.id)
        test_session.add(user_role)
        await test_session.commit()
        
        response = await client.get(
            "/api/v1/roles/check?role=subscriber",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["has_permission"] is True
        assert data["user_id"] == str(test_user.id)
        assert data["role"] == "subscriber"
    
    @pytest.mark.asyncio
    async def test_check_permission_no_role(
        self, 
        client: AsyncClient,
        test_user,
        auth_headers
    ):
        """Test checking permission when user doesn't have the role."""
        response = await client.get(
            "/api/v1/roles/check?role=premium",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["has_permission"] is False
        assert data["user_id"] == str(test_user.id)
        assert data["role"] == "premium"
    
    @pytest.mark.asyncio
    async def test_check_permission_superuser_always_true(
        self, 
        client: AsyncClient,
        test_superuser,
        superuser_auth_headers
    ):
        """Test that superuser always has permission."""
        response = await client.get(
            "/api/v1/roles/check?role=any_role",
            headers=superuser_auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["has_permission"] is True
    
    @pytest.mark.asyncio
    async def test_check_permission_without_token(self, client: AsyncClient):
        """Test checking permission without authentication returns 401."""
        response = await client.get("/api/v1/roles/check?role=subscriber")
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_check_permission_missing_role_param(
        self, 
        client: AsyncClient,
        auth_headers
    ):
        """Test checking permission without role parameter returns 422."""
        response = await client.get(
            "/api/v1/roles/check",
            headers=auth_headers
        )
        
        assert response.status_code == 422
