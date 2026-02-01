import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest.mark.asyncio
async def test_get_current_user_profile(async_client: AsyncClient, auth_headers: dict):
    """Test GET /api/v1/users/me endpoint"""
    # Note: Router prefix is /api/v1 in main.py, and /users in endpoint.
    response = await async_client.get("/api/v1/users/me", headers=auth_headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "id" in data
    assert "username" in data
    assert "role_id" in data
    assert data["username"] == "testuser"


@pytest.mark.asyncio
async def test_get_current_user_profile_no_auth(async_client: AsyncClient):
    """Test GET /api/v1/users/me without authentication"""
    response = await async_client.get("/api/v1/users/me")

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_get_current_user_profile_invalid_token(async_client: AsyncClient):
    """Test GET /api/v1/users/me with invalid token"""
    response = await async_client.get("/api/v1/users/me", headers={"Authorization": "Bearer invalid_token"})

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_change_password(async_client: AsyncClient, auth_headers: dict, test_session: AsyncSession):
    """Test POST /api/v1/auth/password/change endpoint"""
    response = await async_client.post(
        "/api/v1/auth/password/change",
        headers=auth_headers,
        json={"current_password": "testpassword123", "new_password": "newpassword456"},
    )

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["message"] == "Password changed successfully"

    # Verify new password works
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "testuser", "password": "newpassword456"},
    )
    assert login_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_change_password_wrong_current_password(async_client: AsyncClient, auth_headers: dict):
    """Test password change with incorrect current password"""
    response = await async_client.post(
        "/api/v1/auth/password/change",
        headers=auth_headers,
        json={"current_password": "wrongpassword", "new_password": "newpassword456"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "incorrect" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_change_password_same_as_current(async_client: AsyncClient, auth_headers: dict):
    """Test password change with new password same as current"""
    response = await async_client.post(
        "/api/v1/auth/password/change",
        headers=auth_headers,
        json={
            "current_password": "testpassword123",
            "new_password": "testpassword123",
        },
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "different" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_change_password_too_short(async_client: AsyncClient, auth_headers: dict):
    """Test password change with password too short"""
    response = await async_client.post(
        "/api/v1/auth/password/change",
        headers=auth_headers,
        json={"current_password": "testpassword123", "new_password": "short"},
    )

    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


@pytest.mark.asyncio
async def test_change_password_no_auth(async_client: AsyncClient):
    """Test password change without authentication"""
    response = await async_client.post(
        "/api/v1/auth/password/change",
        json={"current_password": "testpassword123", "new_password": "newpassword456"},
    )

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_update_user_profile(async_client: AsyncClient, auth_headers: dict):
    """Test PUT /api/v1/users/me endpoint"""
    response = await async_client.put("/api/v1/users/me", headers=auth_headers, json={"username": "updateduser"})

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["username"] == "updateduser"

    # Verify updated username can be used for login
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "updateduser", "password": "testpassword123"},
    )
    assert login_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_update_user_profile_duplicate_username(
    async_client: AsyncClient, auth_headers: dict, test_session: AsyncSession
):
    """Test profile update with username that already exists"""
    # Create another user
    import bcrypt

    from app.models.db.user import User
    from app.models.db.user import Role
    from sqlalchemy import select

    hashed_password = bcrypt.hashpw(b"password123", bcrypt.gensalt()).decode("utf-8")

    result = await test_session.execute(select(Role).where(Role.name == "user"))
    user_role = result.scalar_one()

    another_user = User(username="anotheruser", password_hash=hashed_password, role_id=user_role.id)
    test_session.add(another_user)
    await test_session.commit()

    # Try to update to existing username
    response = await async_client.put("/api/v1/users/me", headers=auth_headers, json={"username": "anotheruser"})

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "already taken" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_update_user_profile_no_auth(async_client: AsyncClient):
    """Test profile update without authentication"""
    response = await async_client.put("/api/v1/users/me", json={"username": "newusername"})

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_delete_user_account(async_client: AsyncClient, auth_headers: dict):
    """Test DELETE /api/v1/users/me endpoint"""
    response = await async_client.delete("/api/v1/users/me", headers=auth_headers)

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["message"] == "Account deleted successfully"

    # Verify user can no longer login
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "testuser", "password": "testpassword123"},
    )
    assert login_response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.asyncio
async def test_delete_user_account_no_auth(async_client: AsyncClient):
    """Test account deletion without authentication"""
    response = await async_client.delete("/api/v1/users/me")

    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.asyncio
async def test_password_reset(async_client: AsyncClient, test_user):
    """Test POST /api/v1/auth/password/reset endpoint"""
    response = await async_client.post("/api/v1/auth/password/reset", json={"username": "testuser"})

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["message"] == "Password reset successfully"
    assert "temporary_password" in data

    # Verify temporary password works
    temp_password = data["temporary_password"]
    login_response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "testuser", "password": temp_password},
    )
    assert login_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_password_reset_nonexistent_user(async_client: AsyncClient):
    """Test password reset for non-existent user"""
    response = await async_client.post("/api/v1/auth/password/reset", json={"username": "nonexistentuser"})

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_sign_up_user(async_client: AsyncClient, test_session: AsyncSession):
    """Test POST /api/v1/auth/signup endpoint"""
    # Note: We need a fresh user who is not already in the database
    signup_data = {"username": "newuser", "password": "newpassword123"}

    response = await async_client.post("/api/v1/auth/signup", json=signup_data)

    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert "access_token" in data
    assert data["user"]["username"] == "newuser"
    assert data["token_type"] == "bearer"

    # Verify we can login with the new user
    login_response = await async_client.post("/api/v1/auth/login", json=signup_data)
    assert login_response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_sign_up_duplicate_username(async_client: AsyncClient, test_user):
    """Test signup with a username that already exists"""
    signup_data = {
        "username": "testuser",  # Already exists from test_user fixture
        "password": "password123",
    }

    response = await async_client.post("/api/v1/auth/signup", json=signup_data)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "already registered" in response.json()["detail"].lower()
