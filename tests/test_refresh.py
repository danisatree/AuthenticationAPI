import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db.user import RefreshToken


@pytest.mark.asyncio
async def test_refresh_token_flow(async_client: AsyncClient, test_session: AsyncSession, test_user):
    """Test full refresh token flow"""
    # 1. Login to get tokens
    login_data = {"username": "testuser", "password": "testpassword123"}
    response = await async_client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    access_token = data["access_token"]
    refresh_token = data["refresh_token"]

    assert access_token
    assert refresh_token

    # 2. Refresh token
    refresh_response = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refresh_response.status_code == status.HTTP_200_OK
    new_data = refresh_response.json()
    new_access_token = new_data["access_token"]
    new_refresh_token = new_data["refresh_token"]

    assert new_access_token
    assert new_refresh_token
    # Rotation: new refresh token should be different
    assert new_refresh_token != refresh_token

    # 3. Verify old token is revoked
    old_token_db = await test_session.execute(select(RefreshToken).where(RefreshToken.token == refresh_token))
    assert old_token_db.scalar_one().revoked is True

    # 4. Try to reuse old token (should fail)
    reuse_response = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert reuse_response.status_code == status.HTTP_401_UNAUTHORIZED  # Or 403 depending on implementation

    # 5. Logout
    logout_response = await async_client.post("/api/v1/auth/logout", json={"refresh_token": new_refresh_token})
    assert logout_response.status_code == status.HTTP_200_OK

    # 6. Try to refresh with logged out token (should fail)
    logout_reuse_response = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": new_refresh_token})
    assert logout_reuse_response.status_code == status.HTTP_401_UNAUTHORIZED
