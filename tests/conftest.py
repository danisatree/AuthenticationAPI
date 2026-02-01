"""Pytest configuration and shared fixtures"""

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.database import Base, get_session
from app.main import app
from app.models.db.user import Role, User
from app.limiter import limiter


@pytest.fixture(autouse=True)
def disable_rate_limit():
    """Disable rate limiting for tests"""
    limiter.enabled = False
    yield
    limiter.enabled = True


TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture
async def test_session():
    """Create test database session"""
    # Verify models are registered
    assert "roles" in Base.metadata.tables, "Role model not registered!"
    assert "users" in Base.metadata.tables, "User model not registered!"

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def async_client(test_session: AsyncSession):
    """Async HTTP client for testing"""

    async def override_get_session():
        yield test_session

    app.dependency_overrides[get_session] = override_get_session

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def test_user(test_session: AsyncSession):
    """Create a test user in the database"""
    import bcrypt

    # Create user role first
    user_role = Role(name="user", description="Regular user")
    test_session.add(user_role)
    await test_session.commit()
    await test_session.refresh(user_role)

    # Create test user
    hashed_password = bcrypt.hashpw(b"testpassword123", bcrypt.gensalt()).decode("utf-8")
    user = User(username="testuser", password_hash=hashed_password, role_id=user_role.id)
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    return user


@pytest_asyncio.fixture
async def auth_headers(async_client: AsyncClient, test_user: User):
    """Get authentication headers for test user"""
    response = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "testuser", "password": "testpassword123"},
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client():
    """Synchronous HTTP client for testing (for backward compatibility)"""
    return TestClient(app)
