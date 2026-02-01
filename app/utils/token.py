import secrets
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import load_config
from app.models.db.user import RefreshToken

config = load_config()


async def create_and_store_refresh_token(session: AsyncSession, user_id: int) -> str:
    """Generate and store a new refresh token"""
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(days=config.jwt.refresh_token_expire_days)

    refresh_token = RefreshToken(user_id=user_id, token=token, expires_at=expires_at)
    session.add(refresh_token)
    await session.commit()
    return token
