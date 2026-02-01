from datetime import datetime, timedelta

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import load_config
from app.database import get_session
from app.logger import logger
from app.limiter import limiter
from app.models.db.user import Role, User, RefreshToken
from app.models.user import (
    PasswordChange,
    PasswordResetRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserResponse,
    UserSignUp,
)
from app.utils.token import create_and_store_refresh_token

router = APIRouter(prefix="/auth", tags=["Authentication"])

config = load_config()

# Cache for default role IDs to avoid repeated database queries
_USER_ROLE_ID: int | None = None

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_session),
) -> User:
    """Verify JWT token and return current user"""
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, config.jwt.secret_key, algorithms=[config.jwt.algorithm])
        user_id: int | None = payload.get("user_id")
        if user_id is None:
            logger.warning("JWT token missing user_id claim")
            raise credentials_exception
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise credentials_exception from e

    result = await session.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if user is None:
        logger.warning(f"User not found for id: {user_id}")
        raise credentials_exception

    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Generate JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=config.jwt.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    encoded_jwt: str = jwt.encode(to_encode, config.jwt.secret_key, algorithm=config.jwt.algorithm)
    return encoded_jwt


@router.post("/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def sign_up_user(request: Request, user_data: UserSignUp, session: AsyncSession = Depends(get_session)):
    """Register a new user"""
    global _USER_ROLE_ID

    result = await session.execute(select(User).where(User.username == user_data.username))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        logger.warning(f"Signup attempt with existing username: {user_data.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered. Try log in with credentials.",
        )

    if _USER_ROLE_ID is None:
        role_result = await session.execute(select(Role).where(Role.name == "user"))
        db_role = role_result.scalar_one_or_none()

        if not db_role:
            # Auto-create basic roles if they don't exist
            logger.info("Initializing default roles")
            db_role = Role(name="user", description="Regular user")
            session.add(db_role)
            await session.commit()
            await session.refresh(db_role)

        _USER_ROLE_ID = db_role.id

    hashed_password = bcrypt.hashpw(user_data.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    new_user = User(
        username=user_data.username,
        password_hash=hashed_password,
        role_id=_USER_ROLE_ID,
    )
    try:
        session.add(new_user)
        await session.commit()
        await session.refresh(new_user)
    except Exception as e:
        await session.rollback()
        logger.error(f"Database error during signup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed. Please try again",
        ) from e
    logger.info(f"New user registered: {new_user.username} (id={new_user.id})")

    access_token = create_access_token(data={"sub": new_user.username, "user_id": new_user.id})
    refresh_token = await create_and_store_refresh_token(session, new_user.id)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(new_user),
    }


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def user_login(request: Request, user_data: UserSignUp, session: AsyncSession = Depends(get_session)):
    """Authenticate user and return access token"""
    result = await session.execute(select(User).where(User.username == user_data.username))
    user = result.scalar_one_or_none()

    if not user:
        logger.warning(f"Login attempt with non-existent username: {user_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    is_password_correct = bcrypt.checkpw(user_data.password.encode("utf-8"), user.password_hash.encode("utf-8"))

    if not is_password_correct:
        logger.warning(f"Failed login attempt for user: {user_data.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access_token = create_access_token(data={"sub": user.username, "user_id": user.id})
    refresh_token = await create_and_store_refresh_token(session, user.id)

    logger.info(f"User logged in: {user.username} (id={user.id})")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
    }


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("10/minute")
async def refresh_token(
    request: Request,
    token_data: RefreshTokenRequest,
    session: AsyncSession = Depends(get_session),
):
    """Refresh access token using a valid refresh token"""
    # 1. Find the refresh token in DB
    result = await session.execute(select(RefreshToken).where(RefreshToken.token == token_data.refresh_token))
    db_token = result.scalar_one_or_none()

    # 2. Validate token
    if not db_token:
        # Potential security event: invalid token used
        logger.warning("Attempted refresh with invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if db_token.revoked:
        # Security event: Attempt to use revoked token!
        # Potential reuse attack. In a high-security context, we might revoke ALL tokens for this user.
        logger.warning(f"Attempted reuse of revoked token: {db_token.id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if db_token.expires_at < datetime.now():
        logger.info(f"Attempted refresh with expired token: {db_token.id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    # 3. Get user
    # Ensure user logic allows lazy loading or eager loading.
    # Current setup has lazy relationship, but async requires careful handling.
    # It's safer to fetch user explicitly or use select options.
    # Let's fetch the user to be sure.
    user_result = await session.execute(select(User).where(User.id == db_token.user_id))
    user = user_result.scalar_one_or_none()

    if not user:
        # User deleted?
        logger.warning(f"Refresh token found for non-existent user: {db_token.user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    # 4. Rotate tokens
    # Revoke current token
    db_token.revoked = True
    session.add(db_token)

    # Create new tokens
    access_token = create_access_token(data={"sub": user.username, "user_id": user.id})
    new_refresh_token = await create_and_store_refresh_token(session, user.id)

    logger.info(f"Token refreshed for user: {user.username} (id={user.id})")

    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
    }


@router.post("/logout", status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
async def logout(
    request: Request,
    token_data: RefreshTokenRequest,
    session: AsyncSession = Depends(get_session),
):
    """Logout user (revoke refresh token)"""
    result = await session.execute(select(RefreshToken).where(RefreshToken.token == token_data.refresh_token))
    db_token = result.scalar_one_or_none()

    if db_token:
        db_token.revoked = True
        session.add(db_token)
        await session.commit()
        logger.info(f"Refresh token revoked: {db_token.id}")

    # Even if token not found, return success to avoid leaking state
    return {"message": "Logged out successfully"}


@router.post("/password/change", status_code=status.HTTP_200_OK)
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Change password for authenticated user"""
    is_current_password_correct = bcrypt.checkpw(
        password_data.current_password.encode("utf-8"),
        current_user.password_hash.encode("utf-8"),
    )

    if not is_current_password_correct:
        logger.warning(f"Failed password change attempt for user: {current_user.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect",
        )

    if password_data.current_password == password_data.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    new_hashed_password = bcrypt.hashpw(password_data.new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    current_user.password_hash = new_hashed_password

    try:
        await session.commit()
        await session.refresh(current_user)
    except Exception as e:
        await session.rollback()
        logger.error(f"Database error during password change: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password change failed. Please try again",
        ) from e

    logger.info(f"Password changed for user: {current_user.username} (id={current_user.id})")

    return {"message": "Password changed successfully"}


@router.post("/password/reset", status_code=status.HTTP_200_OK)
@limiter.limit("3/minute")
async def reset_password(
    request: Request,
    reset_data: PasswordResetRequest,
    session: AsyncSession = Depends(get_session),
):
    """Reset password for user (generates temporary password)"""
    result = await session.execute(select(User).where(User.username == reset_data.username))
    user = result.scalar_one_or_none()

    if not user:
        logger.warning(f"Password reset attempt for non-existent user: {reset_data.username}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    import secrets

    temp_password = secrets.token_urlsafe(12)

    hashed_password = bcrypt.hashpw(temp_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    user.password_hash = hashed_password

    try:
        await session.commit()
        await session.refresh(user)
    except Exception as e:
        await session.rollback()
        logger.error(f"Database error during password reset: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Password reset failed. Please try again",
        ) from e

    logger.info(f"Password reset for user: {user.username} (id={user.id})")

    return {
        "message": "Password reset successfully",
        "temporary_password": temp_password,
    }
