from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.database import get_session
from app.logger import logger
from app.models.db.user import User
from app.models.user import UserResponse, UserUpdate

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get current authenticated user profile"""
    return UserResponse.model_validate(current_user)


@router.put("/me", response_model=UserResponse)
async def update_user_profile(
    user_data: UserUpdate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Update current user profile"""
    if user_data.username is not None:
        result = await session.execute(select(User).where(User.username == user_data.username))
        existing_user = result.scalar_one_or_none()

        if existing_user and existing_user.id != current_user.id:
            logger.warning(f"Profile update attempt with existing username: {user_data.username}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )

        current_user.username = user_data.username

    try:
        await session.commit()
        await session.refresh(current_user)
    except Exception as e:
        await session.rollback()
        logger.error(f"Database error during profile update: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Profile update failed. Please try again",
        ) from e

    logger.info(f"Profile updated for user: {current_user.username} (id={current_user.id})")

    return UserResponse.model_validate(current_user)


@router.delete("/me", status_code=status.HTTP_200_OK)
async def delete_user_account(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Delete current user account"""
    user_id = current_user.id
    username = current_user.username

    try:
        await session.delete(current_user)
        await session.commit()
    except Exception as e:
        await session.rollback()
        logger.error(f"Database error during account deletion: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Account deletion failed. Please try again",
        ) from e

    logger.info(f"Account deleted for user: {username} (id={user_id})")

    return {"message": "Account deleted successfully"}
