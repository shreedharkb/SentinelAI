from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from loguru import logger

from app.core.database import get_database
from app.core.dependencies import get_current_user, require_admin
from app.models.user import (
    UserInDB,
    UserCreate,
    UserUpdate,
    UserResponse,
    UserRole,
)
from app.services.user_service import UserService


router = APIRouter(prefix="/users", tags=["Users"])


@router.get("", response_model=List[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """
    List all users. **Admin only.**
    
    Supports filtering by role and active status.
    """
    user_service = UserService(db)
    
    users = await user_service.get_users(
        skip=skip,
        limit=limit,
        role=role,
        is_active=is_active
    )
    
    return users


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: UserInDB = Depends(get_current_user)
):
    """Get current user's profile."""
    return UserResponse(
        id=str(current_user.id),
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
    )


@router.get("/stats")
async def get_user_stats(
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """
    Get user statistics. **Admin only.**
    """
    user_service = UserService(db)
    
    total = await user_service.count_users()
    admins = await user_service.count_users(role=UserRole.ADMIN)
    auditors = await user_service.count_users(role=UserRole.AUDITOR)
    regular = await user_service.count_users(role=UserRole.USER)
    
    return {
        "total_users": total,
        "by_role": {
            "admin": admins,
            "auditor": auditors,
            "user": regular,
        }
    }


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """Get a specific user by ID. **Admin only.**"""
    user_service = UserService(db)
    
    user = await user_service.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=str(user.id),
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """
    Create a new user. **Admin only.**
    
    Use this to create users with specific roles.
    For self-registration, use /api/auth/register
    """
    user_service = UserService(db)
    
    try:
        user = await user_service.create_user(user_data)
        logger.info(f"User {user.email} created by admin {current_user.email}")
        return user
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """
    Update a user. **Admin only.**
    
    Only provided fields will be updated.
    """
    user_service = UserService(db)
    
    # Prevent admin from deactivating themselves
    if user_id == str(current_user.id) and user_data.is_active == False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )
    
    try:
        user = await user_service.update_user(user_id, user_data)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        logger.info(f"User {user_id} updated by admin {current_user.email}")
        return user
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """Delete a user. **Admin only.**"""
    user_service = UserService(db)
    
    # Prevent admin from deleting themselves
    if user_id == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    deleted = await user_service.delete_user(user_id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    logger.info(f"User {user_id} deleted by admin {current_user.email}")


@router.post("/{user_id}/activate", response_model=UserResponse)
async def activate_user(
    user_id: str,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """Activate a user account. **Admin only.**"""
    user_service = UserService(db)
    
    user = await user_service.update_user(
        user_id,
        UserUpdate(is_active=True)
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    logger.info(f"User {user_id} activated by admin {current_user.email}")
    return user


@router.post("/{user_id}/deactivate", response_model=UserResponse)
async def deactivate_user(
    user_id: str,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """Deactivate a user account. **Admin only.**"""
    user_service = UserService(db)
    
    # Prevent admin from deactivating themselves
    if user_id == str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )
    
    user = await user_service.update_user(
        user_id,
        UserUpdate(is_active=False)
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    logger.info(f"User {user_id} deactivated by admin {current_user.email}")
    return user
