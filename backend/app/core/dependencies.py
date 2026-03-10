from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from loguru import logger

from app.core.jwt import decode_token, TokenData
from app.core.database import get_database
from app.models.user import UserInDB, UserRole

# HTTP Bearer token scheme - extracts "Bearer <token>" from header
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db = Depends(get_database)
) -> UserInDB:
    """
    Dependency to get the current authenticated user.
    
    Extracts JWT from Authorization header, validates it,
    and returns the user from database.
    
    Raises:
        HTTPException 401: If token is invalid/expired
        HTTPException 401: If user not found
    """
    token = credentials.credentials
    
    # Decode and validate token
    token_data = decode_token(token)
    
    if token_data is None:
        logger.warning("Invalid token attempt")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Fetch user from database
    users_collection = db["users"]
    user_dict = await users_collection.find_one({"_id": token_data.user_id})
    
    if user_dict is None:
        # Try finding by string ID (in case stored differently)
        from bson import ObjectId
        if ObjectId.is_valid(token_data.user_id):
            user_dict = await users_collection.find_one({"_id": ObjectId(token_data.user_id)})
    
    if user_dict is None:
        logger.warning(f"Token valid but user not found: {token_data.user_id}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user_dict.get("is_active", False):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated",
        )
    
    return UserInDB(**user_dict)


async def get_current_active_user(
    current_user: UserInDB = Depends(get_current_user)
) -> UserInDB:
    """
    Dependency to ensure user is active.
    Convenience wrapper around get_current_user.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


def require_role(allowed_roles: list[UserRole]):
    """
    Factory function to create a dependency that checks user role.
    
    Usage:
        @app.get("/admin")
        async def admin_route(user = Depends(require_role([UserRole.ADMIN]))):
            ...
    """
    async def role_checker(
        current_user: UserInDB = Depends(get_current_user)
    ) -> UserInDB:
        if current_user.role not in allowed_roles:
            logger.warning(
                f"Access denied for user {current_user.email}. "
                f"Role {current_user.role} not in {allowed_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    
    return role_checker


# Convenience dependencies for common role checks
require_admin = require_role([UserRole.ADMIN])
require_admin_or_auditor = require_role([UserRole.ADMIN, UserRole.AUDITOR])


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(
        HTTPBearer(auto_error=False)
    ),
    db = Depends(get_database)
) -> Optional[UserInDB]:
    """
    Dependency to get user if authenticated, None otherwise.
    Useful for routes that work both authenticated and anonymously.
    """
    if credentials is None:
        return None
    
    try:
        token_data = decode_token(credentials.credentials)
        if token_data is None:
            return None
        
        users_collection = db["users"]
        user_dict = await users_collection.find_one({"_id": token_data.user_id})
        
        if user_dict is None:
            from bson import ObjectId
            if ObjectId.is_valid(token_data.user_id):
                user_dict = await users_collection.find_one({"_id": ObjectId(token_data.user_id)})
        
        if user_dict:
            return UserInDB(**user_dict)
        
    except Exception:
        pass
    
    return None
