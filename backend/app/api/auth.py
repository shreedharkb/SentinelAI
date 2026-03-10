from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from loguru import logger

from app.core.database import get_database
from app.core.jwt import create_token_pair, decode_token, TokenPair
from app.core.dependencies import get_current_user
from app.models.user import UserCreate, UserResponse, UserInDB
from app.services.user_service import UserService


router = APIRouter(prefix="/auth", tags=["Authentication"])

security = HTTPBearer()


class LoginRequest(BaseModel):
    """Login request body"""
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    """Login response with tokens and user info"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse


class RefreshRequest(BaseModel):
    """Refresh token request"""
    refresh_token: str


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    db = Depends(get_database)
):
    """
    Register a new user account.
    
    - **email**: Valid email address (must be unique)
    - **password**: At least 8 characters
    - **full_name**: User's display name
    """
    user_service = UserService(db)
    
    try:
        user = await user_service.create_user(user_data)
        logger.info(f"New user registered: {user.email}")
        return user
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=LoginResponse)
async def login(
    login_data: LoginRequest,
    db = Depends(get_database)
):
    """
    Authenticate and get access tokens.
    
    Returns access token (short-lived) and refresh token (long-lived).
    """
    user_service = UserService(db)
    
    user = await user_service.authenticate_user(
        email=login_data.email,
        password=login_data.password
    )
    
    if not user:
        logger.warning(f"Failed login attempt for: {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens
    token_pair = create_token_pair(
        user_id=str(user.id),
        email=user.email,
        role=user.role.value if hasattr(user.role, 'value') else user.role
    )
    
    logger.info(f"User logged in: {user.email}")
    
    return LoginResponse(
        access_token=token_pair.access_token,
        refresh_token=token_pair.refresh_token,
        user=UserResponse(
            id=str(user.id),
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login=user.last_login,
        )
    )


@router.post("/refresh", response_model=TokenPair)
async def refresh_token(
    refresh_data: RefreshRequest,
    db = Depends(get_database)
):
    """
    Get new access token using refresh token.
    
    Use this when access token expires (401 error).
    """
    # Decode refresh token
    token_data = decode_token(refresh_data.refresh_token)
    
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Verify user still exists and is active
    user_service = UserService(db)
    user = await user_service.get_user_by_id(token_data.user_id)
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new token pair
    token_pair = create_token_pair(
        user_id=str(user.id),
        email=user.email,
        role=user.role.value if hasattr(user.role, 'value') else user.role
    )
    
    return token_pair


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: UserInDB = Depends(get_current_user)
):
    """
    Get current authenticated user's profile.
    
    Requires valid access token in Authorization header.
    """
    return UserResponse(
        id=str(current_user.id),
        email=current_user.email,
        full_name=current_user.full_name,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
    )
