from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from pydantic import BaseModel

from app.core.config import get_settings


class TokenData(BaseModel):
    """Data extracted from JWT token"""
    user_id: str
    email: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None


class TokenPair(BaseModel):
    """Access and refresh token pair"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Payload to encode (user_id, email, role, etc.)
        expires_delta: Custom expiration time
        
    Returns:
        Encoded JWT token string
    """
    settings = get_settings()
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({"exp": expire, "type": "access"})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Create a JWT refresh token (longer lived).
    
    Args:
        data: Payload to encode
        
    Returns:
        Encoded JWT refresh token
    """
    settings = get_settings()
    to_encode = data.copy()
    
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm
    )
    
    return encoded_jwt


def create_token_pair(user_id: str, email: str, role: str) -> TokenPair:
    """
    Create both access and refresh tokens for a user.
    
    Args:
        user_id: User's database ID
        email: User's email
        role: User's role
        
    Returns:
        TokenPair with both tokens
    """
    token_data = {
        "sub": user_id,  # "sub" is standard JWT claim for subject
        "email": email,
        "role": role
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token
    )


def decode_token(token: str) -> Optional[TokenData]:
    """
    Decode and validate a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        TokenData if valid, None if invalid/expired
    """
    settings = get_settings()
    
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm]
        )
        
        user_id = payload.get("sub")
        if user_id is None:
            return None
            
        return TokenData(
            user_id=user_id,
            email=payload.get("email"),
            role=payload.get("role"),
            exp=datetime.fromtimestamp(payload.get("exp", 0))
        )
        
    except JWTError:
        return None


def is_token_expired(token_data: TokenData) -> bool:
    """Check if token has expired"""
    if token_data.exp is None:
        return True
    return datetime.utcnow() > token_data.exp
