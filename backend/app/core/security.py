from passlib.context import CryptContext

# Bcrypt configuration
# "deprecated=auto" means old schemes will be auto-upgraded
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt.
    
    Args:
        password: Plain text password from user
        
    Returns:
        Hashed password string (safe to store in database)
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.
    
    Args:
        plain_password: Password attempt from user
        hashed_password: Stored hash from database
        
    Returns:
        True if password matches, False otherwise
    """
    return pwd_context.verify(plain_password, hashed_password)
