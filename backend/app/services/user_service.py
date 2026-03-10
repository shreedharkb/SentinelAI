from datetime import datetime
from typing import Optional, List
from bson import ObjectId
from loguru import logger
from pymongo.database import Database

from app.models.user import (
    UserCreate,
    UserUpdate,
    UserInDB,
    UserResponse,
    UserRole,
)
from app.core.security import hash_password, verify_password


class UserService:
    """
    Service layer for user operations.
    Handles business logic between API and database.
    """
    
    def __init__(self, db: Database):
        self.db = db
        self.collection = db["users"]
    
    async def create_user(self, user_data: UserCreate) -> UserResponse:
        """
        Create a new user.
        
        Args:
            user_data: User registration data
            
        Returns:
            Created user (without password)
            
        Raises:
            ValueError: If email already exists
        """
        # Check if email already exists
        existing = await self.collection.find_one({"email": user_data.email})
        if existing:
            raise ValueError("Email already registered")
        
        # Hash password
        hashed_pw = hash_password(user_data.password)
        
        # Prepare document
        user_doc = {
            "email": user_data.email,
            "full_name": user_data.full_name,
            "role": user_data.role.value,
            "is_active": user_data.is_active,
            "hashed_password": hashed_pw,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "last_login": None,
        }
        
        # Insert into database
        result = await self.collection.insert_one(user_doc)
        user_doc["_id"] = result.inserted_id
        
        logger.info(f"Created user: {user_data.email}")
        
        return UserResponse(
            id=str(result.inserted_id),
            email=user_doc["email"],
            full_name=user_doc["full_name"],
            role=user_doc["role"],
            is_active=user_doc["is_active"],
            created_at=user_doc["created_at"],
            last_login=user_doc["last_login"],
        )
    
    async def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        """Get user by ID"""
        if not ObjectId.is_valid(user_id):
            return None
        
        user_doc = await self.collection.find_one({"_id": ObjectId(user_id)})
        
        if user_doc:
            return UserInDB(**user_doc)
        return None
    
    async def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        """Get user by email"""
        user_doc = await self.collection.find_one({"email": email})
        
        if user_doc:
            return UserInDB(**user_doc)
        return None
    
    async def get_users(
        self,
        skip: int = 0,
        limit: int = 100,
        role: Optional[UserRole] = None,
        is_active: Optional[bool] = None
    ) -> List[UserResponse]:
        """
        Get list of users with optional filtering.
        """
        query = {}
        
        if role:
            query["role"] = role.value
        if is_active is not None:
            query["is_active"] = is_active
        
        cursor = self.collection.find(query).skip(skip).limit(limit)
        users = []
        
        async for user_doc in cursor:
            users.append(UserResponse(
                id=str(user_doc["_id"]),
                email=user_doc["email"],
                full_name=user_doc["full_name"],
                role=user_doc["role"],
                is_active=user_doc["is_active"],
                created_at=user_doc["created_at"],
                last_login=user_doc.get("last_login"),
            ))
        
        return users
    
    async def update_user(
        self,
        user_id: str,
        user_data: UserUpdate
    ) -> Optional[UserResponse]:
        """
        Update user fields.
        
        Args:
            user_id: User ID to update
            user_data: Fields to update (only non-None fields)
            
        Returns:
            Updated user or None if not found
        """
        if not ObjectId.is_valid(user_id):
            return None
        
        # Build update document (only non-None fields)
        update_doc = {}
        
        if user_data.email is not None:
            # Check email uniqueness
            existing = await self.collection.find_one({
                "email": user_data.email,
                "_id": {"$ne": ObjectId(user_id)}
            })
            if existing:
                raise ValueError("Email already in use")
            update_doc["email"] = user_data.email
        
        if user_data.full_name is not None:
            update_doc["full_name"] = user_data.full_name
        
        if user_data.role is not None:
            update_doc["role"] = user_data.role.value
        
        if user_data.is_active is not None:
            update_doc["is_active"] = user_data.is_active
        
        if user_data.password is not None:
            update_doc["hashed_password"] = hash_password(user_data.password)
        
        if not update_doc:
            # Nothing to update
            return await self.get_user_by_id(user_id)
        
        update_doc["updated_at"] = datetime.utcnow()
        
        result = await self.collection.find_one_and_update(
            {"_id": ObjectId(user_id)},
            {"$set": update_doc},
            return_document=True
        )
        
        if result:
            logger.info(f"Updated user: {user_id}")
            return UserResponse(
                id=str(result["_id"]),
                email=result["email"],
                full_name=result["full_name"],
                role=result["role"],
                is_active=result["is_active"],
                created_at=result["created_at"],
                last_login=result.get("last_login"),
            )
        
        return None
    
    async def delete_user(self, user_id: str) -> bool:
        """
        Delete a user.
        
        Returns:
            True if deleted, False if not found
        """
        if not ObjectId.is_valid(user_id):
            return False
        
        result = await self.collection.delete_one({"_id": ObjectId(user_id)})
        
        if result.deleted_count > 0:
            logger.info(f"Deleted user: {user_id}")
            return True
        
        return False
    
    async def authenticate_user(
        self,
        email: str,
        password: str
    ) -> Optional[UserInDB]:
        """
        Authenticate user with email and password.
        
        Returns:
            User if credentials valid, None otherwise
        """
        user = await self.get_user_by_email(email)
        
        if not user:
            return None
        
        if not verify_password(password, user.hashed_password):
            return None
        
        if not user.is_active:
            return None
        
        # Update last login
        await self.collection.update_one(
            {"_id": ObjectId(str(user.id))},
            {"$set": {"last_login": datetime.utcnow()}}
        )
        
        return user
    
    async def count_users(self, role: Optional[UserRole] = None) -> int:
        """Count total users, optionally filtered by role"""
        query = {}
        if role:
            query["role"] = role.value
        
        return await self.collection.count_documents(query)
