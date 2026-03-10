from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from bson import ObjectId

from app.models.user import PyObjectId


class ResourceType(str, Enum):
    """Types of resources that can be protected"""
    API = "api"
    FILE = "file"
    DATABASE = "database"
    SERVICE = "service"
    FUNCTION = "function"
    UI_COMPONENT = "ui_component"
    OTHER = "other"


class SensitivityLevel(str, Enum):
    """Data sensitivity classification"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ResourceBase(BaseModel):
    """Base resource fields"""
    name: str = Field(..., min_length=1, max_length=200)
    resource_type: ResourceType
    path: str = Field(..., min_length=1)  # Unique identifier/path
    description: Optional[str] = Field(None, max_length=500)
    
    # Classification
    sensitivity: SensitivityLevel = SensitivityLevel.INTERNAL
    tags: List[str] = Field(default=[])
    
    # Ownership
    owner_id: Optional[str] = None
    department: Optional[str] = None
    
    # Allowed actions on this resource
    allowed_actions: List[str] = Field(default=["read", "write", "delete"])
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default={})
    
    is_active: bool = True


class ResourceCreate(ResourceBase):
    """Schema for creating a resource"""
    pass


class ResourceUpdate(BaseModel):
    """Schema for updating resource (all optional)"""
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    resource_type: Optional[ResourceType] = None
    path: Optional[str] = None
    description: Optional[str] = Field(None, max_length=500)
    sensitivity: Optional[SensitivityLevel] = None
    tags: Optional[List[str]] = None
    owner_id: Optional[str] = None
    department: Optional[str] = None
    allowed_actions: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class ResourceInDB(ResourceBase):
    """Resource as stored in database"""
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    
    class Config:
        populate_by_name = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda v: v.isoformat()
        }


class ResourceResponse(ResourceBase):
    """Resource returned to client"""
    id: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
