from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from bson import ObjectId

from app.models.user import PyObjectId


class PolicyEffect(str, Enum):
    """What happens when policy matches"""
    ALLOW = "allow"
    DENY = "deny"
    EVALUATE = "evaluate"  # Requires AI decision


class PolicyStatus(str, Enum):
    """Policy lifecycle status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DRAFT = "draft"


class ConditionOperator(str, Enum):
    """Operators for condition evaluation"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    IN = "in"
    NOT_IN = "not_in"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    BETWEEN = "between"
    REGEX = "regex"


class Condition(BaseModel):
    """Single condition within a policy rule"""
    attribute: str  # e.g., "user.role", "resource.type", "env.time"
    operator: ConditionOperator
    value: Any  # Value to compare against


class PolicyRule(BaseModel):
    """A rule containing multiple conditions (AND logic)"""
    conditions: List[Condition]
    description: Optional[str] = None


class PolicyBase(BaseModel):
    """Base policy fields"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    effect: PolicyEffect
    priority: int = Field(default=0, ge=0, le=1000)  # Higher = evaluated first
    
    # Target specification
    resources: List[str] = Field(default=["*"])  # Resource patterns
    actions: List[str] = Field(default=["*"])  # Action patterns
    
    # Rules (multiple rules = OR logic between rules)
    rules: List[PolicyRule] = Field(default=[])
    
    status: PolicyStatus = PolicyStatus.DRAFT


class PolicyCreate(PolicyBase):
    """Schema for creating a policy"""
    pass


class PolicyUpdate(BaseModel):
    """Schema for updating policy (all optional)"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    effect: Optional[PolicyEffect] = None
    priority: Optional[int] = Field(None, ge=0, le=1000)
    resources: Optional[List[str]] = None
    actions: Optional[List[str]] = None
    rules: Optional[List[PolicyRule]] = None
    status: Optional[PolicyStatus] = None


class PolicyInDB(PolicyBase):
    """Policy as stored in database"""
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    created_by: str  # User ID who created the policy
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    version: int = Field(default=1)
    
    class Config:
        populate_by_name = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda v: v.isoformat()
        }


class PolicyResponse(PolicyBase):
    """Policy returned to client"""
    id: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    version: int
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
