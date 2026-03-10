from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from bson import ObjectId

from app.models.user import PyObjectId


class AccessDecision(str, Enum):
    """Final access decision"""
    ALLOWED = "allowed"
    DENIED = "denied"
    CHALLENGED = "challenged"  # Required additional verification


class DecisionSource(str, Enum):
    """What made the decision"""
    POLICY = "policy"      # Static policy rule
    AI_ENGINE = "ai_engine"  # AI risk assessment
    DEFAULT = "default"    # No matching policy, used default
    OVERRIDE = "override"  # Admin manual override


class RiskLevel(str, Enum):
    """Risk assessment level"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccessContext(BaseModel):
    """Context captured at time of request"""
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    device_type: Optional[str] = None
    location: Optional[str] = None
    timestamp_hour: Optional[int] = None
    timestamp_day: Optional[str] = None  # Monday, Tuesday, etc.


class AccessRequest(BaseModel):
    """Incoming access request to be evaluated"""
    user_id: str
    resource: str
    action: str
    context: AccessContext = Field(default_factory=AccessContext)
    metadata: Dict[str, Any] = Field(default={})


class AIAnalysis(BaseModel):
    """AI engine analysis results"""
    risk_score: float = Field(ge=0, le=100)  # 0-100
    risk_level: RiskLevel
    anomaly_detected: bool = False
    confidence: float = Field(ge=0, le=1)  # 0-1
    factors: list[str] = Field(default=[])  # Reasons for the score
    recommendation: AccessDecision


class AccessLogBase(BaseModel):
    """Base access log fields"""
    user_id: str
    user_email: Optional[str] = None
    resource: str
    action: str
    
    # Decision details
    decision: AccessDecision
    decision_source: DecisionSource
    policy_id: Optional[str] = None  # Which policy matched
    
    # Context at time of request
    context: AccessContext
    
    # AI analysis (if performed)
    ai_analysis: Optional[AIAnalysis] = None
    
    # Additional info
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None


class AccessLogCreate(AccessLogBase):
    """Schema for creating access log entry"""
    pass


class AccessLogInDB(AccessLogBase):
    """Access log as stored in database"""
    id: Optional[PyObjectId] = Field(default=None, alias="_id")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        populate_by_name = True
        json_encoders = {
            ObjectId: str,
            datetime: lambda v: v.isoformat()
        }


class AccessLogResponse(AccessLogBase):
    """Access log returned to client"""
    id: str
    timestamp: datetime
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class AccessLogQuery(BaseModel):
    """Query parameters for filtering access logs"""
    user_id: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    decision: Optional[AccessDecision] = None
    risk_level: Optional[RiskLevel] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    limit: int = Field(default=100, ge=1, le=1000)
    skip: int = Field(default=0, ge=0)
