import time
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from loguru import logger

from app.core.database import get_database
from app.core.dependencies import get_current_user, get_optional_user
from app.models.user import UserInDB
from app.models.access_log import (
    AccessRequest,
    AccessContext,
    AccessDecision,
    DecisionSource,
    AIAnalysis,
    AccessLogResponse,
    AccessLogQuery,
    RiskLevel,
)
from app.services.policy_service import PolicyService
from app.services.policy_evaluator import PolicyEvaluator
from app.services.access_log_service import AccessLogService
from app.ai.decision_engine import AIDecisionEngine


router = APIRouter(prefix="/access", tags=["Access Control"])

# Initialize AI engine (singleton)
ai_engine = AIDecisionEngine()


class AccessCheckRequest(BaseModel):
    """Request body for access check"""
    resource: str
    action: str
    context: Optional[AccessContext] = None


class AccessCheckResponse(BaseModel):
    """Response for access check"""
    allowed: bool
    decision: AccessDecision
    decision_source: DecisionSource
    risk_score: Optional[float] = None
    risk_level: Optional[RiskLevel] = None
    policy_id: Optional[str] = None
    message: str


@router.post("/check", response_model=AccessCheckResponse)
async def check_access(
    request_body: AccessCheckRequest,
    request: Request,
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Check if current user can access a resource.
    
    This is the main access control endpoint. Call this before
    allowing access to any protected resource.
    
    Flow:
    1. Build access request with context
    2. Evaluate against policies
    3. If policy says "evaluate", use AI engine
    4. Log the decision
    5. Return result
    """
    start_time = time.time()
    
    # Build access context from request
    context = request_body.context or AccessContext()
    if not context.ip_address:
        context.ip_address = request.client.host if request.client else None
    if not context.user_agent:
        context.user_agent = request.headers.get("user-agent")
    
    # Create access request
    access_request = AccessRequest(
        user_id=str(current_user.id),
        resource=request_body.resource,
        action=request_body.action,
        context=context,
    )
    
    # User attributes for evaluation
    user_attributes = {
        "role": current_user.role.value if hasattr(current_user.role, 'value') else current_user.role,
        "email": current_user.email,
        "is_active": current_user.is_active,
    }
    
    # Initialize services
    policy_service = PolicyService(db)
    access_log_service = AccessLogService(db)
    
    # Get active policies
    policies = await policy_service.get_active_policies()
    
    # Evaluate against policies
    evaluator = PolicyEvaluator(policies)
    decision, source, policy_id = evaluator.evaluate(access_request, user_attributes)
    
    ai_analysis = None
    
    # If decision source is AI_ENGINE, run AI analysis
    if source == DecisionSource.AI_ENGINE:
        # Get user's access history
        history = await access_log_service.get_user_history(
            str(current_user.id), limit=100
        )
        
        # Run AI analysis
        ai_analysis = await ai_engine.analyze(
            access_request, user_attributes, history
        )
        
        # Use AI's recommendation
        decision = ai_analysis.recommendation
        
        logger.info(
            f"AI decision for {current_user.email}: "
            f"risk={ai_analysis.risk_score}, decision={decision}"
        )
    
    # Calculate response time
    response_time_ms = int((time.time() - start_time) * 1000)
    
    # Log the access attempt
    await access_log_service.log_access(
        request=access_request,
        decision=decision,
        decision_source=source,
        user_email=current_user.email,
        policy_id=policy_id,
        ai_analysis=ai_analysis,
        response_time_ms=response_time_ms,
    )
    
    # Build response
    allowed = decision == AccessDecision.ALLOWED
    
    if decision == AccessDecision.ALLOWED:
        message = "Access granted"
    elif decision == AccessDecision.CHALLENGED:
        message = "Additional verification required"
    else:
        message = "Access denied"
    
    return AccessCheckResponse(
        allowed=allowed,
        decision=decision,
        decision_source=source,
        risk_score=ai_analysis.risk_score if ai_analysis else None,
        risk_level=ai_analysis.risk_level if ai_analysis else None,
        policy_id=policy_id,
        message=message,
    )


@router.get("/logs", response_model=list[AccessLogResponse])
async def get_access_logs(
    user_id: Optional[str] = None,
    resource: Optional[str] = None,
    action: Optional[str] = None,
    decision: Optional[AccessDecision] = None,
    limit: int = 100,
    skip: int = 0,
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get access logs. 
    
    Regular users can only see their own logs.
    Admins and auditors can see all logs.
    """
    access_log_service = AccessLogService(db)
    
    # Regular users can only see their own logs
    role = current_user.role.value if hasattr(current_user.role, 'value') else current_user.role
    if role not in ["admin", "auditor"]:
        user_id = str(current_user.id)
    
    query = AccessLogQuery(
        user_id=user_id,
        resource=resource,
        action=action,
        decision=decision,
        limit=limit,
        skip=skip,
    )
    
    logs = await access_log_service.get_logs(query)
    return logs


@router.get("/stats")
async def get_access_stats(
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get access statistics for dashboard.
    
    Returns counts, percentages, and averages.
    """
    access_log_service = AccessLogService(db)
    
    stats = await access_log_service.get_stats()
    
    # Calculate percentages
    total = stats.get("total_requests", 0)
    if total > 0:
        stats["allowed_percentage"] = round(stats["allowed"] / total * 100, 1)
        stats["denied_percentage"] = round(stats["denied"] / total * 100, 1)
    else:
        stats["allowed_percentage"] = 0
        stats["denied_percentage"] = 0
    
    return stats


@router.get("/anomalies", response_model=list[AccessLogResponse])
async def get_recent_anomalies(
    limit: int = 10,
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    Get recent high-risk or anomalous access attempts.
    
    Useful for security monitoring dashboard.
    """
    # Only admins/auditors can see anomalies
    role = current_user.role.value if hasattr(current_user.role, 'value') else current_user.role
    if role not in ["admin", "auditor"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    access_log_service = AccessLogService(db)
    anomalies = await access_log_service.get_recent_anomalies(limit)
    
    return anomalies
