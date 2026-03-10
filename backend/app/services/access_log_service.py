from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from bson import ObjectId
from loguru import logger
from pymongo.database import Database

from app.models.access_log import (
    AccessRequest,
    AccessDecision,
    DecisionSource,
    AccessContext,
    AIAnalysis,
    AccessLogCreate,
    AccessLogInDB,
    AccessLogResponse,
    AccessLogQuery,
    RiskLevel,
)


class AccessLogService:
    """
    Service for managing access logs (audit trail).
    Records all access decisions for compliance and analysis.
    """
    
    def __init__(self, db: Database):
        self.db = db
        self.collection = db["access_logs"]
    
    async def log_access(
        self,
        request: AccessRequest,
        decision: AccessDecision,
        decision_source: DecisionSource,
        user_email: Optional[str] = None,
        policy_id: Optional[str] = None,
        ai_analysis: Optional[AIAnalysis] = None,
        response_time_ms: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> AccessLogResponse:
        """
        Log an access decision.
        
        Args:
            request: Original access request
            decision: Final decision (allowed/denied/challenged)
            decision_source: What made the decision
            user_email: User's email for easier querying
            policy_id: ID of matched policy (if any)
            ai_analysis: AI risk assessment (if performed)
            response_time_ms: How long decision took
            error_message: Error details if any
            
        Returns:
            Created access log entry
        """
        log_doc = {
            "user_id": request.user_id,
            "user_email": user_email,
            "resource": request.resource,
            "action": request.action,
            "decision": decision.value,
            "decision_source": decision_source.value,
            "policy_id": policy_id,
            "context": {
                "ip_address": request.context.ip_address,
                "user_agent": request.context.user_agent,
                "device_type": request.context.device_type,
                "location": request.context.location,
                "timestamp_hour": request.context.timestamp_hour or datetime.utcnow().hour,
                "timestamp_day": request.context.timestamp_day or datetime.utcnow().strftime("%A"),
            },
            "ai_analysis": ai_analysis.model_dump() if ai_analysis else None,
            "response_time_ms": response_time_ms,
            "error_message": error_message,
            "timestamp": datetime.utcnow(),
        }
        
        result = await self.collection.insert_one(log_doc)
        log_doc["_id"] = result.inserted_id
        
        logger.debug(
            f"Access logged: user={request.user_id}, "
            f"resource={request.resource}, decision={decision.value}"
        )
        
        return self._to_response(log_doc)
    
    async def get_logs(
        self,
        query: AccessLogQuery
    ) -> List[AccessLogResponse]:
        """
        Query access logs with filters.
        """
        filter_doc = {}
        
        if query.user_id:
            filter_doc["user_id"] = query.user_id
        if query.resource:
            filter_doc["resource"] = {"$regex": query.resource, "$options": "i"}
        if query.action:
            filter_doc["action"] = query.action
        if query.decision:
            filter_doc["decision"] = query.decision.value
        if query.risk_level:
            filter_doc["ai_analysis.risk_level"] = query.risk_level.value
        if query.start_date:
            filter_doc["timestamp"] = {"$gte": query.start_date}
        if query.end_date:
            if "timestamp" in filter_doc:
                filter_doc["timestamp"]["$lte"] = query.end_date
            else:
                filter_doc["timestamp"] = {"$lte": query.end_date}
        
        cursor = self.collection.find(filter_doc).sort(
            "timestamp", -1  # Most recent first
        ).skip(query.skip).limit(query.limit)
        
        logs = []
        async for log_doc in cursor:
            logs.append(self._to_response(log_doc))
        
        return logs
    
    async def get_user_history(
        self,
        user_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get user's access history for AI analysis.
        Returns raw dicts for internal processing.
        """
        cursor = self.collection.find(
            {"user_id": user_id}
        ).sort("timestamp", -1).limit(limit)
        
        history = []
        async for doc in cursor:
            history.append({
                "resource": doc.get("resource"),
                "action": doc.get("action"),
                "decision": doc.get("decision"),
                "context": doc.get("context"),
                "timestamp": doc.get("timestamp"),
                "ai_analysis": doc.get("ai_analysis"),
            })
        
        return history
    
    async def get_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """
        Get access statistics for dashboard.
        """
        match_stage = {}
        if start_date or end_date:
            match_stage["timestamp"] = {}
            if start_date:
                match_stage["timestamp"]["$gte"] = start_date
            if end_date:
                match_stage["timestamp"]["$lte"] = end_date
        
        pipeline = []
        if match_stage:
            pipeline.append({"$match": match_stage})
        
        pipeline.extend([
            {
                "$group": {
                    "_id": None,
                    "total_requests": {"$sum": 1},
                    "allowed": {
                        "$sum": {"$cond": [{"$eq": ["$decision", "allowed"]}, 1, 0]}
                    },
                    "denied": {
                        "$sum": {"$cond": [{"$eq": ["$decision", "denied"]}, 1, 0]}
                    },
                    "challenged": {
                        "$sum": {"$cond": [{"$eq": ["$decision", "challenged"]}, 1, 0]}
                    },
                    "ai_decisions": {
                        "$sum": {"$cond": [{"$eq": ["$decision_source", "ai_engine"]}, 1, 0]}
                    },
                    "policy_decisions": {
                        "$sum": {"$cond": [{"$eq": ["$decision_source", "policy"]}, 1, 0]}
                    },
                    "avg_response_time": {"$avg": "$response_time_ms"},
                    "high_risk_count": {
                        "$sum": {
                            "$cond": [
                                {"$in": ["$ai_analysis.risk_level", ["high", "critical"]]},
                                1, 0
                            ]
                        }
                    },
                }
            }
        ])
        
        result = await self.collection.aggregate(pipeline).to_list(1)
        
        if result:
            stats = result[0]
            stats.pop("_id", None)
            return stats
        
        return {
            "total_requests": 0,
            "allowed": 0,
            "denied": 0,
            "challenged": 0,
            "ai_decisions": 0,
            "policy_decisions": 0,
            "avg_response_time": 0,
            "high_risk_count": 0,
        }
    
    async def get_recent_anomalies(self, limit: int = 10) -> List[AccessLogResponse]:
        """Get recent high-risk or anomalous access attempts"""
        cursor = self.collection.find({
            "$or": [
                {"ai_analysis.risk_level": {"$in": ["high", "critical"]}},
                {"ai_analysis.anomaly_detected": True},
                {"decision": "denied"}
            ]
        }).sort("timestamp", -1).limit(limit)
        
        logs = []
        async for doc in cursor:
            logs.append(self._to_response(doc))
        
        return logs
    
    async def count_logs(
        self,
        user_id: Optional[str] = None,
        decision: Optional[AccessDecision] = None
    ) -> int:
        """Count logs with optional filters"""
        filter_doc = {}
        if user_id:
            filter_doc["user_id"] = user_id
        if decision:
            filter_doc["decision"] = decision.value
        
        return await self.collection.count_documents(filter_doc)
    
    def _to_response(self, log_doc: dict) -> AccessLogResponse:
        """Convert database document to response model"""
        context_data = log_doc.get("context", {})
        ai_data = log_doc.get("ai_analysis")
        
        return AccessLogResponse(
            id=str(log_doc["_id"]),
            user_id=log_doc["user_id"],
            user_email=log_doc.get("user_email"),
            resource=log_doc["resource"],
            action=log_doc["action"],
            decision=log_doc["decision"],
            decision_source=log_doc["decision_source"],
            policy_id=log_doc.get("policy_id"),
            context=AccessContext(**context_data) if context_data else AccessContext(),
            ai_analysis=AIAnalysis(**ai_data) if ai_data else None,
            response_time_ms=log_doc.get("response_time_ms"),
            error_message=log_doc.get("error_message"),
            timestamp=log_doc["timestamp"],
        )
