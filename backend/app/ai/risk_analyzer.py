from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from loguru import logger

from app.models.access_log import (
    AccessRequest,
    AccessDecision,
    RiskLevel,
    AIAnalysis,
)


class RiskAnalyzer:
    """
    Rule-based risk analyzer.
    Calculates risk scores based on context and patterns.
    
    This serves as a fallback when LLM is not available,
    and provides baseline risk factors.
    """
    
    # Risk weights for different factors
    RISK_WEIGHTS = {
        "unusual_time": 15,
        "unusual_location": 20,
        "sensitive_resource": 25,
        "high_frequency": 15,
        "new_device": 10,
        "failed_attempts": 20,
        "admin_action": 15,
    }
    
    def __init__(self):
        self.access_history: Dict[str, List[Dict]] = {}
    
    def analyze(
        self,
        request: AccessRequest,
        user_attributes: Dict[str, Any],
        historical_data: Optional[List[Dict]] = None
    ) -> AIAnalysis:
        """
        Analyze access request and return risk assessment.
        
        Args:
            request: The access request
            user_attributes: User info (role, department, etc.)
            historical_data: Past access logs for this user
            
        Returns:
            AIAnalysis with risk score and factors
        """
        risk_score = 0.0
        factors: List[str] = []
        
        # Time-based risk
        time_risk, time_factors = self._analyze_time(request)
        risk_score += time_risk
        factors.extend(time_factors)
        
        # Location/IP risk
        location_risk, location_factors = self._analyze_location(request, historical_data)
        risk_score += location_risk
        factors.extend(location_factors)
        
        # Resource sensitivity risk
        resource_risk, resource_factors = self._analyze_resource(request)
        risk_score += resource_risk
        factors.extend(resource_factors)
        
        # Action risk
        action_risk, action_factors = self._analyze_action(request, user_attributes)
        risk_score += action_risk
        factors.extend(action_factors)
        
        # Frequency analysis
        freq_risk, freq_factors = self._analyze_frequency(request, historical_data)
        risk_score += freq_risk
        factors.extend(freq_factors)
        
        # Cap risk score at 100
        risk_score = min(risk_score, 100.0)
        
        # Determine risk level
        risk_level = self._score_to_level(risk_score)
        
        # Make recommendation
        recommendation = self._make_recommendation(risk_score, risk_level)
        
        # Calculate confidence (higher with more data)
        confidence = self._calculate_confidence(historical_data)
        
        logger.info(
            f"Risk analysis for user {request.user_id}: "
            f"score={risk_score:.1f}, level={risk_level}, factors={factors}"
        )
        
        return AIAnalysis(
            risk_score=risk_score,
            risk_level=risk_level,
            anomaly_detected=risk_score > 60,
            confidence=confidence,
            factors=factors,
            recommendation=recommendation,
        )
    
    def _analyze_time(self, request: AccessRequest) -> tuple[float, List[str]]:
        """Check if access time is unusual"""
        risk = 0.0
        factors = []
        
        hour = request.context.timestamp_hour
        if hour is None:
            hour = datetime.utcnow().hour
        
        # Outside business hours (9 AM - 6 PM)
        if hour < 9 or hour > 18:
            risk += self.RISK_WEIGHTS["unusual_time"]
            factors.append("access_outside_business_hours")
        
        # Weekend access
        day = request.context.timestamp_day
        if day is None:
            day = datetime.utcnow().strftime("%A")
        
        if day in ["Saturday", "Sunday"]:
            risk += self.RISK_WEIGHTS["unusual_time"] * 0.5
            factors.append("weekend_access")
        
        return risk, factors
    
    def _analyze_location(
        self,
        request: AccessRequest,
        historical_data: Optional[List[Dict]]
    ) -> tuple[float, List[str]]:
        """Check for location anomalies"""
        risk = 0.0
        factors = []
        
        current_ip = request.context.ip_address
        
        if not current_ip:
            return risk, factors
        
        if historical_data:
            # Get unique IPs from history
            known_ips = set()
            for record in historical_data[-100:]:  # Last 100 requests
                if record.get("context", {}).get("ip_address"):
                    known_ips.add(record["context"]["ip_address"])
            
            if known_ips and current_ip not in known_ips:
                risk += self.RISK_WEIGHTS["unusual_location"]
                factors.append("new_ip_address")
        
        # Check for suspicious IP patterns (simplified)
        if current_ip.startswith("10.") or current_ip.startswith("192.168."):
            # Internal network - lower risk
            pass
        else:
            risk += 5  # External IP
            factors.append("external_network")
        
        return risk, factors
    
    def _analyze_resource(self, request: AccessRequest) -> tuple[float, List[str]]:
        """Check resource sensitivity"""
        risk = 0.0
        factors = []
        
        resource = request.resource.lower()
        
        # Sensitive resource patterns
        sensitive_patterns = [
            ("admin", 20),
            ("finance", 15),
            ("secret", 25),
            ("password", 25),
            ("credential", 25),
            ("key", 15),
            ("user", 10),
            ("config", 15),
        ]
        
        for pattern, weight in sensitive_patterns:
            if pattern in resource:
                risk += weight
                factors.append(f"sensitive_resource_{pattern}")
                break  # Only count once
        
        return risk, factors
    
    def _analyze_action(
        self,
        request: AccessRequest,
        user_attributes: Dict[str, Any]
    ) -> tuple[float, List[str]]:
        """Check action risk"""
        risk = 0.0
        factors = []
        
        action = request.action.lower()
        
        # Destructive actions
        if action in ["delete", "drop", "truncate", "destroy"]:
            risk += 20
            factors.append("destructive_action")
        
        # Write actions
        elif action in ["write", "update", "modify", "patch"]:
            risk += 10
            factors.append("write_action")
        
        # Admin actions by non-admin
        user_role = user_attributes.get("role", "user")
        if action in ["admin", "manage", "configure"] and user_role != "admin":
            risk += self.RISK_WEIGHTS["admin_action"]
            factors.append("admin_action_by_non_admin")
        
        return risk, factors
    
    def _analyze_frequency(
        self,
        request: AccessRequest,
        historical_data: Optional[List[Dict]]
    ) -> tuple[float, List[str]]:
        """Check access frequency patterns"""
        risk = 0.0
        factors = []
        
        if not historical_data:
            return risk, factors
        
        # Get requests in last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        recent_requests = [
            r for r in historical_data
            if r.get("timestamp") and r["timestamp"] > one_hour_ago
        ]
        
        # High frequency (more than 100 requests/hour)
        if len(recent_requests) > 100:
            risk += self.RISK_WEIGHTS["high_frequency"]
            factors.append("high_request_frequency")
        
        # Check for failed attempts
        failed_count = sum(
            1 for r in recent_requests
            if r.get("decision") == "denied"
        )
        
        if failed_count > 5:
            risk += self.RISK_WEIGHTS["failed_attempts"]
            factors.append("multiple_failed_attempts")
        
        return risk, factors
    
    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert numeric score to risk level"""
        if score < 25:
            return RiskLevel.LOW
        elif score < 50:
            return RiskLevel.MEDIUM
        elif score < 75:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _make_recommendation(
        self,
        score: float,
        level: RiskLevel
    ) -> AccessDecision:
        """Make access recommendation based on risk"""
        if level == RiskLevel.LOW:
            return AccessDecision.ALLOWED
        elif level == RiskLevel.MEDIUM:
            return AccessDecision.ALLOWED  # Allow but log
        elif level == RiskLevel.HIGH:
            return AccessDecision.CHALLENGED  # Require verification
        else:
            return AccessDecision.DENIED
    
    def _calculate_confidence(
        self,
        historical_data: Optional[List[Dict]]
    ) -> float:
        """
        Calculate confidence in the analysis.
        More historical data = higher confidence.
        """
        if not historical_data:
            return 0.5  # Low confidence without history
        
        data_points = len(historical_data)
        
        if data_points < 10:
            return 0.6
        elif data_points < 50:
            return 0.75
        elif data_points < 100:
            return 0.85
        else:
            return 0.95
