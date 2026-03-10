from typing import Dict, Any, List, Optional
import json
from loguru import logger

from app.core.config import get_settings
from app.models.access_log import (
    AccessRequest,
    AccessDecision,
    RiskLevel,
    AIAnalysis,
)
from app.ai.risk_analyzer import RiskAnalyzer


class AIDecisionEngine:
    """
    AI Decision Engine using LangChain with Ollama.
    
    Combines:
    1. Rule-based risk analyzer (fast, deterministic)
    2. LLM-based analysis using Ollama (local, private, free)
    
    Falls back to rule-based only if Ollama is unavailable.
    """
    
    def __init__(self):
        self.settings = get_settings()
        self.risk_analyzer = RiskAnalyzer()
        self.llm = None
        self._initialize_llm()
    
    def _initialize_llm(self):
        """Initialize LangChain with Ollama (local LLM)"""
        try:
            from langchain_community.llms import Ollama
            
            # Use Mistral - fast and good at reasoning
            # Alternative: llama3, codellama, mixtral
            self.llm = Ollama(
                model=self.settings.ollama_model,
                base_url=self.settings.ollama_base_url,
                temperature=0.1,  # Low temperature for consistent decisions
            )
            
            logger.info(f"Ollama AI engine initialized with model: {self.settings.ollama_model}")
            
        except ImportError as e:
            logger.warning(f"LangChain Ollama not available: {e}")
        except Exception as e:
            logger.warning(f"Failed to initialize Ollama (is it running?): {e}")
    
    def _get_system_prompt(self) -> str:
        """System prompt for the AI decision engine"""
        return """You are an AI security analyst for an access control system called SentinelAI.
Your job is to analyze access requests and determine if they should be allowed or denied.

Consider the following factors:
1. User role and permissions
2. Resource sensitivity
3. Time of access (business hours vs off-hours)
4. Location/IP address patterns
5. Historical behavior patterns
6. Action being performed (read vs write vs delete)

IMPORTANT: Respond ONLY with a valid JSON object, no other text:
{
  "risk_score": <number 0-100>,
  "risk_level": "<low|medium|high|critical>",
  "recommendation": "<allowed|denied|challenged>",
  "reasoning": "<brief explanation>",
  "anomalies": ["<list of suspicious patterns>"]
}

Be conservative - when in doubt, recommend "challenged" for additional verification."""
    
    async def analyze(
        self,
        request: AccessRequest,
        user_attributes: Dict[str, Any],
        historical_data: Optional[List[Dict]] = None
    ) -> AIAnalysis:
        """
        Perform AI analysis on access request.
        
        Args:
            request: The access request
            user_attributes: User info
            historical_data: Past access logs
            
        Returns:
            AIAnalysis with risk assessment
        """
        # First, get rule-based analysis (always runs)
        rule_analysis = self.risk_analyzer.analyze(
            request, user_attributes, historical_data
        )
        
        # If LLM available, enhance with AI analysis
        if self.llm:
            try:
                llm_analysis = await self._llm_analyze(
                    request, user_attributes, historical_data, rule_analysis
                )
                
                # Combine analyses (weighted average)
                combined = self._combine_analyses(rule_analysis, llm_analysis)
                return combined
                
            except Exception as e:
                logger.error(f"LLM analysis failed, using rule-based: {e}")
        
        return rule_analysis
    
    async def _llm_analyze(
        self,
        request: AccessRequest,
        user_attributes: Dict[str, Any],
        historical_data: Optional[List[Dict]],
        rule_analysis: AIAnalysis
    ) -> AIAnalysis:
        """Get LLM analysis from Ollama"""
        # Build context for LLM
        context = self._build_llm_context(
            request, user_attributes, historical_data, rule_analysis
        )
        
        # Full prompt with system instructions
        full_prompt = f"{self._get_system_prompt()}\n\n{context}"
        
        # Call Ollama (async invoke)
        result_text = await self.llm.ainvoke(full_prompt)
        
        # Parse response - extract JSON from response
        try:
            # Try to find JSON in the response
            result = self._extract_json(result_text)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return rule_analysis
        
        # Convert to AIAnalysis
        return AIAnalysis(
            risk_score=float(result.get("risk_score", rule_analysis.risk_score)),
            risk_level=RiskLevel(result.get("risk_level", rule_analysis.risk_level.value)),
            anomaly_detected=result.get("risk_level") in ["high", "critical"],
            confidence=0.85,  # LLM confidence
            factors=result.get("anomalies", []) + [result.get("reasoning", "")],
            recommendation=AccessDecision(result.get("recommendation", "challenged")),
        )
    
    def _extract_json(self, text: str) -> dict:
        """Extract JSON from LLM response text"""
        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON block in text
        import re
        json_pattern = r'\{[^{}]*\}'
        matches = re.findall(json_pattern, text, re.DOTALL)
        
        for match in matches:
            try:
                return json.loads(match)
            except json.JSONDecodeError:
                continue
        
        raise ValueError("No valid JSON found in response")
    
    def _build_llm_context(
        self,
        request: AccessRequest,
        user_attributes: Dict[str, Any],
        historical_data: Optional[List[Dict]],
        rule_analysis: AIAnalysis
    ) -> str:
        """Build context string for LLM"""
        context = f"""
Access Request Analysis:

USER:
- ID: {request.user_id}
- Role: {user_attributes.get('role', 'unknown')}
- Department: {user_attributes.get('department', 'unknown')}

REQUEST:
- Resource: {request.resource}
- Action: {request.action}
- IP Address: {request.context.ip_address or 'unknown'}
- Device: {request.context.device_type or 'unknown'}
- Time: {request.context.timestamp_hour or 'unknown'}:00
- Day: {request.context.timestamp_day or 'unknown'}

RULE-BASED ANALYSIS:
- Risk Score: {rule_analysis.risk_score}
- Risk Factors: {', '.join(rule_analysis.factors)}

HISTORICAL DATA:
- Total past requests: {len(historical_data) if historical_data else 0}
"""
        
        if historical_data and len(historical_data) > 0:
            recent = historical_data[-5:]
            context += "- Recent activity:\n"
            for record in recent:
                context += f"  - {record.get('resource', 'N/A')} ({record.get('action', 'N/A')}) - {record.get('decision', 'N/A')}\n"
        
        return context
    
    def _combine_analyses(
        self,
        rule_analysis: AIAnalysis,
        llm_analysis: AIAnalysis
    ) -> AIAnalysis:
        """Combine rule-based and LLM analyses"""
        # Weighted average (60% LLM, 40% rules)
        combined_score = (llm_analysis.risk_score * 0.6) + (rule_analysis.risk_score * 0.4)
        
        # Use higher risk level
        if llm_analysis.risk_level.value > rule_analysis.risk_level.value:
            combined_level = llm_analysis.risk_level
        else:
            combined_level = rule_analysis.risk_level
        
        # More conservative recommendation
        if llm_analysis.recommendation == AccessDecision.DENIED or \
           rule_analysis.recommendation == AccessDecision.DENIED:
            combined_recommendation = AccessDecision.DENIED
        elif llm_analysis.recommendation == AccessDecision.CHALLENGED or \
             rule_analysis.recommendation == AccessDecision.CHALLENGED:
            combined_recommendation = AccessDecision.CHALLENGED
        else:
            combined_recommendation = AccessDecision.ALLOWED
        
        # Combine factors
        combined_factors = list(set(rule_analysis.factors + llm_analysis.factors))
        
        return AIAnalysis(
            risk_score=combined_score,
            risk_level=combined_level,
            anomaly_detected=llm_analysis.anomaly_detected or rule_analysis.anomaly_detected,
            confidence=(llm_analysis.confidence + rule_analysis.confidence) / 2,
            factors=combined_factors,
            recommendation=combined_recommendation,
        )
