import re
import fnmatch
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime
from loguru import logger

from app.models.policy import (
    PolicyInDB,
    PolicyEffect,
    PolicyRule,
    Condition,
    ConditionOperator,
)
from app.models.access_log import (
    AccessRequest,
    AccessDecision,
    DecisionSource,
)


class PolicyEvaluator:
    """
    Policy Evaluation Engine (Policy Decision Point - PDP).
    
    Evaluates access requests against policies and returns decisions.
    This is the core of the access control system.
    """
    
    def __init__(self, policies: List[PolicyInDB]):
        """
        Initialize with a list of active policies.
        Policies should be pre-sorted by priority (highest first).
        """
        self.policies = policies
    
    def evaluate(
        self,
        request: AccessRequest,
        user_attributes: Dict[str, Any]
    ) -> Tuple[AccessDecision, DecisionSource, Optional[str]]:
        """
        Evaluate an access request against all policies.
        
        Args:
            request: The access request (user, resource, action, context)
            user_attributes: Additional user info (role, department, etc.)
            
        Returns:
            Tuple of (decision, source, matched_policy_id)
        """
        logger.debug(
            f"Evaluating access: user={request.user_id}, "
            f"resource={request.resource}, action={request.action}"
        )
        
        # Build context for condition evaluation
        context = self._build_evaluation_context(request, user_attributes)
        
        # Evaluate policies in priority order
        for policy in self.policies:
            # Check if policy applies to this resource and action
            if not self._matches_resource(policy.resources, request.resource):
                continue
            
            if not self._matches_action(policy.actions, request.action):
                continue
            
            # Evaluate policy rules
            if self._evaluate_rules(policy.rules, context):
                logger.info(
                    f"Policy matched: {policy.name} (id={policy.id}) "
                    f"-> {policy.effect}"
                )
                
                decision = self._effect_to_decision(policy.effect)
                source = DecisionSource.POLICY
                
                # If effect is EVALUATE, let AI decide
                if policy.effect == PolicyEffect.EVALUATE:
                    source = DecisionSource.AI_ENGINE
                
                return decision, source, str(policy.id)
        
        # No policy matched - default deny
        logger.info("No policy matched, default DENY")
        return AccessDecision.DENIED, DecisionSource.DEFAULT, None
    
    def _build_evaluation_context(
        self,
        request: AccessRequest,
        user_attributes: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Build a flat context dictionary for condition evaluation.
        
        Keys are dot-notation paths like 'user.role', 'env.time_hour'
        """
        now = datetime.utcnow()
        
        context = {
            # User attributes
            "user.id": request.user_id,
            "user.role": user_attributes.get("role", "user"),
            "user.department": user_attributes.get("department", ""),
            "user.is_active": user_attributes.get("is_active", True),
            
            # Resource attributes
            "resource.path": request.resource,
            "resource.type": self._extract_resource_type(request.resource),
            
            # Action
            "action": request.action,
            
            # Environment/Context
            "env.ip_address": request.context.ip_address,
            "env.user_agent": request.context.user_agent,
            "env.device_type": request.context.device_type,
            "env.location": request.context.location,
            "env.time_hour": now.hour,
            "env.time_day": now.strftime("%A"),  # Monday, Tuesday, etc.
            "env.timestamp": now.isoformat(),
        }
        
        # Add any additional metadata
        for key, value in request.metadata.items():
            context[f"meta.{key}"] = value
        
        return context
    
    def _matches_resource(self, patterns: List[str], resource: str) -> bool:
        """Check if resource matches any pattern (supports wildcards)"""
        for pattern in patterns:
            if pattern == "*":
                return True
            # Use fnmatch for glob-style matching
            if fnmatch.fnmatch(resource, pattern):
                return True
            # Also try prefix matching for paths
            if resource.startswith(pattern.rstrip("*")):
                return True
        return False
    
    def _matches_action(self, patterns: List[str], action: str) -> bool:
        """Check if action matches any pattern"""
        for pattern in patterns:
            if pattern == "*":
                return True
            if pattern.lower() == action.lower():
                return True
        return False
    
    def _evaluate_rules(
        self,
        rules: List[PolicyRule],
        context: Dict[str, Any]
    ) -> bool:
        """
        Evaluate policy rules.
        
        Multiple rules = OR logic (any rule can match)
        Multiple conditions in a rule = AND logic (all must match)
        """
        if not rules:
            # No rules means policy always applies
            return True
        
        for rule in rules:
            if self._evaluate_single_rule(rule, context):
                return True
        
        return False
    
    def _evaluate_single_rule(
        self,
        rule: PolicyRule,
        context: Dict[str, Any]
    ) -> bool:
        """Evaluate a single rule (all conditions must match)"""
        if not rule.conditions:
            return True
        
        for condition in rule.conditions:
            if not self._evaluate_condition(condition, context):
                return False
        
        return True
    
    def _evaluate_condition(
        self,
        condition: Condition,
        context: Dict[str, Any]
    ) -> bool:
        """
        Evaluate a single condition against the context.
        """
        # Handle both dict and Condition object
        if isinstance(condition, dict):
            attribute = condition.get("attribute", "")
            operator = condition.get("operator", "")
            value = condition.get("value")
        else:
            attribute = condition.attribute
            operator = condition.operator.value if hasattr(condition.operator, 'value') else condition.operator
            value = condition.value
        
        # Get actual value from context
        actual_value = context.get(attribute)
        
        if actual_value is None:
            # Attribute not found
            return operator == ConditionOperator.NOT_EQUALS.value
        
        try:
            return self._compare_values(operator, actual_value, value)
        except Exception as e:
            logger.warning(f"Condition evaluation error: {e}")
            return False
    
    def _compare_values(
        self,
        operator: str,
        actual: Any,
        expected: Any
    ) -> bool:
        """Compare values based on operator"""
        
        if operator == ConditionOperator.EQUALS.value or operator == "equals":
            return str(actual).lower() == str(expected).lower()
        
        elif operator == ConditionOperator.NOT_EQUALS.value or operator == "not_equals":
            return str(actual).lower() != str(expected).lower()
        
        elif operator == ConditionOperator.CONTAINS.value or operator == "contains":
            return str(expected).lower() in str(actual).lower()
        
        elif operator == ConditionOperator.IN.value or operator == "in":
            if isinstance(expected, list):
                return actual in expected
            return str(actual) in str(expected)
        
        elif operator == ConditionOperator.NOT_IN.value or operator == "not_in":
            if isinstance(expected, list):
                return actual not in expected
            return str(actual) not in str(expected)
        
        elif operator == ConditionOperator.GREATER_THAN.value or operator == "greater_than":
            return float(actual) > float(expected)
        
        elif operator == ConditionOperator.LESS_THAN.value or operator == "less_than":
            return float(actual) < float(expected)
        
        elif operator == ConditionOperator.BETWEEN.value or operator == "between":
            if isinstance(expected, list) and len(expected) == 2:
                return float(expected[0]) <= float(actual) <= float(expected[1])
            return False
        
        elif operator == ConditionOperator.REGEX.value or operator == "regex":
            return bool(re.match(str(expected), str(actual)))
        
        return False
    
    def _effect_to_decision(self, effect: PolicyEffect) -> AccessDecision:
        """Convert policy effect to access decision"""
        if effect == PolicyEffect.ALLOW:
            return AccessDecision.ALLOWED
        elif effect == PolicyEffect.DENY:
            return AccessDecision.DENIED
        else:  # EVALUATE
            return AccessDecision.CHALLENGED  # Will be decided by AI
    
    def _extract_resource_type(self, resource: str) -> str:
        """Extract resource type from path"""
        if resource.startswith("/api"):
            return "api"
        if "." in resource.split("/")[-1]:
            return "file"
        return "path"
