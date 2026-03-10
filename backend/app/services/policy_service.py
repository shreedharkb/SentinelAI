from datetime import datetime
from typing import Optional, List
from bson import ObjectId
from loguru import logger
from pymongo.database import Database

from app.models.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyInDB,
    PolicyResponse,
    PolicyStatus,
)


class PolicyService:
    """
    Service layer for policy operations.
    Handles CRUD and policy management.
    """
    
    def __init__(self, db: Database):
        self.db = db
        self.collection = db["policies"]
    
    async def create_policy(
        self,
        policy_data: PolicyCreate,
        created_by: str
    ) -> PolicyResponse:
        """
        Create a new access policy.
        
        Args:
            policy_data: Policy definition
            created_by: User ID of creator
            
        Returns:
            Created policy
        """
        # Prepare document
        policy_doc = {
            "name": policy_data.name,
            "description": policy_data.description,
            "effect": policy_data.effect.value,
            "priority": policy_data.priority,
            "resources": policy_data.resources,
            "actions": policy_data.actions,
            "rules": [rule.model_dump() for rule in policy_data.rules],
            "status": policy_data.status.value,
            "created_by": created_by,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
            "version": 1,
        }
        
        # Insert into database
        result = await self.collection.insert_one(policy_doc)
        policy_doc["_id"] = result.inserted_id
        
        logger.info(f"Created policy: {policy_data.name} by user {created_by}")
        
        return self._to_response(policy_doc)
    
    async def get_policy_by_id(self, policy_id: str) -> Optional[PolicyResponse]:
        """Get policy by ID"""
        if not ObjectId.is_valid(policy_id):
            return None
        
        policy_doc = await self.collection.find_one({"_id": ObjectId(policy_id)})
        
        if policy_doc:
            return self._to_response(policy_doc)
        return None
    
    async def get_policies(
        self,
        skip: int = 0,
        limit: int = 100,
        status: Optional[PolicyStatus] = None,
        include_inactive: bool = False
    ) -> List[PolicyResponse]:
        """
        Get policies ordered by priority (highest first).
        
        Args:
            skip: Pagination offset
            limit: Max results
            status: Filter by status
            include_inactive: Include inactive/draft policies
        """
        query = {}
        
        if status:
            query["status"] = status.value
        elif not include_inactive:
            query["status"] = PolicyStatus.ACTIVE.value
        
        # Sort by priority descending (higher priority first)
        cursor = self.collection.find(query).sort("priority", -1).skip(skip).limit(limit)
        
        policies = []
        async for policy_doc in cursor:
            policies.append(self._to_response(policy_doc))
        
        return policies
    
    async def get_active_policies(self) -> List[PolicyInDB]:
        """
        Get all active policies for evaluation.
        Returns PolicyInDB for internal processing.
        """
        cursor = self.collection.find(
            {"status": PolicyStatus.ACTIVE.value}
        ).sort("priority", -1)
        
        policies = []
        async for policy_doc in cursor:
            policies.append(PolicyInDB(**policy_doc))
        
        return policies
    
    async def update_policy(
        self,
        policy_id: str,
        policy_data: PolicyUpdate,
        updated_by: str
    ) -> Optional[PolicyResponse]:
        """
        Update a policy. Increments version number.
        
        Args:
            policy_id: Policy ID to update
            policy_data: Fields to update
            updated_by: User making the update
        """
        if not ObjectId.is_valid(policy_id):
            return None
        
        # Build update document
        update_doc = {}
        
        if policy_data.name is not None:
            update_doc["name"] = policy_data.name
        if policy_data.description is not None:
            update_doc["description"] = policy_data.description
        if policy_data.effect is not None:
            update_doc["effect"] = policy_data.effect.value
        if policy_data.priority is not None:
            update_doc["priority"] = policy_data.priority
        if policy_data.resources is not None:
            update_doc["resources"] = policy_data.resources
        if policy_data.actions is not None:
            update_doc["actions"] = policy_data.actions
        if policy_data.rules is not None:
            update_doc["rules"] = [rule.model_dump() for rule in policy_data.rules]
        if policy_data.status is not None:
            update_doc["status"] = policy_data.status.value
        
        if not update_doc:
            return await self.get_policy_by_id(policy_id)
        
        update_doc["updated_at"] = datetime.utcnow()
        
        # Increment version and update
        result = await self.collection.find_one_and_update(
            {"_id": ObjectId(policy_id)},
            {
                "$set": update_doc,
                "$inc": {"version": 1}
            },
            return_document=True
        )
        
        if result:
            logger.info(f"Updated policy: {policy_id} by user {updated_by}")
            return self._to_response(result)
        
        return None
    
    async def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy"""
        if not ObjectId.is_valid(policy_id):
            return False
        
        result = await self.collection.delete_one({"_id": ObjectId(policy_id)})
        
        if result.deleted_count > 0:
            logger.info(f"Deleted policy: {policy_id}")
            return True
        
        return False
    
    async def activate_policy(self, policy_id: str) -> Optional[PolicyResponse]:
        """Set policy status to active"""
        return await self.update_policy(
            policy_id,
            PolicyUpdate(status=PolicyStatus.ACTIVE),
            "system"
        )
    
    async def deactivate_policy(self, policy_id: str) -> Optional[PolicyResponse]:
        """Set policy status to inactive"""
        return await self.update_policy(
            policy_id,
            PolicyUpdate(status=PolicyStatus.INACTIVE),
            "system"
        )
    
    async def count_policies(self, status: Optional[PolicyStatus] = None) -> int:
        """Count policies, optionally filtered by status"""
        query = {}
        if status:
            query["status"] = status.value
        
        return await self.collection.count_documents(query)
    
    def _to_response(self, policy_doc: dict) -> PolicyResponse:
        """Convert database document to response model"""
        return PolicyResponse(
            id=str(policy_doc["_id"]),
            name=policy_doc["name"],
            description=policy_doc.get("description"),
            effect=policy_doc["effect"],
            priority=policy_doc["priority"],
            resources=policy_doc["resources"],
            actions=policy_doc["actions"],
            rules=policy_doc["rules"],
            status=policy_doc["status"],
            created_by=policy_doc["created_by"],
            created_at=policy_doc["created_at"],
            updated_at=policy_doc["updated_at"],
            version=policy_doc["version"],
        )
