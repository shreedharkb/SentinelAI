from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from loguru import logger

from app.core.database import get_database
from app.core.dependencies import get_current_user, require_admin
from app.models.user import UserInDB
from app.models.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyResponse,
    PolicyStatus,
)
from app.services.policy_service import PolicyService


router = APIRouter(prefix="/policies", tags=["Policies"])


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy(
    policy_data: PolicyCreate,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """
    Create a new access policy. **Admin only.**
    
    Policies define who can access what resources under what conditions.
    
    - **name**: Descriptive policy name
    - **effect**: allow, deny, or evaluate (AI decides)
    - **resources**: Resource patterns (supports wildcards)
    - **actions**: Actions this policy applies to
    - **rules**: Conditions that must be met
    - **priority**: Higher = evaluated first (0-1000)
    """
    policy_service = PolicyService(db)
    
    policy = await policy_service.create_policy(
        policy_data=policy_data,
        created_by=str(current_user.id)
    )
    
    return policy


@router.get("", response_model=List[PolicyResponse])
async def list_policies(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    status_filter: Optional[PolicyStatus] = Query(None, alias="status"),
    include_inactive: bool = Query(False),
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_database)
):
    """
    List all policies ordered by priority.
    
    By default, only active policies are returned.
    Use `include_inactive=true` to see all policies.
    """
    policy_service = PolicyService(db)
    
    policies = await policy_service.get_policies(
        skip=skip,
        limit=limit,
        status=status_filter,
        include_inactive=include_inactive
    )
    
    return policies


@router.get("/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    current_user: UserInDB = Depends(get_current_user),
    db = Depends(get_database)
):
    """Get a specific policy by ID."""
    policy_service = PolicyService(db)
    
    policy = await policy_service.get_policy_by_id(policy_id)
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    return policy


@router.put("/{policy_id}", response_model=PolicyResponse)
async def update_policy(
    policy_id: str,
    policy_data: PolicyUpdate,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """
    Update a policy. **Admin only.**
    
    Only provided fields will be updated.
    Version number is automatically incremented.
    """
    policy_service = PolicyService(db)
    
    policy = await policy_service.update_policy(
        policy_id=policy_id,
        policy_data=policy_data,
        updated_by=str(current_user.id)
    )
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """Delete a policy. **Admin only.**"""
    policy_service = PolicyService(db)
    
    deleted = await policy_service.delete_policy(policy_id)
    
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    logger.info(f"Policy {policy_id} deleted by {current_user.email}")


@router.post("/{policy_id}/activate", response_model=PolicyResponse)
async def activate_policy(
    policy_id: str,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """Activate a policy. **Admin only.**"""
    policy_service = PolicyService(db)
    
    policy = await policy_service.activate_policy(policy_id)
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    logger.info(f"Policy {policy_id} activated by {current_user.email}")
    return policy


@router.post("/{policy_id}/deactivate", response_model=PolicyResponse)
async def deactivate_policy(
    policy_id: str,
    current_user: UserInDB = Depends(require_admin),
    db = Depends(get_database)
):
    """Deactivate a policy. **Admin only.**"""
    policy_service = PolicyService(db)
    
    policy = await policy_service.deactivate_policy(policy_id)
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy not found"
        )
    
    logger.info(f"Policy {policy_id} deactivated by {current_user.email}")
    return policy
