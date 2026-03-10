from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.policies import router as policies_router
from app.api.access import router as access_router
from app.api.users import router as users_router

# Main API router that includes all sub-routers
api_router = APIRouter(prefix="/api")

# Include authentication routes
api_router.include_router(auth_router)

# Include policy routes
api_router.include_router(policies_router)

# Include access control routes
api_router.include_router(access_router)

# Include user management routes
api_router.include_router(users_router)
