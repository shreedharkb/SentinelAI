from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.policies import router as policies_router

# Main API router that includes all sub-routers
api_router = APIRouter(prefix="/api")

# Include authentication routes
api_router.include_router(auth_router)

# Include policy routes
api_router.include_router(policies_router)
