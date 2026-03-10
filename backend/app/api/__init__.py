from fastapi import APIRouter
from app.api.auth import router as auth_router

# Main API router that includes all sub-routers
api_router = APIRouter(prefix="/api")

# Include authentication routes
api_router.include_router(auth_router)
