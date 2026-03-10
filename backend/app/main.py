from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from app.core.config import get_settings
from app.core.database import mongodb
from app.core.redis import redis_client
from app.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifecycle manager for FastAPI application.
    Code before 'yield' runs on startup.
    Code after 'yield' runs on shutdown.
    """
    # Startup
    logger.info("Starting SentinelAI API...")
    settings = get_settings()
    
    # Connect to databases
    await mongodb.connect()
    await redis_client.connect()
    
    logger.info(f"SentinelAI API started in {settings.app_env} mode")
    
    yield  # Application runs here
    
    # Shutdown
    logger.info("Shutting down SentinelAI API...")
    await mongodb.disconnect()
    await redis_client.disconnect()
    logger.info("SentinelAI API stopped")


settings = get_settings()

app = FastAPI(
    title="SentinelAI",
    description="AI-Powered Dynamic Access Control System",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware - allows frontend to communicate with backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(api_router)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"message": "SentinelAI API is running", "version": "0.1.0"}


@app.get("/health")
async def health_check():
    """Detailed health check"""
    return {
        "status": "healthy",
        "service": "SentinelAI API",
        "version": "0.1.0",
        "environment": settings.app_env
    }
