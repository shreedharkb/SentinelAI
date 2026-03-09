from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.database import Database
from typing import Optional
from loguru import logger

from app.core.config import get_settings


class MongoDB:
    """
    MongoDB connection manager.
    Uses Motor for async operations.
    """
    
    client: Optional[AsyncIOMotorClient] = None
    database: Optional[Database] = None
    
    async def connect(self):
        """Establish connection to MongoDB"""
        settings = get_settings()
        
        logger.info(f"Connecting to MongoDB at {settings.mongodb_url}")
        
        self.client = AsyncIOMotorClient(settings.mongodb_url)
        self.database = self.client[settings.mongodb_db_name]
        
        # Verify connection
        await self.client.admin.command("ping")
        logger.info(f"Connected to MongoDB database: {settings.mongodb_db_name}")
    
    async def disconnect(self):
        """Close MongoDB connection"""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
    
    def get_collection(self, name: str):
        """Get a collection from the database"""
        if self.database is None:
            raise RuntimeError("Database not connected. Call connect() first.")
        return self.database[name]


# Global instance
mongodb = MongoDB()


async def get_database() -> Database:
    """Dependency to get database instance"""
    if mongodb.database is None:
        await mongodb.connect()
    return mongodb.database
