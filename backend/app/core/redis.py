import redis.asyncio as redis
from typing import Optional
from loguru import logger

from app.core.config import get_settings


class RedisClient:
    """
    Redis connection manager.
    Used for caching and pub/sub messaging.
    """
    
    client: Optional[redis.Redis] = None
    
    async def connect(self):
        """Establish connection to Redis"""
        settings = get_settings()
        
        logger.info(f"Connecting to Redis at {settings.redis_url}")
        
        self.client = redis.from_url(
            settings.redis_url,
            db=settings.redis_db,
            decode_responses=True
        )
        
        # Verify connection
        await self.client.ping()
        logger.info("Connected to Redis")
    
    async def disconnect(self):
        """Close Redis connection"""
        if self.client:
            await self.client.close()
            logger.info("Disconnected from Redis")
    
    async def publish(self, channel: str, message: str):
        """Publish message to a channel"""
        if self.client:
            await self.client.publish(channel, message)
    
    async def get(self, key: str) -> Optional[str]:
        """Get value from cache"""
        if self.client:
            return await self.client.get(key)
        return None
    
    async def set(self, key: str, value: str, expire: int = None):
        """Set value in cache with optional expiration (seconds)"""
        if self.client:
            await self.client.set(key, value, ex=expire)


# Global instance
redis_client = RedisClient()


async def get_redis() -> redis.Redis:
    """Dependency to get Redis client"""
    if redis_client.client is None:
        await redis_client.connect()
    return redis_client.client
