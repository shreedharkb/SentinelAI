from pydantic_settings import BaseSettings
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    Pydantic automatically reads from .env file.
    """
    
    # Application
    app_name: str = "SentinelAI"
    app_env: str = "development"
    debug: bool = True
    secret_key: str = "sentinel"
    
    # MongoDB
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "sentinel_ai"
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    redis_db: int = 0
    
    # JWT
    jwt_secret_key: str = "sentinel"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # Ollama (Local LLM)
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "phi3:mini"  # Options: phi3:mini, gemma:2b, mistral
    
    # CORS
    cors_origins: str = "http://localhost:3000"
    
    # Logging
    log_level: str = "DEBUG"
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Convert comma-separated CORS origins to list"""
        return [origin.strip() for origin in self.cors_origins.split(",")]
    
    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached settings instance.
    Using lru_cache ensures settings are only loaded once.
    """
    return Settings()
