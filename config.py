from datetime import timedelta
from pathlib import Path
from typing import ClassVar, Optional

from decouple import config
from pydantic_settings import BaseSettings

# Use this to build paths inside the project
BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    # Debug mode
    DEBUG: bool = config("DEBUG", default=False, cast=bool)
    ENVIRONMENT: str = config("ENVIRONMENT", default="dev")

    # Application port
    APP_PORT: int = config("APP_PORT", default=8000, cast=int)

    # Database configurations
    DB_HOST: str = config("DB_HOST", default="localhost")
    DB_PORT: int = config("DB_PORT", default=5432, cast=int)
    POSTGRES_USER: str = config("POSTGRES_USER", default="user")
    POSTGRES_PASSWORD: str = config("POSTGRES_PASSWORD", default="password")
    POSTGRES_DB: str = config("POSTGRES_DB", default="db.sqlite3")
    DB_TYPE: str = config("DB_TYPE", default="sqlite")
    
    # Optional database URL (if provided directly)
    database_url: Optional[str] = None

    # JWT Configuration
    JWT_SECRET: str = config("JWT_SECRET", default="your_default_secret")
    JWT_ALGORITHM: str = config("JWT_ALGORITHM", default="HS256")
    ACCESS_TOKEN_EXPIRY: int = config("ACCESS_TOKEN_EXPIRY", default=300, cast=int)
    REFRESH_TOKEN_EXPIRY: int = config("REFRESH_TOKEN_EXPIRY", default=2, cast=int)
    JTI_EXPIRY: int = config("JTI_EXPIRY", default=300, cast=int)

    # Redis Configuration
    REDIS_HOST: str = config("REDIS_HOST", default="localhost")
    REDIS_PORT: int = config("REDIS_PORT", default=6379, cast=int)

    # Cookie configuration
    COOKIE_DOMAIN: ClassVar[str] = "<YOUR-APP-NAME.COM>  E.G google.com"
    COOKIE_MAX_AGE: ClassVar[int] = int(timedelta(days=REFRESH_TOKEN_EXPIRY).total_seconds())



    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()   