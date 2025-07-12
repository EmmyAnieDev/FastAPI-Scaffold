from pathlib import Path

from decouple import config
from pydantic_settings import BaseSettings

# Use this to build paths inside the project
BASE_DIR = Path(__file__).resolve().parent


class Settings(BaseSettings):
    # Debug mode
    DEBUG: bool = config("DEBUG", default=False, cast=bool)

    # Application port
    APP_PORT: int = config("APP_PORT", default=8000, cast=int)


    class Config:
        env_file = ".env"
        extra = "allow"


settings = Settings()   