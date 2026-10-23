from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration loaded from the .env file.
    """

    # Application
    APP_NAME: str = "CyberShield"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # Server
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Security
    SECRET_KEY: str = "4F9vL8mQ2xN7pR5tY1kW6cH3jD9sZ0aE8uB5nX2qP7mR4tK"

    # Database
    DATABASE_URL: str = "sqlite:///./cybershield.db"

    # Storage
    UPLOAD_DIR: str = "uploads"
    REPORT_DIR: str = "reports"
    RECOVERY_OUTPUT_DIR: str = "recovery-output"

    # Upload Settings
    MAX_FILE_SIZE: int = 50 * 1024 * 1024
    ALLOWED_EXTENSIONS: str = "exe,dll,zip,7z,rar,bin,pdf,docx,txt"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
