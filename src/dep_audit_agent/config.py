"""Application settings, loaded from environment / .env."""

from functools import cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    anthropic_api_key: SecretStr
    anthropic_model: str = "claude-sonnet-5"


@cache
def get_settings() -> Settings:
    return Settings()
