"""Module with settings."""

from pydantic import BaseSettings, IPvAnyAddress, PostgresDsn, validator


class Settings(BaseSettings):
    """Settigns with database dsn."""

    DEBUG: bool
    HOST: IPvAnyAddress

    POSTGRES_SCHEMA: str = 'postgresql+asyncpg'
    POSTGRES_DB: str = 'postgres'

    POSTGRES_HOST: str
    POSTGRES_USER: str
    POSTGRES_PWD: str

    POSTGRES_URI: PostgresDsn = None  # type: ignore

    @validator('POSTGRES_URI', pre=True, always=True)
    def create_postgres(cls, v, values):  # noqa: N805
        """Build postgres DSN."""
        return (
            f"{values['POSTGRES_SCHEMA']}://"  # type: ignore
            f"{values['POSTGRES_USER']}:"
            f"{values['POSTGRES_PWD']}@"
            f"{values['POSTGRES_HOST']}/"
            f"{values['POSTGRES_DB']}"
        )

    VENDOR_NAME: str = "MultiFactor"
    VENDOR_VERSION: str = '0.1.2'


settings = Settings()
