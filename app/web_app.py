"""Multidirectory api module."""

from fastapi import FastAPI

from api import auth_router
from config import Settings, get_settings
from models.database import get_async_session, get_session


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create FastAPI app with dependencies overrides."""
    settings = settings or Settings()
    app = FastAPI(name="multidirectory", debug=settings.DEBUG)
    app.dependency_overrides = {
        get_settings: lambda: settings,
        get_session: get_async_session,
    }
    app.include_router(auth_router)
    return app
