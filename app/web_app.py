"""Multidirectory api module."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import auth_router, entry_router
from config import Settings, get_settings
from models.database import get_async_session, get_session


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create FastAPI app with dependencies overrides."""
    settings = settings or Settings()
    app = FastAPI(name="multidirectory", debug=settings.DEBUG)
    origins = ["*"]
    app.dependency_overrides = {
        get_settings: lambda: settings,
        get_session: get_async_session,
    }
    app.include_router(auth_router)
    app.include_router(entry_router)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app
