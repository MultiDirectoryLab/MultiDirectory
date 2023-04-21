"""Multidirectory api module."""

from fastapi import Depends, FastAPI

from config import Settings, get_settings
from models.database import AsyncSession, get_session


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create FastAPI app with dependencies overrides."""
    settings = settings or Settings()
    app = FastAPI(name="multidirectory", debug=settings.DEBUG)
    app.dependency_overrides = {
        get_settings: lambda: settings,
    }
    app.dependency_overrides[AsyncSession] = get_session
    return app


app = create_app()


@app.get('/')
def hello_world(settings: Settings = Depends(get_settings)):
    return "Hello World!"