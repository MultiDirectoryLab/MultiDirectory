"""API module."""
from .auth.router import auth_router
from .main.router import entry_router

__all__ = ['auth_router', 'entry_router']
