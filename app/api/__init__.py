"""API module."""
from .auth.router import auth_router
from .main.router import entry_router
from .multifactor.router import mfa_router
from .network.router import network_router

__all__ = ['auth_router', 'entry_router', 'network_router', 'mfa_router']
