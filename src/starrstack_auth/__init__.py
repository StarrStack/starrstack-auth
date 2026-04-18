"""Shared Auth0 authentication for StarrStack FastAPI projects."""

from starrstack_auth.core import init_auth, require_login

__all__ = ["init_auth", "require_login"]
__version__ = "0.1.0"
