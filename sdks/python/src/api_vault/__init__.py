from .client import APIVault
from .errors import (
    APIVaultError,
    AuthenticationError,
    AuthorizationError,
)

__all__ = [
    "APIVault",
    "APIVaultError",
    "AuthenticationError",
    "AuthorizationError",
]

__version__ = "1.0.0"