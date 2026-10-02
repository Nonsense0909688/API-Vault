class APIVaultError(Exception):
    """Base API-Vault error."""


class AuthenticationError(APIVaultError):
    """Authentication failed or session expired."""


class AuthorizationError(APIVaultError):
    """Authenticated user is not allowed to perform the action."""