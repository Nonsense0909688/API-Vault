import requests
from .errors import (
    APIVaultError,
    AuthenticationError,
    AuthorizationError,
)


class HTTPClient:
    def __init__(self, base_url, timeout=10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def request(self, method, path, **kwargs):
        kwargs.setdefault("timeout", self.timeout)

        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                **kwargs
            )
        except requests.RequestException as e:
            raise APIVaultError(f"Failed to connect: {e}") from e

        if response.status_code == 401:
            raise AuthenticationError("Authentication failed or session expired")

        if response.status_code == 403:
            raise AuthorizationError("You are not allowed to perform this action")

        response.raise_for_status()
        return response

    @staticmethod
    def json(response):
        try:
            return response.json()
        except ValueError as e:
            raise APIVaultError(
                f"Server returned invalid JSON ({response.status_code}): "
                f"{response.text[:500]}"
            ) from e

    def close(self):
        self.session.close()