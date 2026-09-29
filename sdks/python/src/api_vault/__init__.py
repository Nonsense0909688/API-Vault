import requests


class APIVaultError(Exception):
    """Base API-Vault error."""


class AuthenticationError(APIVaultError):
    """Authentication failed or session expired."""


class APIVault:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        # Browser-like HTTP client
        self.session = requests.Session()

        self.session_id = None
        self.authenticated = False

    # -------------------------
    # Internal request handler
    # -------------------------

    def _request(self, method: str, path: str, **kwargs):
        kwargs.setdefault("timeout", self.timeout)

        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                **kwargs
            )
        except requests.RequestException as e:
            raise APIVaultError(
                f"Failed to connect to API-Vault: {e}"
            ) from e

        if response.status_code == 401:
            self.authenticated = False
            self.session_id = None

            raise AuthenticationError(
                "Authentication failed or session expired"
            )

        response.raise_for_status()

        return response

    def _json(self, response):
        try:
            return response.json()

        except ValueError as e:
            raise APIVaultError(
                f"Server returned invalid JSON "
                f"({response.status_code}): "
                f"{response.text[:500]}"
            ) from e

    # -------------------------
    # Authentication
    # -------------------------

    def login(self, key: str):
        try:
            response = self.session.post(
                f"{self.base_url}/login/post",
                json={"key": key},
                timeout=self.timeout,
                allow_redirects=False
            )
        except requests.RequestException as e:
            raise APIVaultError(f"Failed to connect: {e}") from e

        if response.status_code != 303:
            raise APIVaultError(
                f"Login failed: {response.status_code}: {response.text}"
            )

        self.session_id = self.session.cookies.get("session")

        if not self.session_id:
            raise APIVaultError("No session cookie received")

        self.authenticated = True

        return {
            "authenticated": True,
            "session_id": self.session_id
        }

    def logout(self):
        response = self._request(
            "GET",
            "/logout"
        )

        self.session_id = None
        self.authenticated = False
        self.session.cookies.clear()

        return response

    def is_authenticated(self):
        return (
            self.authenticated
            and self.session_id is not None
        )

    # -------------------------
    # Secrets
    # -------------------------

    def get_secrets(self):
        response = self._request(
            "GET",
            "/view_secrets"
        )

        return self._json(response)

    def save_secret(self, key: str, value: str):
        response = self._request(
            "POST",
            "/save_secrets",
            json={
                "key": key,
                "value": value
            }
        )

        return self._json(response)

    def delete_secret(self, key: str):
        response = self._request(
            "DELETE",
            "/remove_secrets",
            json={
                "key": key
            }
        )

        return self._json(response)

    def get_secret(self, key: str):
        secrets = self.get_secrets()

        for secret in secrets:
            if secret.get("key") == key:
                return secret.get("value")

        return None

    # -------------------------
    # Session information
    # -------------------------

    def get_session_id(self):
        return self.session_id

    def get_session_cookie(self):
        return self.session.cookies.get("session")

    # -------------------------
    # Connection
    # -------------------------

    def close(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

