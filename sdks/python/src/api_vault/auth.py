from .errors import (
    APIVaultError,
    AuthenticationError
)

class AuthAPI:
    def __init__(self, client):
        self.client = client

    def login(self, username, password):
        response = self.client.session.post(
            f"{self.client.base_url}/login/post",
            json={
                "username": username,
                "password": password
            },
            timeout=self.client.timeout,
            allow_redirects=False
        )

        if response.status_code == 429:
            raise APIVaultError(
                "Too many failed login attempts. Try again later."
            )

        if response.status_code == 401:
            raise AuthenticationError("Invalid username or password")

        if response.status_code != 303:
            raise APIVaultError(
                f"Login failed: {response.status_code}: {response.text}"
            )

        if not self.client.session.cookies.get("session"):
            raise APIVaultError(
                "Login succeeded but no session cookie was received"
            )

        self.client.authenticated = True

        return {"authenticated": True}

    def logout(self):
        response = self.client.request("GET", "/logout")

        self.client.authenticated = False
        self.client.session.cookies.clear()

        return response