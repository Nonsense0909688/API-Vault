from .http import HTTPClient
from .auth import AuthAPI
from .secrets import SecretsAPI


class APIVault:
    def __init__(self, base_url, timeout=10):
        self.authenticated = False

        self.http = HTTPClient(
            base_url,
            timeout
        )

        self.auth = AuthAPI(self.http)
        self.secrets = SecretsAPI(self.http)

    def login(self, username, password):
        return self.auth.login(username, password)

    def logout(self):
        return self.auth.logout()

    def is_authenticated(self):
        return self.authenticated

    def get_session_cookie(self):
        return self.http.session.cookies.get("session")

    def close(self):
        self.http.close()
        self.authenticated = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()