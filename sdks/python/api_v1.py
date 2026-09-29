import requests


class APIVault:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def login(self, key: str):
        response = self.session.post(
            f"{self.base_url}/login/post",
            json={"key": key}
        )

        response.raise_for_status()
        return response

    def get_secrets(self):
        response = self.session.get(
            f"{self.base_url}/api/v1/secrets"
        )

        response.raise_for_status()
        return response.json()

    def logout(self):
        response = self.session.get(
            f"{self.base_url}/logout"
        )

        response.raise_for_status()
        return response
    
    def __del__(self):
        self.logout()