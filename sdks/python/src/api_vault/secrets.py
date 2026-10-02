from .errors import APIVaultError


class SecretsAPI:
    def __init__(self, client):
        self.client = client

    def get_all(self):
        response = self.client.request("GET", "/api/secrets")
        data = self.client.json(response)

        for secret in data:
            secret.pop("value", None)

        return data

    def reveal(self, secret_id):
        response = self.client.request(
            "GET",
            "/api/secrets/value",
            params={"id": secret_id}
        )

        return self.client.json(response).get("value")

    def get(self, key):
        for secret in self.get_all():
            if secret.get("key") == key:
                secret_id = secret.get("id")

                if secret_id is None:
                    raise APIVaultError(
                        f"Secret '{key}' does not contain an ID"
                    )

                return self.reveal(secret_id)

        return None

    def save(self, key, value):
        response = self.client.request(
            "POST",
            "/save_secrets",
            json={"key": key, "value": value}
        )

        return self.client.json(response)

    def delete(self, key):
        response = self.client.request(
            "DELETE",
            "/remove_secrets",
            json={"key": key}
        )

        return self.client.json(response)