## Python

The API-Vault Python client allows you to authenticate with an API-Vault server, access secrets, and automatically manage the session.

### Installation

```bash
pip install requests
```

### Basic Usage

```python
from client import APIVault

vault = APIVault("http://localhost:8080")
vault.login("your-login-key")

secrets = vault.get_secrets()
print(secrets)

vault.logout()
```

### Automatic Logout

You can use `APIVault` as a context manager. The client will automatically log out when the `with` block ends.

```python
from client import APIVault

with APIVault("http://localhost:8080") as vault:
    vault.login("your-login-key")

    secrets = vault.get_secrets()
    print(secrets)
```

This is equivalent to:

```python
vault = APIVault("http://localhost:8080")

vault.login("your-login-key")

try:
    secrets = vault.get_secrets()
    print(secrets)
finally:
    vault.logout()
```

### API

#### `APIVault(base_url)`

Creates a client connected to an API-Vault server.

```python
vault = APIVault("http://localhost:8080")
```

#### `login(key)`

Authenticates with the API-Vault server and creates a session.

```python
vault.login("your-login-key")
```

#### `get_secrets()`

Retrieves the secrets available to the authenticated session.

```python
secrets = vault.get_secrets()
print(secrets)
```

#### `logout()`

Terminates the current session.

```python
vault.logout()
```

### Example

```python
from client import APIVault

vault = APIVault("http://localhost:8080")
vault.login("your-login-key")

for secret in vault.get_secrets():
    print(secret)

vault.logout()
```

> **Security:** Never hard-code your API-Vault login key or expose it in source code, public repositories, or logs.
