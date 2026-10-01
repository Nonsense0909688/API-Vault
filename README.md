# API-Vault

_"A secure, self-hosted way to save, view, and use your API secrets."_

## Why?

Secrets don't always get leaked by hackers.

A developer can accidentally commit a `.env` file, push credentials to GitHub, or store API keys as plain text. As a project grows, managing secrets securely can become increasingly difficult.

**API-Vault** provides a self-hosted central place to securely store and manage API keys, tokens, passwords, and other secrets.

## Features

- AES-256-GCM encrypted secret storage
- Self-hosted
- Web dashboard
- REST API
- Python SDK
- JavaScript SDK
- Session-based authentication with bcrypt password hashing
- Automatic session expiration
- Per-user ownership and explicit sharing, with admin override
- Create, view, update, and delete secrets
- Configurable server, storage, and session settings
- Local storage
- Runs on Windows, Linux, and macOS
- Lightweight deployment
- 12.6 MB(s) executable

## How?

API-Vault encrypts stored secret values using **AES-256-GCM** encryption.

Each installation generates a random **32-byte encryption key** which is stored locally and reused across restarts.

By default that key is written to `<appfolder>/encryption.key`, right next to the encrypted `secrets.json`. That is convenient, but it means anyone who can read the data directory can also decrypt it. For anything beyond a single-user machine, move the key out of that directory with `storage.key_file` or the `API_VAULT_ENCRYPTION_KEY` environment variable (see [Configuration](#configuration)).

```text
Secret
   │
   ▼
AES-256-GCM
   │
   ▼
Encrypted Value
   │
   ▼
secrets.json
```

## Architecture

```text
Client
  │
  ├── Web Dashboard
  ├── REST API
  └── Python SDK
          │
          ▼
      API-Vault
          │
          ▼
   AES-256-GCM Encryption
          │
          ▼
      Local Storage
```

## Installation

```bash
pip install api-vault-sdk
```

## Configuration

On first start API-Vault writes a `config.yml` next to the executable and generates a random admin password, which it prints to the log once. Log in with it, then change it.

```yaml
app-settings:
  port: 3000
  address: 127.0.0.1

auth:
  admin_username: "Admin"
  admin_password: "<generated on first run>"

storage:
  appfolder: "appdata"
  # Where to keep the AES key. Empty means <appfolder>/encryption.key,
  # which stores it beside the secrets it protects.
  key_file: ""

session:
  duration: 24h
  # Send the session cookie only over HTTPS. Turn this on whenever the
  # vault is reachable over TLS, including behind a TLS-terminating proxy.
  secure_cookies: false
```

| Setting | Default | Notes |
|---|---|---|
| `app-settings.port` | `3000` | Listening port. |
| `app-settings.address` | `127.0.0.1` | Bind address. Leave it on loopback unless you intend to expose the vault. |
| `auth.admin_username` | `Admin` | The admin account created on first start. |
| `auth.admin_password` | generated | Used only to create the admin account; changing it later does not change an existing account's password. |
| `storage.appfolder` | `appdata` | Directory for `secrets.json`, `users.json`, `permissions.json`, `sessions.json`. |
| `storage.key_file` | *(empty)* | Path to the AES key. Set it to keep the key off the data directory. |
| `session.duration` | `24h` | Any Go duration, e.g. `30m`, `12h`. |
| `session.secure_cookies` | `false` | Marks the session cookie `Secure`. |

`config.yml` holds the admin password, so it is written with `0600`. API-Vault warns at startup if it finds looser permissions.

### Supplying the key from the environment

`API_VAULT_ENCRYPTION_KEY` takes precedence over both the config and the key file. It expects a hex-encoded 32-byte key:

```bash
export API_VAULT_ENCRYPTION_KEY=$(openssl rand -hex 32)
```

Keep a copy. Losing the key means losing every stored secret.

## Building from source

Requires Go 1.26 or newer.

```bash
go build -o api-vault .     # Linux / macOS
go build -o api-vault.exe . # Windows, or run utils\build.bat
```

Run the tests with:

```bash
go test ./...
```

## Self-Hosting

API-Vault is designed to run on your own machine or server, giving you control over where your secrets are stored and how the service is accessed.

## Security

API-Vault uses:

- AES-256-GCM for secret encryption
- Random 32-byte encryption keys
- bcrypt for password hashing
- Session-based authentication with random 256-bit session IDs
- Configurable session expiration
- Rate-limited login
- Local encrypted secret storage

### Access model

- A secret is owned by the user who created it.
- Only its owner and admins can overwrite it, delete it, or change who it is shared with.
- Other users see a secret only when the owner or an admin has explicitly shared it, and being able to read a shared secret does not allow changing it.
- Admins can see and manage everything.
- Deactivating or deleting an account invalidates its sessions immediately.

### Known limitations

- The default key location puts the encryption key in the same directory as the ciphertext. Use `storage.key_file` or `API_VAULT_ENCRYPTION_KEY` to separate them.
- Secrets are decrypted in the server process and returned in plaintext over the connection, so run the vault behind TLS and set `session.secure_cookies: true`.
- There is no built-in audit trail beyond the process log, and no secret versioning or rollback.

> API-Vault is intended to provide secure secret management, but proper server security, access control, backups, and network configuration are still the responsibility of the operator.

## Visuals

![Image description](<images/new/Screenshot%20(497).png>)
![Image description](<images/new/Screenshot%20(498).png>)
![Image description](<images/new/Screenshot (499).png>)
![Image description](<images/new/Screenshot (500).png>)
![Image description](<images/new/Screenshot (501).png>)
