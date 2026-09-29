# API-Vault

*"A secure, self-hosted way to save, view, and use your API secrets."*

## Why?

Secrets don't always get leaked by hackers.

A developer can accidentally commit a `.env` file, push credentials to GitHub, or store API keys as plain text. As a project grows, managing secrets securely can become increasingly difficult.

**API-Vault** provides a self-hosted central place to securely store and manage API keys, tokens, passwords, and other secrets.

It provides:

- A web dashboard for managing secrets
- A REST API for programmatic access
- Python and JavaScript SDKs
- Encrypted secret storage
- Session-based authentication
- Automatic session expiration

---

## How?

API-Vault encrypts stored secret values using **AES-256-GCM** encryption.

Each installation generates a random **32-byte encryption key** which is stored locally and reused across restarts.

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