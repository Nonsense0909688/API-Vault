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
- Session-based authentication
- Automatic session expiration
- Create, view, update, and delete secrets
- Configurable server and authentication settings
- Local storage
- Lightweight deployment
- 12.6 MB(s) executable

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

## Self-Hosting

API-Vault is designed to run on your own machine or server, giving you control over where your secrets are stored and how the service is accessed.

## Security

API-Vault uses:

- AES-256-GCM for secret encryption
- Random 32-byte encryption keys
- Session-based authentication
- Configurable session expiration
- Local encrypted secret storage

> API-Vault is intended to provide secure secret management, but proper server security, access control, backups, and network configuration are still the responsibility of the operator.

## Visuals

![Image description](<images/new/Screenshot%20(497).png>)
![Image description](<images/new/Screenshot%20(498).png>)
![Image description](<images/new/Screenshot (499).png>)
![Image description](<images/new/Screenshot (500).png>)
![Image description](<images/new/Screenshot (501).png>)
