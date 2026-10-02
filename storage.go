package main

// storage.go
//
// API-Vault persistent application data is stored in MySQL.
//
// MySQL tables:
//   - users
//   - sessions
//   - secrets
//   - secret_permissions
//
// JSON-based storage has been removed.
//
// The encryption key is still stored on disk and is handled by the
// encryption-key management code. This file does not manage the key.
